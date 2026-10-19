using System.Collections.Concurrent;
using System.Security.Claims;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Data;
using BTCPayServer.Plugins.NostrLogin;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using static BTCPayServer.Plugins.NostrLogin.Tests.TwoFactorGateTests;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// The pubkey → user map must keep "one key, one account" under concurrency: ownership checks
/// run in the same locked read-modify-write as the write they guard.
/// </summary>
public class PubkeyLinkAtomicityTests
{
    private const string BlackholeRelay = "wss://10.255.255.1:9";

    /// <summary>Settings store with an async read delay, so concurrent callers really interleave
    /// (a synchronous fake would serialize them and hide the race).</summary>
    private sealed class SlowSettingsRepository : ISettingsRepository
    {
        public ConcurrentDictionary<string, object> Store { get; } = new();

        public async Task<T?> GetSettingAsync<T>(string? name = null) where T : class
        {
            await Task.Delay(20);
            return Store.TryGetValue(typeof(T).Name, out var v) ? v as T : null;
        }

        public Task UpdateSetting<T>(T obj, string? name = null) where T : class
        {
            Store[typeof(T).Name] = obj!;
            return Task.CompletedTask;
        }

        public Task<T> WaitSettingsChanged<T>(CancellationToken cancellationToken = default) where T : class
            => throw new NotSupportedException();
    }

    private static UINostrLoginController ControllerFor(ApplicationUser user, ISettingsRepository repo,
        NostrLoginService service, Dictionary<string, ApplicationUser> users)
    {
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id)], "test"))
        };
        var userManager = new FakeUserManager(users);
        var signIn = new FakeSignInManager(userManager, new HttpContextAccessor { HttpContext = http }, false);
        return new UINostrLoginController(service, null!, new FakeProfilePictureService(), signIn, userManager,
            userService: null!, repo, new PoliciesSettings(), NullLogger<UINostrLoginController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
            Url = new SessionReuseTests.FakeUrlHelper()
        };
    }

    private static async Task<string> ApprovedLinkSession(NostrLoginService service, string userId, string pubkey)
    {
        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Link, [BlackholeRelay], "test", linkUserId: userId);
        session.Status = Nip46SessionStatus.Approved;
        session.UserPubkey = pubkey;
        return session.Id;
    }

    [Fact]
    public async Task ConcurrentLinksOfSameKey_ExactlyOneWins()
    {
        var (_, pubkey) = await NewKey();
        var alice = new ApplicationUser { Id = "alice" };
        var bob = new ApplicationUser { Id = "bob" };
        var users = new Dictionary<string, ApplicationUser> { [alice.Id] = alice, [bob.Id] = bob };
        var repo = new SlowSettingsRepository();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);

        var aliceSession = await ApprovedLinkSession(service, alice.Id, pubkey);
        var bobSession = await ApprovedLinkSession(service, bob.Id, pubkey);

        var results = await Task.WhenAll(
            ControllerFor(alice, repo, service, users).LinkStatus(aliceSession),
            ControllerFor(bob, repo, service, users).LinkStatus(bobSession));

        var statuses = results.Select(r => JsonOf(r).GetProperty("status").GetString()).ToArray();
        Assert.Single(statuses, s => s == "approved");
        Assert.Single(statuses, s => s == "failed");

        // The map owner must be the account that was told "approved".
        var winner = statuses[0] == "approved" ? alice.Id : bob.Id;
        var map = Assert.IsType<NostrLoginUserMap>(repo.Store[nameof(NostrLoginUserMap)]);
        Assert.Equal(winner, map.PubkeyToUserId[pubkey]);
    }

    [Fact]
    public async Task Unlink_ByNonOwner_LeavesLinkIntact()
    {
        var (_, pubkey) = await NewKey();
        var owner = new ApplicationUser { Id = "owner" };
        var other = new ApplicationUser { Id = "other" };
        var users = new Dictionary<string, ApplicationUser> { [owner.Id] = owner, [other.Id] = other };
        var repo = new SlowSettingsRepository();
        repo.Store[nameof(NostrLoginUserMap)] = new NostrLoginUserMap
        {
            PubkeyToUserId = new Dictionary<string, string> { [pubkey] = owner.Id }
        };
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);

        await ControllerFor(other, repo, service, users).Unlink(pubkey);

        var map = Assert.IsType<NostrLoginUserMap>(repo.Store[nameof(NostrLoginUserMap)]);
        Assert.Equal(owner.Id, map.PubkeyToUserId[pubkey]);
    }

    [Fact]
    public async Task UnlinkThenLogin_FailsImmediately()
    {
        var (_, pubkey) = await NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        const string nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        var rig = BuildRig(pubkey, twoFactorEnabled: false, service, bindCookieNonce: nonce);
        rig.HttpContext.User = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, rig.User.Id)], "test"));
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();

        Assert.IsType<RedirectToActionResult>(await rig.Controller.Unlink(pubkey));

        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Login, [BlackholeRelay], "test",
            bindingNonce: nonce);
        session.Status = Nip46SessionStatus.Approved;
        session.UserPubkey = pubkey;

        var body = JsonOf(await rig.Controller.LoginStatus(session.Id, "/"));
        Assert.Equal("failed", body.GetProperty("status").GetString());
        Assert.Equal(0, rig.SignIn.FullSignInCount);
    }
}
