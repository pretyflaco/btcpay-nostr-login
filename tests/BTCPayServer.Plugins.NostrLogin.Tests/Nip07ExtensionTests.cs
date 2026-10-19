using System.Security.Claims;
using System.Text.Json;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;
using NBitcoin.Secp256k1;
using NNostr.Client;
using static BTCPayServer.Plugins.NostrLogin.Tests.TwoFactorGateTests;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// NIP-07 (browser extension) login + link: the page signs a NIP-98 event (u = the extension
/// endpoint, method POST, challenge = the session's extension challenge) and posts it. The proof
/// must be session-, URL-, method- and browser-bound, fresh and single-use, and completion must
/// apply the same gates as the QR flow (2FA hand-off, CanLogin).
/// </summary>
public class Nip07ExtensionTests
{
    private const string BlackholeRelay = "wss://10.255.255.1:9";
    private const string Nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

    private static string LoginUrl(string sessionId) => $"https://{TestHost}/login/nostr/nip07/{sessionId}";
    private static string LinkUrl(string sessionId) => $"https://{TestHost}/account/nostr/link/nip07/{sessionId}";

    /// <summary>What window.nostr.signEvent returns, serialized as the page posts it.</summary>
    private static async Task<string> SignedJson(ECPrivKey key, string url, string challenge, string method = "POST",
        DateTimeOffset? createdAt = null)
    {
        var evt = new NostrEvent
        {
            Kind = 27235,
            PublicKey = key.CreateXOnlyPubKey().ToHex(),
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
            Content = $"Sign in to BTCPay Server at {TestHost}"
        };
        evt.SetTag("u", url);
        evt.SetTag("method", method);
        evt.SetTag("challenge", challenge);
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return JsonSerializer.Serialize(evt);
    }

    private sealed record Setup(Rig Rig, NostrLoginService Service, Nip46Session Session, ECPrivKey Key);

    /// <summary>Synchronous on purpose: BuildRig sets an HttpContextAccessor (AsyncLocal), which
    /// would not flow back to the test from an async helper (the 2FA path needs it).</summary>
    private static Setup LoginSetup(bool twoFactor = false, bool bindCookie = true)
    {
        var key = NostrExtensions.ParseKey(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var pubkey = key.CreateXOnlyPubKey().ToHex();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = service.CreateSessionAsync(Nip46SessionPurpose.Login, [BlackholeRelay], "test",
            bindingNonce: Nonce).GetAwaiter().GetResult(); // completes synchronously
        var repo = new FakeSettingsRepository();
        var rig = BuildRig(pubkey, twoFactor, service,
            replayStore: new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance),
            bindCookieNonce: bindCookie ? Nonce : null);
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();
        return new Setup(rig, service, session, key);
    }

    private static string Status(IActionResult result) => JsonBody(result).GetProperty("status").GetString()!;

    private static JsonElement JsonBody(IActionResult result) => result switch
    {
        JsonResult json => JsonSerializer.SerializeToElement(json.Value),
        ObjectResult obj => JsonSerializer.SerializeToElement(obj.Value),
        _ => throw new Xunit.Sdk.XunitException($"unexpected result {result.GetType().Name}")
    };

    // --- login ---

    [Fact]
    public async Task ValidProof_SignsIn_AndConsumesSession()
    {
        var s = LoginSetup();
        var json = await SignedJson(s.Key, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        var result = await s.Rig.Controller.ExtensionLogin(s.Session.Id, json, "/wallets");

        Assert.Equal("approved", Status(result));
        Assert.Equal("/wallets", JsonBody(result).GetProperty("redirect").GetString());
        Assert.Equal(1, s.Rig.SignIn.FullSignInCount);
        Assert.Null(s.Service.GetSession(s.Session.Id));
    }

    [Fact]
    public async Task TwoFactorAccount_HandsOffToSecondFactor()
    {
        var s = LoginSetup(twoFactor: true);
        var json = await SignedJson(s.Key, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        var result = await s.Rig.Controller.ExtensionLogin(s.Session.Id, json);

        Assert.Equal("2fa_required", Status(result));
        Assert.Equal("/login/second-login", JsonBody(result).GetProperty("redirect").GetString());
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
        Assert.Contains(IdentityConstants.TwoFactorUserIdScheme, s.Rig.Auth.SignInSchemes);
    }

    public static TheoryData<string> BadProofs() => new() { "wrong-challenge", "wrong-url", "wrong-method", "stale", "malformed", "oversized" };

    [Theory]
    [MemberData(nameof(BadProofs))]
    public async Task BadProof_Rejected_SessionStaysUsable(string kind)
    {
        var s = LoginSetup();
        var url = LoginUrl(s.Session.Id);
        var challenge = s.Session.ExtensionChallenge;
        var json = kind switch
        {
            "wrong-challenge" => await SignedJson(s.Key, url, "not-the-session-challenge"),
            "wrong-url" => await SignedJson(s.Key, LoginUrl(Guid.NewGuid().ToString("N")), challenge),
            "wrong-method" => await SignedJson(s.Key, url, challenge, method: "GET"),
            "stale" => await SignedJson(s.Key, url, challenge, createdAt: DateTimeOffset.UtcNow.AddMinutes(-11)),
            "malformed" => "{not json",
            _ => "{\"content\":\"" + new string('x', 20 * 1024) + "\"}"
        };

        var result = await s.Rig.Controller.ExtensionLogin(s.Session.Id, json);

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("failed", Status(result));
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
        // A bad proof must not consume the session: the real user can still complete it.
        var good = await SignedJson(s.Key, url, challenge);
        Assert.Equal("approved", Status(await s.Rig.Controller.ExtensionLogin(s.Session.Id, good)));
    }

    [Fact]
    public async Task OtherBrowser_WithoutBindCookie_Rejected()
    {
        var s = LoginSetup(bindCookie: false);
        var json = await SignedJson(s.Key, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        var result = await s.Rig.Controller.ExtensionLogin(s.Session.Id, json);

        Assert.Equal("failed", Status(result));
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
        Assert.NotNull(s.Service.GetSession(s.Session.Id));
    }

    [Fact]
    public async Task UnlinkedKey_Fails_AndProofIsSingleUse()
    {
        var s = LoginSetup();
        var (stranger, _) = await NewKey();
        var json = await SignedJson(stranger, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        Assert.Equal("failed", Status(await s.Rig.Controller.ExtensionLogin(s.Session.Id, json)));
        var replay = await s.Rig.Controller.ExtensionLogin(s.Session.Id, json);
        Assert.Equal("failed", Status(replay));
        Assert.Contains("already used", JsonBody(replay).GetProperty("error").GetString());
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
    }

    [Fact]
    public async Task RelayFailure_DoesNotBlockExtension()
    {
        // The NIP-46 leg failed (e.g. no relay reachable): the extension path needs no relays.
        var s = LoginSetup();
        s.Session.Status = Nip46SessionStatus.Failed;
        var json = await SignedJson(s.Key, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        Assert.Equal("approved", Status(await s.Rig.Controller.ExtensionLogin(s.Session.Id, json)));
    }

    [Fact]
    public async Task ExpiredSession_Rejected()
    {
        var s = LoginSetup();
        s.Session.CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-6);
        var json = await SignedJson(s.Key, LoginUrl(s.Session.Id), s.Session.ExtensionChallenge);

        Assert.Equal("failed", Status(await s.Rig.Controller.ExtensionLogin(s.Session.Id, json)));
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
    }

    [Fact]
    public async Task LinkSession_CannotBeUsedToLogIn()
    {
        var s = LoginSetup();
        var link = await s.Service.CreateSessionAsync(Nip46SessionPurpose.Link, [BlackholeRelay], "test", linkUserId: "user-1");
        var json = await SignedJson(s.Key, LoginUrl(link.Id), link.ExtensionChallenge);

        Assert.Equal("failed", Status(await s.Rig.Controller.ExtensionLogin(link.Id, json)));
        Assert.Equal(0, s.Rig.SignIn.FullSignInCount);
    }

    [Fact]
    public async Task LoginPage_RendersExtensionChallengeForItsSession()
    {
        var s = LoginSetup();
        s.Rig.Controller.TempData = new TempDataDictionary(s.Rig.HttpContext, new SessionReuseTests.FakeTempDataProvider());

        var view = Assert.IsType<ViewResult>(await s.Rig.Controller.Login());
        var vm = Assert.IsType<NostrLoginViewModel>(view.Model);
        var session = s.Service.GetSession(vm.SessionId)!;

        Assert.Equal(LoginUrl(session.Id), vm.ExtensionAuthUrl);
        Assert.Equal(session.ExtensionChallenge, vm.ExtensionChallenge);
        Assert.Contains(TestHost, vm.ExtensionPrompt);
    }

    // --- link ---

    private static async Task<(Setup S, Nip46Session Link)> LinkSetup(string userId = "user-1")
    {
        var s = LoginSetup();
        s.Rig.HttpContext.User = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, s.Rig.User.Id)], "test"));
        var link = await s.Service.CreateSessionAsync(Nip46SessionPurpose.Link, [BlackholeRelay], "test", linkUserId: userId);
        return (s, link);
    }

    private static NostrLoginUserMap Map(Setup s) => (NostrLoginUserMap)s.Rig.Repo.Store[nameof(NostrLoginUserMap)];

    [Fact]
    public async Task ExtensionLink_LinksNewKey()
    {
        var (s, link) = await LinkSetup();
        var (newKey, newPubkey) = await NewKey();
        var json = await SignedJson(newKey, LinkUrl(link.Id), link.ExtensionChallenge);

        Assert.Equal("approved", Status(await s.Rig.Controller.ExtensionLink(link.Id, json)));
        Assert.Equal(s.Rig.User.Id, Map(s).PubkeyToUserId[newPubkey]);
        Assert.Null(s.Service.GetSession(link.Id));
    }

    [Fact]
    public async Task ExtensionLink_KeyOwnedByAnotherAccount_Rejected()
    {
        var (s, link) = await LinkSetup();
        var (otherKey, otherPubkey) = await NewKey();
        Map(s).PubkeyToUserId[otherPubkey] = "someone-else";
        var json = await SignedJson(otherKey, LinkUrl(link.Id), link.ExtensionChallenge);

        var result = await s.Rig.Controller.ExtensionLink(link.Id, json);

        Assert.Equal("failed", Status(result));
        Assert.Equal("someone-else", Map(s).PubkeyToUserId[otherPubkey]);
    }

    [Fact]
    public async Task ExtensionLink_AnotherUsersSession_Rejected()
    {
        var (s, link) = await LinkSetup(userId: "someone-else");
        var (newKey, newPubkey) = await NewKey();
        var json = await SignedJson(newKey, LinkUrl(link.Id), link.ExtensionChallenge);

        Assert.Equal("failed", Status(await s.Rig.Controller.ExtensionLink(link.Id, json)));
        Assert.False(Map(s).PubkeyToUserId.ContainsKey(newPubkey));
    }

    [Fact]
    public async Task ExtensionLink_LoginUrlProof_Rejected()
    {
        // A proof minted for the login endpoint must not link (u-tag binding).
        var (s, link) = await LinkSetup();
        var (newKey, newPubkey) = await NewKey();
        var json = await SignedJson(newKey, LoginUrl(link.Id), link.ExtensionChallenge);

        Assert.IsType<UnauthorizedObjectResult>(await s.Rig.Controller.ExtensionLink(link.Id, json));
        Assert.False(Map(s).PubkeyToUserId.ContainsKey(newPubkey));
    }
}
