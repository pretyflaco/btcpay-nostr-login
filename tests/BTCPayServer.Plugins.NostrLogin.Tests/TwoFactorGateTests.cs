using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Data;
using BTCPayServer.Plugins.NostrLogin;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NBitcoin.Secp256k1;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// The 2FA gate (audit: nostr login must not downgrade a 2FA-enabled account to single-factor).
/// Possession of a nostr key is one possession factor, so when <c>TwoFactorEnabled</c> is set the
/// plugin must NOT issue the full auth cookie from key proof alone: the interactive paths hand off
/// to core's second-factor flow (/login/second-login), and the non-interactive NIP-98 POST refuses.
/// </summary>
public class TwoFactorGateTests
{
    private const string TestHost = "nostr.test";
    private static readonly string LoginUrl = $"https://{TestHost}/login/nostr/nip98";

    // --- fakes (no mocking framework in this project) ---

    private class FakeSettingsRepository : ISettingsRepository
    {
        public ConcurrentDictionary<string, object> Store { get; } = new();

        public Task<T?> GetSettingAsync<T>(string? name = null) where T : class
            => Task.FromResult(Store.TryGetValue(typeof(T).Name, out var v) ? v as T : null);

        public Task UpdateSetting<T>(T obj, string? name = null) where T : class
        {
            Store[typeof(T).Name] = obj!;
            return Task.CompletedTask;
        }

        public Task<T> WaitSettingsChanged<T>(CancellationToken cancellationToken = default) where T : class
            => throw new NotSupportedException();
    }

    private class FakeUserStore : IUserStore<ApplicationUser>
    {
        public void Dispose() { }
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.Id);
        public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.UserName);
        public Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken ct) => Task.CompletedTask;
        public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken ct) => Task.FromResult(user.UserName);
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken ct) => Task.CompletedTask;
        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken ct) => throw new NotSupportedException();
        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken ct) => throw new NotSupportedException();
        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken ct) => throw new NotSupportedException();
    }

    private class FakeUserManager : UserManager<ApplicationUser>
    {
        private readonly Dictionary<string, ApplicationUser> _byId;

        public FakeUserManager(Dictionary<string, ApplicationUser> byId)
            : base(new FakeUserStore(), null!, null!, null!, null!, null!, null!, null!, null!)
            => _byId = byId;

        public override Task<ApplicationUser?> FindByIdAsync(string userId)
            => Task.FromResult(_byId.TryGetValue(userId, out var u) ? u : null);
    }

    private class FakeClaimsPrincipalFactory : IUserClaimsPrincipalFactory<ApplicationUser>
    {
        public Task<ClaimsPrincipal> CreateAsync(ApplicationUser user)
            => Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity("test")));
    }

    private class FakeSchemeProvider : IAuthenticationSchemeProvider
    {
        public void AddScheme(AuthenticationScheme scheme) { }
        public void RemoveScheme(string name) { }
        public Task<AuthenticationScheme?> GetSchemeAsync(string name) => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync()
            => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
        public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync()
            => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
    }

    private class FakeUserConfirmation : IUserConfirmation<ApplicationUser>
    {
        public Task<bool> IsConfirmedAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
            => Task.FromResult(true);
    }

    private class FakeSignInManager : SignInManager<ApplicationUser>
    {
        private readonly bool _twoFactorEnabled;

        /// <summary>Full sign-ins — MUST stay zero for every 2FA path in these tests.</summary>
        public int FullSignInCount { get; private set; }

        public FakeSignInManager(UserManager<ApplicationUser> userManager, IHttpContextAccessor accessor, bool twoFactorEnabled)
            : base(userManager, accessor, new FakeClaimsPrincipalFactory(),
                Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
                NullLogger<SignInManager<ApplicationUser>>.Instance,
                new FakeSchemeProvider(), new FakeUserConfirmation())
            => _twoFactorEnabled = twoFactorEnabled;

        public override Task<bool> IsTwoFactorEnabledAsync(ApplicationUser user)
            => Task.FromResult(_twoFactorEnabled);

        public override Task SignInAsync(ApplicationUser user, bool isPersistent, string? authenticationMethod = null)
        {
            FullSignInCount++;
            return Task.CompletedTask;
        }
    }

    /// <summary>Records the schemes signed in on the HttpContext (the 2FA hand-off uses IdentityConstants.TwoFactorUserIdScheme).</summary>
    private class FakeAuthenticationService : IAuthenticationService
    {
        public List<string> SignInSchemes { get; } = new();

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            SignInSchemes.Add(scheme ?? "");
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => throw new NotSupportedException();
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
    }

    private class FakeServiceProvider : IServiceProvider
    {
        private readonly IAuthenticationService _auth;
        public FakeServiceProvider(IAuthenticationService auth) => _auth = auth;
        public object? GetService(Type serviceType)
            => serviceType == typeof(IAuthenticationService) ? _auth : null;
    }

    private class FakeSession : ISession
    {
        private readonly Dictionary<string, byte[]> _data = new();
        public bool IsAvailable => true;
        public string Id => "test";
        public IEnumerable<string> Keys => _data.Keys;
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public void Clear() => _data.Clear();
        public void Remove(string key) => _data.Remove(key);
        public void Set(string key, byte[] value) => _data[key] = value;
        public bool TryGetValue(string key, out byte[] value) => _data.TryGetValue(key, out value!);
    }

    private class FakeProfilePictureService : NostrProfilePictureService
    {
        public FakeProfilePictureService() : base(null!, NullLogger<NostrProfilePictureService>.Instance) { }
        public override void SyncInBackground(string userId, string pubkey) { }
    }

    // --- scaffolding ---

    private sealed class Rig
    {
        public required UINostrLoginController Controller { get; init; }
        public required FakeSignInManager SignIn { get; init; }
        public required FakeAuthenticationService Auth { get; init; }
        public required DefaultHttpContext HttpContext { get; init; }
        public required ApplicationUser User { get; init; }
        public required string Pubkey { get; init; }
    }

    private static async Task<(ECPrivKey Key, string Pubkey)> NewKey()
    {
        await Task.CompletedTask;
        var key = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        return (key, key.CreateXOnlyPubKey().ToHex());
    }

    private static Rig BuildRig(string pubkey, bool twoFactorEnabled, NostrLoginService service,
        Nip98ReplayStore? replayStore = null, string? bindCookieNonce = null)
    {
        var user = new ApplicationUser { Id = "user-1", UserName = "a@b.c", Email = "a@b.c" };
        var repo = new FakeSettingsRepository();
        repo.Store[typeof(NostrLoginUserMap).Name] = new NostrLoginUserMap
        {
            PubkeyToUserId = new Dictionary<string, string> { [pubkey] = user.Id }
        };

        var auth = new FakeAuthenticationService();
        var http = new DefaultHttpContext
        {
            Session = new FakeSession(),
            RequestServices = new FakeServiceProvider(auth)
        };
        http.Request.Scheme = "https";
        http.Request.Host = new HostString(TestHost);
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.7");
        if (bindCookieNonce is not null)
            http.Request.Headers.Cookie = $"NostrLogin.Bind={bindCookieNonce}";

        var accessor = new HttpContextAccessor { HttpContext = http };
        var userManager = new FakeUserManager(new Dictionary<string, ApplicationUser> { [user.Id] = user });
        var signIn = new FakeSignInManager(userManager, accessor, twoFactorEnabled);

        var controller = new UINostrLoginController(
            service,
            replayStore!,
            new FakeProfilePictureService(),
            signIn,
            userManager,
            userService: null!,
            repo,
            new PoliciesSettings(),
            NullLogger<UINostrLoginController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http }
        };
        return new Rig { Controller = controller, SignIn = signIn, Auth = auth, HttpContext = http, User = user, Pubkey = pubkey };
    }

    private static async Task<string> SignEventBase64(ECPrivKey key, string pubkey, string method)
    {
        var evt = new NostrEvent
        {
            Kind = 27235,
            PublicKey = pubkey,
            CreatedAt = DateTimeOffset.UtcNow,
            Content = ""
        };
        evt.SetTag("u", LoginUrl);
        evt.SetTag("method", method);
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(evt)));
    }

    private static JsonElement JsonOf(IActionResult result)
    {
        var json = Assert.IsType<JsonResult>(result);
        return JsonSerializer.SerializeToElement(json.Value);
    }

    // --- tests ---

    [Fact]
    public async Task QrFlow_TwoFactorUser_HandsOffToCoreSecondFactor()
    {
        var (_, pubkey) = await NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        const string nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Login,
            ["wss://10.255.255.1:9"], "test", bindingNonce: nonce);
        session.Status = Nip46SessionStatus.Approved;
        session.UserPubkey = pubkey;

        var rig = BuildRig(pubkey, twoFactorEnabled: true, service, bindCookieNonce: nonce);

        var result = await rig.Controller.LoginStatus(session.Id, "/wallets");

        var body = JsonOf(result);
        Assert.Equal("2fa_required", body.GetProperty("status").GetString());
        Assert.Equal("/login/second-login", body.GetProperty("redirect").GetString());
        // The account must NOT be fully signed in from key proof alone...
        Assert.Equal(0, rig.SignIn.FullSignInCount);
        // ...only the 2FA user-id cookie may be issued, so core can collect the second factor.
        Assert.Contains(IdentityConstants.TwoFactorUserIdScheme, rig.Auth.SignInSchemes);
        // ReturnUrl + method continuity for core's RedirectLoginSuccess.
        Assert.True(rig.HttpContext.Session.TryGetValue("LoginSession", out var ls));
        Assert.Contains("NostrLogin", Encoding.UTF8.GetString(ls));
        Assert.Contains("/wallets", Encoding.UTF8.GetString(ls));
        // Single-use: the nostr session is gone.
        Assert.Null(service.GetSession(session.Id));
    }

    [Fact]
    public async Task Nip98Post_TwoFactorUser_Rejected()
    {
        var (key, pubkey) = await NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var repo = new FakeSettingsRepository();
        var replayStore = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await replayStore.StartAsync(CancellationToken.None);
        var rig = BuildRig(pubkey, twoFactorEnabled: true, service, replayStore);
        rig.HttpContext.Request.Headers.Authorization = "Nostr " + await SignEventBase64(key, pubkey, "POST");

        var result = await rig.Controller.Nip98Login();

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, obj.StatusCode);
        var body = JsonSerializer.SerializeToElement(obj.Value);
        Assert.Equal("failed", body.GetProperty("status").GetString());
        Assert.Contains("two-factor", body.GetProperty("error").GetString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, rig.SignIn.FullSignInCount);
        Assert.Empty(rig.Auth.SignInSchemes);
    }

    [Fact]
    public async Task Nip98GetLink_TwoFactorUser_RedirectedToSecondLogin()
    {
        var (key, pubkey) = await NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var repo = new FakeSettingsRepository();
        var replayStore = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await replayStore.StartAsync(CancellationToken.None);
        var rig = BuildRig(pubkey, twoFactorEnabled: true, service, replayStore);
        var eventParam = (await SignEventBase64(key, pubkey, "GET"))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var result = await rig.Controller.Nip98LoginLink(eventParam, "/wallets");

        var redirect = Assert.IsType<LocalRedirectResult>(result);
        Assert.Equal("/login/second-login", redirect.Url);
        Assert.Equal(0, rig.SignIn.FullSignInCount);
        Assert.Contains(IdentityConstants.TwoFactorUserIdScheme, rig.Auth.SignInSchemes);
    }
}
