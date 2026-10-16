using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Session reuse (GET /login/nostr): a browser carrying a valid bind cookie for a still-pending
/// Login session gets the same QR re-rendered instead of minting a fresh session. The M2 nonce
/// gate is unchanged — reuse requires the constant-time nonce match, same as sign-in.
/// </summary>
public class SessionReuseTests
{
    private static readonly string[] Blackhole = ["wss://10.255.255.1:9"];
    private const string Nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    private const string OtherNonce = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    // --- service-level gate ---

    [Fact]
    public async Task ReuseReturnsPendingLoginSessionWithMatchingNonce()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", bindingNonce: Nonce);

        Assert.Same(session, service.TryReuseSession(session.Id, Nonce));
    }

    [Theory]
    [InlineData(null)]        // QRLjacker: no bind cookie at all
    [InlineData(OtherNonce)]  // foreign cookie: right shape, wrong nonce
    public async Task ReuseRejectsMissingOrForeignNonce(string? presented)
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", bindingNonce: Nonce);

        Assert.Null(service.TryReuseSession(session.Id, presented));
    }

    [Fact]
    public async Task ReuseRejectsUnknownSessionId()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        Assert.Null(service.TryReuseSession("00000000000000000000000000000000", Nonce));
    }

    [Fact]
    public async Task ReuseRejectsResolvedSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", bindingNonce: Nonce);
        session.Status = Nip46SessionStatus.Failed;

        Assert.Null(service.TryReuseSession(session.Id, Nonce));
    }

    [Fact]
    public async Task ReuseRejectsLinkSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        // Link sessions are never reusable, even if a nonce somehow matches.
        var link = await service.CreateSessionAsync(
            Nip46SessionPurpose.Link, Blackhole, "test", linkUserId: "user1", bindingNonce: Nonce);

        Assert.Null(service.TryReuseSession(link.Id, Nonce));
    }

    [Fact]
    public async Task ReuseRejectsSessionNearExpiry()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", bindingNonce: Nonce);
        // 30s of lifetime left — a nearly-dead QR is not worth re-rendering.
        session.CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(30);

        Assert.Null(service.TryReuseSession(session.Id, Nonce));
    }

    [Fact]
    public async Task ReuseAcceptsYoungSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", bindingNonce: Nonce);
        session.CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(2);

        Assert.Same(session, service.TryReuseSession(session.Id, Nonce));
    }

    // --- controller-level flow ---

    private class FakeUrlHelper : IUrlHelper
    {
        public ActionContext ActionContext => null!;
        public string? Action(UrlActionContext actionContext) => "/login/nostr/status/x";
        public string? Content(string? contentPath) => contentPath;
        public bool IsLocalUrl(string? url) => url is not null && url.StartsWith('/');
        public string? Link(string? routeName, object? values) => null;
        public string? RouteUrl(UrlRouteContext routeContext) => null;
    }

    private static string ExtractBindCookie(StringValues setCookie)
    {
        var header = setCookie.ToString();
        const string prefix = "NostrLogin.Bind=";
        var start = header.IndexOf(prefix, StringComparison.Ordinal);
        Assert.True(start >= 0, "expected a NostrLogin.Bind Set-Cookie header");
        start += prefix.Length;
        var end = header.IndexOf(';', start);
        return header[start..(end < 0 ? header.Length : end)];
    }

    private class FakeTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    private static async Task<NostrLoginViewModel> GetLoginPage(TwoFactorGateTests.Rig rig)
    {
        rig.Controller.Url = new FakeUrlHelper();
        rig.Controller.TempData = new TempDataDictionary(rig.HttpContext, new FakeTempDataProvider());
        var view = Assert.IsType<ViewResult>(await rig.Controller.Login());
        return Assert.IsType<NostrLoginViewModel>(view.Model);
    }

    [Fact]
    public async Task ReloadWithBindCookieReRendersSameSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var (_, pubkey) = await TwoFactorGateTests.NewKey();

        var rig1 = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        var vm1 = await GetLoginPage(rig1);
        Assert.Null(vm1.InitialError);
        Assert.Equal(1, service.SessionCountForTest);

        // The cookie now names the session it is bound to.
        var bind = ExtractBindCookie(rig1.HttpContext.Response.Headers.SetCookie);
        Assert.StartsWith(vm1.SessionId + ".", bind);

        // Same browser reloads /login/nostr carrying the bind cookie.
        var rig2 = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        rig2.HttpContext.Request.Headers.Cookie = "NostrLogin.Bind=" + bind;
        var vm2 = await GetLoginPage(rig2);

        Assert.Equal(vm1.SessionId, vm2.SessionId);
        Assert.Equal(vm1.ConnectUri, vm2.ConnectUri);
        // No second session minted, no cookie rewrite on the reuse path.
        Assert.Equal(1, service.SessionCountForTest);
        Assert.DoesNotContain("NostrLogin.Bind", rig2.HttpContext.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public async Task ForeignBindCookieMintsFreshSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var (_, pubkey) = await TwoFactorGateTests.NewKey();

        var rig1 = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        var vm1 = await GetLoginPage(rig1);

        // Another browser that knows the session id but not the nonce (e.g. a QRLjacker who
        // scraped the status URL) must NOT be able to attach to the session.
        var rig2 = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        rig2.HttpContext.Request.Headers.Cookie = $"NostrLogin.Bind={vm1.SessionId}.{OtherNonce}";
        var vm2 = await GetLoginPage(rig2);

        Assert.NotEqual(vm1.SessionId, vm2.SessionId);
        Assert.Equal(2, service.SessionCountForTest);
        Assert.StartsWith(vm2.SessionId + ".", ExtractBindCookie(rig2.HttpContext.Response.Headers.SetCookie));
    }

    [Fact]
    public async Task LegacyNonceOnlyCookieMintsFreshSession()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var (_, pubkey) = await TwoFactorGateTests.NewKey();

        // Cookies set before the "{sessionId}.{nonce}" format shipped carry no session id:
        // parse failure falls through to minting a fresh session (no reuse, no crash).
        var rig = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        rig.HttpContext.Request.Headers.Cookie = "NostrLogin.Bind=" + Nonce;
        var vm = await GetLoginPage(rig);

        Assert.Null(vm.InitialError);
        Assert.Equal(1, service.SessionCountForTest);
        Assert.StartsWith(vm.SessionId + ".", ExtractBindCookie(rig.HttpContext.Response.Headers.SetCookie));
    }
}
