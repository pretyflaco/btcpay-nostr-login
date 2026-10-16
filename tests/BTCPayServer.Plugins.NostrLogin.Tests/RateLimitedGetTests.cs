using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// A throttled GET /login/nostr answers 429 + Retry-After (machine-readable back-off for
/// scanners/crawlers) while still rendering the same friendly error page for humans.
/// </summary>
public class RateLimitedGetTests
{
    [Fact]
    public async Task ThrottledGetReturns429WithRetryAfterAndFriendlyPage()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var (_, pubkey) = await TwoFactorGateTests.NewKey();
        var rig = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();
        rig.Controller.TempData = new TempDataDictionary(rig.HttpContext, new SessionReuseTests.FakeTempDataProvider());

        // Exhaust the per-minute window for the rig's client IP (BuildRig uses 203.0.113.7).
        for (var i = 0; i < NostrLoginService.MaxLoginSessionsPerWindowForTest; i++)
            service.AllowLoginAttemptForTest("203.0.113.7");

        var view = Assert.IsType<ViewResult>(await rig.Controller.Login());
        var vm = Assert.IsType<NostrLoginViewModel>(view.Model);

        Assert.Equal(StatusCodes.Status429TooManyRequests, rig.HttpContext.Response.StatusCode);
        Assert.Equal("60", rig.HttpContext.Response.Headers.RetryAfter.ToString());
        // The human-facing page is unchanged: friendly error, no QR, no poller.
        Assert.Contains("Too many", vm.InitialError);
        Assert.Empty(vm.QrDataUri);
        // No bind cookie is written for a throttled (never-registered) session.
        Assert.DoesNotContain("NostrLogin.Bind", rig.HttpContext.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public async Task UnthrottledGetStays200()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var (_, pubkey) = await TwoFactorGateTests.NewKey();
        var rig = TwoFactorGateTests.BuildRig(pubkey, twoFactorEnabled: false, service);
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();
        rig.Controller.TempData = new TempDataDictionary(rig.HttpContext, new SessionReuseTests.FakeTempDataProvider());

        Assert.IsType<ViewResult>(await rig.Controller.Login());

        Assert.Equal(StatusCodes.Status200OK, rig.HttpContext.Response.StatusCode);
        Assert.Empty(rig.HttpContext.Response.Headers.RetryAfter.ToString());
    }
}
