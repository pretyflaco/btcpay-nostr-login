using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NBitcoin.Secp256k1;
using NNostr.Client;
using static BTCPayServer.Plugins.NostrLogin.Tests.TwoFactorGateTests;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>Follow-ups from the v0.8.3 security review (0.8.4).</summary>
public class HardeningTests
{
    // --- UntrustedEvent.Verify: equivalent to NNostr on well-formed events, never weaker ---

    private static async Task<NostrEvent> Signed(ECPrivKey key, params NostrEventTag[] extraTags)
    {
        var evt = new NostrEvent
        {
            Kind = 27235, PublicKey = key.CreateXOnlyPubKey().ToHex(), CreatedAt = DateTimeOffset.UtcNow, Content = "x",
            Tags = [new NostrEventTag { TagIdentifier = "u", Data = ["https://h/x"] }, .. extraTags]
        };
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return evt;
    }

    private static ECPrivKey NewPriv() => NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public async Task Verify_AgreesWithNNostr_OnWellFormedEvents()
    {
        var plain = await Signed(NewPriv());
        var withValuelessTag = await Signed(NewPriv(), new NostrEventTag { TagIdentifier = "x", Data = [] });
        foreach (var evt in new[] { plain, withValuelessTag })
        {
            Assert.True(evt.Verify());
            Assert.True(UntrustedEvent.Verify(evt));
        }
    }

    [Fact]
    public async Task Verify_RejectsCorrectIdWithWrongSignature()
    {
        var evt = await Signed(NewPriv());
        var other = await Signed(NewPriv());

        var foreignSig = Clone(evt); foreignSig.Signature = other.Signature; // valid format, other key
        var flipped = Clone(evt);
        flipped.Signature = (evt.Signature![0] == 'a' ? "b" : "a") + evt.Signature[1..];
        var upperId = Clone(evt); upperId.Id = evt.Id!.ToUpperInvariant();

        Assert.False(UntrustedEvent.Verify(foreignSig));
        Assert.False(UntrustedEvent.Verify(flipped));
        Assert.False(UntrustedEvent.Verify(upperId));
    }

    private static NostrEvent Clone(NostrEvent e) => JsonSerializer.Deserialize<NostrEvent>(JsonSerializer.Serialize(e))!;

    // --- QR capacity: oversized host / relay list must not throw on anonymous GET /login/nostr ---

    [Fact]
    public void RelayBudget_FitsQr_WithWorstCaseHost()
    {
        var host = new string('h', 253);
        var relays = new List<string>();
        var i = 0;
        while (true)
        {
            var next = relays.Append($"wss://relay{i++}.example-relay-domain.org").ToList();
            if (NostrLoginService.RelayParamsLength(next) > NostrLoginService.MaxRelayParamsLength) break;
            relays = next;
        }
        var uri = NostrLoginService.BuildConnectUri(new string('a', 64), relays.ToArray(), new string('b', 32),
            $"BTCPay Server ({host})", $"https://{host}", NostrLoginService.DefaultImageUrl);

        Assert.NotNull(UINostrLoginController.TryGenerateQrDataUri(uri));
        Assert.Null(UINostrLoginController.TryGenerateQrDataUri(new string('x', 4000))); // and it never throws
    }

    private static Rig LoginRig(string? host = null, List<string>? relays = null, string? cookie = null)
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var rig = BuildRig(new string('a', 64), false, service);
        if (relays is not null)
            rig.Repo.Store[nameof(NostrLoginSettings)] = new NostrLoginSettings { Relays = relays };
        if (host is not null)
            rig.HttpContext.Request.Host = new HostString(host);
        if (cookie is not null)
            rig.HttpContext.Request.Headers.Cookie = $"NostrLogin.Bind={cookie}";
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();
        rig.Controller.TempData = new TempDataDictionary(rig.HttpContext, new SessionReuseTests.FakeTempDataProvider());
        return rig;
    }

    [Fact]
    public async Task OversizedHost_IsClamped_QrStillRenders()
    {
        var rig = LoginRig(host: new string('h', 2000) + ".example");

        var vm = Assert.IsType<NostrLoginViewModel>(Assert.IsType<ViewResult>(await rig.Controller.Login()).Model);

        Assert.Null(vm.InitialError);
        Assert.NotEmpty(vm.QrDataUri);
        Assert.True(vm.ConnectUri.Length < 1600);
    }

    [Fact]
    public async Task OversizedRelayList_ShowsError_InsteadOfThrowing()
    {
        var relays = Enumerable.Range(0, 60).Select(i => $"wss://relay{i}.a-rather-long-relay-hostname.example.org").ToList();
        var rig = LoginRig(relays: relays);

        var vm = Assert.IsType<NostrLoginViewModel>(Assert.IsType<ViewResult>(await rig.Controller.Login()).Model);

        Assert.Contains("relay settings", vm.InitialError);
        Assert.Empty(vm.QrDataUri);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("x.")]
    [InlineData(".x")]
    [InlineData("....")]
    public async Task OddBindCookies_DoNotThrow(string cookie)
    {
        var rig = LoginRig(cookie: cookie);
        Assert.IsType<ViewResult>(await rig.Controller.Login());
    }

    [Fact]
    public async Task HugeBindCookie_DoesNotThrow()
    {
        var rig = LoginRig(cookie: new string('a', 3000) + "." + new string('b', 3000));
        Assert.IsType<ViewResult>(await rig.Controller.Login());
    }

    [Fact]
    public async Task ServerSettings_RejectsRelayListTooLongForQr()
    {
        var rig = LoginRig();
        var relays = string.Join("\n", Enumerable.Range(0, 60).Select(i => $"wss://relay{i}.a-rather-long-relay-hostname.example.org"));

        var result = await rig.Controller.ServerSettings(new NostrLoginServerSettingsViewModel { Relays = relays });

        Assert.IsType<ViewResult>(result);
        Assert.False(rig.Controller.ModelState.IsValid);
    }

    // --- returnUrl: non-ASCII must not reach the Location header ---

    private sealed class RealLocalUrlHelper : IUrlHelper
    {
        public ActionContext ActionContext => null!;
        public string? Action(Microsoft.AspNetCore.Mvc.Routing.UrlActionContext actionContext) => null;
        public string? Content(string? contentPath) => contentPath;
        // Same rule as ASP.NET Core's UrlHelperBase.IsLocalUrl for the cases below.
        public bool IsLocalUrl(string? url) => url is { Length: > 0 } && url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));
        public string? Link(string? routeName, object? values) => null;
        public string? RouteUrl(Microsoft.AspNetCore.Mvc.Routing.UrlRouteContext routeContext) => null;
    }

    [Theory]
    [InlineData("/wallets", "/wallets")]
    [InlineData("/stores/abc?x=1", "/stores/abc?x=1")]
    [InlineData("/é", "/")]
    [InlineData("/\u0001", "/")]
    [InlineData("//evil.example", "/")]
    [InlineData("https://evil.example", "/")]
    [InlineData(null, "/")]
    public void SafeReturnUrl_OnlyPrintableAsciiLocal(string? input, string expected) =>
        Assert.Equal(expected, UINostrLoginController.SafeReturnUrl(new RealLocalUrlHelper(), input));

    [Fact]
    public async Task GetLink_NonAsciiReturnUrl_RedirectsHome()
    {
        var (key, pubkey) = await NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var rig = BuildRig(pubkey, false, service,
            new Nip98ReplayStore(new FakeSettingsRepository(), NullLogger<Nip98ReplayStore>.Instance));
        rig.Controller.Url = new RealLocalUrlHelper();
        var evt = new NostrEvent { Kind = 27235, PublicKey = pubkey, CreatedAt = DateTimeOffset.UtcNow, Content = "" };
        evt.SetTag("u", LoginUrl);
        evt.SetTag("method", "GET");
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        var param = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(evt)));

        var result = await rig.Controller.Nip98LoginLink(param, "/é");

        Assert.Equal("/", Assert.IsType<LocalRedirectResult>(result).Url);
        Assert.Equal(1, rig.SignIn.FullSignInCount);
    }

    // --- end to end: the filter keeps exceptions away from an IExceptionHandler like BTCPay's ---

    internal sealed class RecordingExceptionHandler : IExceptionHandler
    {
        public static int Calls;
        public ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return ValueTask.FromResult(false); // like PluginExceptionHandler: observe, then let it be a 500
        }
    }

    [Fact]
    public async Task Filter_KeepsActionAndResultExceptionsFromTheExceptionHandler()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddControllers().ConfigureApplicationPartManager(m =>
        {
            m.ApplicationParts.Clear();
            m.ApplicationParts.Add(new AssemblyPart(typeof(HardeningTests).Assembly));
        });
        builder.Services.AddExceptionHandler<RecordingExceptionHandler>();
        await using var app = builder.Build();
        app.UseExceptionHandler(new ExceptionHandlerOptions { ExceptionHandler = _ => Task.CompletedTask });
        app.MapControllers();
        await app.StartAsync();
        using var http = new HttpClient { BaseAddress = new Uri(app.Urls.First()) };

        RecordingExceptionHandler.Calls = 0;
        // Harness sanity: an uncontained throw DOES reach the handler (this is the kill switch path).
        Assert.Equal(HttpStatusCode.InternalServerError, (await http.GetAsync("uncontained/action")).StatusCode);
        Assert.Equal(1, RecordingExceptionHandler.Calls);

        RecordingExceptionHandler.Calls = 0;
        Assert.Equal(HttpStatusCode.InternalServerError, (await http.GetAsync("contained/action")).StatusCode);
        Assert.Equal(HttpStatusCode.InternalServerError, (await http.GetAsync("contained/result")).StatusCode);
        Assert.Equal(0, RecordingExceptionHandler.Calls);

        await app.StopAsync();
    }
}

// Test controllers must be top-level public types: MVC's controller discovery skips nested types.
internal sealed class ThrowingResult : IActionResult
{
    public Task ExecuteResultAsync(ActionContext context) => throw new InvalidOperationException("render boom");
}

[ContainPluginExceptions]
[Route("contained")]
public sealed class ContainedTestController : Controller
{
    [HttpGet("action")] public IActionResult ThrowInAction() => throw new InvalidOperationException("action boom");
    [HttpGet("result")] public IActionResult ThrowInResult() => new ThrowingResult();
}

[Route("uncontained")]
public sealed class UncontainedTestController : Controller
{
    [HttpGet("action")] public IActionResult ThrowInAction() => throw new InvalidOperationException("action boom");
}
