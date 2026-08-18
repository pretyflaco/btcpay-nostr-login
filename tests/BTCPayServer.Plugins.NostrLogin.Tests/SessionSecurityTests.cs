using System.Web;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

public class BindingNonceTests
{
    [Fact]
    public void MatchesEqualNonce()
    {
        var nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        Assert.True(NostrLoginService.BindingNonceMatches(nonce, nonce));
    }

    [Fact]
    public void RejectsWrongNonce()
    {
        Assert.False(NostrLoginService.BindingNonceMatches(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "ffffffffffffffffffffffffffffffff"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RejectsAbsentPresentedNonce(string? presented)
    {
        // The QRLjacker has no bind cookie: must be rejected, never throw.
        Assert.False(NostrLoginService.BindingNonceMatches("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", presented));
    }

    [Fact]
    public void RejectsDifferentLengthWithoutThrowing()
    {
        // FixedTimeEquals throws on unequal spans; the helper must guard against it.
        Assert.False(NostrLoginService.BindingNonceMatches("short", "a-much-longer-value"));
    }
}

public class ConnectUriTests
{
    [Fact]
    public void EncodesPubkeyRelaysSecretAndPerms()
    {
        var uri = NostrLoginService.BuildConnectUri(
            "abc123",
            ["wss://nos.lol", "wss://relay.primal.net"],
            "deadbeef",
            "BTCPay Server");

        Assert.StartsWith("nostrconnect://abc123?", uri);
        Assert.Contains("relay=" + Uri.EscapeDataString("wss://nos.lol"), uri);
        Assert.Contains("relay=" + Uri.EscapeDataString("wss://relay.primal.net"), uri);
        Assert.Contains("secret=deadbeef", uri);
        // NIP-98 (kind 27235) sign + pubkey read is requested by default so standards-aware
        // signers can pre-grant it; the 22242 challenge remains as a runtime fallback.
        var query = HttpUtility.ParseQueryString(new Uri(uri).Query);
        Assert.Equal("sign_event:27235,get_public_key", query["perms"]);
        Assert.Equal("BTCPay Server", query["name"]);
    }

    [Fact]
    public void OmitsUrlAndImageWhenNotProvided()
    {
        var uri = NostrLoginService.BuildConnectUri("abc123", ["wss://nos.lol"], "deadbeef", "BTCPay Server");
        var query = HttpUtility.ParseQueryString(new Uri(uri).Query);
        Assert.Null(query["url"]);
        Assert.Null(query["image"]);
    }

    [Fact]
    public void EncodesUrlAndImageWhenProvided()
    {
        // NIP-46 url/image so the signer shows a recognisable avatar and can tell instances apart.
        var uri = NostrLoginService.BuildConnectUri(
            "abc123",
            ["wss://nos.lol"],
            "deadbeef",
            "BTCPay Server (btcpay.example.org)",
            appUrl: "https://btcpay.example.org",
            imageUrl: "https://avatars.example.com/logo.png");

        var query = HttpUtility.ParseQueryString(new Uri(uri).Query);
        Assert.Equal("BTCPay Server (btcpay.example.org)", query["name"]);
        Assert.Equal("https://btcpay.example.org", query["url"]);
        Assert.Equal("https://avatars.example.com/logo.png", query["image"]);
    }
}

public class NonBlockingSessionTests
{
    [Fact]
    public async Task ReturnsPromptlyWithConnectUriEvenWhenRelaysUnreachable()
    {
        // The QR-rendering request must never block on relay connectivity: a dead relay used to
        // hang /login/nostr for the full per-relay timeout. Session creation is now synchronous;
        // all relay work happens on a background task.
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var unreachable = new[] { "wss://10.255.255.1:9", "wss://192.0.2.1:9" };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Login, unreachable, "BTCPay Server");
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"CreateSessionAsync should return promptly, took {sw.Elapsed.TotalSeconds:0.00}s");
        Assert.False(string.IsNullOrEmpty(session.ConnectUri));
        Assert.StartsWith("nostrconnect://", session.ConnectUri);
        Assert.Equal(Nip46SessionStatus.Pending, session.Status);
    }
}

public class RateLimitedSessionTests
{
    [Fact]
    public async Task RejectedSessionIsRegisteredAndSurfacesReason()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var max = NostrLoginService.MaxLoginSessionsPerWindowForTest;

        // Exhaust the window via the limiter directly (avoids opening real relay connections).
        for (var i = 0; i < max; i++)
            Assert.True(service.AllowLoginAttemptForTest("1.2.3.4"));

        // The next CreateSessionAsync is rejected before any relay connection is attempted.
        var rejected = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, NostrLoginService.DefaultRelays, "test",
            rateLimitKey: "1.2.3.4");

        Assert.Equal(Nip46SessionStatus.Failed, rejected.Status);
        Assert.Contains("Too many", rejected.Error);
        // Registered, so the status poller returns the real reason rather than "expired".
        var fetched = service.GetSession(rejected.Id);
        Assert.NotNull(fetched);
        Assert.Equal(rejected.Id, fetched!.Id);
    }
}
