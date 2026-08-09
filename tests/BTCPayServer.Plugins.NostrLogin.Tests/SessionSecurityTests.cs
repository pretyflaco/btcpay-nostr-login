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
        // Only the sign_event:22242 permission is requested — never a broader scope.
        var query = HttpUtility.ParseQueryString(new Uri(uri).Query);
        Assert.Equal("sign_event:22242", query["perms"]);
        Assert.Equal("BTCPay Server", query["name"]);
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
