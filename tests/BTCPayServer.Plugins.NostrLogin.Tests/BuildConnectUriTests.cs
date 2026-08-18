using BTCPayServer.Plugins.NostrLogin;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// The nostrconnect:// URI must request NIP-98 signing by default (so standards-aware signers can
/// pre-grant it) while still carrying relays, secret, name, url and image.
/// </summary>
public class BuildConnectUriTests
{
    private const string ClientPubkey = "abc123";
    private static readonly string[] Relays = ["wss://nos.lol", "wss://relay.damus.io"];

    [Fact]
    public void RequestsNip98PermsByDefault()
    {
        var uri = NostrLoginService.BuildConnectUri(ClientPubkey, Relays, "secret", "BTCPay Server (host)");
        Assert.Contains("perms=sign_event%3A27235%2Cget_public_key", uri);
    }

    [Fact]
    public void HonoursExplicitPermsOverride()
    {
        var uri = NostrLoginService.BuildConnectUri(ClientPubkey, Relays, "secret", "app", perms: "sign_event:22242");
        Assert.Contains("perms=sign_event%3A22242", uri);
        Assert.DoesNotContain("27235", uri);
    }

    [Fact]
    public void EmitsAllRelaysAndCoreParams()
    {
        var uri = NostrLoginService.BuildConnectUri(ClientPubkey, Relays, "thesecret", "app",
            appUrl: "https://btcpay.twentyone.ist", imageUrl: "https://img/x.png");
        Assert.StartsWith("nostrconnect://abc123?", uri);
        Assert.Contains("relay=wss%3A%2F%2Fnos.lol", uri);
        Assert.Contains("relay=wss%3A%2F%2Frelay.damus.io", uri);
        Assert.Contains("secret=thesecret", uri);
        Assert.Contains("name=app", uri);
        Assert.Contains("url=https%3A%2F%2Fbtcpay.twentyone.ist", uri);
        Assert.Contains("image=https%3A%2F%2Fimg%2Fx.png", uri);
    }
}
