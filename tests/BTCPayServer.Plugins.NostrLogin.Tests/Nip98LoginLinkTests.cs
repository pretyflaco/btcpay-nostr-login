using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BTCPayServer.Plugins.NostrLogin;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Covers the same-device "magic link" login (GET /login/nostr/nip98?event=...): the base64url
/// event decoding must accept both alphabets and unpadded input, and a GET-bound signed event
/// must validate as GET while failing the POST expectation (the method tag binds the transport).
/// </summary>
public class Nip98LoginLinkTests
{
    private const string Url = "https://btcpay.twentyone.ist/login/nostr/nip98";

    private static async Task<(NostrEvent Event, string Pubkey)> SignGetEvent(string method = "GET")
    {
        var key = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var pubkey = key.CreateXOnlyPubKey().ToHex();
        var evt = new NostrEvent
        {
            Kind = 27235,
            PublicKey = pubkey,
            CreatedAt = DateTimeOffset.UtcNow,
            Content = ""
        };
        evt.SetTag("u", Url);
        evt.SetTag("method", method);
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return (evt, pubkey);
    }

    private static string ToBase64Url(NostrEvent evt)
    {
        var json = JsonSerializer.Serialize(evt);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    [Fact]
    public async Task DecodesBase64UrlEvent()
    {
        var (evt, _) = await SignGetEvent();
        var decoded = UINostrLoginController.TryDecodeNostrEvent(ToBase64Url(evt));
        Assert.NotNull(decoded);
        Assert.Equal(evt.Id, decoded!.Id);
    }

    [Fact]
    public async Task DecodesStandardBase64Event()
    {
        var (evt, _) = await SignGetEvent();
        var json = JsonSerializer.Serialize(evt);
        var standard = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)); // +/ and = padding
        var decoded = UINostrLoginController.TryDecodeNostrEvent(standard);
        Assert.NotNull(decoded);
        Assert.Equal(evt.Id, decoded!.Id);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-base64!!!")]
    [InlineData("aGVsbG8")] // valid base64, not a JSON event
    public void RejectsMalformedEventParam(string? encoded)
    {
        Assert.Null(UINostrLoginController.TryDecodeNostrEvent(encoded));
    }

    [Fact]
    public async Task GetBoundEventValidatesAsGet()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignGetEvent();
        Assert.Null(Nip98.Validate(evt, pubkey, Url, "GET", null));
    }

    [Fact]
    public async Task GetBoundEventFailsPostExpectation()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignGetEvent();
        var error = Nip98.Validate(evt, pubkey, Url, "POST", null);
        Assert.NotNull(error);
        Assert.Contains("method", error, StringComparison.OrdinalIgnoreCase);
    }
}
