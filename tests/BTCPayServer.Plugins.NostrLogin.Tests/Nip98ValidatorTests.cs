using System.Security.Cryptography;
using BTCPayServer.Plugins.NostrLogin;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Exercises the shared NIP-98 (kind 27235) validation gate used by both the QR/session flow and
/// the open POST /login/nostr/nip98 endpoint: accept a genuine event, reject every tampered variant,
/// enforce the URL/method binding, freshness, and single-use replay guard.
/// </summary>
public class Nip98ValidatorTests
{
    private const string Url = "https://btcpay.twentyone.ist/login/nostr/nip98";
    private const string Nonce = "0123456789abcdef0123456789abcdef";

    private static async Task<(NostrEvent Event, string Pubkey)> SignNip98(
        string url = Url, string method = "POST", string? nonce = Nonce, int kind = 27235,
        DateTimeOffset? createdAt = null)
    {
        var key = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var pubkey = key.CreateXOnlyPubKey().ToHex();
        var evt = new NostrEvent
        {
            Kind = kind,
            PublicKey = pubkey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
            Content = ""
        };
        evt.SetTag("u", url);
        evt.SetTag("method", method);
        if (nonce is not null)
            evt.SetTag("challenge", nonce);
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return (evt, pubkey);
    }

    [Fact]
    public async Task AcceptsGenuineEvent()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98();
        Assert.Null(await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce));
    }

    [Fact]
    public async Task AcceptsWithoutNonceWhenNonceExpectationNull()
    {
        Nip98.ResetReplayStoreForTest();
        // Open endpoint: no session nonce. An event that carries no challenge tag is fine.
        var (evt, pubkey) = await SignNip98(nonce: null);
        Assert.Null(await Nip98.ValidateAsync(evt, pubkey, Url, "POST", null));
    }

    [Fact]
    public async Task RejectsNullEvent()
    {
        Assert.NotNull(await Nip98.ValidateAsync(null, "pubkey", Url, "POST", null));
    }

    [Fact]
    public async Task RejectsWrongKind()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98(kind: 1);
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("kind", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsMismatchedPubkey()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, _) = await SignNip98();
        var otherKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var otherPubkey = otherKey.CreateXOnlyPubKey().ToHex();
        var error = await Nip98.ValidateAsync(evt, otherPubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("pubkey", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsUrlMismatch()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98(url: "https://evil.example/login/nostr/nip98");
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("URL", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsMethodMismatch()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98(method: "GET");
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("method", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsWrongNonce()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98();
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", "ffffffffffffffffffffffffffffffff");
        Assert.NotNull(error);
        Assert.Contains("challenge", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsStaleTimestamp()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98(createdAt: DateTimeOffset.UtcNow.AddMinutes(-30));
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("timestamp", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsFutureTimestamp()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98(createdAt: DateTimeOffset.UtcNow.AddMinutes(30));
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
        Assert.Contains("timestamp", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsTamperedSignature()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98();
        evt.Content += " tampered"; // id/sig no longer match
        var error = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);
        Assert.NotNull(error);
    }

    [Fact]
    public async Task RejectsReplayedEvent()
    {
        Nip98.ResetReplayStoreForTest();
        var (evt, pubkey) = await SignNip98();
        Assert.Null(await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce));      // first use ok
        var second = await Nip98.ValidateAsync(evt, pubkey, Url, "POST", Nonce);      // same id again
        Assert.NotNull(second);
        Assert.Contains("replay", second, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://Host.Example/login", "https://host.example/login")]        // case
    [InlineData("https://host.example:443/login", "https://host.example/login")]    // default port
    [InlineData("https://host.example/login/", "https://host.example/login")]       // trailing slash
    public void UrlMatchesNormalizesEquivalentUrls(string a, string b)
    {
        Assert.True(Nip98.UrlMatches(a, b));
    }

    [Theory]
    [InlineData("https://host.example/login", "http://host.example/login")]         // scheme
    [InlineData("https://host.example/login", "https://host.example/other")]        // path
    [InlineData("https://host.example:8443/login", "https://host.example/login")]   // non-default port
    public void UrlMatchesRejectsDifferentUrls(string a, string b)
    {
        Assert.False(Nip98.UrlMatches(a, b));
    }
}
