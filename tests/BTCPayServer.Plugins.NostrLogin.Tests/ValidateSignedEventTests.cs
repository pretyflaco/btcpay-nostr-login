using System.Security.Cryptography;
using BTCPayServer.Plugins.NostrLogin;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Exercises the auth-critical gate: ValidateSignedEvent must accept a genuine signed
/// kind-22242 challenge and reject every tampered variant.
/// </summary>
public class ValidateSignedEventTests
{
    private const string Challenge = "0123456789abcdef0123456789abcdef";

    private static async Task<(NostrEvent Event, string Pubkey)> SignChallenge(
        string challenge = Challenge, int kind = 22242, DateTimeOffset? createdAt = null)
    {
        var key = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var pubkey = key.CreateXOnlyPubKey().ToHex();
        var evt = new NostrEvent
        {
            Kind = kind,
            PublicKey = pubkey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
            Content = $"BTCPay Server sign-in challenge: {challenge}"
        };
        evt.SetTag("challenge", challenge);
        await evt.ComputeIdAndSignAsync(key, handlenip4: false);
        return (evt, pubkey);
    }

    [Fact]
    public async Task AcceptsGenuineEvent()
    {
        var (evt, pubkey) = await SignChallenge();
        Assert.Null(NostrLoginService.ValidateSignedEvent(evt, pubkey, Challenge));
    }

    [Fact]
    public void RejectsNullEvent()
    {
        Assert.NotNull(NostrLoginService.ValidateSignedEvent(null, "pubkey", Challenge));
    }

    [Fact]
    public async Task RejectsWrongKind()
    {
        var (evt, pubkey) = await SignChallenge(kind: 1);
        var error = NostrLoginService.ValidateSignedEvent(evt, pubkey, Challenge);
        Assert.NotNull(error);
        Assert.Contains("kind", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsMismatchedPubkey()
    {
        var (evt, _) = await SignChallenge();
        var otherKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var otherPubkey = otherKey.CreateXOnlyPubKey().ToHex();
        var error = NostrLoginService.ValidateSignedEvent(evt, otherPubkey, Challenge);
        Assert.NotNull(error);
        Assert.Contains("pubkey", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsWrongChallenge()
    {
        var (evt, pubkey) = await SignChallenge();
        var error = NostrLoginService.ValidateSignedEvent(evt, pubkey, "ffffffffffffffffffffffffffffffff");
        Assert.NotNull(error);
        Assert.Contains("challenge", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsStaleTimestamp()
    {
        var (evt, pubkey) = await SignChallenge(createdAt: DateTimeOffset.UtcNow.AddMinutes(-30));
        var error = NostrLoginService.ValidateSignedEvent(evt, pubkey, Challenge);
        Assert.NotNull(error);
        Assert.Contains("timestamp", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsFutureTimestamp()
    {
        var (evt, pubkey) = await SignChallenge(createdAt: DateTimeOffset.UtcNow.AddMinutes(30));
        var error = NostrLoginService.ValidateSignedEvent(evt, pubkey, Challenge);
        Assert.NotNull(error);
        Assert.Contains("timestamp", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RejectsTamperedSignature()
    {
        var (evt, pubkey) = await SignChallenge();
        // Mutate the content after signing: the id/signature no longer match.
        evt.Content += " tampered";
        var error = NostrLoginService.ValidateSignedEvent(evt, pubkey, Challenge);
        Assert.NotNull(error);
    }
}
