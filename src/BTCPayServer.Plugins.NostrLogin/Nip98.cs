using System;
using System.Collections.Concurrent;
using System.Linq;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// NIP-98 (HTTP Auth, kind 27235) signed-event validation. This is the auth-critical gate shared
/// by both the QR/session flow (<see cref="NostrLoginService"/>) and the open
/// <c>POST /login/nostr/nip98</c> endpoint, so it is <c>internal static</c> and unit tested.
///
/// A NIP-98 event proves the sender controls <c>event.pubkey</c> AND binds the proof to a specific
/// URL (<c>u</c> tag) + HTTP method (<c>method</c> tag) + moment in time (freshness), and is
/// single-use (replay guard). Semantics mirror the vezir reference verifier
/// (<c>vezir/server/nip98.py</c>) so the two stay compatible.
/// </summary>
internal static class Nip98
{
    internal const int Kind = 27235;
    private const int MaxAgeMinutes = 10;

    /// <summary>Much shorter window for the GET magic-link variant: the proof travels in a URL
    /// (server logs, proxies, browser history), so its usable lifetime is deliberately tight
    /// (audit finding 7). Signer apps mint the link on tap, so 90 s is ample.</summary>
    internal const double GetLinkMaxAgeMinutes = 1.5;

    private static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(1);

    // Replay guard: consumed event id -> expiry. TTL = the full window an event can be accepted.
    private static readonly ConcurrentDictionary<string, DateTimeOffset> Consumed = new();

    /// <summary>
    /// Validates a signed NIP-98 event. Returns null when valid, otherwise a human-readable
    /// rejection reason.
    /// </summary>
    /// <param name="expectedNonce">
    /// The per-session nonce that must appear as a <c>challenge</c> tag (QR/session flow). Pass null
    /// for the open HTTP endpoint, where there is no prior session — the Schnorr signature, URL
    /// binding and replay guard are the gate there.
    /// </param>
    /// <param name="maxAgeMinutes">Freshness window in minutes; defaults to the standard 10.
    /// Callers carrying a proof in a URL (GET magic link) pass a much tighter value.</param>
    internal static string? Validate(NostrEvent? signed, string expectedPubkey, string expectedUrl,
        string expectedMethod, string? expectedNonce, double maxAgeMinutes = MaxAgeMinutes)
    {
        if (signed is null)
            return "Signer returned an invalid event.";
        if (signed.Kind != Kind)
            return "Signed event has the wrong kind.";
        if (string.IsNullOrEmpty(signed.PublicKey)
            || !string.Equals(signed.PublicKey, expectedPubkey, StringComparison.OrdinalIgnoreCase))
            return "Signed event pubkey does not match.";

        var u = signed.GetTaggedData("u").FirstOrDefault();
        if (u is null || !UrlMatches(u, expectedUrl))
            return "Signed event 'u' tag does not match the expected URL.";

        var method = signed.GetTaggedData("method").FirstOrDefault();
        if (!string.Equals(method, expectedMethod, StringComparison.OrdinalIgnoreCase))
            return "Signed event 'method' tag mismatch.";

        if (expectedNonce is not null && !signed.GetTaggedData("challenge").Contains(expectedNonce))
            return "Signed event does not contain the expected challenge.";

        var age = DateTimeOffset.UtcNow - (signed.CreatedAt ?? DateTimeOffset.MinValue);
        if (age > TimeSpan.FromMinutes(maxAgeMinutes) || age < -FutureTolerance)
            return "Signed event timestamp is out of range.";

        if (!signed.Verify())
            return "Signed event has an invalid signature.";

        // Replay guard LAST: only record a fully-valid id so bogus ids can't poison the store.
        if (string.IsNullOrEmpty(signed.Id) || !TryConsume(signed.Id))
            return "Signed event already used (replay rejected).";

        return null;
    }

    /// <summary>Normalized-equality of two URLs for the <c>u</c>-tag binding check.</summary>
    internal static bool UrlMatches(string a, string b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.Ordinal);

    /// <summary>
    /// Lowercase scheme+host, strip default ports, strip trailing slashes on the path — so equivalent
    /// URLs compare equal regardless of insignificant differences (mirrors vezir <c>_normalize_url</c>).
    /// </summary>
    internal static string Normalize(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u))
            return url.TrimEnd('/');
        var scheme = u.Scheme.ToLowerInvariant();
        var host = u.Host.ToLowerInvariant();
        var portDefault = (scheme == "https" && u.Port == 443) || (scheme == "http" && u.Port == 80);
        var authority = portDefault ? host : $"{host}:{u.Port}";
        var path = u.AbsolutePath.TrimEnd('/');
        return $"{scheme}://{authority}{path}{u.Query}";
    }

    private static bool TryConsume(string id)
    {
        var now = DateTimeOffset.UtcNow;
        // Opportunistic prune (cheap; the store stays tiny at login scale).
        foreach (var kv in Consumed)
            if (kv.Value <= now)
                Consumed.TryRemove(kv.Key, out _);
        return Consumed.TryAdd(id.ToLowerInvariant(),
            now + TimeSpan.FromMinutes(MaxAgeMinutes) + FutureTolerance);
    }

    /// <summary>Test-only: clear the replay store so cases don't leak state into one another.</summary>
    internal static void ResetReplayStoreForTest() => Consumed.Clear();
}
