using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NBitcoin.Secp256k1;
using NNostr.Client;
using NNostr.Client.Protocols;

namespace BTCPayServer.Plugins.NostrLogin;

public enum Nip46SessionPurpose
{
    Login,
    Link
}

public enum Nip46SessionStatus
{
    Pending,
    Approved,
    Failed
}

public class Nip46Session
{
    public required string Id { get; init; }
    public required Nip46SessionPurpose Purpose { get; init; }

    /// <summary>User id that initiated a Link session (null for Login sessions).</summary>
    public string? LinkUserId { get; init; }

    public required string ConnectUri { get; init; }
    public DateTimeOffset CreatedAt { get; } = DateTimeOffset.UtcNow;

    public Nip46SessionStatus Status { get; internal set; } = Nip46SessionStatus.Pending;

    /// <summary>x-only pubkey (hex, lowercase) of the nostr user, set when Status == Approved.</summary>
    public string? UserPubkey { get; internal set; }

    public string? Error { get; internal set; }

    /// <summary>Per-session NIP-98 nonce embedded as the signed event's <c>challenge</c> tag (QR flow).</summary>
    internal string? Nip98Nonce { get; set; }

    /// <summary>Per-session kind-22242 challenge (fallback path).</summary>
    internal string? Challenge22242 { get; set; }

    /// <summary>
    /// HTTPS auth_url the bound signer asked the user to open to approve (web-signer flow). Surfaced
    /// to the browser by the status poller; cleared once the signer returns the real signed event.
    /// </summary>
    public string? AuthUrl { get; internal set; }

    /// <summary>
    /// Random nonce bound to the browser that created a Login session (M2, anti-QRLjacking).
    /// The sign-in cookie is only issued when the caller presents a matching bind cookie.
    /// Null for Link sessions (already authenticated + CSRF-bound to the user).
    /// </summary>
    public string? BindingNonce { get; init; }

    /// <summary>
    /// Origin classification for the probe counter ("onion" / "clearnet:{ip}"), set by the
    /// controller from the request. Null in tests / non-HTTP callers.
    /// </summary>
    internal string? OriginKey { get; init; }

    /// <summary>
    /// x-only pubkey (hex) of the first signer that sent a decryptable kind-24133 RPC, set the
    /// moment the hello arrives — even when auth subsequently fails (probe vs member forensics).
    /// </summary>
    internal string? SignerHelloPubkey { get; set; }

    /// <summary>Relays connected at session start (-1 = connect phase never completed).</summary>
    internal int RelaysConnected { get; set; } = -1;

    internal CancellationTokenSource Cts { get; } = new();
}

/// <summary>
/// Manages NIP-46 (Nostr Connect) sign-in sessions. For each session an ephemeral client key
/// is generated and a nostrconnect:// URI is displayed as QR code. The relay connections and
/// the kind-24133 subscription are established BEFORE the session is returned (and the QR is
/// rendered): the signer's connect ack is an ephemeral event sent exactly once, so we must
/// already be listening when the signer scans. A background task then drives the RPC flow
/// (connect ack -> get_public_key -> sign_event kind-22242) and validates the result.
/// </summary>
public class NostrLoginService : IDisposable
{
    public static readonly string[] DefaultRelays =
    [
        "wss://nos.lol",
        "wss://relay.damus.io",
        "wss://relay.primal.net",
        "wss://offchain.pub"
    ];

    /// <summary>
    /// Image advertised to the signer via the nostrconnect:// <c>image</c> param (NIP-46), shown
    /// as the service avatar so users recognise what they are connecting to.
    /// </summary>
    public const string DefaultImageUrl = "https://avatars.githubusercontent.com/u/31132886?s=200&v=4";

    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(5);
    private const int SignedEventMaxAgeMinutes = 10;

    // M3: throttle anonymous login-session creation to bound relay connections / background tasks.
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromMinutes(1);
    private const int MaxLoginSessionsPerWindow = 10;

    // Probe signal: login sessions that expire without any signer hello, counted per origin
    // class ("onion" / "clearnet:{ip}"). A single warn fires when the hourly count crosses the
    // threshold — Tor probers enumerate /login/nostr (creating sessions) without ever scanning
    // the QR, which is otherwise indistinguishable from a user who simply closed the tab.
    private static readonly TimeSpan ProbeWindow = TimeSpan.FromHours(1);
    private const int ProbeAlertThreshold = 5;

    private readonly ConcurrentDictionary<string, Nip46Session> _sessions = new();
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _rateLimit = new();
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _probelessSessions = new();
    private readonly ILogger<NostrLoginService> _logger;
    private readonly Nip98ReplayStore? _replayStore;

    public NostrLoginService(ILogger<NostrLoginService> logger, Nip98ReplayStore? replayStore = null)
    {
        _logger = logger;
        _replayStore = replayStore;
    }

    /// <summary>
    /// Returns true if a new login session is allowed for this rate-limit key (typically the
    /// client IP), and records the attempt. Link sessions (authenticated) are not rate limited.
    /// </summary>
    private bool AllowLoginAttempt(string rateLimitKey)
    {
        Cleanup(); // sweep on every attempt too: the open POST/GET endpoints never create sessions (audit finding 10)
        var now = DateTimeOffset.UtcNow;
        var updated = _rateLimit.AddOrUpdate(
            rateLimitKey,
            _ => (1, now),
            (_, current) => now - current.WindowStart > RateLimitWindow
                ? (1, now)
                : (current.Count + 1, current.WindowStart));
        return updated.Count <= MaxLoginSessionsPerWindow;
    }

    /// <summary>
    /// Creates a NIP-46 session and returns immediately with a ready-to-render nostrconnect:// URI.
    /// Relay connection, subscription and the RPC flow all run on a background task so the HTTP
    /// request rendering the QR never blocks on relay connectivity (a slow/dead relay used to hang
    /// the login request for up to the per-relay timeout, spinning the browser tab).
    /// </summary>
    public Task<Nip46Session> CreateSessionAsync(Nip46SessionPurpose purpose, string[] relays, string appName,
        string? linkUserId = null, string? bindingNonce = null, string? rateLimitKey = null,
        string? appUrl = null, string? imageUrl = null, bool diagnostics = false, string? loginUrl = null,
        bool relaysFromSettings = false, string? originKey = null)
    {
        Cleanup();

        // M3: only throttle anonymous login sessions; link sessions are already authenticated.
        if (purpose == Nip46SessionPurpose.Login && rateLimitKey is not null && !AllowLoginAttempt(rateLimitKey))
        {
            var rejected = new Nip46Session
            {
                Id = Guid.NewGuid().ToString("N"),
                Purpose = purpose,
                ConnectUri = "",
                Status = Nip46SessionStatus.Failed,
                Error = "Too many sign-in attempts. Please wait a moment and reload the page."
            };
            // Register it so the status poller surfaces the real reason rather than "expired".
            _sessions[rejected.Id] = rejected;
            return Task.FromResult(rejected);
        }

        if (relays.Length == 0)
            relays = DefaultRelays;

        var clientKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var clientPubkey = clientKey.CreateXOnlyPubKey().ToHex();
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var connectUri = BuildConnectUri(clientPubkey, relays, secret, appName, appUrl, imageUrl);

        var session = new Nip46Session
        {
            Id = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            LinkUserId = linkUserId,
            ConnectUri = connectUri,
            BindingNonce = bindingNonce,
            OriginKey = originKey
        };
        _sessions[session.Id] = session;
        session.Cts.CancelAfter(SessionLifetime);

        _logger.LogInformation(
            "NostrLogin session {SessionId} created (purpose={Purpose}, relays=[{Relays}], relaySource={RelaySource})",
            session.Id, purpose, string.Join(", ", relays), relaysFromSettings ? "settings" : "defaults");

        // Everything relay-related runs off the request thread. The QR is returned synchronously
        // below; by the time a human scans it (seconds later) the background connect has completed.
        _ = Task.Run(() => RunSessionAsync(session, clientKey, clientPubkey, secret, relays, diagnostics, loginUrl));

        return Task.FromResult(session);
    }

    /// <summary>
    /// Background driver: connects to the relays (in parallel), subscribes, and runs the RPC flow.
    /// Isolated from <see cref="CreateSessionAsync"/> so the request thread never waits on relays.
    /// </summary>
    private async Task RunSessionAsync(Nip46Session session, ECPrivKey clientKey, string clientPubkey,
        string secret, string[] relays, bool diagnostics, string? loginUrl)
    {
        var ct = session.Cts.Token;
        // The pool owns all per-relay connections + the kind-24133 subscription and provides the
        // reliability primitives (fan-out publish, reconnect-dead). Subscribe-before-read is
        // preserved: ConnectAsync subscribes each relay before ProcessAsync reads any event, so the
        // one-shot connect ack is never missed.
        var pool = new RelayPool(relays, clientPubkey, _logger, session.Id, diagnostics);
        try
        {
            // Connect to all relays in parallel and tolerate partial failures: one dead relay must
            // neither kill the session nor delay the others.
            var connected = await pool.ConnectAsync(ct);
            session.RelaysConnected = connected;
            if (connected == 0)
            {
                _logger.LogInformation(
                    "NostrLogin session {SessionId} expired unauthenticated ({Reason})",
                    session.Id, ExpiryRelayDead);
                Fail(session, "Could not connect to any nostr relay.", diagnostics);
                return;
            }

            // DIAG (off by default; toggle via admin "Enable diagnostic logging"): surface the
            // handshake start so a signer that never completes can be triaged (the failure path is
            // otherwise Debug-only / browser-only).
            if (diagnostics)
                _logger.LogInformation(
                    "NostrLogin DIAG session {SessionId}: listening on {RelayCount} relay(s) [{Relays}] for #p={ClientPubkey}",
                    session.Id, connected, string.Join(", ", relays), clientPubkey);

            await ProcessAsync(session, clientKey, clientPubkey, secret, pool, ct, diagnostics, loginUrl);
        }
        catch (OperationCanceledException)
        {
            // The Cts fires on session-lifetime expiry AND on RemoveSession after a terminal
            // state; only a still-Pending session is a genuine unauthenticated expiry.
            if (session.Status == Nip46SessionStatus.Pending)
            {
                var reason = ClassifyUnauthenticatedExpiry(session);
                _logger.LogInformation(
                    "NostrLogin session {SessionId} expired unauthenticated ({Reason})", session.Id, reason);
                // Probe counter is for anonymous login sessions; a Link session expiring is a
                // user who changed their mind, not recon.
                if (reason == ExpiryNoHello && session.Purpose == Nip46SessionPurpose.Login)
                    RecordProbelessExpiry(session.OriginKey);
            }
            Fail(session, "Timed out waiting for signer approval.", diagnostics);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "NostrLogin session {SessionId} failed", session.Id);
            Fail(session, "Unexpected error: " + ex.Message, diagnostics);
        }
        finally
        {
            pool.Dispose();
            // M1: ProcessAsync returns immediately on any terminal state (approved / failed /
            // timeout / exception), so the ephemeral key is wiped and disposed promptly on
            // resolution rather than lingering until the stale-session sweep.
            ZeroizeAndDispose(clientKey);
        }
    }

    /// <summary>
    /// Overwrites the private key bytes before disposing. Dispose alone frees the handle but
    /// does not guarantee the 32-byte secret is cleared from memory (M1 defense-in-depth).
    /// </summary>
    private static void ZeroizeAndDispose(ECPrivKey key)
    {
        try
        {
            Span<byte> scratch = stackalloc byte[32];
            key.WriteToSpan(scratch);
            scratch.Clear();
        }
        catch (Exception)
        {
        }
        finally
        {
            key.Dispose();
        }
    }

    public Nip46Session? GetSession(string id) => _sessions.GetValueOrDefault(id);

    public void RemoveSession(string id)
    {
        if (_sessions.TryRemove(id, out var session))
            session.Cts.Cancel();
    }

    private void Fail(Nip46Session session, string error, bool diagnostics = false)
    {
        if (session.Status == Nip46SessionStatus.Pending)
        {
            session.Status = Nip46SessionStatus.Failed;
            session.Error = error;
            // DIAG (off by default; toggle via admin "Enable diagnostic logging"): the failure
            // reason is otherwise browser-only. Surface it so a stuck handshake can be triaged.
            if (diagnostics)
                _logger.LogInformation("NostrLogin DIAG session {SessionId}: FAILED — {Error}", session.Id, error);
        }
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        var cutoff = now - SessionLifetime - TimeSpan.FromMinutes(5);
        foreach (var (id, session) in _sessions)
            if (session.CreatedAt < cutoff)
                RemoveSession(id);

        // Sweep stale rate-limit windows so the dictionary cannot grow unbounded.
        foreach (var (key, window) in _rateLimit)
            if (now - window.WindowStart > RateLimitWindow)
                _rateLimit.TryRemove(key, out _);

        // Same for the probe counter.
        foreach (var (key, window) in _probelessSessions)
            if (now - window.WindowStart > ProbeWindow)
                _probelessSessions.TryRemove(key, out _);
    }

    /// <summary>
    /// Public rate-limit gate for the anonymous NIP-98 endpoint: returns true if a login attempt is
    /// allowed for this key (typically the client IP) and records it.
    /// </summary>
    public bool AllowLogin(string rateLimitKey) => AllowLoginAttempt(rateLimitKey);

    // Exposed for unit tests.
    internal bool AllowLoginAttemptForTest(string rateLimitKey) => AllowLoginAttempt(rateLimitKey);
    internal static int MaxLoginSessionsPerWindowForTest => MaxLoginSessionsPerWindow;
    internal void RecordProbelessExpiryForTest(string originKey) => RecordProbelessExpiry(originKey);
    internal static int ProbeAlertThresholdForTest => ProbeAlertThreshold;

    internal const string ExpiryRelayDead = "relay-dead";
    internal const string ExpiryNoHello = "no-hello";
    internal const string ExpiryHelloNoAuth = "hello-no-auth";

    /// <summary>
    /// Why a session ended without approval: no relay carried the handshake, no signer ever
    /// spoke, or a signer hello arrived but the auth event never completed.
    /// </summary>
    internal static string ClassifyUnauthenticatedExpiry(Nip46Session session) =>
        session.RelaysConnected <= 0 ? ExpiryRelayDead
        : session.SignerHelloPubkey is null ? ExpiryNoHello
        : ExpiryHelloNoAuth;

    /// <summary>
    /// Counts a session that expired without any signer hello against its origin class and
    /// warns once when the hourly threshold is crossed. Fires exactly once per window per key
    /// (== threshold), so a persistent prober does not spam the alert channel.
    /// </summary>
    private void RecordProbelessExpiry(string? originKey)
    {
        var key = originKey ?? "unknown";
        var now = DateTimeOffset.UtcNow;
        var updated = _probelessSessions.AddOrUpdate(
            key,
            _ => (1, now),
            (_, current) => now - current.WindowStart > ProbeWindow
                ? (1, now)
                : (current.Count + 1, current.WindowStart));
        if (updated.Count == ProbeAlertThreshold)
            _logger.LogWarning(
                "NostrLogin: {Count} NostrConnect sessions expired without signer contact in the last hour from {Origin}",
                updated.Count, key);
    }

    /// <summary>First 8 hex chars of a pubkey, matching the truncation used elsewhere in logs.</summary>
    internal static string TruncatePubkey(string? pubkey) =>
        pubkey is { Length: > 8 } ? pubkey[..8] : pubkey ?? "?";

    /// <summary>
    /// Builds the nostrconnect:// URI encoding the ephemeral client pubkey, relays, one-time
    /// secret, requested permission (sign_event:22242), app name and — when provided — the
    /// instance URL and service image (NIP-46 <c>url</c>/<c>image</c> params) so the signer can
    /// show a recognisable avatar and tell instances apart.
    /// </summary>
    internal static string BuildConnectUri(string clientPubkey, string[] relays, string secret, string appName,
        string? appUrl = null, string? imageUrl = null, string perms = "sign_event:27235,get_public_key")
    {
        var relayParams = string.Join("&", relays.Select(r => "relay=" + Uri.EscapeDataString(r)));
        var uri = $"nostrconnect://{clientPubkey}?{relayParams}&secret={secret}" +
                  $"&perms={Uri.EscapeDataString(perms)}" +
                  $"&name={Uri.EscapeDataString(appName)}";
        if (!string.IsNullOrEmpty(appUrl))
            uri += $"&url={Uri.EscapeDataString(appUrl)}";
        if (!string.IsNullOrEmpty(imageUrl))
            uri += $"&image={Uri.EscapeDataString(imageUrl)}";
        return uri;
    }

    /// <summary>
    /// Constant-time comparison of the browser-bound nonce (M2). Returns true only when both
    /// values are present and equal. Handles differing lengths without throwing (unlike a bare
    /// CryptographicOperations.FixedTimeEquals on mismatched spans).
    /// </summary>
    internal static bool BindingNonceMatches(string? expected, string? presented)
    {
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(presented))
            return false;
        var a = System.Text.Encoding.ASCII.GetBytes(expected);
        var b = System.Text.Encoding.ASCII.GetBytes(presented);
        if (a.Length != b.Length)
            return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private class Nip46Rpc
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("method")] public string? Method { get; set; }
        [JsonPropertyName("params")] public string[]? Params { get; set; }
        [JsonPropertyName("result")] public string? Result { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    private enum AuthScheme
    {
        Nip98,
        Challenge22242
    }

    // How long we wait for the signer to sign the NIP-98 (27235) event before falling back to the
    // legacy kind-22242 challenge. A signer that does not pre-grant 27235 raises a per-request
    // approval the user may never see (they only expect one tap), so we time out and try 22242.
    private static readonly TimeSpan Nip98SignSubTimeout = TimeSpan.FromSeconds(20);

    // Re-broadcast an in-flight request this often while awaiting its response. Ephemeral
    // kind-24133 events can be dropped; periodic republish (+ reconnecting dead relays first)
    // self-heals a lost publish and picks up a relay that came back mid-wait.
    private static readonly TimeSpan RepublishInterval = TimeSpan.FromSeconds(4);

    private async Task ProcessAsync(Nip46Session session, ECPrivKey clientKey, string clientPubkey,
        string secret, RelayPool pool, CancellationToken ct, bool diagnostics, string? loginUrl)
    {
        // Broadcast (with a dead-relay reconnect first) so our and the signer's relay sets keep
        // overlapping — the common cause of a request never reaching the signer is too few shared,
        // live relays carrying it.
        async Task<int> Publish(NostrEvent evt)
        {
            await pool.ReconnectDeadAsync(ct);
            return await pool.PublishAsync(evt, ct);
        }

        string? signerPubkey = null;
        string? userPubkey = null;
        var useNip04 = false;
        var seenEventIds = new HashSet<string>();

        // The single in-flight request we are awaiting (build once, republish many). Null between
        // requests. Rebuilt for each new request so republish re-sends the exact same event.
        NostrEvent? inflight = null;
        string? inflightId = null;
        var lastPublish = DateTimeOffset.UtcNow;

        // NIP-98 sign attempt bookkeeping (for the 22242 fallback).
        var scheme = AuthScheme.Nip98;
        DateTimeOffset? nip98SignSentAt = null;

        async Task<(NostrEvent evt, string id)> Send(string method, string[] parameters)
        {
            var (evt, id) = await BuildRequestEvent(clientKey, clientPubkey, signerPubkey!, method, parameters, useNip04);
            inflight = evt;
            inflightId = id;
            lastPublish = DateTimeOffset.UtcNow;
            if (await Publish(evt) == 0)
                _logger.LogDebug("NostrLogin session {SessionId}: {Method} reached no relay (will republish)", session.Id, method);
            return (evt, id);
        }

        // Build the sign_event request for the current scheme against the resolved user pubkey.
        async Task SendSignRequest()
        {
            JsonObject unsigned;
            if (scheme == AuthScheme.Nip98)
            {
                // NIP-98 (kind 27235): bind to the login URL + method; embed the per-session nonce
                // as a `challenge` tag so the plugin's browser-session binding and NIP-98
                // request-binding coexist. loginUrl is always set for a real login/link flow.
                session.Nip98Nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
                unsigned = new JsonObject
                {
                    ["kind"] = 27235,
                    ["created_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["content"] = "",
                    ["tags"] = new JsonArray(
                        new JsonArray("u", loginUrl ?? ""),
                        new JsonArray("method", "POST"),
                        new JsonArray("challenge", session.Nip98Nonce))
                };
                nip98SignSentAt = DateTimeOffset.UtcNow;
            }
            else
            {
                session.Challenge22242 = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
                unsigned = new JsonObject
                {
                    ["kind"] = 22242,
                    ["created_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["content"] = $"BTCPay Server sign-in challenge: {session.Challenge22242}",
                    ["tags"] = new JsonArray(new JsonArray("challenge", session.Challenge22242))
                };
            }
            await Send("sign_event", [unsigned.ToJsonString()]);
        }

        while (!ct.IsCancellationRequested)
        {
            // Republish the in-flight request on a timer so a dropped/mis-routed publish self-heals.
            if (inflight is not null && DateTimeOffset.UtcNow - lastPublish >= RepublishInterval)
            {
                lastPublish = DateTimeOffset.UtcNow;
                await Publish(inflight);
            }

            // Fall back to the legacy 22242 challenge if the signer never signs the NIP-98 event
            // (it likely raised a per-request approval the user does not expect). Only while the
            // sign request is the in-flight one and we are still on the NIP-98 attempt.
            if (scheme == AuthScheme.Nip98 && userPubkey is not null && nip98SignSentAt is not null
                && DateTimeOffset.UtcNow - nip98SignSentAt >= Nip98SignSubTimeout)
            {
                if (diagnostics)
                    _logger.LogInformation("NostrLogin DIAG session {SessionId}: NIP-98 sign timed out; falling back to kind-22242", session.Id);
                scheme = AuthScheme.Challenge22242;
                nip98SignSentAt = null;
                await SendSignRequest();
            }

            NostrEvent? evt;
            try
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(TimeSpan.FromSeconds(1)); // wake to run the republish/fallback timers
                evt = await pool.Events.ReadAsync(readCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                continue; // timer tick, no event this second
            }

            if (evt.Id is null || !seenEventIds.Add(evt.Id))
                continue; // deduplicate across relays
            if (signerPubkey is not null && evt.PublicKey != signerPubkey)
                continue;

            Nip46Rpc? msg;
            bool msgWasNip04;
            try
            {
                (msg, msgWasNip04) = await DecryptRpc(evt, clientKey);
            }
            catch (Exception ex)
            {
                // DIAG (off by default; toggle via admin "Enable diagnostic logging"): a decrypt
                // mismatch (wrong conversation key / scheme) is surfaced on the server log, not
                // just Debug, so it can be triaged.
                if (diagnostics)
                    _logger.LogInformation(ex, "NostrLogin DIAG session {SessionId}: could not decrypt event {EventId} from {Pubkey}", session.Id, evt.Id, evt.PublicKey);
                continue;
            }
            if (msg is null)
                continue;

            // Earliest identity signal: a signer sent a decryptable kind-24133 RPC. Log its
            // pubkey immediately, even if the ack/auth subsequently fails — today a prober who
            // scans but never completes leaves no identity trace at all.
            if (signerPubkey is null && session.SignerHelloPubkey is null)
            {
                session.SignerHelloPubkey = evt.PublicKey;
                _logger.LogInformation("NostrLogin session {SessionId}: signer hello from pubkey {PubkeyPrefix}",
                    session.Id, TruncatePubkey(evt.PublicKey));
            }

            if (signerPubkey is null)
            {
                // Expect connect ack: result echoes our secret ("ack" for legacy signers)
                if (msg.Result == secret || msg.Result == "ack")
                {
                    signerPubkey = evt.PublicKey;
                    useNip04 = msgWasNip04;
                    // DIAG (off by default; toggle via admin "Enable diagnostic logging"):
                    // milestone log — the handshake reached ack.
                    if (diagnostics)
                        _logger.LogInformation("NostrLogin DIAG session {SessionId}: ACK accepted from {Pubkey}, sending get_public_key (nip04={Nip04})", session.Id, signerPubkey, useNip04);
                    await Send("get_public_key", []);
                }
                continue;
            }

            // auth_url challenge: surface it (guarded) so a web signer can complete, then keep
            // waiting for the real result on the same request. Only honour an HTTPS auth_url from
            // the bound signer (anti-phishing); anything else is logged and dropped.
            if (msg.Result == "auth_url")
            {
                var url = msg.Error;
                if (url is not null && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                    && evt.PublicKey == signerPubkey)
                {
                    if (session.AuthUrl != url)
                    {
                        session.AuthUrl = url;
                        _logger.LogInformation("NostrLogin session {SessionId}: signer requested auth_url approval", session.Id);
                    }
                }
                else
                {
                    _logger.LogWarning("NostrLogin session {SessionId}: ignoring untrusted auth_url", session.Id);
                }
                continue;
            }

            if (msg.Id == inflightId && userPubkey is null)
            {
                // This is the get_public_key response.
                if (!string.IsNullOrEmpty(msg.Error))
                {
                    Fail(session, "Signer returned an error: " + msg.Error, diagnostics);
                    return;
                }
                if (msg.Result is not { Length: 64 } || !msg.Result.All(Uri.IsHexDigit))
                {
                    Fail(session, "Signer returned an invalid public key.", diagnostics);
                    return;
                }
                userPubkey = msg.Result.ToLowerInvariant();
                await SendSignRequest();
                continue;
            }

            if (msg.Id == inflightId && userPubkey is not null)
            {
                // This is a sign_event response for the current scheme.
                if (!string.IsNullOrEmpty(msg.Error))
                {
                    // On the NIP-98 attempt, a signer error means it will not pre-grant 27235;
                    // fall back to 22242 rather than failing the whole login.
                    if (scheme == AuthScheme.Nip98)
                    {
                        if (diagnostics)
                            _logger.LogInformation("NostrLogin DIAG session {SessionId}: NIP-98 sign rejected ({Error}); falling back to kind-22242", session.Id, msg.Error);
                        scheme = AuthScheme.Challenge22242;
                        nip98SignSentAt = null;
                        await SendSignRequest();
                        continue;
                    }
                    Fail(session, "Signer rejected the request: " + msg.Error, diagnostics);
                    return;
                }
                if (msg.Result is null)
                    continue;

                NostrEvent? signed;
                try
                {
                    signed = JsonSerializer.Deserialize<NostrEvent>(msg.Result);
                }
                catch (Exception)
                {
                    Fail(session, "Signer returned an invalid event.", diagnostics);
                    return;
                }

                string? error;
                if (scheme == AuthScheme.Nip98)
                    error = await Nip98.ValidateAsync(signed, userPubkey!, loginUrl ?? "", "POST",
                        session.Nip98Nonce,
                        tryConsume: _replayStore is null ? null : _replayStore.TryConsumeAsync);
                else
                    error = ValidateSignedEvent(signed, userPubkey!, session.Challenge22242!);
                if (error is not null)
                {
                    Fail(session, error, diagnostics);
                    return;
                }

                session.UserPubkey = userPubkey;
                session.Status = Nip46SessionStatus.Approved;
                session.AuthUrl = null;
                // "Verified" only means the signer proved key ownership — whether that key maps
                // to a user is decided (and logged) by the controller's mapping step.
                _logger.LogInformation("NostrLogin session {SessionId}: auth event verified for pubkey {PubkeyPrefix} (scheme={Scheme})",
                    session.Id, TruncatePubkey(userPubkey), scheme);
                return;
            }
        }

        ct.ThrowIfCancellationRequested();
    }

    /// <summary>
    /// Validates a signed kind-22242 challenge event. Returns null when valid, otherwise a
    /// human-readable rejection reason. This is the auth-critical gate — exposed as internal
    /// so its accept/reject cases can be unit tested.
    /// </summary>
    internal static string? ValidateSignedEvent(NostrEvent? signed, string expectedPubkey, string expectedChallenge)
    {
        if (signed is null)
            return "Signer returned an invalid event.";
        if (signed.Kind != 22242)
            return "Signed event has the wrong kind.";
        if (!string.Equals(signed.PublicKey, expectedPubkey, StringComparison.OrdinalIgnoreCase))
            return "Signed event pubkey does not match the signer's user pubkey.";
        if (!signed.GetTaggedData("challenge").Contains(expectedChallenge))
            return "Signed event does not contain the expected challenge.";
        var age = DateTimeOffset.UtcNow - (signed.CreatedAt ?? DateTimeOffset.MinValue);
        if (age > TimeSpan.FromMinutes(SignedEventMaxAgeMinutes) || age < TimeSpan.FromMinutes(-SignedEventMaxAgeMinutes))
            return "Signed event timestamp is out of range.";
        if (!signed.Verify())
            return "Signed event has an invalid signature.";
        return null;
    }

    private static async Task<(Nip46Rpc?, bool)> DecryptRpc(NostrEvent evt, ECPrivKey clientKey)
    {
        if (string.IsNullOrEmpty(evt.Content))
            return (null, false);
        string json;
        bool wasNip04;
        if (evt.Content.Contains("?iv="))
        {
            json = await evt.DecryptNip04EventAsync(clientKey, skipKindVerification: true);
            wasNip04 = true;
        }
        else
        {
            json = NIP44.Decrypt(clientKey, evt.GetPublicKey(), evt.Content);
            wasNip04 = false;
        }
        return (JsonSerializer.Deserialize<Nip46Rpc>(json), wasNip04);
    }

    /// <summary>
    /// Encrypt + sign a kind-24133 request event. Building is kept separate from publishing so the
    /// wait loop can re-broadcast the exact same event on a flaky link (a single ws.send the local
    /// OS accepts does not guarantee the relay delivered it).
    /// </summary>
    private static async Task<(NostrEvent evt, string requestId)> BuildRequestEvent(ECPrivKey clientKey, string clientPubkey,
        string signerPubkey, string method, string[] parameters, bool useNip04)
    {
        var requestId = Guid.NewGuid().ToString("N");
        var json = JsonSerializer.Serialize(new Nip46Rpc { Id = requestId, Method = method, Params = parameters });

        var evt = new NostrEvent
        {
            Kind = 24133,
            PublicKey = clientPubkey,
            CreatedAt = DateTimeOffset.UtcNow,
            Content = json
        };
        evt.SetTag("p", signerPubkey);

        if (useNip04)
            await evt.EncryptNip04EventAsync(clientKey, skipKindVerification: true);
        else
            evt.Content = NIP44.Encrypt(clientKey, NostrExtensions.ParsePubKey(signerPubkey), json);

        await evt.ComputeIdAndSignAsync(clientKey, handlenip4: false);
        return (evt, requestId);
    }

    public void Dispose()
    {
        foreach (var id in _sessions.Keys)
            RemoveSession(id);
    }
}
