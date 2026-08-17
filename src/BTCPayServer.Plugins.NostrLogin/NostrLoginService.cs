using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;
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

    /// <summary>
    /// Random nonce bound to the browser that created a Login session (M2, anti-QRLjacking).
    /// The sign-in cookie is only issued when the caller presents a matching bind cookie.
    /// Null for Link sessions (already authenticated + CSRF-bound to the user).
    /// </summary>
    public string? BindingNonce { get; init; }

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
    public static readonly string[] DefaultRelays = ["wss://nos.lol", "wss://relay.primal.net"];
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RelayConnectTimeout = TimeSpan.FromSeconds(15);
    private const int SignedEventMaxAgeMinutes = 10;

    // M3: throttle anonymous login-session creation to bound relay connections / background tasks.
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromMinutes(1);
    private const int MaxLoginSessionsPerWindow = 10;

    private readonly ConcurrentDictionary<string, Nip46Session> _sessions = new();
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _rateLimit = new();
    private readonly ILogger<NostrLoginService> _logger;

    public NostrLoginService(ILogger<NostrLoginService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Returns true if a new login session is allowed for this rate-limit key (typically the
    /// client IP), and records the attempt. Link sessions (authenticated) are not rate limited.
    /// </summary>
    private bool AllowLoginAttempt(string rateLimitKey)
    {
        var now = DateTimeOffset.UtcNow;
        var updated = _rateLimit.AddOrUpdate(
            rateLimitKey,
            _ => (1, now),
            (_, current) => now - current.WindowStart > RateLimitWindow
                ? (1, now)
                : (current.Count + 1, current.WindowStart));
        return updated.Count <= MaxLoginSessionsPerWindow;
    }

    public async Task<Nip46Session> CreateSessionAsync(Nip46SessionPurpose purpose, string[] relays, string appName,
        string? linkUserId = null, string? bindingNonce = null, string? rateLimitKey = null)
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
            return rejected;
        }

        if (relays.Length == 0)
            relays = DefaultRelays;

        var clientKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var clientPubkey = clientKey.CreateXOnlyPubKey().ToHex();
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var connectUri = BuildConnectUri(clientPubkey, relays, secret, appName);

        var session = new Nip46Session
        {
            Id = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            LinkUserId = linkUserId,
            ConnectUri = connectUri,
            BindingNonce = bindingNonce
        };
        _sessions[session.Id] = session;
        session.Cts.CancelAfter(SessionLifetime);
        var ct = session.Cts.Token;

        // Connect per relay and tolerate partial failures: one dead relay must not kill the session.
        var clients = new List<NostrClient>();
        foreach (var relay in relays)
        {
            var relayClient = new NostrClient(new Uri(relay));
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(RelayConnectTimeout);
                await relayClient.ConnectAndWaitUntilConnected(connectCts.Token, ct);
                clients.Add(relayClient);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("NostrLogin session {SessionId}: could not connect to relay {Relay}: {Error}",
                    session.Id, relay, ex.Message);
                relayClient.Dispose();
            }
        }
        if (clients.Count == 0)
        {
            Fail(session, "Could not connect to any nostr relay.");
            ZeroizeAndDispose(clientKey);
            return session;
        }

        // Subscribe before handing out the QR: the connect ack is sent exactly once.
        var events = Channel.CreateUnbounded<NostrEvent>();
        var subscriptionId = Guid.NewGuid().ToString("N");
        var filters = new[]
        {
            new NostrSubscriptionFilter
            {
                Kinds = [24133],
                ReferencedPublicKeys = [clientPubkey]
            }
        };
        // DIAG (this instance only — do NOT ship publicly): surface the handshake start on the
        // server log so a signer that never completes can be triaged (the failure path is
        // otherwise Debug-only / browser-only).
        _logger.LogInformation(
            "NostrLogin DIAG session {SessionId}: listening on {RelayCount} relay(s) [{Relays}] for #p={ClientPubkey}",
            session.Id, clients.Count, string.Join(", ", relays), clientPubkey);
        foreach (var relayClient in clients)
        {
            relayClient.EventsReceived += (_, args) =>
            {
                if (args.subscriptionId != subscriptionId)
                    return;
                foreach (var evt in args.events)
                    events.Writer.TryWrite(evt);
            };
            await relayClient.CreateSubscription(subscriptionId, filters, ct);
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await ProcessAsync(session, clientKey, clientPubkey, secret, clients, events, ct);
            }
            catch (OperationCanceledException)
            {
                Fail(session, "Timed out waiting for signer approval.");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "NostrLogin session {SessionId} failed", session.Id);
                Fail(session, "Unexpected error: " + ex.Message);
            }
            finally
            {
                foreach (var relayClient in clients)
                {
                    try
                    {
                        relayClient.Dispose();
                    }
                    catch (Exception)
                    {
                    }
                }
                // M1: ProcessAsync returns immediately on any terminal state (approved /
                // failed / timeout / exception), so the ephemeral key is wiped and disposed
                // promptly on resolution rather than lingering until the stale-session sweep.
                ZeroizeAndDispose(clientKey);
            }
        });

        return session;
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

    private void Fail(Nip46Session session, string error)
    {
        if (session.Status == Nip46SessionStatus.Pending)
        {
            session.Status = Nip46SessionStatus.Failed;
            session.Error = error;
            // DIAG (this instance only): the failure reason is otherwise browser-only. Surface it
            // on the server log so a stuck handshake can be triaged post-hoc.
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
    }

    // Exposed for unit tests.
    internal bool AllowLoginAttemptForTest(string rateLimitKey) => AllowLoginAttempt(rateLimitKey);
    internal static int MaxLoginSessionsPerWindowForTest => MaxLoginSessionsPerWindow;

    /// <summary>
    /// Builds the nostrconnect:// URI encoding the ephemeral client pubkey, relays, one-time
    /// secret, requested permission (sign_event:22242) and app name.
    /// </summary>
    internal static string BuildConnectUri(string clientPubkey, string[] relays, string secret, string appName)
    {
        var relayParams = string.Join("&", relays.Select(r => "relay=" + Uri.EscapeDataString(r)));
        return $"nostrconnect://{clientPubkey}?{relayParams}&secret={secret}" +
               $"&perms={Uri.EscapeDataString("sign_event:22242")}" +
               $"&name={Uri.EscapeDataString(appName)}";
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

    private async Task ProcessAsync(Nip46Session session, ECPrivKey clientKey, string clientPubkey,
        string secret, List<NostrClient> clients, Channel<NostrEvent> events, CancellationToken ct)
    {
        async Task Publish(NostrEvent evt)
        {
            foreach (var relayClient in clients)
            {
                try
                {
                    await relayClient.PublishEvent(evt, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug("NostrLogin session {SessionId}: publish failed on a relay: {Error}", session.Id, ex.Message);
                }
            }
        }

        string? signerPubkey = null;
        string? userPubkey = null;
        var useNip04 = false;
        string? getPubkeyRequestId = null;
        string? signRequestId = null;
        string? challenge = null;
        var seenEventIds = new HashSet<string>();

        await foreach (var evt in events.Reader.ReadAllAsync(ct))
        {
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
                // DIAG (this instance only): promoted to Info so a decrypt mismatch (wrong
                // conversation key / scheme) is visible on the server log, not just Debug.
                _logger.LogInformation(ex, "NostrLogin DIAG session {SessionId}: could not decrypt event {EventId} from {Pubkey}", session.Id, evt.Id, evt.PublicKey);
                continue;
            }
            if (msg is null)
                continue;

            if (signerPubkey is null)
            {
                // Expect connect ack: result echoes our secret ("ack" for legacy signers)
                if (msg.Result == secret || msg.Result == "ack")
                {
                    signerPubkey = evt.PublicKey;
                    useNip04 = msgWasNip04;
                    // DIAG (this instance only): milestone log — the handshake reached ack.
                    _logger.LogInformation("NostrLogin DIAG session {SessionId}: ACK accepted from {Pubkey}, sending get_public_key (nip04={Nip04})", session.Id, signerPubkey, useNip04);
                    getPubkeyRequestId = await SendRequest(Publish, clientKey, clientPubkey, signerPubkey,
                        "get_public_key", [], useNip04);
                }
                continue;
            }

            if (msg.Result == "auth_url")
            {
                Fail(session, "This signer requires a browser-based authorization flow which is not supported. Please use a signer like Amber.");
                return;
            }

            if (msg.Id == getPubkeyRequestId && userPubkey is null)
            {
                if (!string.IsNullOrEmpty(msg.Error))
                {
                    Fail(session, "Signer returned an error: " + msg.Error);
                    return;
                }
                if (msg.Result is not { Length: 64 } || !msg.Result.All(Uri.IsHexDigit))
                {
                    Fail(session, "Signer returned an invalid public key.");
                    return;
                }
                userPubkey = msg.Result.ToLowerInvariant();

                challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
                var unsigned = new JsonObject
                {
                    ["kind"] = 22242,
                    ["created_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["content"] = $"BTCPay Server sign-in challenge: {challenge}",
                    ["tags"] = new JsonArray(new JsonArray("challenge", challenge))
                };
                signRequestId = await SendRequest(Publish, clientKey, clientPubkey, signerPubkey,
                    "sign_event", [unsigned.ToJsonString()], useNip04);
                continue;
            }

            if (msg.Id == signRequestId)
            {
                if (!string.IsNullOrEmpty(msg.Error))
                {
                    Fail(session, "Signer rejected the request: " + msg.Error);
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
                    Fail(session, "Signer returned an invalid event.");
                    return;
                }

                var error = ValidateSignedEvent(signed, userPubkey!, challenge!);
                if (error is not null)
                {
                    Fail(session, error);
                    return;
                }

                session.UserPubkey = userPubkey;
                session.Status = Nip46SessionStatus.Approved;
                _logger.LogInformation("NostrLogin session {SessionId} approved for pubkey {Pubkey}", session.Id, userPubkey);
                return;
            }
        }
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

    private static async Task<string> SendRequest(Func<NostrEvent, Task> publish, ECPrivKey clientKey, string clientPubkey,
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
        await publish(evt);
        return requestId;
    }

    public void Dispose()
    {
        foreach (var id in _sessions.Keys)
            RemoveSession(id);
    }
}
