using System;
using System.Collections.Concurrent;
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

    internal CancellationTokenSource Cts { get; } = new();
}

/// <summary>
/// Manages NIP-46 (Nostr Connect) sign-in sessions. For each session an ephemeral client key
/// is generated and a nostrconnect:// URI is displayed as QR code. A background task connects
/// to the relays, waits for the signer's connect ack, requests the user pubkey and a signed
/// kind-22242 challenge event, verifies it, and marks the session approved.
/// </summary>
public class NostrLoginService : IDisposable
{
    public static readonly string[] DefaultRelays = ["wss://nos.lol", "wss://relay.primal.net"];
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(5);
    private const int SignedEventMaxAgeMinutes = 10;

    private readonly ConcurrentDictionary<string, Nip46Session> _sessions = new();
    private readonly ILogger<NostrLoginService> _logger;

    public NostrLoginService(ILogger<NostrLoginService> logger)
    {
        _logger = logger;
    }

    public Nip46Session CreateSession(Nip46SessionPurpose purpose, string[] relays, string appName, string? linkUserId = null)
    {
        Cleanup();
        if (relays.Length == 0)
            relays = DefaultRelays;

        var clientKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var clientPubkey = clientKey.CreateXOnlyPubKey().ToHex();
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        var relayParams = string.Join("&", relays.Select(r => "relay=" + Uri.EscapeDataString(r)));
        var connectUri =
            $"nostrconnect://{clientPubkey}?{relayParams}&secret={secret}" +
            $"&perms={Uri.EscapeDataString("sign_event:22242")}" +
            $"&name={Uri.EscapeDataString(appName)}";

        var session = new Nip46Session
        {
            Id = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            LinkUserId = linkUserId,
            ConnectUri = connectUri
        };
        _sessions[session.Id] = session;
        session.Cts.CancelAfter(SessionLifetime);

        _ = Task.Run(async () =>
        {
            try
            {
                await RunSessionAsync(session, clientKey, clientPubkey, secret, relays, session.Cts.Token);
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
                clientKey.Dispose();
            }
        });

        return session;
    }

    public Nip46Session? GetSession(string id) => _sessions.GetValueOrDefault(id);

    public void RemoveSession(string id)
    {
        if (_sessions.TryRemove(id, out var session))
            session.Cts.Cancel();
    }

    private static void Fail(Nip46Session session, string error)
    {
        if (session.Status == Nip46SessionStatus.Pending)
        {
            session.Status = Nip46SessionStatus.Failed;
            session.Error = error;
        }
    }

    private void Cleanup()
    {
        var cutoff = DateTimeOffset.UtcNow - SessionLifetime - TimeSpan.FromMinutes(5);
        foreach (var (id, session) in _sessions)
            if (session.CreatedAt < cutoff)
                RemoveSession(id);
    }

    private class Nip46Rpc
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("method")] public string? Method { get; set; }
        [JsonPropertyName("params")] public string[]? Params { get; set; }
        [JsonPropertyName("result")] public string? Result { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    private async Task RunSessionAsync(Nip46Session session, ECPrivKey clientKey, string clientPubkey,
        string secret, string[] relays, CancellationToken ct)
    {
        // Connect per relay and tolerate partial failures: one dead relay must not kill the session.
        var clients = new List<NostrClient>();
        foreach (var relay in relays)
        {
            var relayClient = new NostrClient(new Uri(relay));
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(15));
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
            return;
        }

        var filters = new[]
        {
            new NostrSubscriptionFilter
            {
                Kinds = [24133],
                ReferencedPublicKeys = [clientPubkey]
            }
        };

        var events = Channel.CreateUnbounded<NostrEvent>();
        foreach (var relayClient in clients)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await foreach (var evt in relayClient.SubscribeForEvents(filters, false, ct))
                        events.Writer.TryWrite(evt);
                }
                catch (OperationCanceledException)
                {
                }
            }, ct);
        }

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

        try
        {
        string? signerPubkey = null;
        string? userPubkey = null;
        var useNip04 = false;
        string? getPubkeyRequestId = null;
        string? signRequestId = null;
        string? challenge = null;
        var seenEventIds = new ConcurrentDictionary<string, byte>();

        await foreach (var evt in events.Reader.ReadAllAsync(ct))
        {
            if (evt.Id is null || !seenEventIds.TryAdd(evt.Id, 0))
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
                _logger.LogDebug(ex, "NostrLogin session {SessionId}: could not decrypt event {EventId}", session.Id, evt.Id);
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
        }
    }

    private static string? ValidateSignedEvent(NostrEvent? signed, string expectedPubkey, string expectedChallenge)
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
