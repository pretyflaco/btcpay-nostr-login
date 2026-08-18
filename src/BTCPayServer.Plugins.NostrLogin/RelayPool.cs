using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Owns the per-relay <see cref="NostrClient"/> connections for one NIP-46 session and provides
/// the reliability primitives the RPC flow needs against lossy public relays (C3):
///
///  - <see cref="ConnectAsync"/>: connect to all relays in parallel, tolerate partial failure,
///    subscribe the kind-24133 <c>#p==clientPubkey</c> filter, and fan received events into one
///    channel (deduped downstream by event id).
///  - <see cref="PublishAsync"/>: broadcast an event to every live relay.
///  - <see cref="ReconnectDeadAsync"/>: reopen any relay that failed at startup or dropped
///    mid-session and re-subscribe it, so the signer's relay set and ours keep overlapping.
///
/// Ephemeral kind-24133 events have no delivery guarantee; a single publish to a single relay can
/// be silently dropped. Fanning out + republishing (driven by the caller) + reconnecting dead
/// relays is what makes the handshake reliable against signers that are not co-located.
/// </summary>
internal sealed class RelayPool : IDisposable
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly string[] _relays;
    private readonly string _clientPubkey;
    private readonly string _subscriptionId;
    private readonly NostrSubscriptionFilter[] _filters;
    private readonly ILogger _logger;
    private readonly string _sessionId;
    private readonly bool _diagnostics;

    // relayUrl -> live client. A relay absent from the map is currently disconnected.
    private readonly ConcurrentDictionary<string, NostrClient> _clients = new();
    private readonly Channel<NostrEvent> _events = Channel.CreateUnbounded<NostrEvent>();

    public RelayPool(string[] relays, string clientPubkey, ILogger logger, string sessionId, bool diagnostics)
    {
        _relays = relays;
        _clientPubkey = clientPubkey;
        _subscriptionId = Guid.NewGuid().ToString("N");
        _filters =
        [
            new NostrSubscriptionFilter { Kinds = [24133], ReferencedPublicKeys = [clientPubkey] }
        ];
        _logger = logger;
        _sessionId = sessionId;
        _diagnostics = diagnostics;
    }

    public ChannelReader<NostrEvent> Events => _events.Reader;

    public int LiveCount => _clients.Count;

    /// <summary>
    /// Connect to all relays in parallel and subscribe each. Returns the number of relays that
    /// connected. Callers must treat 0 as a hard failure (no relay carries the handshake).
    /// </summary>
    public async Task<int> ConnectAsync(CancellationToken ct)
    {
        await Task.WhenAll(_relays.Select(relay => OpenAndSubscribe(relay, ct)));
        return _clients.Count;
    }

    /// <summary>Broadcast an event to every live relay. Returns the number of relays written to.</summary>
    public async Task<int> PublishAsync(NostrEvent evt, CancellationToken ct)
    {
        var sent = 0;
        foreach (var client in _clients.Values)
        {
            try
            {
                await client.PublishEvent(evt, ct);
                sent++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug("NostrLogin session {SessionId}: publish failed on a relay: {Error}",
                    _sessionId, ex.Message);
            }
        }
        return sent;
    }

    /// <summary>
    /// Reopen (and re-subscribe) any advertised relay that is not currently connected. Best-effort;
    /// a still-dead relay is skipped. Keeps the signer's relay set and ours overlapping over the
    /// session lifetime.
    /// </summary>
    public async Task ReconnectDeadAsync(CancellationToken ct)
    {
        var missing = _relays.Where(r => !_clients.ContainsKey(r)).ToList();
        if (missing.Count == 0)
            return;
        await Task.WhenAll(missing.Select(relay => OpenAndSubscribe(relay, ct, reconnect: true)));
    }

    private async Task OpenAndSubscribe(string relay, CancellationToken ct, bool reconnect = false)
    {
        if (_clients.ContainsKey(relay))
            return;
        var client = new NostrClient(new Uri(relay));
        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(ConnectTimeout);
            await client.ConnectAndWaitUntilConnected(connectCts.Token, ct);
            client.EventsReceived += OnEventsReceived;
            await client.CreateSubscription(_subscriptionId, _filters, ct);
            if (!_clients.TryAdd(relay, client))
            {
                // Lost a race with another reconnect for the same relay; drop this duplicate.
                client.EventsReceived -= OnEventsReceived;
                client.Dispose();
                return;
            }
            if (reconnect)
                _logger.LogInformation("NostrLogin session {SessionId}: (re)connected relay {Relay}",
                    _sessionId, relay);
        }
        catch (Exception ex)
        {
            if (reconnect)
                _logger.LogDebug("NostrLogin session {SessionId}: relay {Relay} still unavailable: {Error}",
                    _sessionId, relay, ex.Message);
            else
                _logger.LogWarning("NostrLogin session {SessionId}: could not connect to relay {Relay}: {Error}",
                    _sessionId, relay, ex.Message);
            client.Dispose();
        }
    }

    private void OnEventsReceived(object? sender, (string subscriptionId, NostrEvent[] events) args)
    {
        if (args.subscriptionId != _subscriptionId)
            return;
        foreach (var evt in args.events)
            _events.Writer.TryWrite(evt);
    }

    public void Dispose()
    {
        foreach (var client in _clients.Values)
        {
            try
            {
                client.EventsReceived -= OnEventsReceived;
                client.Dispose();
            }
            catch (Exception)
            {
            }
        }
        _clients.Clear();
    }
}
