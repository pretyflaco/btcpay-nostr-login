using System;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// <see cref="NostrClient"/> whose websocket refuses any single relay message larger than
/// <see cref="MaxMessageBytes"/>. NNostr's receive loop grows its buffer without bound (1000-byte
/// steps, full copy each time), so one relay sending a huge frame — valid event or not — could
/// exhaust memory/CPU in the BTCPay process before any plugin code sees the content. Every relay
/// connection the plugin opens must go through this type.
/// </summary>
internal sealed class CappedNostrClient : NostrClient
{
    /// <summary>
    /// Generous for everything the plugin subscribes to (NIP-46 kind-24133 RPCs, one kind-0
    /// profile); real messages of either kind are a few KB.
    /// </summary>
    internal const int MaxMessageBytes = 256 * 1024;

    public CappedNostrClient(Uri relay) : base(relay)
    {
    }

    protected override async Task<WebSocket> Connect()
        => new MaxMessageSizeWebSocket(await base.Connect(), MaxMessageBytes);
}

/// <summary>
/// Pass-through <see cref="WebSocket"/> decorator that aborts the connection once a single
/// incoming message exceeds a byte cap, bounding what the reader can be made to buffer.
/// </summary>
internal sealed class MaxMessageSizeWebSocket : WebSocket
{
    private readonly WebSocket _inner;
    private readonly int _maxMessageBytes;
    private long _currentMessageBytes;

    public MaxMessageSizeWebSocket(WebSocket inner, int maxMessageBytes)
    {
        _inner = inner;
        _maxMessageBytes = maxMessageBytes;
    }

    public override WebSocketCloseStatus? CloseStatus => _inner.CloseStatus;
    public override string? CloseStatusDescription => _inner.CloseStatusDescription;
    public override WebSocketState State => _inner.State;
    public override string? SubProtocol => _inner.SubProtocol;

    public override async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken)
    {
        var result = await _inner.ReceiveAsync(buffer, cancellationToken);
        _currentMessageBytes += result.Count;
        if (_currentMessageBytes > _maxMessageBytes)
        {
            _inner.Abort();
            throw new WebSocketException(WebSocketError.Faulted,
                $"Relay message exceeded {_maxMessageBytes} bytes; connection aborted.");
        }
        if (result.EndOfMessage)
            _currentMessageBytes = 0;
        return result;
    }

    public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage, CancellationToken cancellationToken)
        => _inner.SendAsync(buffer, messageType, endOfMessage, cancellationToken);

    public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
        => _inner.CloseAsync(closeStatus, statusDescription, cancellationToken);

    public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
        => _inner.CloseOutputAsync(closeStatus, statusDescription, cancellationToken);

    public override void Abort() => _inner.Abort();

    public override void Dispose() => _inner.Dispose();
}
