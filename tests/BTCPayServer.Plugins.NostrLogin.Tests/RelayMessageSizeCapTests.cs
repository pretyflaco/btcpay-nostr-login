using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using BTCPayServer.Plugins.NostrLogin;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// A relay (malicious or compromised) must not be able to make the plugin buffer an unbounded
/// message: NNostr grows its receive buffer without limit, so the cap lives in the websocket.
/// </summary>
public class RelayMessageSizeCapTests
{
    /// <summary>Scripted inner socket: returns the given frames' byte counts in order.</summary>
    private sealed class ScriptedWebSocket : WebSocket
    {
        private readonly Queue<(int Count, bool End)> _frames;
        public bool Aborted { get; private set; }

        public ScriptedWebSocket(params (int Count, bool End)[] frames) => _frames = new(frames);

        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct)
        {
            var (count, end) = _frames.Dequeue();
            return Task.FromResult(new WebSocketReceiveResult(count, WebSocketMessageType.Text, end));
        }

        public override void Abort() => Aborted = true;
        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override WebSocketState State => Aborted ? WebSocketState.Aborted : WebSocketState.Open;
        public override string? SubProtocol => null;
        public override Task CloseAsync(WebSocketCloseStatus s, string? d, CancellationToken ct) => Task.CompletedTask;
        public override Task CloseOutputAsync(WebSocketCloseStatus s, string? d, CancellationToken ct) => Task.CompletedTask;
        public override Task SendAsync(ArraySegment<byte> b, WebSocketMessageType t, bool e, CancellationToken ct) => Task.CompletedTask;
        public override void Dispose() { }
    }

    [Fact]
    public async Task MessageOverCap_AbortsSocket()
    {
        var inner = new ScriptedWebSocket((600, false), (600, false));
        var capped = new MaxMessageSizeWebSocket(inner, maxMessageBytes: 1000);
        var buffer = new ArraySegment<byte>(new byte[1000]);

        await capped.ReceiveAsync(buffer, CancellationToken.None);
        await Assert.ThrowsAsync<WebSocketException>(() => capped.ReceiveAsync(buffer, CancellationToken.None));
        Assert.True(inner.Aborted);
    }

    [Fact]
    public async Task ManyMessagesUnderCap_PassThrough()
    {
        // The counter is per message: it must reset on EndOfMessage, so a long-lived connection
        // carrying many small messages is never cut off.
        var inner = new ScriptedWebSocket((600, false), (400, true), (600, false), (400, true));
        var capped = new MaxMessageSizeWebSocket(inner, maxMessageBytes: 1000);
        var buffer = new ArraySegment<byte>(new byte[1000]);

        for (var i = 0; i < 4; i++)
            await capped.ReceiveAsync(buffer, CancellationToken.None);
        Assert.False(inner.Aborted);
    }

    [Fact]
    public void ParsePictureUrl_OversizedContent_SkippedWithoutParsing()
    {
        // Valid JSON with a usable picture, padded past the cap: must be rejected on length alone.
        var huge = "{\"picture\":\"https://example.com/a.png\",\"about\":\"" + new string('x', 1024 * 1024) + "\"}";
        Assert.Null(NostrProfilePictureService.ParsePictureUrl(huge));
        Assert.Equal("https://example.com/a.png",
            NostrProfilePictureService.ParsePictureUrl("{\"picture\":\"https://example.com/a.png\"}"));
    }

    /// <summary>
    /// End-to-end through NNostr's real receive loop against a localhost websocket "relay": a
    /// small NOTICE is delivered, then a 1 MB frame kills the connection without being delivered.
    /// </summary>
    [Fact]
    public async Task CappedNostrClient_DropsOversizedRelayMessage()
    {
        var port = FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var serverDone = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            var ws = (await ctx.AcceptWebSocketAsync(null)).WebSocket;
            await ws.SendAsync(Encoding.UTF8.GetBytes("[\"NOTICE\",\"hello\"]"), WebSocketMessageType.Text, true, CancellationToken.None);
            var chunk = Encoding.UTF8.GetBytes(new string('x', 64 * 1024));
            try
            {
                for (var i = 0; i < 16; i++) // 1 MB, one message
                    await ws.SendAsync(chunk, WebSocketMessageType.Text, i == 15, CancellationToken.None);
            }
            catch (Exception)
            {
                // client aborted mid-message — expected
            }
        });

        using var client = new CappedNostrClient(new Uri($"ws://127.0.0.1:{port}/"));
        var notice = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var oversizedDelivered = false;
        client.NoticeReceived += (_, msg) => notice.TrySetResult(msg);
        client.MessageReceived += (_, msg) => oversizedDelivered |= msg.Length > CappedNostrClient.MaxMessageBytes;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await client.ConnectAndWaitUntilConnected(cts.Token);

        Assert.Equal("hello", await notice.Task.WaitAsync(cts.Token));
        while (client.State == WebSocketState.Open)
            await Task.Delay(50, cts.Token);
        Assert.Equal(WebSocketState.Aborted, client.State);
        Assert.False(oversizedDelivered);
        await serverDone.WaitAsync(cts.Token);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
