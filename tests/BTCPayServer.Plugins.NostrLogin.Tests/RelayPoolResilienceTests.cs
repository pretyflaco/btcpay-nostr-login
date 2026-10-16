using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// A relay that accepts TCP but never answers the WebSocket upgrade simulates a silently
/// dropping endpoint (firewalled/banned IP). NNostr does not observe the caller's cancellation
/// during the socket connect, so without the hard timeout race such a relay hangs for the OS
/// TCP timeout (~2 min), stalling both the initial connect and every republish's reconnect.
/// </summary>
public class RelayPoolResilienceTests
{
    private static TcpListener StartStallingRelay(out string url)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        _ = Task.Run(async () =>
        {
            // Accept and hold connections open without ever responding.
            while (true)
                _ = await listener.AcceptSocketAsync();
        });
        url = $"ws://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        return listener;
    }

    [Fact]
    public async Task StallingRelayIsBoundedByConnectTimeout()
    {
        var listener = StartStallingRelay(out var url);
        using var pool = new RelayPool([url], new string('a', 64),
            NullLogger.Instance, "s1", diagnostics: false);

        var sw = Stopwatch.StartNew();
        var connected = await pool.ConnectAsync(CancellationToken.None);
        sw.Stop();

        Assert.Equal(0, connected);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15),
            $"connect should be bounded by the per-relay timeout (~5s), took {sw.Elapsed.TotalSeconds:0.0}s");
        listener.Stop();
    }

    [Fact]
    public async Task SessionCancellationDuringConnectDoesNotWaitForTimeout()
    {
        var listener = StartStallingRelay(out var url);
        using var pool = new RelayPool([url], new string('a', 64),
            NullLogger.Instance, "s1", diagnostics: false);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        var sw = Stopwatch.StartNew();
        var connected = await pool.ConnectAsync(cts.Token);
        sw.Stop();

        Assert.Equal(0, connected);
        // The session token (expiry/shutdown) must abort the connect promptly — not ride out
        // the 5s relay timeout.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3),
            $"cancellation should abort the connect promptly, took {sw.Elapsed.TotalSeconds:0.0}s");
        listener.Stop();
    }

    [Fact]
    public async Task FailedRelayIsNotRetriedWithinBackoffWindow()
    {
        var listener = StartStallingRelay(out var url);
        using var pool = new RelayPool([url], new string('a', 64),
            NullLogger.Instance, "s1", diagnostics: false)
        {
            ReconnectBackoff = TimeSpan.FromMinutes(5)
        };
        await pool.ConnectAsync(CancellationToken.None); // ~5s, fails with timeout

        var sw = Stopwatch.StartNew();
        await pool.ReconnectDeadAsync(CancellationToken.None);
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2),
            $"reconnect within the backoff window should be skipped, took {sw.Elapsed.TotalSeconds:0.0}s");
        listener.Stop();
    }

    [Fact]
    public async Task FailedRelayIsRetriedAfterBackoffExpires()
    {
        var listener = StartStallingRelay(out var url);
        using var pool = new RelayPool([url], new string('a', 64),
            NullLogger.Instance, "s1", diagnostics: false)
        {
            ReconnectBackoff = TimeSpan.Zero // every reconnect call retries
        };
        await pool.ConnectAsync(CancellationToken.None); // fails

        var sw = Stopwatch.StartNew();
        await pool.ReconnectDeadAsync(CancellationToken.None);
        sw.Stop();

        Assert.True(sw.Elapsed >= TimeSpan.FromSeconds(4),
            $"reconnect should have retried (and timed out again), took {sw.Elapsed.TotalSeconds:0.0}s");
        listener.Stop();
    }
}
