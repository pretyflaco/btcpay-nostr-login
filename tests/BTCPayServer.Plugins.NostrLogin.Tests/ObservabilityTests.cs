using System.Collections.Concurrent;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>In-memory logger capturing (level, formatted message) for assertions.</summary>
internal class ListLogger : ILogger
{
    private readonly ConcurrentQueue<(LogLevel Level, string Message)> _entries = new();

    public IReadOnlyCollection<(LogLevel Level, string Message)> Entries => _entries;

    public IEnumerable<string> At(LogLevel level) =>
        _entries.Where(e => e.Level == level).Select(e => e.Message);

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter) =>
        _entries.Enqueue((logLevel, formatter(state, exception)));
}

internal sealed class ListLogger<T> : ListLogger, ILogger<T>;

public class SessionCreationLogTests
{
    [Fact]
    public async Task CreationIsLoggedWithPurposeRelaysAndSource()
    {
        var logger = new ListLogger<NostrLoginService>();
        using var service = new NostrLoginService(logger);

        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, ["ws://127.0.0.1:1"], "test", originKey: "onion");

        var created = Assert.Single(logger.At(LogLevel.Information), m => m.Contains("created"));
        Assert.Contains(session.Id, created);
        Assert.Contains("purpose=Login", created);
        Assert.Contains("ws://127.0.0.1:1", created);
        Assert.Contains("relaySource=defaults", created);
    }

    [Fact]
    public async Task CreationLogsSettingsSourceWhenRelaysComeFromSettings()
    {
        var logger = new ListLogger<NostrLoginService>();
        using var service = new NostrLoginService(logger);

        var session = await service.CreateSessionAsync(
            Nip46SessionPurpose.Link, ["ws://127.0.0.1:1"], "test",
            linkUserId: "user1", relaysFromSettings: true);

        var created = Assert.Single(logger.At(LogLevel.Information), m => m.Contains("created"));
        Assert.Contains(session.Id, created);
        Assert.Contains("purpose=Link", created);
        Assert.Contains("relaySource=settings", created);
    }
}

public class RelayAggregateLogTests
{
    [Fact]
    public async Task TotalConnectFailureWarnsOnceWithAggregate()
    {
        // Port 1 refuses immediately, so no real timeout is waited out.
        var logger = new ListLogger();
        using var pool = new RelayPool(["ws://127.0.0.1:1", "ws://127.0.0.1:2"],
            new string('a', 64), logger, "s1", diagnostics: false);

        var connected = await pool.ConnectAsync(CancellationToken.None);

        Assert.Equal(0, connected);
        var warn = Assert.Single(logger.At(LogLevel.Warning));
        Assert.Contains("0/2 relays", warn);
        Assert.Contains("127.0.0.1", warn);
        // Per-relay failures were downgraded: no individual per-relay warns.
        Assert.DoesNotContain(logger.At(LogLevel.Warning), m => m.Contains("could not connect to relay"));
        Assert.Equal(2, logger.At(LogLevel.Debug).Count(m => m.Contains("could not connect to relay")));
    }
}

public class ExpiryClassificationTests
{
    [Fact]
    public void RelayDeadWhenNoRelayConnected()
    {
        var session = new Nip46Session { Id = "a", Purpose = Nip46SessionPurpose.Login, ConnectUri = "" };
        Assert.Equal(NostrLoginService.ExpiryRelayDead, NostrLoginService.ClassifyUnauthenticatedExpiry(session));

        session.RelaysConnected = 0;
        Assert.Equal(NostrLoginService.ExpiryRelayDead, NostrLoginService.ClassifyUnauthenticatedExpiry(session));
    }

    [Fact]
    public void NoHelloWhenConnectedButSignerNeverSpoke()
    {
        var session = new Nip46Session { Id = "a", Purpose = Nip46SessionPurpose.Login, ConnectUri = "" };
        session.RelaysConnected = 2;
        Assert.Equal(NostrLoginService.ExpiryNoHello, NostrLoginService.ClassifyUnauthenticatedExpiry(session));
    }

    [Fact]
    public void HelloNoAuthWhenSignerSpokeButNeverApproved()
    {
        var session = new Nip46Session { Id = "a", Purpose = Nip46SessionPurpose.Login, ConnectUri = "" };
        session.RelaysConnected = 2;
        session.SignerHelloPubkey = new string('b', 64);
        Assert.Equal(NostrLoginService.ExpiryHelloNoAuth, NostrLoginService.ClassifyUnauthenticatedExpiry(session));
    }
}

public class ProbeCounterTests
{
    [Fact]
    public void WarnsOnceWhenThresholdCrossed()
    {
        var logger = new ListLogger<NostrLoginService>();
        using var service = new NostrLoginService(logger);
        var threshold = NostrLoginService.ProbeAlertThresholdForTest;

        for (var i = 0; i < threshold - 1; i++)
            service.RecordProbelessExpiryForTest("onion");
        Assert.Empty(logger.At(LogLevel.Warning));

        service.RecordProbelessExpiryForTest("onion");
        var warn = Assert.Single(logger.At(LogLevel.Warning));
        Assert.Contains("onion", warn);
        Assert.Contains(threshold.ToString(), warn);

        // Crossing is logged once per window, not on every subsequent expiry.
        service.RecordProbelessExpiryForTest("onion");
        Assert.Single(logger.At(LogLevel.Warning));
    }

    [Fact]
    public void CountsArePerOriginKey()
    {
        var logger = new ListLogger<NostrLoginService>();
        using var service = new NostrLoginService(logger);
        var threshold = NostrLoginService.ProbeAlertThresholdForTest;

        for (var i = 0; i < threshold - 1; i++)
        {
            service.RecordProbelessExpiryForTest("onion");
            service.RecordProbelessExpiryForTest("clearnet:1.2.3.4");
        }
        Assert.Empty(logger.At(LogLevel.Warning));

        service.RecordProbelessExpiryForTest("clearnet:1.2.3.4");
        var warn = Assert.Single(logger.At(LogLevel.Warning));
        Assert.Contains("clearnet:1.2.3.4", warn);
    }
}
