using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Contracts;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>Persisted consumed-NIP-98-event-id map (eventId → acceptance expiry).</summary>
public class NostrLoginReplayMap
{
    /// <summary>Lowercased event id → the instant after which the event can no longer be valid.</summary>
    public Dictionary<string, DateTimeOffset> ConsumedEventIds { get; set; } = new();
}

/// <summary>
/// Durable replay guard for NIP-98 events (audit finding 5): the previous guard was a bare
/// in-process dictionary, so a restart allowed replay of still-fresh events. This store keeps
/// the fast in-memory layer but persists every consumption into <see cref="NostrLoginReplayMap"/>
/// and reloads it at startup. Write volume is login-rate (tiny), so each consumption flushes
/// immediately; pruning drops expired ids on every persist.
/// </summary>
public class Nip98ReplayStore : IHostedService
{
    private readonly ISettingsRepository _settingsRepository;
    private readonly ILogger<Nip98ReplayStore> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumed = new();
    private readonly SemaphoreSlim _persistLock = new(1, 1);
    private volatile Task? _loadTask;

    public Nip98ReplayStore(ISettingsRepository settingsRepository, ILogger<Nip98ReplayStore> logger)
    {
        _settingsRepository = settingsRepository;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _loadTask = LoadAsync();
        return Task.CompletedTask; // don't block boot; consumers await the load below
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Records an event id as consumed. True on first sighting, false on replay. Blocks until
    /// the persisted state has been reloaded so a post-restart replay cannot slip through.
    /// </summary>
    public async Task<bool> TryConsumeAsync(string eventId)
    {
        var load = _loadTask ??= LoadAsync();
        await load;

        var now = DateTimeOffset.UtcNow;
        PruneExpired(now);
        if (!_consumed.TryAdd(eventId.ToLowerInvariant(), now + Nip98.ReplayRetention))
            return false;

        await PersistAsync();
        return true;
    }

    /// <summary>Test hook: clears all state (memory only; persistence untouched).</summary>
    internal void ResetForTest() => _consumed.Clear();

    private async Task LoadAsync()
    {
        try
        {
            var map = await _settingsRepository.GetSettingAsync<NostrLoginReplayMap>();
            if (map is null)
                return;
            foreach (var (id, expiry) in map.ConsumedEventIds)
            {
                if (expiry > DateTimeOffset.UtcNow)
                    _consumed.TryAdd(id.ToLowerInvariant(), expiry);
            }
            _logger.LogInformation("NostrLogin: replay guard restored {Count} consumed NIP-98 event id(s)",
                _consumed.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "NostrLogin: replay-guard reload failed — falling back to memory-only");
        }
    }

    private void PruneExpired(DateTimeOffset now)
    {
        foreach (var kv in _consumed)
            if (kv.Value <= now)
                _consumed.TryRemove(kv.Key, out _);
    }

    private async Task PersistAsync()
    {
        await _persistLock.WaitAsync();
        try
        {
            PruneExpired(DateTimeOffset.UtcNow);
            var map = new NostrLoginReplayMap
            {
                ConsumedEventIds = new Dictionary<string, DateTimeOffset>(_consumed)
            };
            await _settingsRepository.UpdateSetting(map);
        }
        catch (Exception ex)
        {
            // Memory layer already recorded the consumption; a failed flush only weakens
            // restart protection, never correctness of live rejection.
            _logger.LogWarning(ex, "NostrLogin: replay-guard persist failed");
        }
        finally
        {
            _persistLock.Release();
        }
    }
}
