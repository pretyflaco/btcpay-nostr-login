using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Contracts;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Durable replay guard (audit finding 5): consumption must be recorded, reject replays,
/// survive a "restart" (new store instance over the same settings storage), and prune
/// expired ids.
/// </summary>
public class Nip98ReplayStoreTests
{
    private class FakeSettingsRepository : ISettingsRepository
    {
        public ConcurrentDictionary<string, object> Store { get; } = new();

        public Task<T?> GetSettingAsync<T>(string? name = null) where T : class
            => Task.FromResult(Store.TryGetValue(typeof(T).Name, out var v) ? v as T : null);

        public Task UpdateSetting<T>(T obj, string? name = null) where T : class
        {
            Store[typeof(T).Name] = obj!;
            return Task.CompletedTask;
        }

        public Task<T> WaitSettingsChanged<T>(CancellationToken cancellationToken = default) where T : class
            => throw new NotSupportedException();
    }

    private static async Task<(Nip98ReplayStore Store, FakeSettingsRepository Repo)> NewStartedStore()
    {
        var repo = new FakeSettingsRepository();
        var store = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await store.StartAsync(CancellationToken.None);
        return (store, repo);
    }

    [Fact]
    public async Task FirstConsumeSucceeds_SecondFails()
    {
        var (store, _) = await NewStartedStore();
        Assert.True(await store.TryConsumeAsync("event-a"));
        Assert.False(await store.TryConsumeAsync("event-a"));
        Assert.True(await store.TryConsumeAsync("event-b"));
    }

    [Fact]
    public async Task ConsumptionSurvivesRestart()
    {
        var repo = new FakeSettingsRepository();
        var first = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await first.StartAsync(CancellationToken.None);
        Assert.True(await first.TryConsumeAsync("event-x"));

        // "Restart": fresh instance over the same persisted storage.
        var second = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await second.StartAsync(CancellationToken.None);
        Assert.False(await second.TryConsumeAsync("event-x"), "replay after restart must be rejected");
        Assert.True(await second.TryConsumeAsync("event-y"));
    }

    [Fact]
    public async Task ExpiredEntriesAreDroppedOnLoadAndNotPersistedBack()
    {
        var repo = new FakeSettingsRepository();
        var future = DateTimeOffset.UtcNow.AddMinutes(10);
        var past = DateTimeOffset.UtcNow.AddHours(-1);
        await repo.UpdateSetting(new NostrLoginReplayMap
        {
            ConsumedEventIds = new Dictionary<string, DateTimeOffset>
            {
                ["event-old"] = past,
                ["event-kept"] = future
            }
        });

        // "Restart": fresh instance over the same storage.
        var store = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await store.StartAsync(CancellationToken.None);
        Assert.True(await store.TryConsumeAsync("event-new"));

        var after = (NostrLoginReplayMap)repo.Store[nameof(NostrLoginReplayMap)];
        Assert.False(after.ConsumedEventIds.ContainsKey("event-old"), "expired id must be pruned");
        Assert.True(after.ConsumedEventIds.ContainsKey("event-kept"));
        Assert.True(after.ConsumedEventIds.ContainsKey("event-new"));
    }
}
