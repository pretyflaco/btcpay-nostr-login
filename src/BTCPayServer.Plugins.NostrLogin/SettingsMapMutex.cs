using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Contracts;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Serializes read-modify-write cycles over the plugin's settings maps (audit finding 9):
/// every site previously did GetSettingAsync → mutate → UpdateSetting on a whole JSON blob,
/// so concurrent logins could drop each other's entries. All writers go through this single
/// process-wide mutex — write volume is login rate, so contention is negligible.
/// (Multi-instance deployments would need real storage-level concurrency; out of scope.)
/// </summary>
public static class SettingsMapMutex
{
    private static readonly SemaphoreSlim Lock = new(1, 1);

    /// <summary>Loads <typeparamref name="T"/>, runs <paramref name="mutate"/> against it
    /// (mutating in place) and persists — atomically with respect to all other callers.</summary>
    public static async Task UpdateAsync<T>(ISettingsRepository repository, Func<T, Task> mutate)
        where T : class, new()
    {
        await Lock.WaitAsync();
        try
        {
            var map = await repository.GetSettingAsync<T>() ?? new T();
            await mutate(map);
            await repository.UpdateSetting(map);
        }
        finally
        {
            Lock.Release();
        }
    }

    /// <summary>
    /// Check-and-mutate under the same lock: <paramref name="tryMutate"/> inspects the current
    /// map, mutates it and returns true, or returns false to leave it untouched (nothing is
    /// persisted). Use this whenever a write depends on a read (ownership checks), so the
    /// decision can never be made on a copy another writer has since changed.
    /// </summary>
    public static async Task<bool> TryUpdateAsync<T>(ISettingsRepository repository, Func<T, bool> tryMutate)
        where T : class, new()
    {
        await Lock.WaitAsync();
        try
        {
            var map = await repository.GetSettingAsync<T>() ?? new T();
            if (!tryMutate(map))
                return false;
            await repository.UpdateSetting(map);
            return true;
        }
        finally
        {
            Lock.Release();
        }
    }

    /// <summary>Synchronous convenience overload of <see cref="UpdateAsync{T}"/>.</summary>
    public static Task UpdateAsync<T>(ISettingsRepository repository, Action<T> mutate)
        where T : class, new()
        => UpdateAsync<T>(repository, map =>
        {
            mutate(map);
            return Task.CompletedTask;
        });
}
