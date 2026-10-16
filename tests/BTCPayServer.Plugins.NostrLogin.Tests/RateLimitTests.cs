using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

public class RateLimitTests
{
    [Fact]
    public void AllowsUpToLimitThenBlocks()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var max = NostrLoginService.MaxLoginSessionsPerWindowForTest;

        for (var i = 0; i < max; i++)
            Assert.True(service.AllowLoginAttemptForTest("1.2.3.4"), $"attempt {i + 1} should be allowed");

        Assert.False(service.AllowLoginAttemptForTest("1.2.3.4"), "attempt over the limit should be blocked");
    }

    [Fact]
    public void LimitIsPerKey()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var max = NostrLoginService.MaxLoginSessionsPerWindowForTest;

        for (var i = 0; i < max; i++)
            service.AllowLoginAttemptForTest("10.0.0.1");

        // A different key is unaffected by another key's exhausted window.
        Assert.True(service.AllowLoginAttemptForTest("10.0.0.2"));
        Assert.False(service.AllowLoginAttemptForTest("10.0.0.1"));
    }
}

public class PendingSessionCapTests
{
    // Blackhole address: the connect attempt hangs until the per-relay timeout, so sessions
    // stay Pending for the duration of the test (pattern from NonBlockingSessionTests).
    private static readonly string[] Blackhole = ["wss://10.255.255.1:9"];

    [Fact]
    public async Task SessionOverThePendingCapIsRejected()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var cap = NostrLoginService.MaxPendingLoginSessionsForTest;

        for (var i = 0; i < cap; i++)
        {
            var s = await service.CreateSessionAsync(
                Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "1.2.3.4");
            Assert.Equal(Nip46SessionStatus.Pending, s.Status);
        }

        var rejected = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "1.2.3.4");

        Assert.Equal(Nip46SessionStatus.Failed, rejected.Status);
        Assert.Contains("open sign-in sessions", rejected.Error);
        // Registered, so the status poller surfaces the real reason rather than "expired".
        Assert.NotNull(service.GetSession(rejected.Id));
    }

    [Fact]
    public async Task PendingCapIsPerKey()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var cap = NostrLoginService.MaxPendingLoginSessionsForTest;

        for (var i = 0; i < cap; i++)
            await service.CreateSessionAsync(
                Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "10.0.0.1");

        // A different origin still gets a live session.
        var other = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "10.0.0.2");
        Assert.Equal(Nip46SessionStatus.Pending, other.Status);

        var rejected = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "10.0.0.1");
        Assert.Equal(Nip46SessionStatus.Failed, rejected.Status);
    }

    [Fact]
    public async Task ResolvedSessionsFreePendingSlots()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var cap = NostrLoginService.MaxPendingLoginSessionsForTest;

        var sessions = new System.Collections.Generic.List<Nip46Session>();
        for (var i = 0; i < cap; i++)
            sessions.Add(await service.CreateSessionAsync(
                Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "1.2.3.4"));

        // A session that resolved (approved / failed / expired) no longer counts.
        sessions[0].Status = Nip46SessionStatus.Failed;

        var allowed = await service.CreateSessionAsync(
            Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "1.2.3.4");
        Assert.Equal(Nip46SessionStatus.Pending, allowed.Status);
    }

    [Fact]
    public async Task LinkSessionsAreNotCapped()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var cap = NostrLoginService.MaxPendingLoginSessionsForTest;

        for (var i = 0; i < cap; i++)
            await service.CreateSessionAsync(
                Nip46SessionPurpose.Login, Blackhole, "test", rateLimitKey: "1.2.3.4");

        // Link sessions are authenticated and bypass the login throttles entirely.
        var link = await service.CreateSessionAsync(
            Nip46SessionPurpose.Link, Blackhole, "test", linkUserId: "user1", rateLimitKey: "1.2.3.4");
        Assert.Equal(Nip46SessionStatus.Pending, link.Status);
    }
}
