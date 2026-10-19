using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static BTCPayServer.Plugins.NostrLogin.Tests.TwoFactorGateTests;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Relays start lazily: a session is dormant until its first status poll (sent by the page only
/// once the QR is shown). Page views without JS and NIP-07 sign-ins never open relay connections,
/// and a dormant session still cleans up (key wipe) and reports expiry like a started one.
/// </summary>
public class LazyRelayTests
{
    private const string BlackholeRelay = "wss://10.255.255.1:9";

    private static Task<Nip46Session> NewSession(NostrLoginService service, string? origin = null) =>
        service.CreateSessionAsync(Nip46SessionPurpose.Login, [BlackholeRelay], "test", originKey: origin);

    [Fact]
    public async Task NewSession_IsDormant()
    {
        var session = await NewSession(new NostrLoginService(NullLogger<NostrLoginService>.Instance));
        Assert.Equal(Nip46Session.RelaysDormant, session.RelayState);
        Assert.Equal(-1, session.RelaysConnected);
    }

    [Fact]
    public async Task EnsureRelaysStarted_StartsExactlyOnce()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await NewSession(service);
        var starts = 0;
        session.StartRelays = () => Interlocked.Increment(ref starts);

        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() => service.EnsureRelaysStarted(session))));

        Assert.Equal(1, starts);
        Assert.Equal(Nip46Session.RelaysStarted, session.RelayState);
    }

    [Fact]
    public async Task DormantExpiry_WipesState_LogsNoPoll_AndFeedsProbeCounter()
    {
        var logger = new ListLogger<NostrLoginService>();
        var service = new NostrLoginService(logger);
        var sessions = new List<Nip46Session>();
        for (var i = 0; i < NostrLoginService.ProbeAlertThresholdForTest; i++)
            sessions.Add(await NewSession(service, origin: "onion"));

        foreach (var s in sessions)
            s.Cts.Cancel(); // what the session lifetime timer does

        foreach (var s in sessions)
        {
            Assert.Equal(Nip46Session.RelaysNeverStarted, s.RelayState);
            Assert.Equal(Nip46SessionStatus.Failed, s.Status);
        }
        Assert.Equal(sessions.Count, logger.At(LogLevel.Information).Count(m => m.Contains("expired unauthenticated (no-poll)")));
        Assert.Single(logger.At(LogLevel.Warning), m => m.Contains("expired without signer contact") && m.Contains("onion"));
    }

    [Fact]
    public async Task ExpiredSession_IsNeverStartedLater()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await NewSession(service);
        var starts = 0;
        session.StartRelays = () => starts++;
        session.Cts.Cancel();

        service.EnsureRelaysStarted(session);

        Assert.Equal(0, starts);
    }

    [Fact]
    public async Task RemovedDormantSession_IsNotReportedAsExpiry()
    {
        // e.g. a NIP-07 sign-in completed the session without ever showing the QR
        var logger = new ListLogger<NostrLoginService>();
        var service = new NostrLoginService(logger);
        var session = await NewSession(service, origin: "clearnet:1.2.3.4");

        service.RemoveSession(session.Id);

        Assert.Equal(Nip46Session.RelaysNeverStarted, session.RelayState);
        Assert.Equal(Nip46SessionStatus.Pending, session.Status);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("expired unauthenticated"));
    }

    [Fact]
    public async Task RemovedStartedSession_IsNotReportedAsExpiry()
    {
        // Pre-existing since #9: a NIP-07 completion of a session whose relays had started was
        // logged (and counted) as an unauthenticated expiry by the relay task.
        var logger = new ListLogger<NostrLoginService>();
        var service = new NostrLoginService(logger);
        var session = await NewSession(service, origin: "clearnet:1.2.3.4");
        service.EnsureRelaysStarted(session);

        service.RemoveSession(session.Id);
        for (var i = 0; i < 100 && session.Status == Nip46SessionStatus.Pending; i++)
            await Task.Delay(50); // relay task observes the cancellation

        Assert.Equal(Nip46SessionStatus.Failed, session.Status);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("expired unauthenticated"));
    }

    [Fact]
    public async Task StatusPoll_StartsRelays_PageGetDoesNot()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var rig = BuildRig(new string('a', 64), false, service);
        rig.Controller.Url = new SessionReuseTests.FakeUrlHelper();
        rig.Controller.TempData = new Microsoft.AspNetCore.Mvc.ViewFeatures.TempDataDictionary(
            rig.HttpContext, new SessionReuseTests.FakeTempDataProvider());

        var view = Assert.IsType<Microsoft.AspNetCore.Mvc.ViewResult>(await rig.Controller.Login());
        var session = service.GetSession(Assert.IsType<NostrLoginViewModel>(view.Model).SessionId)!;
        Assert.Equal(Nip46Session.RelaysDormant, session.RelayState); // GET /login/nostr: no relays

        await rig.Controller.LoginStatus(session.Id);
        Assert.Equal(Nip46Session.RelaysStarted, session.RelayState); // first poll: relays
    }
}
