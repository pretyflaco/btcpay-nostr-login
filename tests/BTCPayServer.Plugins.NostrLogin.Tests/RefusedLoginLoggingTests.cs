using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

public class ToNpubTests
{
    [Fact]
    public async Task ValidHexEncodesAsNpub()
    {
        var (_, pubkey) = await TwoFactorGateTests.NewKey();
        var npub = pubkey.ToNpub();
        Assert.StartsWith("npub1", npub);
        Assert.Equal(63, npub.Length);
    }

    [Fact]
    public void InvalidHexPassesThrough()
    {
        Assert.Equal("not-a-pubkey", "not-a-pubkey".ToNpub());
    }
}

/// <summary>
/// The "verified but no linked user" warn must identify the key fully (64-hex + npub) so a
/// genuine login attempt by an unlinked key is attributable; 8-char truncation is kept only on
/// routine info logs.
/// </summary>
public class RefusedLoginLoggingTests
{
    [Fact]
    public async Task QrStatus_UnlinkedKey_LogsFullPubkeyAndNpub()
    {
        var (_, pubkey) = await TwoFactorGateTests.NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        const string nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Login,
            ["wss://10.255.255.1:9"], "test", bindingNonce: nonce);
        session.Status = Nip46SessionStatus.Approved;
        session.UserPubkey = pubkey;

        var logger = new ListLogger<UINostrLoginController>();
        // BuildRig maps its own key; the session's key stays unlinked.
        var (_, otherPubkey) = await TwoFactorGateTests.NewKey();
        var rig = TwoFactorGateTests.BuildRig(otherPubkey, twoFactorEnabled: false, service,
            bindCookieNonce: nonce, logger: logger);

        var result = await rig.Controller.LoginStatus(session.Id);

        var body = TwoFactorGateTests.JsonOf(result);
        Assert.Equal("failed", body.GetProperty("status").GetString());
        var warn = Assert.Single(logger.At(LogLevel.Warning), m => m.Contains("no linked user"));
        Assert.Contains(pubkey, warn);
        Assert.Contains(pubkey.ToNpub(), warn);
    }

    [Fact]
    public async Task Nip98Post_UnlinkedKey_LogsFullPubkeyAndNpub()
    {
        var (key, pubkey) = await TwoFactorGateTests.NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var repo = new TwoFactorGateTests.FakeSettingsRepository();
        var replayStore = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await replayStore.StartAsync(CancellationToken.None);
        var logger = new ListLogger<UINostrLoginController>();
        var (_, otherPubkey) = await TwoFactorGateTests.NewKey();
        var rig = TwoFactorGateTests.BuildRig(otherPubkey, twoFactorEnabled: false, service,
            replayStore, logger: logger);
        rig.HttpContext.Request.Headers.Authorization =
            "Nostr " + await TwoFactorGateTests.SignEventBase64(key, pubkey, "POST");

        var result = await rig.Controller.Nip98Login();

        var body = TwoFactorGateTests.JsonOf(result);
        Assert.Equal("failed", body.GetProperty("status").GetString());
        var warn = Assert.Single(logger.At(LogLevel.Warning), m => m.Contains("no linked user"));
        Assert.Contains(pubkey, warn);
        Assert.Contains(pubkey.ToNpub(), warn);
    }

    [Fact]
    public async Task Nip98GetLink_UnlinkedKey_LogsFullPubkeyAndNpub()
    {
        var (key, pubkey) = await TwoFactorGateTests.NewKey();
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var repo = new TwoFactorGateTests.FakeSettingsRepository();
        var replayStore = new Nip98ReplayStore(repo, NullLogger<Nip98ReplayStore>.Instance);
        await replayStore.StartAsync(CancellationToken.None);
        var logger = new ListLogger<UINostrLoginController>();
        var (_, otherPubkey) = await TwoFactorGateTests.NewKey();
        var rig = TwoFactorGateTests.BuildRig(otherPubkey, twoFactorEnabled: false, service,
            replayStore, logger: logger);
        var eventParam = (await TwoFactorGateTests.SignEventBase64(key, pubkey, "GET"))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var result = await rig.Controller.Nip98LoginLink(eventParam);

        var body = TwoFactorGateTests.JsonOf(result);
        Assert.Equal("failed", body.GetProperty("status").GetString());
        var warn = Assert.Single(logger.At(LogLevel.Warning), m => m.Contains("no linked user"));
        Assert.Contains(pubkey, warn);
        Assert.Contains(pubkey.ToNpub(), warn);
    }
}
