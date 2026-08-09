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
