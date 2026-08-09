using BTCPayServer.Plugins.NostrLogin;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

public class LoginButtonInjectionTests
{
    private const string LoginPageFragment =
        """
        <div class="d-flex gap-2 only-for-js">
            <button type="button" class="btn btn-outline-secondary w-100" id="passkey-login-btn" style="display:none;">Passkey</button>
            <button type="button" class="btn btn-outline-secondary w-100" data-bs-toggle="modal" data-bs-target="#scanModal" title="Scan">
                <span>LoginCode</span>
            </button>
        </div>
        """;

    [Fact]
    public void InjectsButtonAfterLoginCodeButton()
    {
        var result = LoginButtonInjectionMiddleware.TryInjectButton(LoginPageFragment, "", null);
        Assert.NotNull(result);
        Assert.Contains("id=\"nostr-login-btn\"", result);
        Assert.Contains("href=\"/login/nostr\"", result);
        // Injected inside the flex row (before its closing tag)
        Assert.True(result!.IndexOf("nostr-login-btn") < result.LastIndexOf("</div>"));
    }

    [Fact]
    public void InjectsResponsiveWrapStyle()
    {
        var result = LoginButtonInjectionMiddleware.TryInjectButton(LoginPageFragment, "", null);
        Assert.NotNull(result);
        // The row must be allowed to wrap so the third button doesn't clip on mobile.
        Assert.Contains("flex-wrap:wrap", result);
        Assert.Contains("flex:1 1 120px", result);
    }

    [Fact]
    public void PassesThroughReturnUrlAndPathBase()
    {
        var result = LoginButtonInjectionMiddleware.TryInjectButton(LoginPageFragment, "/btcpay", "/stores/abc");
        Assert.NotNull(result);
        Assert.Contains("href=\"/btcpay/login/nostr?returnUrl=%2Fstores%2Fabc\"", result);
        Assert.Contains("/btcpay/img/icon-sprite.svg#social-nostr", result);
    }

    [Fact]
    public void LeavesPageWithoutAnchorUntouched()
    {
        Assert.Null(LoginButtonInjectionMiddleware.TryInjectButton("<html><body>2fa page</body></html>", "", null));
        Assert.Null(LoginButtonInjectionMiddleware.TryInjectButton("", "", null));
    }
}
