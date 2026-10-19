using System.Reflection;
using BTCPayServer.Filters;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// CSRF protection for the plugin's POST actions comes from BTCPay core's global
/// <see cref="UIControllerAntiforgeryTokenAttribute"/> (Startup.cs), which validates the token on
/// every non-GET request to a controller named "UI*". These tests run that real filter against
/// every POST action, so renaming the controller or adding a stray opt-out cannot silently drop
/// CSRF protection. New POST actions are covered automatically.
/// </summary>
public class CsrfProtectionTests
{
    /// <summary>The only intended opt-out: anonymous, authenticated by the NIP-98 signature
    /// itself (no ambient cookie authority to ride on).</summary>
    private static readonly string[] AllowedOptOuts = [nameof(UINostrLoginController.Nip98Login)];

    private sealed class RejectingAntiforgery : IAntiforgery
    {
        public int Validations { get; private set; }

        public Task ValidateRequestAsync(HttpContext httpContext)
        {
            Validations++;
            throw new AntiforgeryValidationException("missing token");
        }

        public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext) => throw new NotSupportedException();
        public AntiforgeryTokenSet GetTokens(HttpContext httpContext) => throw new NotSupportedException();
        public Task<bool> IsRequestValidAsync(HttpContext httpContext) => throw new NotSupportedException();
        public void SetCookieTokenAndHeader(HttpContext httpContext) => throw new NotSupportedException();
    }

    private sealed class Services(IAntiforgery antiforgery) : IServiceProvider
    {
        public object? GetService(Type serviceType) => serviceType == typeof(IAntiforgery) ? antiforgery : null;
    }

    public static TheoryData<string> PostActions()
    {
        var data = new TheoryData<string>();
        foreach (var m in PostMethods())
            data.Add(m.Name + "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.Name)) + ")");
        return data;
    }

    private static IEnumerable<MethodInfo> PostMethods() =>
        typeof(UINostrLoginController)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes<HttpPostAttribute>().Any());

    /// <summary>Runs core's global filter the way MVC would: global filter first, then the
    /// controller- and action-level filter attributes (the last antiforgery policy wins).</summary>
    private static async Task<(IActionResult? Result, int Validations)> RunGlobalFilter(MethodInfo action)
    {
        var type = typeof(UINostrLoginController);
        var descriptor = new ControllerActionDescriptor
        {
            ControllerName = type.Name[..^"Controller".Length], // MVC's default controller naming
            ActionName = action.Name,
            ControllerTypeInfo = type.GetTypeInfo(),
            MethodInfo = action
        };
        var antiforgery = new RejectingAntiforgery();
        var http = new DefaultHttpContext { RequestServices = new Services(antiforgery) };
        http.Request.Method = HttpMethods.Post;

        var globalFilter = new UIControllerAntiforgeryTokenAttribute();
        var filters = new List<IFilterMetadata> { globalFilter };
        filters.AddRange(type.GetCustomAttributes(true).OfType<IFilterMetadata>());
        filters.AddRange(action.GetCustomAttributes(true).OfType<IFilterMetadata>());

        var context = new AuthorizationFilterContext(
            new ActionContext(http, new RouteData(), descriptor), filters);
        await globalFilter.OnAuthorizationAsync(context);
        return (context.Result, antiforgery.Validations);
    }

    [Theory]
    [MemberData(nameof(PostActions))]
    public async Task PostWithoutToken_IsRejected_UnlessDeliberatelyOptedOut(string signature)
    {
        var action = PostMethods().Single(m =>
            m.Name + "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.Name)) + ")" == signature);

        var (result, validations) = await RunGlobalFilter(action);

        if (AllowedOptOuts.Contains(action.Name))
        {
            Assert.Null(result);
            Assert.Equal(0, validations);
        }
        else
        {
            Assert.Equal(1, validations);
            Assert.IsType<AntiforgeryValidationFailedResult>(result);
        }
    }

    [Fact]
    public void StateChangingEndpoints_ArePostOnly()
    {
        foreach (var name in new[]
                 {
                     nameof(UINostrLoginController.StartLink), nameof(UINostrLoginController.Unlink)
                 })
        {
            var method = typeof(UINostrLoginController).GetMethod(name)!;
            Assert.NotEmpty(method.GetCustomAttributes<HttpPostAttribute>());
            Assert.Empty(method.GetCustomAttributes<HttpGetAttribute>());
        }

        // ServerSettings: GET renders the form, only the model-bound overload (POST) writes.
        var settingsWrite = typeof(UINostrLoginController).GetMethods()
            .Single(m => m.Name == nameof(UINostrLoginController.ServerSettings) && m.GetParameters().Length == 1);
        Assert.NotEmpty(settingsWrite.GetCustomAttributes<HttpPostAttribute>());
        Assert.Empty(settingsWrite.GetCustomAttributes<HttpGetAttribute>());
    }

    [Fact]
    public void OptOuts_AreOnlyTheIntendedOnes()
    {
        Assert.Empty(typeof(UINostrLoginController).GetCustomAttributes<IgnoreAntiforgeryTokenAttribute>(true));
        var optedOut = typeof(UINostrLoginController)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes<IgnoreAntiforgeryTokenAttribute>().Any())
            .Select(m => m.Name)
            .ToArray();
        Assert.Equal(AllowedOptOuts, optedOut);
    }
}
