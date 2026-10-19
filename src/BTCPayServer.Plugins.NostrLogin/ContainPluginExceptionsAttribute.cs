using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Keeps any unhandled exception from the plugin's actions away from BTCPay core's
/// PluginExceptionHandler, which DISABLES the plugin and RESTARTS the whole server on an
/// unhandled plugin exception. Most of this controller is anonymous, so without this filter any
/// input that slips past validation would be a remote kill switch (one request = server restart
/// + Nostr login off until an admin re-enables it). A genuine bug is logged at Error and answered
/// with a generic 500 instead — strictly better than letting an anonymous caller restart BTCPay.
/// Validation code must still never throw on untrusted input (see <see cref="UntrustedEvent"/>);
/// this is the safety net.
/// </summary>
public sealed class ContainPluginExceptionsAttribute : ExceptionFilterAttribute
{
    public override void OnException(ExceptionContext context)
    {
        context.HttpContext.RequestServices?.GetService<ILoggerFactory>()
            ?.CreateLogger("BTCPayServer.Plugins.NostrLogin")
            .LogError(context.Exception,
                "NostrLogin: unhandled exception on {Method} {Path}; answered 500 (contained so BTCPay does not disable the plugin)",
                context.HttpContext.Request.Method, context.HttpContext.Request.Path);
        context.Result = new ObjectResult(new { status = "failed", error = "Unexpected error. Please try again." })
        {
            StatusCode = StatusCodes.Status500InternalServerError
        };
        context.ExceptionHandled = true;
    }
}
