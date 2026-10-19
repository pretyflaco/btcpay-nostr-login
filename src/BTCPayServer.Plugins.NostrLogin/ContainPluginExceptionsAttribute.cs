using System;
using System.Threading.Tasks;
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
///
/// Covers both stages MVC distinguishes: action execution (exception filter: controller
/// creation, model binding, action filters, the action) AND result execution (always-run result
/// filter: view rendering, JSON serialization, redirects), which exception filters do not see.
/// Validation code must still never throw on untrusted input (see <see cref="UntrustedEvent"/>);
/// this is the safety net.
/// </summary>
public sealed class ContainPluginExceptionsAttribute : ExceptionFilterAttribute, IAsyncAlwaysRunResultFilter
{
    public override void OnException(ExceptionContext context)
    {
        Log(context.HttpContext, context.Exception, "action");
        context.Result = new ObjectResult(new { status = "failed", error = "Unexpected error. Please try again." })
        {
            StatusCode = StatusCodes.Status500InternalServerError
        };
        context.ExceptionHandled = true;
    }

    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        var executed = await next();
        if (executed.Exception is null || executed.ExceptionHandled)
            return;
        Log(context.HttpContext, executed.Exception, "result");
        executed.ExceptionHandled = true;
        // Nothing sensible can be rendered once the response has started; otherwise a bare 500
        // (core's status-code pages may render their generic error page for it).
        if (!context.HttpContext.Response.HasStarted)
            context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
    }

    private static void Log(HttpContext http, Exception exception, string stage) =>
        http.RequestServices?.GetService<ILoggerFactory>()
            ?.CreateLogger("BTCPayServer.Plugins.NostrLogin")
            .LogError(exception,
                "NostrLogin: unhandled exception ({Stage}) on {Method} {Path}; answered 500 (contained so BTCPay does not disable the plugin)",
                stage, http.Request.Method, http.Request.Path);
}
