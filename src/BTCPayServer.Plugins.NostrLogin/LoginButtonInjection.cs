using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Core Login.cshtml has no ui-extension-point and compiled core views cannot be
/// shadowed by plugin views (first-registered application part wins). This startup
/// filter injects a "NostrConnect" button into the alternative sign-in row of
/// GET /login responses by anchored string rewrite. Degrades gracefully: if the
/// anchor is not found, the page is served unchanged.
/// </summary>
public class NostrLoginStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.UseMiddleware<LoginButtonInjectionMiddleware>();
        next(app);
    };
}

public class LoginButtonInjectionMiddleware
{
    // The LoginCode button is the last element of the alternative sign-in row.
    private const string Anchor = "data-bs-target=\"#scanModal\"";
    private readonly RequestDelegate _next;

    public LoginButtonInjectionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method) ||
            !context.Request.Path.Equals("/login", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        var originalBody = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;
        try
        {
            await _next(context);

            byte[] bytes = buffer.ToArray();
            if (context.Response.StatusCode == 200 &&
                context.Response.ContentType?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true)
            {
                var html = Encoding.UTF8.GetString(bytes);
                var rewritten = TryInjectButton(html, context.Request);
                if (rewritten is not null)
                    bytes = Encoding.UTF8.GetBytes(rewritten);
            }

            context.Response.Body = originalBody;
            context.Response.ContentLength = bytes.Length;
            await originalBody.WriteAsync(bytes, context.RequestAborted);
        }
        finally
        {
            context.Response.Body = originalBody;
        }
    }

    private static string? TryInjectButton(string html, HttpRequest request)
    {
        var pathBase = request.PathBase.HasValue ? request.PathBase.Value : "";
        var returnUrl = request.Query["returnUrl"];
        return TryInjectButton(html, pathBase ?? "", returnUrl);
    }

    internal static string? TryInjectButton(string html, string pathBase, string? returnUrl)
    {
        var anchorIndex = html.IndexOf(Anchor, StringComparison.Ordinal);
        if (anchorIndex < 0)
            return null;
        var insertAt = html.IndexOf("</button>", anchorIndex, StringComparison.Ordinal);
        if (insertAt < 0)
            return null;
        insertAt += "</button>".Length;

        var href = $"{pathBase}/login/nostr";
        if (!string.IsNullOrEmpty(returnUrl))
            href += "?returnUrl=" + Uri.EscapeDataString(returnUrl);

        // The button plus a scoped style so the three-item row wraps on narrow screens
        // instead of clipping the extra button (core's row is d-flex with no wrap and the
        // buttons don't all shrink evenly). flex-basis lets 3 sit inline on desktop and the
        // third drop to its own full-width line on mobile. CSP on /login only restricts
        // script-src, so an inline <style> is permitted.
        var button =
            $"<a href=\"{href}\" class=\"btn btn-outline-secondary w-100 nostr-login-btn\" id=\"nostr-login-btn\" title=\"Sign in with a NIP-46 Nostr signer\">" +
            $"<svg role=\"img\" class=\"icon icon-social-nostr\"><use href=\"{pathBase}/img/icon-sprite.svg#social-nostr\"></use></svg>" +
            "<span>NostrConnect</span></a>" +
            "<style>" +
            "#login-form .d-flex.gap-2{flex-wrap:wrap;}" +
            "#login-form .d-flex.gap-2>.btn{flex:1 1 120px;}" +
            "</style>";

        return html.Insert(insertAt, button);
    }
}
