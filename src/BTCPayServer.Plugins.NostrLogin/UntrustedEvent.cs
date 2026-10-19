using System;
using System.Collections.Generic;
using System.Linq;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Never-throwing accessors for events that come from untrusted input (anonymous HTTP endpoints,
/// relays). NNostr's helpers assume well-formed events: <c>GetTaggedData</c> calls
/// <c>Data.First()</c> (throws on a value-less tag like <c>["u"]</c>) and <c>Verify()</c> throws on
/// null tags or non-hex pubkey/sig.
///
/// This matters beyond a 500: BTCPay core's PluginExceptionHandler DISABLES a plugin and RESTARTS
/// the whole server on any unhandled exception thrown from plugin code during a request, so one
/// malformed anonymous request would be a remote kill switch. Validators must use these helpers.
/// </summary>
internal static class UntrustedEvent
{
    /// <summary>First value of every tag named <paramref name="identifier"/>; malformed tags
    /// (null, no value, null value) are skipped.</summary>
    internal static string[] TagValues(NostrEvent e, string identifier) =>
        e.Tags is null
            ? []
            : e.Tags
                .Where(t => t is not null && t.TagIdentifier == identifier && t.Data is { Count: > 0 } && t.Data[0] is not null)
                .Select(t => t.Data[0])
                .ToArray();

    /// <summary>Id + Schnorr signature check; false (never an exception) for anything malformed.</summary>
    internal static bool Verify(NostrEvent e)
    {
        if (e.Id is not { Length: 64 } || e.PublicKey is not { Length: 64 } || e.Signature is not { Length: 128 }
            || e.Tags is null || e.Tags.Any(t => t?.Data is null || t.TagIdentifier is null || t.Data.Any(d => d is null)))
            return false;
        try
        {
            return e.Verify();
        }
        catch (Exception)
        {
            return false;
        }
    }
}
