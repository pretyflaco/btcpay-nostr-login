using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using NNostr.Client;
using static BTCPayServer.Plugins.NostrLogin.Tests.TwoFactorGateTests;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Untrusted events must be rejected cleanly, never by an exception: BTCPay core's
/// PluginExceptionHandler disables the plugin AND restarts the server on any unhandled plugin
/// exception during a request, so a throw on an anonymous endpoint is a remote kill switch
/// (happened in production 2026-10-19 with a value-less "u" tag).
/// </summary>
public class MalformedEventTests
{
    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>Raw event JSON for each malformation; <paramref name="url"/>/<paramref name="method"/>
    /// are filled in where the case needs to get past the earlier checks.</summary>
    internal static string Build(string kind, string url, string method)
    {
        var tags = new JsonArray(new JsonArray("u", url), new JsonArray("method", method));
        // Well-formed pubkey/sig/id by default so the malformation is what the validator hits
        // (an empty pubkey is rejected before the tags are ever read).
        JsonObject Evt(JsonNode? tagsNode, string? pubkey = null, string? sig = null, string? id = "")
        {
            var o = new JsonObject
            {
                ["id"] = id == "" ? new string('a', 64) : id, ["pubkey"] = pubkey ?? new string('a', 64), ["created_at"] = Now, ["kind"] = 27235,
                ["tags"] = tagsNode, ["content"] = "", ["sig"] = sig ?? new string('a', 128)
            };
            return o;
        }

        switch (kind)
        {
            case "valueless-u-tag": // the production crash
                return Evt(new JsonArray(new JsonArray("u"), new JsonArray("method", method))).ToJsonString();
            case "valueless-challenge-tag":
                return Evt(new JsonArray(new JsonArray("u", url), new JsonArray("method", method), new JsonArray("challenge"))).ToJsonString();
            case "valueless-method-tag":
                return Evt(new JsonArray(new JsonArray("u", url), new JsonArray("method"))).ToJsonString();
            case "null-tags":
                return Evt(null).ToJsonString();
            case "null-tag-entry":
                return Evt(new JsonArray((JsonNode?)null)).ToJsonString();
            case "null-tag-value":
                return Evt(new JsonArray(new JsonArray("u", null), new JsonArray("method", method))).ToJsonString();
            case "non-hex-pubkey":
                return SelfConsistent(new string('z', 64), new string('a', 128), url, method);
            case "non-hex-sig":
                return SelfConsistent(new string('a', 64), new string('z', 128), url, method);
            case "short-sig":
                return SelfConsistent(new string('a', 64), "abcd", url, method);
            case "missing-id":
                return Evt(tags.DeepClone(), new string('a', 64), new string('a', 128), id: null).ToJsonString();
            case "absurd-created-at":
                return "{\"id\":\"\",\"pubkey\":\"\",\"created_at\":1e300,\"kind\":27235,\"tags\":[],\"content\":\"\",\"sig\":\"\"}";
            case "wrong-type-kind":
                return "{\"kind\":\"x\",\"tags\":[]}";
            case "array-root":
                return "[]";
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }
    }

    /// <summary>Well-formed shape with a correct id over a non-hex/short pubkey or sig: passes
    /// the id check, so NNostr's Verify reaches Convert.FromHexString.</summary>
    private static string SelfConsistent(string pubkey, string sig, string url, string method)
    {
        var evt = new NostrEvent
        {
            Kind = 27235, PublicKey = pubkey, CreatedAt = DateTimeOffset.UtcNow, Content = "",
            Tags = [new NostrEventTag { TagIdentifier = "u", Data = [url] }, new NostrEventTag { TagIdentifier = "method", Data = [method] }]
        };
        evt.Id = evt.ComputeId();
        evt.Signature = sig;
        return JsonSerializer.Serialize(evt);
    }

    public static TheoryData<string> Cases() => new()
    {
        "valueless-u-tag", "valueless-method-tag", "valueless-challenge-tag", "null-tags", "null-tag-entry", "null-tag-value",
        "non-hex-pubkey", "non-hex-sig", "short-sig", "missing-id", "absurd-created-at", "wrong-type-kind", "array-root"
    };

    private static NostrEvent? Parse(string json) => UINostrLoginController.TryDecodeNostrEvent(
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)));

    private static string Status(IActionResult result) => result switch
    {
        JsonResult j => JsonSerializer.SerializeToElement(j.Value).GetProperty("status").GetString()!,
        ObjectResult o => JsonSerializer.SerializeToElement(o.Value).GetProperty("status").GetString()!,
        _ => throw new Xunit.Sdk.XunitException(result.GetType().Name)
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Nip98Validator_RejectsWithoutThrowing(string kind)
    {
        // Both shapes: open endpoints (no nonce) and session flows (challenge tag required).
        foreach (var nonce in new string?[] { null, "expected-nonce" })
        {
            var signed = Parse(Build(kind, LoginUrl, "POST"));
            var error = await Nip98.ValidateAsync(signed, signed?.PublicKey ?? "", LoginUrl, "POST", nonce,
                tryConsume: _ => Task.FromResult(true));
            Assert.NotNull(error);
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void ChallengeValidator_RejectsWithoutThrowing(string kind)
    {
        var signed = Parse(Build(kind, LoginUrl, "POST"));
        if (signed is not null)
            signed.Kind = 22242;
        Assert.NotNull(NostrLoginService.ValidateSignedEvent(signed, signed?.PublicKey ?? "", "challenge"));
    }

    private static Rig NewRig()
    {
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var replay = new Nip98ReplayStore(new FakeSettingsRepository(), NullLogger<Nip98ReplayStore>.Instance);
        return BuildRig(new string('a', 64), twoFactorEnabled: false, service, replay);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task OpenPostEndpoint_RejectsWithoutThrowing(string kind)
    {
        var rig = NewRig();
        var json = Build(kind, LoginUrl, "POST");
        rig.HttpContext.Request.Headers.Authorization = "Nostr " + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

        var result = await rig.Controller.Nip98Login();

        Assert.Equal("failed", Status(result));
        Assert.Equal(0, rig.SignIn.FullSignInCount);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task OpenGetLink_RejectsWithoutThrowing(string kind)
    {
        var rig = NewRig();
        var json = Build(kind, LoginUrl, "GET");
        var param = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var result = await rig.Controller.Nip98LoginLink(param);

        Assert.Equal("failed", Status(result));
        Assert.Equal(0, rig.SignIn.FullSignInCount);
    }

    // --- safety net ---

    [Fact]
    public void Controller_ContainsPluginExceptions()
    {
        Assert.NotEmpty(typeof(UINostrLoginController).GetCustomAttributes(typeof(ContainPluginExceptionsAttribute), true));
    }

    [Fact]
    public void ExceptionFilter_HandlesException_With500()
    {
        var http = new DefaultHttpContext();
        var context = new ExceptionContext(new ActionContext(http, new RouteData(), new ActionDescriptor()), [])
        {
            Exception = new InvalidOperationException("boom")
        };

        new ContainPluginExceptionsAttribute().OnException(context);

        Assert.True(context.ExceptionHandled); // never reaches BTCPay's PluginExceptionHandler
        var result = Assert.IsType<ObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status500InternalServerError, result.StatusCode);
    }
}
