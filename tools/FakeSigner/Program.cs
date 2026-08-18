// Minimal NIP-46 signer for development: acts like Amber for a nostrconnect:// URI.
// Usage: dotnet run -- "<nostrconnect://...>" [priv-key-hex] [flags]
// If no key is given, a random one is generated and printed (reuse it to test login after linking).
//
// Test/dev flags (any order, after the URI and optional key):
//   --delay-ms N       Sleep N ms before EACH response (exercises client republish / retry).
//   --drop-first N      Silently ignore the first N inbound requests (forces client republish).
//   --error-on-sign     Reply with an error to sign_event (exercises the client's 22242 fallback).
//   --auth-url URL      Emit an auth_url response (URL as the error field) before signing.
//   --expect-kind K     Log a warning if the signed event's kind != K (sanity for 27235/22242).

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Web;
using NNostr.Client;
using NNostr.Client.Protocols;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: FakeSigner <nostrconnect-uri> [priv-key-hex] [flags]");
    return 1;
}

// Parse flags (and an optional positional priv-key-hex that is not a --flag).
string? privKeyHex = null;
var delayMs = 0;
var dropFirst = 0;
var errorOnSign = false;
string? authUrl = null;
int? expectKind = null;
for (var i = 1; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--delay-ms": delayMs = int.Parse(args[++i]); break;
        case "--drop-first": dropFirst = int.Parse(args[++i]); break;
        case "--error-on-sign": errorOnSign = true; break;
        case "--auth-url": authUrl = args[++i]; break;
        case "--expect-kind": expectKind = int.Parse(args[++i]); break;
        default:
            if (!args[i].StartsWith("--")) privKeyHex = args[i];
            else Console.Error.WriteLine($"unknown flag: {args[i]}");
            break;
    }
}

var uri = new Uri(args[0]);
var clientPubkeyHex = uri.Host;
var query = HttpUtility.ParseQueryString(uri.Query);
var secret = query["secret"] ?? throw new InvalidOperationException("URI has no secret");
var relays = query.GetValues("relay") ?? throw new InvalidOperationException("URI has no relays");

var signerKey = privKeyHex is not null
    ? NostrExtensions.ParseKey(privKeyHex)
    : NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
var signerPubkeyHex = signerKey.CreateXOnlyPubKey().ToHex();
var clientPubkey = NostrExtensions.ParsePubKey(clientPubkeyHex);

Console.WriteLine($"signer privkey: {signerKey.ToHex()}");
Console.WriteLine($"signer pubkey:  {signerPubkeyHex}");
Console.WriteLine($"relays:         {string.Join(", ", relays)}");
if (delayMs > 0 || dropFirst > 0 || errorOnSign || authUrl is not null || expectKind is not null)
    Console.WriteLine($"flags:          delay-ms={delayMs} drop-first={dropFirst} error-on-sign={errorOnSign} auth-url={authUrl ?? "-"} expect-kind={expectKind?.ToString() ?? "-"}");

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
using var client = new NostrClient(new Uri(relays[0]));
await client.ConnectAndWaitUntilConnected(cts.Token);
Console.WriteLine($"connected to {relays[0]}");

async Task Send(Rpc payload)
{
    if (delayMs > 0)
        await Task.Delay(delayMs, cts.Token);
    var json = JsonSerializer.Serialize(payload);
    var evt = new NostrEvent
    {
        Kind = 24133,
        PublicKey = signerPubkeyHex,
        CreatedAt = DateTimeOffset.UtcNow,
        Content = NIP44.Encrypt(signerKey, clientPubkey, json)
    };
    evt.SetTag("p", clientPubkeyHex);
    await evt.ComputeIdAndSignAsync(signerKey, handlenip4: false);
    await client.PublishEvent(evt, cts.Token);
}

await Send(new Rpc { Id = Guid.NewGuid().ToString("N"), Result = secret });
Console.WriteLine("sent connect ack");

var filters = new[] { new NostrSubscriptionFilter { Kinds = [24133], ReferencedPublicKeys = [signerPubkeyHex] } };
var seen = new HashSet<string>();
var dropped = 0;
var authUrlSent = false;
await foreach (var evt in client.SubscribeForEvents(filters, false, cts.Token))
{
    if (evt.PublicKey != clientPubkeyHex || evt.Id is null || !seen.Add(evt.Id))
        continue;
    var req = JsonSerializer.Deserialize<Rpc>(NIP44.Decrypt(signerKey, clientPubkey, evt.Content!))!;
    if (dropped < dropFirst)
    {
        dropped++;
        Console.WriteLine($"request: {req.Method} (dropped {dropped}/{dropFirst})");
        continue;
    }
    Console.WriteLine($"request: {req.Method}");
    switch (req.Method)
    {
        case "get_public_key":
            await Send(new Rpc { Id = req.Id, Result = signerPubkeyHex });
            break;
        case "sign_event":
            if (errorOnSign)
            {
                await Send(new Rpc { Id = req.Id, Error = "user rejected the request" });
                Console.WriteLine("replied error to sign_event");
                await Task.Delay(TimeSpan.FromSeconds(3), cts.Token);
                return 0;
            }
            if (authUrl is not null && !authUrlSent)
            {
                authUrlSent = true;
                await Send(new Rpc { Id = req.Id, Result = "auth_url", Error = authUrl });
                Console.WriteLine($"sent auth_url: {authUrl}");
                // Fall through to also sign, simulating the user approving in the web signer.
            }
            var template = JsonNode.Parse(req.Params![0])!;
            var kind = template["kind"]!.GetValue<int>();
            if (expectKind is not null && kind != expectKind)
                Console.Error.WriteLine($"WARNING: signed kind {kind} != expected {expectKind}");
            var toSign = new NostrEvent
            {
                Kind = kind,
                Content = template["content"]!.GetValue<string>(),
                CreatedAt = DateTimeOffset.FromUnixTimeSeconds(template["created_at"]!.GetValue<long>()),
                PublicKey = signerPubkeyHex,
                Tags = template["tags"]!.AsArray().Select(t => new NostrEventTag
                {
                    TagIdentifier = t![0]!.GetValue<string>(),
                    Data = t.AsArray().Skip(1).Select(d => d!.GetValue<string>()).ToList()
                }).ToList()
            };
            await toSign.ComputeIdAndSignAsync(signerKey, handlenip4: false);
            await Send(new Rpc { Id = req.Id, Result = JsonSerializer.Serialize(toSign) });
            // Give the relay client time to flush before disposing
            await Task.Delay(TimeSpan.FromSeconds(3), cts.Token);
            Console.WriteLine("signed and sent event, done");
            return 0;
    }
}
return 0;

class Rpc
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("params")] public string[]? Params { get; set; }
    [JsonPropertyName("result")] public string? Result { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}
