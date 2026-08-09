// Minimal NIP-46 signer for development: acts like Amber for a nostrconnect:// URI.
// Usage: dotnet run -- "<nostrconnect://...>" [priv-key-hex]
// If no key is given, a random one is generated and printed (reuse it to test login after linking).

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Web;
using NNostr.Client;
using NNostr.Client.Protocols;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: FakeSigner <nostrconnect-uri> [priv-key-hex]");
    return 1;
}

var uri = new Uri(args[0]);
var clientPubkeyHex = uri.Host;
var query = HttpUtility.ParseQueryString(uri.Query);
var secret = query["secret"] ?? throw new InvalidOperationException("URI has no secret");
var relays = query.GetValues("relay") ?? throw new InvalidOperationException("URI has no relays");

var signerKey = args.Length > 1
    ? NostrExtensions.ParseKey(args[1])
    : NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
var signerPubkeyHex = signerKey.CreateXOnlyPubKey().ToHex();
var clientPubkey = NostrExtensions.ParsePubKey(clientPubkeyHex);

Console.WriteLine($"signer privkey: {signerKey.ToHex()}");
Console.WriteLine($"signer pubkey:  {signerPubkeyHex}");
Console.WriteLine($"relays:         {string.Join(", ", relays)}");

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
using var client = new NostrClient(new Uri(relays[0]));
await client.ConnectAndWaitUntilConnected(cts.Token);
Console.WriteLine($"connected to {relays[0]}");

async Task Send(Rpc payload)
{
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
await foreach (var evt in client.SubscribeForEvents(filters, false, cts.Token))
{
    if (evt.PublicKey != clientPubkeyHex || evt.Id is null || !seen.Add(evt.Id))
        continue;
    var req = JsonSerializer.Deserialize<Rpc>(NIP44.Decrypt(signerKey, clientPubkey, evt.Content!))!;
    Console.WriteLine($"request: {req.Method}");
    switch (req.Method)
    {
        case "get_public_key":
            await Send(new Rpc { Id = req.Id, Result = signerPubkeyHex });
            break;
        case "sign_event":
            var template = JsonNode.Parse(req.Params![0])!;
            var toSign = new NostrEvent
            {
                Kind = template["kind"]!.GetValue<int>(),
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
            await Task.Delay(TimeSpan.FromSeconds(3));
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
