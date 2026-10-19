// Minimal NIP-46 signer for development: acts like Amber for a nostrconnect:// URI.
// Usage: dotnet run -- "<nostrconnect://...>" [flags]
//
// Signer key (never taken on the command line, never printed — argv is world-readable via
// /proc/<pid>/cmdline and stdout ends up in scrollback/CI logs):
//   NOSTR_SIGNER_KEY=<hex>  Use this private key.
//   --key-file PATH         Use the key in PATH; if PATH does not exist, generate a key and save it
//                           there (mode 0600). Reuse the same file to log in after linking.
//   (neither)               Throwaway random key.
//
// Test/dev flags (any order, after the URI):
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

const string usage = "Usage: FakeSigner <nostrconnect-uri> [--key-file PATH] [flags]  (or NOSTR_SIGNER_KEY=<hex>)";
if (args.Length < 1)
{
    Console.Error.WriteLine(usage);
    return 1;
}

string? keyFile = null;
var delayMs = 0;
var dropFirst = 0;
var errorOnSign = false;
string? authUrl = null;
int? expectKind = null;
try
{
    string Value(ref int i) => i + 1 < args.Length ? args[++i] : throw new FormatException($"{args[i]} needs a value");
    for (var i = 1; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--key-file": keyFile = Value(ref i); break;
            case "--delay-ms": delayMs = int.Parse(Value(ref i)); break;
            case "--drop-first": dropFirst = int.Parse(Value(ref i)); break;
            case "--error-on-sign": errorOnSign = true; break;
            case "--auth-url": authUrl = Value(ref i); break;
            case "--expect-kind": expectKind = int.Parse(Value(ref i)); break;
            default:
                throw new FormatException(args[i].StartsWith("--")
                    ? $"unknown flag: {args[i]}"
                    : "positional private keys are no longer accepted (visible in the process table); use NOSTR_SIGNER_KEY or --key-file");
        }
    }
}
catch (FormatException ex)
{
    Console.Error.WriteLine($"{ex.Message}\n{usage}");
    return 1;
}

if (!Uri.TryCreate(args[0], UriKind.Absolute, out var uri) || uri.Scheme != "nostrconnect")
{
    Console.Error.WriteLine($"not a nostrconnect:// URI: {args[0]}\n{usage}");
    return 1;
}
var clientPubkeyHex = uri.Host;
var query = HttpUtility.ParseQueryString(uri.Query);
var secret = query["secret"];
var relays = query.GetValues("relay");
if (secret is null || relays is null)
{
    Console.Error.WriteLine("nostrconnect URI must carry a secret and at least one relay");
    return 1;
}

var signerKey = LoadSignerKey(keyFile);
var signerPubkeyHex = signerKey.CreateXOnlyPubKey().ToHex();
var clientPubkey = NostrExtensions.ParsePubKey(clientPubkeyHex);

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
    Rpc? req = null;
    try
    {
        req = JsonSerializer.Deserialize<Rpc>(NIP44.Decrypt(signerKey, clientPubkey, evt.Content ?? ""))
              ?? throw new FormatException("empty request");
        if (await Handle(req) is { } exitCode)
            return exitCode;
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        // Malformed request: log and keep serving instead of crashing the dev tool.
        Console.Error.WriteLine($"ignoring malformed request {evt.Id}: {ex.Message}");
        if (req?.Id is not null)
            await Send(new Rpc { Id = req.Id, Error = $"malformed request: {ex.Message}" });
    }
}
return 0;

// Returns an exit code when the session is done, null to keep listening.
async Task<int?> Handle(Rpc req)
{
    if (dropped < dropFirst)
    {
        dropped++;
        Console.WriteLine($"request: {req.Method} (dropped {dropped}/{dropFirst})");
        return null;
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
    return null;
}

// NOSTR_SIGNER_KEY > --key-file (created 0600 with a fresh key if missing) > throwaway key.
static NBitcoin.Secp256k1.ECPrivKey LoadSignerKey(string? keyFile)
{
    if (Environment.GetEnvironmentVariable("NOSTR_SIGNER_KEY") is { Length: > 0 } envKey)
        return NostrExtensions.ParseKey(envKey.Trim());
    if (keyFile is null)
        return NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
    if (File.Exists(keyFile))
        return NostrExtensions.ParseKey(File.ReadAllText(keyFile).Trim());

    var key = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
    var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
    if (!OperatingSystem.IsWindows())
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    using (var writer = new StreamWriter(keyFile, options))
        writer.Write(key.ToHex());
    Console.WriteLine($"saved new signer key to {keyFile} (0600)");
    return key;
}

class Rpc
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("params")] public string[]? Params { get; set; }
    [JsonPropertyName("result")] public string? Result { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}
