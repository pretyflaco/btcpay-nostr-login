using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Web;
using BTCPayServer.Plugins.NostrLogin;
using Microsoft.Extensions.Logging.Abstractions;
using NNostr.Client;
using NNostr.Client.Protocols;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// End-to-end protocol test: runs a fake NIP-46 signer over real public relays
/// against NostrLoginService, exactly like Amber would behave.
/// </summary>
public class Nip46FlowTests
{
    private class Rpc
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("method")] public string? Method { get; set; }
        [JsonPropertyName("params")] public string[]? Params { get; set; }
        [JsonPropertyName("result")] public string? Result { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    [Fact]
    public async Task FullLoginFlowWithFakeSigner()
    {
        // Run the complete handshake against each default relay in turn, pinning BOTH the service
        // session and the fake signer to that single relay, and accept the first relay that carries
        // the flow end-to-end. A relay can accept a websocket yet drop/rate-limit ephemeral
        // (kind-24133) events, so mere connectivity is not enough — only a completed round-trip
        // counts. This keeps the smoke test deterministic and robust to any one relay being blocked
        // or degraded on a given network, without depending on relay ordering.
        foreach (var relay in NostrLoginService.DefaultRelays)
        {
            if (await TryFlowOnRelay(relay))
                return; // a relay carried the full flow: success
        }

        Assert.Skip("No default relay carried the NIP-46 flow end-to-end from this environment.");
    }

    /// <summary>
    /// Attempts the full connect -> get_public_key -> sign_event flow over a single relay.
    /// Returns true if the session was approved; false if the relay was unreachable or the
    /// round-trip did not complete within the per-relay budget.
    /// </summary>
    private static async Task<bool> TryFlowOnRelay(string relay)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));

        var signerKey = NostrExtensions.ParseKey(RandomNumberGenerator.GetBytes(32));
        var signerPubkeyHex = signerKey.CreateXOnlyPubKey().ToHex();

        using var client = new NostrClient(new Uri(relay));
        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
            connectCts.CancelAfter(TimeSpan.FromSeconds(10));
            await client.ConnectAndWaitUntilConnected(connectCts.Token);
        }
        catch (Exception)
        {
            return false; // relay unreachable from here
        }

        var relays = new[] { relay };
        var service = new NostrLoginService(NullLogger<NostrLoginService>.Instance);
        var session = await service.CreateSessionAsync(Nip46SessionPurpose.Login, relays, "NostrLoginTest");

        // Parse the nostrconnect:// URI like a signer app would
        var uri = new Uri(session.ConnectUri);
        var clientPubkeyHex = uri.Host;
        Assert.Equal(64, clientPubkeyHex.Length);
        var query = HttpUtility.ParseQueryString(uri.Query);
        var secret = query["secret"]!;
        Assert.NotNull(secret);
        Assert.Contains("sign_event:22242", query["perms"]);
        var clientPubkey = NostrExtensions.ParsePubKey(clientPubkeyHex);

        var filters = new[]
        {
            new NostrSubscriptionFilter { Kinds = [24133], ReferencedPublicKeys = [signerPubkeyHex] }
        };

        async Task Send(object payload)
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

        var signerLoop = Task.Run(async () =>
        {
            // 1. connect ack: echo the secret
            await Send(new Rpc { Id = Guid.NewGuid().ToString("N"), Result = secret });

            var seen = new HashSet<string>();
            await foreach (var evt in client.SubscribeForEvents(filters, false, cts.Token))
            {
                if (evt.PublicKey != clientPubkeyHex || evt.Id is null || !seen.Add(evt.Id))
                    continue;
                var json = NIP44.Decrypt(signerKey, clientPubkey, evt.Content!);
                var req = JsonSerializer.Deserialize<Rpc>(json)!;
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
                        return; // done
                }
            }
        }, cts.Token);

        // Wait for the service to approve the session (or the per-relay budget to elapse)
        while (session.Status == Nip46SessionStatus.Pending && !cts.IsCancellationRequested)
            await Task.Delay(500, CancellationToken.None);

        try
        {
            await signerLoop;
        }
        catch (OperationCanceledException)
        {
            // relay accepted the socket but did not deliver the round-trip in time: try the next
        }

        if (session.Status != Nip46SessionStatus.Approved)
            return false;

        Assert.Equal(signerPubkeyHex, session.UserPubkey);
        return true;
    }
}
