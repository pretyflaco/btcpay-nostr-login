using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NNostr.Client;

namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Per-user avatar source-URL map (userId → the kind-0 picture URL currently reflected in the
/// user's ImageUrl). Lets login-time sync skip the download when nothing changed.
/// </summary>
public class NostrLoginAvatarMap
{
    public Dictionary<string, string> UserIdToSourceUrl { get; set; } = new();
}

/// <summary>
/// Syncs the signed-in Nostr user's profile picture: fetch the identity's kind-0 `picture`
/// from relays, download it, store it via BTCPay's own file storage, and set the user blob's
/// ImageUrl — which core's GlobalNav renders as the top-right account avatar (no view fork).
/// Runs on every Nostr login (sync-on-login policy), fully off the request path via a fresh
/// DI scope, and never blocks or fails a sign-in.
/// </summary>
public class NostrProfilePictureService
{
    private static readonly TimeSpan RelayFetchTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(10);
    private const long MaxImageBytes = 5 * 1024 * 1024;

    // Read set = the full profile-indexer set the Blink signer publishes kind-0 to +
    // the instance's configured NIP-46 relays.
    private static readonly string[] ProfileIndexerRelays =
    [
        "wss://purplepag.es",
        "wss://user.kindpag.es",
        "wss://profiles.nostr1.com",
        "wss://directory.yabu.me"
    ];

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<NostrProfilePictureService> _logger;

    public NostrProfilePictureService(IServiceScopeFactory scopeFactory,
        ILogger<NostrProfilePictureService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <summary>Fire-and-forget sync entry — safe to call from a request path.</summary>
    public void SyncInBackground(string userId, string pubkey)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                await Sync(scope.ServiceProvider, userId, pubkey, CancellationToken.None);
            }
            catch (Exception ex)
            {
                // POC triage: Information until the pipeline is proven, then back to Debug.
                _logger.LogInformation(ex, "NostrLogin: avatar sync threw for user {UserId}", userId);
            }
        });
    }

    private async Task Sync(IServiceProvider services, string userId, string pubkey, CancellationToken ct)
    {
        var settingsRepository = services.GetRequiredService<ISettingsRepository>();
        var settings = await settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        if (!settings.SyncProfilePictures)
            return;

        var relays = ProfileIndexerRelays
            .Concat(settings.Relays is { Count: > 0 } ? settings.Relays.ToArray() : NostrLoginService.DefaultRelays)
            .Distinct().ToArray();

        var sourceUrl = await FetchProfilePictureUrl(pubkey, relays);
        if (sourceUrl is null)
        {
            _logger.LogInformation(
                "NostrLogin: avatar sync found no kind-0 picture for npub {PubkeyPrefix}… on {RelayCount} relays",
                pubkey[..8], relays.Length);
            return;
        }
        _logger.LogInformation("NostrLogin: avatar sync found picture for npub {PubkeyPrefix}…: {Url}",
            pubkey[..8], sourceUrl);

        var avatarMap = await settingsRepository.GetSettingAsync<NostrLoginAvatarMap>() ?? new NostrLoginAvatarMap();
        if (avatarMap.UserIdToSourceUrl.TryGetValue(userId, out var current) && current == sourceUrl)
            return; // unchanged since last sync

        var download = await Download(services, sourceUrl);
        if (download is null)
        {
            _logger.LogInformation("NostrLogin: avatar download failed/rejected for {Url}", sourceUrl);
            return;
        }
        var (imageBytes, contentType) = download.Value;
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var fileService = services.GetRequiredService<IFileService>();
        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
            return;

        var fileName = Path.GetFileName(new Uri(sourceUrl).AbsolutePath);
        if (string.IsNullOrWhiteSpace(fileName)) fileName = "avatar";
        // FormFile's ContentType reads from Headers — a bare FormFile has null Headers and
        // FileService.UploadImage NREs on ContentType. Set both explicitly.
        var formFile = new FormFile(new MemoryStream(imageBytes), 0, imageBytes.Length, "file", fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType
        };
        var upload = await fileService.UploadImage(formFile, user.Id);
        if (!upload.Success || upload.StoredFile is null)
        {
            _logger.LogInformation("NostrLogin: avatar upload rejected for user {UserId}: {Reason}", userId, upload.Response);
            return;
        }

        var blob = user.GetBlob() ?? new UserBlob();
        blob.ImageUrl = new UnresolvedUri.FileIdUri(upload.StoredFile.Id).ToString();
        user.SetBlob(blob);
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            return;

        avatarMap.UserIdToSourceUrl[userId] = sourceUrl;
        await settingsRepository.UpdateSetting(avatarMap);
        _logger.LogInformation("NostrLogin: synced Nostr profile picture for user {UserId}", userId);
    }

    /// <summary>
    /// Parallel fetch across relays (indexers first), per-relay timeout, first hit wins.
    /// The earlier sequential loop with one shared deadline let a connected-but-empty relay
    /// starve the indexer that actually holds kind-0s (observed live 2026-08-21).
    /// </summary>
    private async Task<string?> FetchProfilePictureUrl(string pubkey, string[] relays)
    {
        var tasks = relays.Select(r => FetchFromRelay(r, pubkey)).ToList();
        await foreach (var completed in Task.WhenEach(tasks))
        {
            try
            {
                if (completed.Result is { } url)
                    return url;
            }
            catch (Exception)
            {
                // relay failed — others may still answer
            }
        }
        return null;
    }

    private async Task<string?> FetchFromRelay(string relay, string pubkey)
    {
        using var cts = new CancellationTokenSource(RelayFetchTimeout);
        try
        {
            using var client = new NostrClient(new Uri(relay));
            await client.ConnectAndWaitUntilConnected(cts.Token);
            var filters = new[]
            {
                new NostrSubscriptionFilter { Kinds = [0], Authors = [pubkey], Limit = 1 }
            };
            await foreach (var evt in client.SubscribeForEvents(filters, false, cts.Token))
            {
                if (evt.PublicKey != pubkey || evt.Content is null)
                    continue;
                var url = ParsePictureUrl(evt.Content);
                if (url is not null)
                    return url;
            }
            // POC diagnostics (Information on purpose — the avatar pipeline is under triage):
            _logger.LogInformation("NostrLogin: avatar fetch — {Relay} answered but had no usable kind-0 picture", relay);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogInformation("NostrLogin: avatar fetch — {Relay} failed: {Reason}", relay, ex.Message);
            return null;
        }
    }

    private static string? ParsePictureUrl(string kind0Content)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(kind0Content);
            if (!doc.RootElement.TryGetProperty("picture", out var picture))
                return null;
            var url = picture.GetString();
            if (string.IsNullOrEmpty(url) || url.Length > 2048)
                return null;
            return url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                ? url
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async Task<(byte[] Bytes, string ContentType)?> Download(IServiceProvider services, string url)
    {
        try
        {
            var http = services.GetRequiredService<IHttpClientFactory>().CreateClient();
            using var cts = new CancellationTokenSource(DownloadTimeout);
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!resp.IsSuccessStatusCode)
                return null;
            var mediaType = resp.Content.Headers.ContentType?.MediaType;
            if (mediaType is null || !mediaType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                return null;
            if (resp.Content.Headers.ContentLength > MaxImageBytes)
                return null;
            await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token);
            var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(chunk, cts.Token)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > MaxImageBytes)
                    return null;
            }
            return (buffer.ToArray(), mediaType);
        }
        catch (Exception)
        {
            return null;
        }
    }
}
