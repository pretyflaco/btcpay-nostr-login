using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Abstractions.Extensions;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Data;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NNostr.Client;
using NNostr.Client.Protocols;
using QRCoder;

namespace BTCPayServer.Plugins.NostrLogin;

public class NostrLoginViewModel
{
    public required string SessionId { get; init; }
    public required string ConnectUri { get; init; }
    public required string QrDataUri { get; init; }
    public required string StatusUrl { get; init; }
    public string? ReturnUrl { get; init; }

    /// <summary>Set when the session was rejected before it could start (e.g. rate limited).</summary>
    public string? InitialError { get; init; }
}

public class NostrAccountViewModel
{
    public string[] LinkedPubkeys { get; init; } = [];
    public NostrLoginViewModel? LinkSession { get; init; }
}

public class NostrLoginServerSettingsViewModel
{
    public bool AllowAutoUserCreation { get; set; }

    /// <summary>One relay URL per line; empty means the built-in defaults.</summary>
    public string? Relays { get; set; }

    /// <summary>Verbose NIP-46 handshake logging; off by default, for debugging a stuck signer.</summary>
    public bool EnableDiagnosticLogging { get; set; }

    /// <summary>Sync the Nostr kind-0 profile picture into the user's BTCPay avatar on login.</summary>
    public bool SyncProfilePictures { get; set; }

    public int LinkedKeyCount { get; set; }
    public string[] DefaultRelays { get; set; } = [];
}

public class UINostrLoginController : Controller
{
    private readonly NostrLoginService _nostrLoginService;
    private readonly Nip98ReplayStore _replayStore;
    private readonly NostrProfilePictureService _profilePictureService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly UserService _userService;
    private readonly ISettingsRepository _settingsRepository;
    private readonly PoliciesSettings _policiesSettings;

    public UINostrLoginController(
        NostrLoginService nostrLoginService,
        Nip98ReplayStore replayStore,
        NostrProfilePictureService profilePictureService,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        UserService userService,
        ISettingsRepository settingsRepository,
        PoliciesSettings policiesSettings)
    {
        _nostrLoginService = nostrLoginService;
        _replayStore = replayStore;
        _profilePictureService = profilePictureService;
        _signInManager = signInManager;
        _userManager = userManager;
        _userService = userService;
        _settingsRepository = settingsRepository;
        _policiesSettings = policiesSettings;
    }

    // M2: cookie that binds a login session to the browser that rendered its QR (anti-QRLjacking).
    private const string BindCookieName = "NostrLogin.Bind";

    private async Task<string[]> GetRelays()
    {
        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        return settings.Relays is { Count: > 0 } ? settings.Relays.ToArray() : NostrLoginService.DefaultRelays;
    }

    private async Task<bool> GetDiagnosticsEnabled()
    {
        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        return settings.EnableDiagnosticLogging;
    }

    /// <summary>This instance's base URL, advertised to the signer so multiple BTCPay instances
    /// are distinguishable (they otherwise all show the same generic name).</summary>
    private string InstanceUrl() => $"{Request.Scheme}://{Request.Host}";

    /// <summary>App name shown by the signer, suffixed with the host so instances can be told apart.</summary>
    private string InstanceAppName() => $"BTCPay Server ({Request.Host})";

    /// <summary>
    /// The absolute URL the NIP-98 <c>u</c> tag is bound to (and the real open login endpoint).
    /// Uses Request.Scheme/Host, which reflect the reverse proxy through BTCPay core's configured
    /// ForwardedHeaders middleware (Startup.cs) — deliberately NOT raw X-Forwarded-* headers,
    /// which a proxy passing client input through could spoof (audit finding 6).
    /// </summary>
    private string Nip98LoginUrl() => $"{Request.Scheme}://{Request.Host}/login/nostr/nip98";

    private NostrLoginViewModel ToViewModel(Nip46Session session, string statusUrl, string? returnUrl = null)
    {
        var failedUpFront = session.Status == Nip46SessionStatus.Failed;
        return new()
        {
            SessionId = session.Id,
            ConnectUri = session.ConnectUri,
            QrDataUri = failedUpFront ? "" : GenerateQrDataUri(session.ConnectUri),
            StatusUrl = statusUrl,
            ReturnUrl = returnUrl,
            InitialError = failedUpFront ? session.Error : null
        };
    }

    private static string GenerateQrDataUri(string data)
    {
        using var generator = new QRCodeGenerator();
        using var qrData = generator.CreateQrCode(data, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(qrData).GetGraphic(5);
        return "data:image/png;base64," + Convert.ToBase64String(png);
    }

    [AllowAnonymous]
    [HttpGet("/login/nostr")]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated is true)
            return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");

        // M2: mint a per-session nonce, bind it to this browser via a strict cookie, and store
        // it on the session. The sign-in cookie is only issued to a caller presenting this nonce.
        var bindingNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        Response.Cookies.Append(BindCookieName, bindingNonce, new CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            IsEssential = true,
            MaxAge = TimeSpan.FromMinutes(10)
        });

        var session = await _nostrLoginService.CreateSessionAsync(
            Nip46SessionPurpose.Login, await GetRelays(), InstanceAppName(),
            bindingNonce: bindingNonce,
            rateLimitKey: HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            appUrl: InstanceUrl(), imageUrl: NostrLoginService.DefaultImageUrl,
            diagnostics: await GetDiagnosticsEnabled(), loginUrl: Nip98LoginUrl());
        var statusUrl = Url.Action(nameof(LoginStatus), new { sessionId = session.Id, returnUrl })!;
        return View("/Views/NostrLogin/Login.cshtml", ToViewModel(session, statusUrl, returnUrl));
    }

    [AllowAnonymous]
    [HttpGet("/login/nostr/status/{sessionId}")]
    public async Task<IActionResult> LoginStatus(string sessionId, string? returnUrl = null)
    {
        var session = _nostrLoginService.GetSession(sessionId);
        if (session is null || session.Purpose != Nip46SessionPurpose.Login)
            return Json(new { status = "failed", error = "Session expired. Reload the page to try again." });
        switch (session.Status)
        {
            case Nip46SessionStatus.Pending:
                // Web-signer flow: the signer asked the user to open an auth_url to approve. Surface
                // it so the login page can show the link; the handshake continues in the background.
                return session.AuthUrl is not null
                    ? Json(new { status = "auth_required", authUrl = session.AuthUrl })
                    : Json(new { status = "pending" });
            case Nip46SessionStatus.Failed:
                _nostrLoginService.RemoveSession(session.Id);
                return Json(new { status = "failed", error = session.Error });
        }

        // Approved. M2: enforce browser-origin binding before issuing any cookie.
        var presentedNonce = Request.Cookies[BindCookieName];
        if (session.BindingNonce is not null &&
            !NostrLoginService.BindingNonceMatches(session.BindingNonce, presentedNonce))
        {
            _nostrLoginService.RemoveSession(session.Id);
            return Json(new
            {
                status = "failed",
                error = "Please complete this sign-in in the same browser that displayed the QR code."
            });
        }

        var (user, resolveError) = await ResolveOrCreateUser(session.UserPubkey!);
        if (user is null)
            return Json(new { status = "failed", error = resolveError });

        if (!CanLoginOk(user, out var loginError))
            return Json(new { status = "failed", error = loginError });

        _profilePictureService.SyncInBackground(user.Id, session.UserPubkey!);

        await _signInManager.SignInAsync(user, false, "NostrLogin");
        _nostrLoginService.RemoveSession(session.Id); // single use, removed only after success
        Response.Cookies.Delete(BindCookieName);
        var redirect = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";
        return Json(new { status = "approved", redirect });
    }

    /// <summary>
    /// Resolves a proven nostr pubkey to a BTCPay user, auto-creating one when the admin enabled it
    /// (honouring the server's own registration policies). Shared by the QR status poller and the
    /// open NIP-98 endpoint. Returns (null, error) when no login is possible.
    /// </summary>
    private async Task<(ApplicationUser? User, string? Error)> ResolveOrCreateUser(string pubkey)
    {
        var user = await FindUserByPubkey(pubkey);
        if (user is not null)
            return (user, null);

        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        if (!settings.AllowAutoUserCreation)
            return (null, "No account is linked to this Nostr key. Sign in another way and link it under Account -> Nostr.");

        var (createdUser, createError) = await AutoCreateUser(pubkey);
        return createdUser is null
            ? (null, createError ?? "Could not create a new account for this Nostr key.")
            : (createdUser, null);
    }

    /// <summary>Runs BTCPay's CanLogin gate; returns false + a human error when the user may not sign in.</summary>
    private bool CanLoginOk(ApplicationUser user, out string? error)
    {
        var ctx = new UserService.CanLoginContext(user);
        if (_userService.CanLogin(ctx).GetAwaiter().GetResult())
        {
            error = null;
            return true;
        }
        error = ctx.Failures.Count > 0
            ? string.Join(" ", ctx.Failures.Select(f => f.ToString()))
            : "This account is not allowed to log in.";
        return false;
    }

    /// <summary>
    /// Open NIP-98 (HTTP Auth, kind 27235) login endpoint. Accepts <c>Authorization: Nostr &lt;base64&gt;</c>
    /// and signs in the proven key if it maps to an allowlisted user (or auto-creation is enabled).
    ///
    /// SECURITY: this is a standalone entry point WITHOUT the QR browser-binding (anti-QRLjacking)
    /// step — by design, so external NIP-98 clients (e.g. the vezir CLI) can log in. The gate is the
    /// full NIP-98 proof: a valid Schnorr signature by an allowlisted key, bound to THIS URL + POST,
    /// fresh, and single-use (replay-guarded), plus per-IP rate limiting. A stolen event is
    /// URL-bound and replay-blocked; it cannot be replayed here.
    /// </summary>
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    [HttpPost("/login/nostr/nip98")]
    public async Task<IActionResult> Nip98Login(string? returnUrl = null)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!_nostrLoginService.AllowLogin(ip))
            return StatusCode(StatusCodes.Status429TooManyRequests,
                new { status = "failed", error = "Too many sign-in attempts. Please wait a moment and try again." });

        var signed = TryDecodeNostrAuthHeader(Request.Headers.Authorization.ToString());
        if (signed is null)
            return Unauthorized(new { status = "failed", error = "Missing or malformed Authorization: Nostr header." });

        // expectedNonce = null: no prior session, so the signature + URL binding + replay guard are
        // the gate. The `u` tag must equal this endpoint's public URL.
        var error = await Nip98.ValidateAsync(signed, signed.PublicKey ?? "", Nip98LoginUrl(), "POST", null,
            tryConsume: _replayStore.TryConsumeAsync);
        if (error is not null)
            return Unauthorized(new { status = "failed", error });

        var (user, resolveError) = await ResolveOrCreateUser(signed.PublicKey!.ToLowerInvariant());
        if (user is null)
            return Json(new { status = "failed", error = resolveError });

        if (!CanLoginOk(user, out var loginError))
            return Json(new { status = "failed", error = loginError });

        _profilePictureService.SyncInBackground(user.Id, signed.PublicKey!);

        await _signInManager.SignInAsync(user, false, "NostrLogin");
        var redirect = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";
        return Json(new { status = "approved", redirect });
    }

    /// <summary>
    /// Same-device "magic link" NIP-98 login: the GET variant of the open endpoint above, for a
    /// signer app running on the SAME device as the browser (the one-click BTCPay setup flow).
    /// The app signs a kind-27235 event locally (<c>u</c> = this URL, <c>method</c> = GET) and
    /// opens the browser to <c>/login/nostr/nip98?event=&lt;base64url&gt;</c>; validation, user
    /// resolution and sign-in are identical to the POST form — the only difference is the
    /// transport (query param instead of an Authorization header a browser cannot send).
    ///
    /// SECURITY: same posture as the POST endpoint (no QR browser-binding — by design; the gate
    /// is the full NIP-98 proof + per-IP rate limiting). The event travels in a URL (server logs,
    /// browser history), which is acceptable because it is single-use (replay guard), tightly
    /// freshness-windowed (90 s, audit finding 7), and URL/method-bound. The redirect drops the
    /// query immediately.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("/login/nostr/nip98")]
    public async Task<IActionResult> Nip98LoginLink([FromQuery(Name = "event")] string? eventParam,
        string? returnUrl = null)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!_nostrLoginService.AllowLogin(ip))
            return StatusCode(StatusCodes.Status429TooManyRequests,
                new { status = "failed", error = "Too many sign-in attempts. Please wait a moment and try again." });

        var signed = TryDecodeNostrEvent(eventParam);
        if (signed is null)
            return Unauthorized(new { status = "failed", error = "Missing or malformed event parameter." });

        // expectedNonce = null: no prior session (same open posture as the POST endpoint). The
        // `u` tag must equal this endpoint's public URL and the method tag must be GET. Tight
        // 90 s freshness because the proof travels in a URL (audit finding 7).
        var error = await Nip98.ValidateAsync(signed, signed.PublicKey ?? "", Nip98LoginUrl(), "GET", null,
            Nip98.GetLinkMaxAgeMinutes, _replayStore.TryConsumeAsync);
        if (error is not null)
            return Unauthorized(new { status = "failed", error });

        var (user, resolveError) = await ResolveOrCreateUser(signed.PublicKey!.ToLowerInvariant());
        if (user is null)
            return Json(new { status = "failed", error = resolveError });

        if (!CanLoginOk(user, out var loginError))
            return Json(new { status = "failed", error = loginError });

        _profilePictureService.SyncInBackground(user.Id, signed.PublicKey!);

        await _signInManager.SignInAsync(user, false, "NostrLogin");
        return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");
    }

    /// <summary>Decode an <c>Authorization: Nostr &lt;base64-json-event&gt;</c> header to an event, or null.</summary>
    private static NostrEvent? TryDecodeNostrAuthHeader(string? header)
    {
        if (string.IsNullOrWhiteSpace(header))
            return null;
        var parts = header.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !string.Equals(parts[0], "Nostr", StringComparison.OrdinalIgnoreCase))
            return null;
        return TryDecodeNostrEvent(parts[1]);
    }

    /// <summary>
    /// Decode a base64url (or standard base64) encoded JSON event to an event, or null.
    /// Tolerates both alphabets and missing padding so callers can pass it through a URL query
    /// without re-encoding concerns.
    /// </summary>
    internal static NostrEvent? TryDecodeNostrEvent(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
            return null;
        try
        {
            var base64 = encoded.Replace('-', '+').Replace('_', '/');
            base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
            return System.Text.Json.JsonSerializer.Deserialize<NostrEvent>(json);
        }
        catch (Exception)
        {
            return null;
        }
    }

    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpGet("/account/nostr")]
    public async Task<IActionResult> Account(string? linkSession = null)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
            return NotFound();

        NostrLoginViewModel? linkVm = null;
        if (linkSession is not null &&
            _nostrLoginService.GetSession(linkSession) is { Purpose: Nip46SessionPurpose.Link } session &&
            session.LinkUserId == user.Id)
        {
            var statusUrl = Url.Action(nameof(LinkStatus), new { sessionId = session.Id })!;
            linkVm = ToViewModel(session, statusUrl);
        }

        var map = await GetUserMap();
        return View("/Views/NostrLogin/Account.cshtml", new NostrAccountViewModel
        {
            LinkedPubkeys = map.PubkeyToUserId
                .Where(kv => kv.Value == user.Id)
                .Select(kv => kv.Key)
                .ToArray(),
            LinkSession = linkVm
        });
    }

    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpPost("/account/nostr/link")]
    public async Task<IActionResult> StartLink()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
            return NotFound();
        var session = await _nostrLoginService.CreateSessionAsync(
            Nip46SessionPurpose.Link, await GetRelays(), InstanceAppName(), user.Id,
            appUrl: InstanceUrl(), imageUrl: NostrLoginService.DefaultImageUrl,
            diagnostics: await GetDiagnosticsEnabled(), loginUrl: Nip98LoginUrl());
        return RedirectToAction(nameof(Account), new { linkSession = session.Id });
    }

    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpGet("/account/nostr/link/status/{sessionId}")]
    public async Task<IActionResult> LinkStatus(string sessionId)
    {
        var user = await _userManager.GetUserAsync(User);
        var session = _nostrLoginService.GetSession(sessionId);
        if (user is null || session is null || session.Purpose != Nip46SessionPurpose.Link || session.LinkUserId != user.Id)
            return Json(new { status = "failed", error = "Session expired. Reload the page to try again." });
        switch (session.Status)
        {
            case Nip46SessionStatus.Pending:
                return session.AuthUrl is not null
                    ? Json(new { status = "auth_required", authUrl = session.AuthUrl })
                    : Json(new { status = "pending" });
            case Nip46SessionStatus.Failed:
                _nostrLoginService.RemoveSession(session.Id);
                return Json(new { status = "failed", error = session.Error });
        }

        var pubkey = session.UserPubkey!;
        var map = await GetUserMap();
        if (map.PubkeyToUserId.TryGetValue(pubkey, out var ownerId) && ownerId != user.Id)
        {
            _nostrLoginService.RemoveSession(session.Id);
            return Json(new { status = "failed", error = "This Nostr key is already linked to another account." });
        }
        map.PubkeyToUserId[pubkey] = user.Id;
        await _settingsRepository.UpdateSetting(map);
        _nostrLoginService.RemoveSession(session.Id);

        return Json(new { status = "approved", redirect = Url.Action(nameof(Account)) });
    }

    [Authorize(AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpPost("/account/nostr/unlink")]
    public async Task<IActionResult> Unlink(string pubkey)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
            return NotFound();
        var map = await GetUserMap();
        if (map.PubkeyToUserId.TryGetValue(pubkey, out var ownerId) && ownerId == user.Id)
        {
            map.PubkeyToUserId.Remove(pubkey);
            await _settingsRepository.UpdateSetting(map);
        }
        return RedirectToAction(nameof(Account));
    }

    [Authorize(Policy = BTCPayServer.Client.Policies.CanModifyServerSettings, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpGet("/server/nostr-login")]
    public async Task<IActionResult> ServerSettings()
    {
        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        return View("/Views/NostrLogin/ServerSettings.cshtml", new NostrLoginServerSettingsViewModel
        {
            AllowAutoUserCreation = settings.AllowAutoUserCreation,
            Relays = settings.Relays is { Count: > 0 } ? string.Join("\n", settings.Relays) : "",
            EnableDiagnosticLogging = settings.EnableDiagnosticLogging,
            SyncProfilePictures = settings.SyncProfilePictures,
            LinkedKeyCount = (await GetUserMap()).PubkeyToUserId.Count,
            DefaultRelays = NostrLoginService.DefaultRelays
        });
    }

    [Authorize(Policy = BTCPayServer.Client.Policies.CanModifyServerSettings, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
    [HttpPost("/server/nostr-login")]
    public async Task<IActionResult> ServerSettings(NostrLoginServerSettingsViewModel model)
    {
        var relays = (model.Relays ?? "")
            .Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        foreach (var relay in relays)
        {
            if (!Uri.TryCreate(relay, UriKind.Absolute, out var uri) || (uri.Scheme != "wss" && uri.Scheme != "ws"))
                ModelState.AddModelError(nameof(model.Relays), $"Invalid relay URL: {relay} (must be ws:// or wss://)");
        }
        if (!ModelState.IsValid)
        {
            model.LinkedKeyCount = (await GetUserMap()).PubkeyToUserId.Count;
            model.DefaultRelays = NostrLoginService.DefaultRelays;
            return View("/Views/NostrLogin/ServerSettings.cshtml", model);
        }

        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        settings.AllowAutoUserCreation = model.AllowAutoUserCreation;
        settings.Relays = relays.Count > 0 ? relays : null;
        settings.EnableDiagnosticLogging = model.EnableDiagnosticLogging;
        settings.SyncProfilePictures = model.SyncProfilePictures;
        await _settingsRepository.UpdateSetting(settings);
        TempData[BTCPayServer.Abstractions.Constants.WellKnownTempData.SuccessMessage] = "Nostr Login settings updated.";
        return RedirectToAction(nameof(ServerSettings));
    }

    private async Task<NostrLoginUserMap> GetUserMap() =>
        await _settingsRepository.GetSettingAsync<NostrLoginUserMap>() ?? new NostrLoginUserMap();

    private async Task<ApplicationUser?> FindUserByPubkey(string pubkey)
    {
        var map = await GetUserMap();
        return map.PubkeyToUserId.TryGetValue(pubkey, out var userId)
            ? await _userManager.FindByIdAsync(userId)
            : null;
    }

    /// <summary>
    /// Creates a new account for an unknown npub. Only runs when AllowAutoUserCreation is
    /// enabled, and even then defers to the server's own registration policies.
    /// </summary>
    private async Task<(ApplicationUser? User, string? Error)> AutoCreateUser(string pubkey)
    {
        if (_policiesSettings.LockSubscription)
            return (null, "New account registration is disabled on this server.");
        if (_policiesSettings.RequiresConfirmedEmail)
            return (null, "This server requires a confirmed email address; accounts cannot be created via Nostr sign-in. Register normally, then link your Nostr key.");

        var requiresApproval = _policiesSettings.RequiresUserApproval;
        var email = $"nostr-{pubkey[..12]}@nostr.invalid";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            RequiresEmailConfirmation = false,
            RequiresApproval = requiresApproval,
            Approved = !requiresApproval,
            Created = DateTimeOffset.UtcNow
        };
        // Random password: never disclosed, only exists because accounts without a
        // password hash are rejected by the default CanLogin checks.
        var password = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) + "aA1!";
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            return (null, "Could not create a new account for this Nostr key.");
        var map = await GetUserMap();
        map.PubkeyToUserId[pubkey] = user.Id;
        await _settingsRepository.UpdateSetting(map);
        // With RequiresUserApproval the subsequent CanLogin check reports the pending state.
        return (user, null);
    }
}

public static class NostrPubkeyExtensions
{
    public static string ToNpub(this string pubkeyHex)
    {
        try
        {
            return NNostr.Client.NostrExtensions.ParsePubKey(pubkeyHex).ToNIP19();
        }
        catch (Exception)
        {
            return pubkeyHex;
        }
    }
}
