using System;
using System.Linq;
using System.Threading.Tasks;
using BTCPayServer.Abstractions.Constants;
using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Data;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
}

public class NostrAccountViewModel
{
    public string[] LinkedPubkeys { get; init; } = [];
    public NostrLoginViewModel? LinkSession { get; init; }
}

public class NostrLoginController : Controller
{
    private readonly NostrLoginService _nostrLoginService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly UserService _userService;
    private readonly ISettingsRepository _settingsRepository;

    public NostrLoginController(
        NostrLoginService nostrLoginService,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        UserService userService,
        ISettingsRepository settingsRepository)
    {
        _nostrLoginService = nostrLoginService;
        _signInManager = signInManager;
        _userManager = userManager;
        _userService = userService;
        _settingsRepository = settingsRepository;
    }

    private async Task<string[]> GetRelays()
    {
        var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
        return settings.Relays is { Count: > 0 } ? settings.Relays.ToArray() : NostrLoginService.DefaultRelays;
    }

    private NostrLoginViewModel ToViewModel(Nip46Session session, string statusUrl, string? returnUrl = null) => new()
    {
        SessionId = session.Id,
        ConnectUri = session.ConnectUri,
        QrDataUri = GenerateQrDataUri(session.ConnectUri),
        StatusUrl = statusUrl,
        ReturnUrl = returnUrl
    };

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
        var session = await _nostrLoginService.CreateSessionAsync(Nip46SessionPurpose.Login, await GetRelays(), "BTCPay Server");
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
                return Json(new { status = "pending" });
            case Nip46SessionStatus.Failed:
                _nostrLoginService.RemoveSession(session.Id);
                return Json(new { status = "failed", error = session.Error });
        }

        // Approved
        var pubkey = session.UserPubkey!;
        var user = await FindUserByPubkey(pubkey);
        if (user is null)
        {
            var settings = await _settingsRepository.GetSettingAsync<NostrLoginSettings>() ?? new NostrLoginSettings();
            if (!settings.AllowAutoUserCreation)
                return Json(new
                {
                    status = "failed",
                    error = "No account is linked to this Nostr key. Sign in another way and link it under Account -> Nostr."
                });
            user = await AutoCreateUser(pubkey);
            if (user is null)
                return Json(new { status = "failed", error = "Could not create a new account for this Nostr key." });
        }

        var canLoginContext = new UserService.CanLoginContext(user);
        if (!await _userService.CanLogin(canLoginContext))
            return Json(new
            {
                status = "failed",
                error = canLoginContext.Failures.Count > 0
                    ? string.Join(" ", canLoginContext.Failures.Select(f => f.ToString()))
                    : "This account is not allowed to log in."
            });

        await _signInManager.SignInAsync(user, false, "NostrLogin");
        _nostrLoginService.RemoveSession(session.Id); // single use, removed only after success
        var redirect = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";
        return Json(new { status = "approved", redirect });
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
        var session = await _nostrLoginService.CreateSessionAsync(Nip46SessionPurpose.Link, await GetRelays(), "BTCPay Server", user.Id);
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
                return Json(new { status = "pending" });
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

    private async Task<NostrLoginUserMap> GetUserMap() =>
        await _settingsRepository.GetSettingAsync<NostrLoginUserMap>() ?? new NostrLoginUserMap();

    private async Task<ApplicationUser?> FindUserByPubkey(string pubkey)
    {
        var map = await GetUserMap();
        return map.PubkeyToUserId.TryGetValue(pubkey, out var userId)
            ? await _userManager.FindByIdAsync(userId)
            : null;
    }

    private async Task<ApplicationUser?> AutoCreateUser(string pubkey)
    {
        var email = $"nostr-{pubkey[..12]}@nostr.invalid";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            RequiresEmailConfirmation = false,
            RequiresApproval = false,
            Approved = true,
            Created = DateTimeOffset.UtcNow
        };
        // Random password: never disclosed, only exists because accounts without a
        // password hash are rejected by the default CanLogin checks.
        var password = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) + "aA1!";
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            return null;
        var map = await GetUserMap();
        map.PubkeyToUserId[pubkey] = user.Id;
        await _settingsRepository.UpdateSetting(map);
        return user;
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
