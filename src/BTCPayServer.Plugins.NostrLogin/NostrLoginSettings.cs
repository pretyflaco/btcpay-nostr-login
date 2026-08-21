namespace BTCPayServer.Plugins.NostrLogin;

/// <summary>
/// Server-wide settings, stored via ISettingsRepository (single JSON row, no migrations).
/// </summary>
public class NostrLoginSettings
{
    /// <summary>
    /// When true, a successful NIP-46 sign-in with an unknown pubkey creates a new user.
    /// Default false: only pre-linked keys can sign in.
    /// </summary>
    public bool AllowAutoUserCreation { get; set; }

    /// <summary>
    /// Relays encoded into the nostrconnect:// URI. Falls back to defaults when empty.
    /// </summary>
    public List<string>? Relays { get; set; }

    /// <summary>
    /// When true, verbose NIP-46 handshake milestones and failure reasons are written to the
    /// server log (the "DIAG" lines). Off by default: kept in the code for debugging a stuck
    /// signer, but silent in normal operation. Flip on temporarily to triage, then off again.
    /// </summary>
    public bool EnableDiagnosticLogging { get; set; }

    /// <summary>
    /// When true (default), a Nostr sign-in syncs the identity's kind-0 profile picture into
    /// the user's BTCPay avatar (shown in the top-right account menu). Read-only relay fetch +
    /// BTCPay file storage; runs off the request path.
    /// </summary>
    public bool SyncProfilePictures { get; set; } = true;
}

/// <summary>
/// Mapping of nostr pubkey (x-only hex, lowercase) to BTCPay user id.
/// Stored via ISettingsRepository: BTCPay's AspNetUserClaims table cannot be
/// inserted into by plugins (its Id column has no value generation).
/// </summary>
public class NostrLoginUserMap
{
    public Dictionary<string, string> PubkeyToUserId { get; set; } = new();
}
