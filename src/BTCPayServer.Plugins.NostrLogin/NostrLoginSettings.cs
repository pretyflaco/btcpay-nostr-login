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
