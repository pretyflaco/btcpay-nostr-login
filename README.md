# BTCPay Server Nostr Login plugin

Sign in to BTCPay Server with a **NIP-46 Nostr remote signer** (Nostr Connect).

Scan a `nostrconnect://` QR code with a NIP-46 signer app (e.g. [Amber](https://github.com/greenart7c3/Amber) on Android), approve a single `kind:22242` signing request, and you are logged in.

This plugin is **purely additive**: password, Passkey and LoginCode sign-in remain untouched. It adds a third alternative sign-in path served by the plugin at `/login/nostr`.

## Status

Early MVP / proof of concept. Validates that a BTCPay plugin can own a complete alternative login vertical:

- [x] `/login/nostr` page rendering a `nostrconnect://` QR + URI
- [x] NIP-46 relay client: connect ack, `get_public_key`, `sign_event` request for a kind-22242 challenge, signature verification (NIP-44 with NIP-04 fallback)
- [x] npub → BTCPay user linking at `/account/nostr` (proof of possession via the same NIP-46 flow), optional auto-create behind a feature flag (off by default)
- [x] Standard cookie issuance via `SignInManager` after the core `CanLogin` policy checks
- [x] End-to-end validated against public relays (see `tools/FakeSigner`, a minimal NIP-46 signer CLI for development)
- [x] End-to-end validated with Amber (Android)
- [x] "NostrConnect" button on the core `/login` page, next to Passkey and LoginCode (injected via a response-rewriting startup filter, since `Login.cshtml` has no UI extension point; degrades gracefully if the markup anchor is not found)
- [x] CSRF protection on all state-changing endpoints (controller follows the `UI*` naming convention required by BTCPay's global antiforgery filter)
- [x] Server settings page at `/server/nostr-login` (admin only): toggle account creation via Nostr, configure relays
- [x] Account creation via Nostr (off by default) honors the server's registration policies: disabled registration, required email confirmation, and admin approval

Deliberately out of scope for now: session-to-origin binding hardening (anti-QRLjacking) and rate limiting on session creation (BTCPay core applies none to `/login` either).

Deliberately out of scope for the MVP: disabling password login and any subscription/LN-address gating.

## Requirements

- BTCPay Server >= 2.4.2

## Development

```bash
git clone --recurse-submodules https://github.com/pretyflaco/btcpay-nostr-login
cd btcpay-nostr-login
dotnet build src/BTCPayServer.Plugins.NostrLogin/BTCPayServer.Plugins.NostrLogin.csproj
```

Register the plugin with the BTCPay Server development environment:

```bash
./plugin-register.sh
cd submodules/btcpayserver/BTCPayServer.Tests
docker compose up -d dev
```

Then run BTCPay Server with the `Bitcoin-HTTPS` launch profile; the plugin is loaded via `DEBUG_PLUGINS`.

## License

MIT
