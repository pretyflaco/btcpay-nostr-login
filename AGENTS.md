# AGENTS.md

Guidance for AI agents and new contributors working in this repository.

## What this is

A **BTCPay Server plugin** (C# / .NET 10, `Microsoft.NET.Sdk.Razor`) that adds
**NIP-46 (Nostr Connect)** remote-signer sign-in. It is purely additive: a
"NostrConnect" button appears next to Passkey / LoginCode on `/login`; password
sign-in is untouched. `NNostr.Client` handles the Nostr protocol/relays;
`QRCoder` renders the connect QR.

## Layout

```
src/BTCPayServer.Plugins.NostrLogin/     # the plugin
  Plugin.cs                  # DI registration (service, startup filter, nav extensions)
  NostrLoginService.cs       # CORE: NIP-46 sessions, relays, nostrconnect URI, RPC flow
  UINostrLoginController.cs  # MVC routes, QR generation, login/link/settings
  LoginButtonInjection.cs    # IStartupFilter injecting the login button (core Login.cshtml has no extension point)
  NostrLoginSettings.cs      # POCOs stored via ISettingsRepository (no EF migrations)
  Views/NostrLogin/*.cshtml  # Login, Account, ServerSettings, nav partials
tests/BTCPayServer.Plugins.NostrLogin.Tests/   # xUnit v3 (Microsoft.Testing.Platform)
tools/FakeSigner/            # dev CLI that mimics an Amber-like NIP-46 signer
submodules/btcpayserver/     # FULL BTCPay Server source as a git submodule (build/reference only)
docs/assets/                 # images (btcpay_square.png etc.); NOT served at runtime
```

Clone with submodules: `git clone --recurse-submodules ...`. If already cloned,
`git submodule update --init --recursive`.

## Build / test / run — environment specifics

**`dotnet` is NOT on `PATH`.** It lives at `~/.dotnet/dotnet`. Prefix commands:

```bash
export PATH="$HOME/.dotnet:$PATH" DOTNET_ROOT="$HOME/.dotnet"
```

Build the plugin:
```bash
dotnet build src/BTCPayServer.Plugins.NostrLogin/BTCPayServer.Plugins.NostrLogin.csproj -c Release
```

**Tests use xUnit v3 on Microsoft.Testing.Platform (MTP)** — the test project is
an executable (`OutputType=Exe`). `dotnet test` output/counters are unreliable in
this environment; run the built test executable directly instead:

```bash
dotnet build tests/BTCPayServer.Plugins.NostrLogin.Tests/BTCPayServer.Plugins.NostrLogin.Tests.csproj -c Debug
./tests/BTCPayServer.Plugins.NostrLogin.Tests/bin/Debug/net10.0/BTCPayServer.Plugins.NostrLogin.Tests
# filter (xUnit v3 query language), e.g. exclude the live-relay flow test:
#   ... -filter "/*/*/!Nip46FlowTests/*"
```

`Nip46FlowTests` reaches **real public relays** and iterates the default relays
until one carries the handshake end-to-end (a relay can accept a websocket yet
drop ephemeral kind-24133 events, so mere connectivity is not enough). It is a
network-dependent smoke test; it `Assert.Skip`s if no relay works from the
current network. All other tests are offline and fast.

Pre-existing build warnings (`NU1903` SSH.NET, a submodule pattern warning) come
from the BTCPay submodule, not this plugin — ignore them.

### Local dev against a running BTCPay

```bash
./plugin-register.sh            # writes DEBUG_PLUGINS into the submodule's appsettings.dev.json
cd submodules/btcpayserver/BTCPayServer.Tests && docker compose up -d dev
# then run BTCPayServer with the Bitcoin-HTTPS launch profile
```

## Architecture notes (read before changing the flow)

- **Login must never block on relays.** `CreateSessionAsync` returns
  synchronously with the ready `nostrconnect://` URI; all relay connect +
  subscribe + RPC work runs in a background task (`RunSessionAsync`). Relays are
  connected **in parallel** with a short per-relay timeout (`RelayConnectTimeout`).
  Regressing this to await relays before rendering the QR reintroduces the
  "spinning login tab" bug. There is a test asserting prompt return with
  unreachable relays.
- **The connect ack is one-shot.** The kind-24133 subscription must be created
  *before* reading events. Keep that ordering in `RunSessionAsync`.
- **nostrconnect URI** is built in `NostrLoginService.BuildConnectUri`. It emits
  `relay`, `secret`, `perms=sign_event:22242`, `name`, and (NIP-46 optional)
  `url` + `image`. `name` is per-instance (`BTCPay Server ({host})`) and `url` is
  the instance base URL so signers can distinguish instances; `image` is the
  service avatar (`NostrLoginService.DefaultImageUrl`).
- **Default relays** are `NostrLoginService.DefaultRelays`. Admins can override
  them in Server Settings → Nostr Login (stored via `ISettingsRepository`;
  overrides win over defaults). Tests reference `DefaultRelays` dynamically, so
  changing the list does not break them.
- **Diagnostics:** verbose NIP-46 handshake logs ("DIAG" lines) are gated behind
  `NostrLoginSettings.EnableDiagnosticLogging` (admin toggle, **off by default**).
  Keep them gated — do not ship them always-on, and do not delete them.

## Security invariants (do not weaken)

- **Anti-QRLjacking:** a login session is bound to the browser that rendered the
  QR via an HttpOnly `SameSite=Strict` bind cookie; the sign-in cookie is only
  issued to that browser. Compared in constant time (`BindingNonceMatches`).
- **Signed-event validation** (`ValidateSignedEvent`) is the auth-critical gate:
  kind 22242, pubkey match, challenge tag match, timestamp freshness, valid
  Schnorr signature. It is `internal` so it can be unit tested — keep it covered.
- **Rate limiting** on anonymous login-session creation (per IP). Ephemeral
  per-session keys are zeroized on resolution.
- **Auto user creation** is off by default and, when enabled, still honours the
  server's registration policies (locked registration, required email
  confirmation, admin approval).

## Deploying to a live instance (Docker BTCPay)

Instances are standard Docker BTCPay deployments. SSH is configured (e.g. host
alias `btcpay.twentyone.ist`). The plugin is deployed as an **unpacked directory**
of DLLs (not a `.btcpay` package), replacing the contents of the plugin folder in
the BTCPay container, then restarting the container.

1. Publish the exact DLL set:
   ```bash
   dotnet publish src/BTCPayServer.Plugins.NostrLogin/BTCPayServer.Plugins.NostrLogin.csproj -c Release -o /tmp/nostr-release
   ```
   Output = `BTCPayServer.Plugins.NostrLogin.dll` + its NuGet dependency DLLs
   (NNostr.Client, NBitcoin.Secp256k1, System.Linq.Async, etc.) +
   `.deps.json` + `.staticwebassets.endpoints.json`. This must match the file set
   already present in the container's plugin dir.
2. Container: `generated_btcpayserver_1`. Plugin dir:
   `/root/.btcpayserver/Plugins/BTCPayServer.Plugins.NostrLogin/`.
3. Back up the current dir in-container (`cp -a ...bak-<version>`), `docker cp`
   the new files in, then `sudo docker restart generated_btcpayserver_1`.
4. Verify: `docker logs ... | grep "Running plugin BTCPayServer.Plugins.NostrLogin"`
   shows the new version and `Now listening`; `GET /login/nostr` returns quickly;
   the QR's `relay=` params match the intended default set.
5. **Bump `<Version>`** in the csproj for every deploy so the loaded version is
   visibly distinguishable in logs / the plugin list.

Plugin settings live in the `Settings` table of the `btcpayservermainnet`
Postgres DB (container `generated_postgres_1`). If no `NostrLoginSettings` row
exists, the built-in `DefaultRelays` are in effect (changing code defaults then
takes effect); an admin-saved relay list overrides them.

## Conventions

- Keep changes minimal and additive; never break password/Passkey/LoginCode.
- Do not commit, push, or deploy unless explicitly asked.
- Do not create docs/*.md proactively.
- BTCPay dependency floor is declared in `Plugin.cs` (`>=2.4.2`).
