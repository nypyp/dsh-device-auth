# dsh-device-auth

> Stable, revocable per-device login tokens for the DeepSeek Harness Web UI — paired clients survive restarts instead of copying the rotating 43-character launch token again.

[![ci](https://github.com/nypyp/dsh-device-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/nypyp/dsh-device-auth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/dsh-device-auth)](https://www.npmjs.com/package/dsh-device-auth)
![license](https://img.shields.io/badge/license-MIT-2e8b57)
![dsh](https://img.shields.io/badge/dsh-%3E%3D0.2.2--rc.1%20%3C0.3.0--0-4d6bfe)
[中文](README.md)

## Why

DeepSeek Harness mints one random Web launch token per process and prints it once in the startup log. Every remote client (DSH Go, scripts, other machines) has to store it, so every restart invalidates all paired clients, forces a manual copy of a 43-character secret from `journalctl`, and leaves the credential in plaintext logs. There is no supported way to pin, rotate, or revoke it per device.

`dsh-device-auth` adds that layer **in the profile**, without modifying any installed DSH package and without losing it on `dsh` upgrades.

## Features

- **Stable**: one long-lived token per device; survives `dsh web` restarts, reboots, and `npm i -g @deepseek-ai/dsh@<next>`.
- **Rotatable**: re-issuing for the same device rotates in place; the old token receives 401 on its next request.
- **Per device and immediately revoked**: `dsh-auth list / revoke`; one credential per device, and a revoked device's **already-minted cookie is rejected on its next request**, not only when it tries to exchange again.
- **No credentials in logs**: the bundle layer turns off the printed launch URL; a token is shown once, only by an explicit `dsh-auth add|rotate`.
- **Zero regression**: a device token is swapped for the process launch token and handed to the original implementation. `/?token=`, 302/303 redirects, the 30-day signed cookie, the Host/Origin fence, `--trusted-host` and `--public-url` all behave exactly as before.
- **Self-contained**: no runtime dependencies and no build step; the server stores only SHA-256 hashes.

## Install

```sh
# from npm (available since 0.2.0)
dsh plugin --profile web add -w dsh-device-auth

# update
dsh plugin --profile web update dsh-device-auth@latest

# from a local checkout (development)
dsh plugin --profile web add -w file:/absolute/path/to/dsh-device-auth
```

Installing or updating reloads the plugin through the normal loader path; restart `dsh web` only if the profile asks for it.

The bundle patch also sets `web-runtime.printUrl: false`, so the startup log no longer contains a usable launch token. You can also install it from the Web GUI's **Plugins → Add plugin** search once the package is published.

## Usage

```sh
dsh-auth add phone --kind dsh-go        # mint for a phone (the token is shown once)
dsh-auth add laptop --kind browser      # mint for a browser
dsh-auth list                           # label / id / status / dates
dsh-auth rotate phone                   # rotate: the previous token stops working immediately
dsh-auth revoke phone                   # revoke one device
dsh-auth revoke --all                   # revoke everything
dsh-auth purge                          # drop revoked records
```

`add` / `rotate` print a token and two links:

```
token (shown once): dsh_dev_…
app connect link:   http://127.0.0.1:3080/connect?token=dsh_dev_…
browser login link: http://127.0.0.1:3080/?token=dsh_dev_…
```

- **DSH Go / SSH-tunnel client**: paste `dsh_dev_…` into the host's launch-token field. A changing tunnel port does not matter: each reconnect exchanges the same token for a fresh cookie.
- **Browser**: open the browser login link with your public origin (for example `https://dsh.example.com/?token=dsh_dev_…`); the normal 30-day cookie takes over afterwards.

The CLI reads and writes `$DSH_HOME/remote-auth.json` (default `~/.dsh/remote-auth.json`); `--store` and `--origin` override that path and the origin used in printed links.

## How it works

```
client ──► GET /connect?token=dsh_dev_<43>
              │
              ├─ not in the device store ──► delegate untouched (launch token / wrong token behaviour unchanged)
              │
              └─ match ──► substitute the process launch token
                             └─► original authorizeConnect: 302 + 30-day signed cookie (authority-bound, Host/Origin fence intact)
```

The plugin wraps `connection.authorizeConnect` / `authorizeIndex`, which are called dynamically per request. It only acts on `dsh_dev_` tokens present in the store; the real launch token is obtained through the documented `authenticatedUrl()` service method and is never modified.

The store is read-only for the plugin. Rotation and revocation are performed by the CLI under a cross-process lock and written atomically, so a stale in-process snapshot can never resurrect a revoked device.

A separate session index records a hash of every cookie minted during a device exchange, with the device id. The plugin wraps `admit` and `authorizeIndex` so a cookie whose device was revoked is refused on its very next request; launch-token cookies have no entry and are delegated to the original check.

See [docs/DESIGN.md](docs/DESIGN.md) for the threat model, OpenChamber mapping, and upgrade strategy.

## Compatibility

| | |
|---|---|
| DSH | `>=0.2.2-rc.1 <0.3.0-0` (tested on `0.2.2-rc.1`) |
| Node | `>=24.9.0` (the DSH Web runtime) |
| Surface | Web / Desktop profile (Host plugin, no client UI) |

Activation probes the required service methods; on a future DSH version that renames them the plugin **fails loudly** instead of silently leaving authentication open.

## Known limits

1. **Scope of immediate revocation**: the plugin indexes every cookie minted by a device exchange (SHA-256 of the cookie pair + device id) and rejects those cookies on the next request once the device is revoked. Two kinds of cookies cannot be attributed: owner sessions minted with the real launch token, and cookies minted before this plugin was installed/updated. Those keep working until they expire. If the session index is lost, such cookies fall back to the original authentication (no false rejection, but the corresponding device is not evicted either).
2. Every device is an owner: DSH has no per-device permission model, so "per device" here means credential-level only.
3. Device tokens are stored in plaintext on the client (secure storage / DSH Go config); the server keeps only hashes.
4. One-time pairing codes are not implemented (DSH Go only exchanges `token=`).

## Development

```sh
npm test               # unit tests (no dependencies, no DSH needed)
npm run check          # node --check + bash -n
./test/acceptance.sh   # isolated end-to-end sandbox (own DSH_HOME, :3099, production untouched)
```

## Rollback

```sh
dsh plugin --profile web remove dsh-device-auth   # or plugin_manager remove_bundle
```

Remove the bundle selection from the profile as well, then restart `dsh web`. Baseline behaviour (random launch token, startup URL printed) returns.

## Releasing (maintainers)

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml): checks, unit tests, `npm pack` verification, then `npm publish --provenance` (signed with GitHub OIDC provenance). Authentication uses the `NPM_TOKEN` repository secret (a granular npm token scoped to publishing `dsh-device-auth`).

### Optional, preferred: trusted publishing (OIDC, no long-lived token)

Enable it on `https://www.npmjs.com/package/dsh-device-auth/settings` → **Trusted publishing** → GitHub Actions: repository `nypyp/dsh-device-auth`, workflow `release.yml`. Once registered, delete the `NPM_TOKEN` secret and the workflow publishes through OIDC (it already has `id-token: write`).

## Credits

The credential model is inspired by [OpenChamber](https://github.com/openchamber/openchamber): an opaque random bearer stored server-side as SHA-256, in-place rotation for the same device, and per-device revocation.

## License

[MIT](LICENSE)
