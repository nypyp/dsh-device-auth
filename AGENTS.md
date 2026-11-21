# AGENTS.md

Conventions for agents (and humans) working in this repository.

## What this is

A DeepSeek Harness **profile bundle** (Host plugin) that adds durable per-device
login credentials to the DSH Web UI. It does not modify DSH packages; it lives
in the user's profile and wraps two `connection` service methods at runtime.

## Layout

| Path | Purpose |
|---|---|
| `lib/index.js` | Host plugin: wraps `authorizeConnect` / `authorizeIndex`. |
| `lib/store.mjs` | Credential store: hashing, constant-time compare, atomic write, lock. |
| `lib/sessions.mjs` | Derived cookie→device index powering immediate revocation. |
| `bin/dsh-auth.mjs` | Management CLI (`add/rotate/revoke/list/purge`). |
| `cordis.patch.yml` | Bundle layer: inserts the plugin row + disables `printUrl`. |
| `locale/*.json` | Plugin Manager display metadata (`meta.title`, `meta.description`). |
| `docs/DESIGN.md` | Mechanism, threat model, limits, upgrade strategy. |
| `test/` | Unit tests and the isolated sandbox acceptance script. |

## Rules

- **Never** modify installed DSH packages, the user's profile files, or
  `~/.dsh` from this repository's tooling. Install/uninstall goes through
  `dsh plugin` or the Plugin Manager.
- The plugin must stay read-only on the credential store. Mutations belong to
  the CLI under the lock in `lib/store.mjs`. The session index is derived state:
  the plugin may append hashes, the CLI prunes them with the device records.
- Never log, print, or persist a plaintext token outside the explicit
  `add`/`rotate` output. Keep `printUrl` disabled in the bundle patch.
- Keep the real launch-token path working untouched: unknown tokens must be
  delegated to the original implementation without changes.
- If DSH renames the wrapped methods, fail loudly at activation; never degrade
  silently into an unauthenticated state.
- Add a CHANGELOG entry and bump `package.json` `dsh.compatibility.dshReleases`
  after verifying against a new DSH release.

## Commands

```sh
npm test                 # unit tests
npm run check            # node --check + bash -n
./test/acceptance.sh     # isolated sandbox end-to-end (own DSH_HOME, :3099)
npm run pack:check       # inspect the published file list
```

`test/acceptance.sh` must never touch the production instance (`:3080`) or the
real `~/.dsh`; it copies a minimal home into `/tmp` and starts its own `dsh web`.

## Verify before release

1. `npm test`, `npm run check`, `npm run pack:check` clean.
2. `./test/acceptance.sh` → `PASS=12 FAIL=0` (or the current full count).
3. Manual: install the bundle in a scratch profile, add a device, restart
   `dsh web`, confirm the device token still exchanges (302) and the launch URL
   is no longer printed.
