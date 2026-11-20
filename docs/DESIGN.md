# Design

This document records the mechanism, the reference model it borrows from, the
verification evidence, and the known boundaries of `dsh-device-auth`.

## Problem

DeepSeek Harness's Web launch token is process-scoped:

- `dsh-client-connection` creates it with `encodeBase64Url(randomBytes(32))` on
  every process start and caches it on the root context (it survives plugin
  reloads within the process, nothing more).
- The browser session cookie, by contrast, is signed with a **durable** secret
  kept in the credentials store, so it survives restarts. The token does not.
- Remote clients such as DSH Go authenticate by exchanging the launch token at
  `GET /connect?token=…` for that cookie. On restart the stored token is stale,
  the endpoint answers 401, and the client fails before it can reach the cookie
  flow.

There is no documented extension point for token validation: the only related
event (`connection/request`) runs after `admit()` has already authenticated the
request. Patching the installed package is not viable either, since `dsh`
upgrades replace it.

## Mechanism

The plugin wraps two methods **on the live service instance**:

```js
const connection = ctx.get('connection')
connection.authorizeConnect = function (req, res) { /* wrapper */ }
connection.authorizeIndex   = function (req, res, secure) { /* wrapper */ }
```

This works because the `/connect` route handler and the static-index fallback
call those methods dynamically per request (`connection.authorizeConnect(req,
res)`, `ctx.connection.authorizeIndex(request, response)`). No route, config
value, or package file is replaced.

On a request the wrapper:

1. reads the single `token` query value;
2. skips work entirely unless it starts with the device prefix (`dsh_dev_`) —
   the real launch token and every malformed request take the original path;
3. looks the token up in the device store (SHA-256 digest, constant-time
   compare, skip revoked/expired records);
4. on a match, rewrites the request so it carries the **current process launch
   token** (read via the documented `connection.authenticatedUrl()` method) and
   calls the original implementation;
5. restores the incoming URL for callers that inspect it afterwards.

The original implementation then performs the unchanged 302/303 + `Set-Cookie`
flow, including the Host/Origin fence, the authority-bound cookie name and
payload, and the 30-day lifetime. The wrapper never mints cookies, never touches
`BrowserAuth`, and never weakens a comparison.

### Why the store is not the cookie

Keeping the device token separate from the browser cookie is deliberate:

- The cookie is bound to a `host:port` authority. Through an SSH tunnel the
  local port can change between sessions, which would orphan a stored cookie.
- Chrome/OS cookie jars are not available to native clients like DSH Go.
- A cookie carries no device identity, so it cannot express rotation or
  revocation.

A per-device token that is exchanged for a fresh cookie on each connection
solves all three: rotation and revocation are store operations, and the
authority problem disappears because the cookie is re-minted per connection.

## Reference model

The credential model follows [OpenChamber](https://github.com/openchamber/openchamber):

| OpenChamber | `dsh-device-auth` |
|---|---|
| `oc_client_` opaque bearer; server keeps SHA-256 only | `dsh_dev_` token; `tokenHash` in the store |
| One store file, `0700` dir / `0600` file, serialized writes | Same, plus a lock directory for the CLI |
| Same `dedupeKey` re-mint replaces the record (rotation) | Same label re-`add`/`rotate` replaces the hash in place |
| `revokedAt` per device; next request rejected | Same; the plugin's next lookup misses |
| Pairing token without `expiresAt` lives until revoked | Device records have `expiresAt: null` by default |
| Password/passkey/pairing are issuance methods only | `dsh-auth add` is the issuance method |

Not copied: relay transport, passkeys, the password login surface (DSH has no
client that consumes it) and one-time pairing sessions (no consumer in DSH Go).
The reference project's known defects were avoided: tokens are deduplicated on
rotation, the client-side store is not written by the server, and revocation is
effective immediately for new exchanges.

## Verification

`test/unit.test.mjs` (9 tests, no DSH needed):

- hash-only persistence, file/dir modes;
- exact matching, foreign/expired/revoked rejection;
- in-place rotation keeps `id`/`createdAt`, invalidates the old token;
- revoke + purge, `revoke --all`, TTL;
- serialized concurrent writers;
- wrapper substitution, request-URL restoration, unknown-token delegation,
  revocation within one process, unload restoration;
- loud failure when the connection service changes shape, and required
  `storePath`.

`test/acceptance.sh` (isolated `DSH_HOME` + `:3099`, production untouched):

- device token `/connect` → 302 + cookie; v2 cookie passes the `/api` fence;
- browser `/?token=` → 303 + v1 cookie → `GET /` 200 `text/html`;
- real launch token still 302; bogus 401; foreign Host 403;
- rotate → old 401 / new 302; revoke → 401; **restart** → device token still 302;
- store and logs contain no plaintext token; `printUrl:false` leaves no launch
  URL in the log.

Production verification on `0.2.2-rc.1` (Web profile, live process) confirmed
the same checks through `curl`, including rotation and revocation without a
restart, and no `dsh web: http` line after installation.

## Boundaries and upgrade strategy

1. `authorizeConnect` / `authorizeIndex` are class methods but not part of the
   public Service type catalog (`authenticatedUrl` is). Activation feature-
   detects both and throws a descriptive error when absent; it never becomes a
   silent no-op.
2. The bundle patch replaces the `web-runtime` config wholesale (the Loader does
   not deep-merge config), so it restates all four fields of the shipped row. A
   future `dsh-web-app` that adds a *required* config field must be reflected
   here; the probe is `dsh --profile <name> --dump-config`.
3. The real launch token keeps working, so the plugin is additive. Rollback is
   uninstalling the bundle and restarting; no state outside
   `$DSH_HOME/remote-auth.json` is touched.
4. The long-term upstream fix would be a `launchToken` / `launchTokenFile`
   config on `client-connection` (roughly ten lines). If that lands, this
   plugin can be retired in favor of the built-in option.

## Open questions

- Should revocation also evict a device's live cookie (self-minted cookie with a
  device id + `admit` wrapper)? Adds a private cookie format and upgrade risk.
- Would a one-time pairing code help browser onboarding for users who do not
  want a long-lived token in a URL? DSH Go cannot consume it today.
