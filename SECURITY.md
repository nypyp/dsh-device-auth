# Security policy

## Supported versions

| Version | DSH | Supported |
|---|---|---|
| 0.1.x | `>=0.2.2-rc.1 <0.3.0-0` | ✅ |

## Reporting a vulnerability

Please use GitHub's private [security advisory](https://github.com/nypyp/dsh-device-auth/security/advisories/new)
flow instead of a public issue. Include the DSH version, the plugin version, and
a minimal reproduction. Please do not attach real tokens or store files.

## Design guarantees

- Device tokens are 32 random bytes (`dsh_dev_` + base64url), never derived from
  user input or the launch token.
- The server stores only the SHA-256 hex digest of each token. Tokens are
  compared in constant time over decoded, equal-length hex buffers.
- The store file is `0600` inside a `0700` directory and written atomically
  (temp file + rename). Mutations run under a cross-process lock directory.
- Only `dsh_dev_` tokens that match an active store record are substituted. All
  other requests — including the real launch token, expired and revoked device
  tokens — are delegated to the original implementation.
- The plugin never writes the device store, so a stale in-process snapshot
  cannot resurrect a revoked device. It only appends cookie hashes to the
  derived session index.
- The plugin never logs credentials. The bundle layer disables the startup URL
  line so a usable launch token is not written to the journal.

## Threat model and known limits

- The plugin runs inside the DSH host process, under the same OS user. Anything
  that can read that user's files or environment can already read the store,
  the session logs, or attach to the process; this plugin does not claim
  protection against a compromised local account.
- Revocation is enforced synchronously: the plugin records only a SHA-256 hash
  of each cookie minted during a device exchange and rejects cookies mapped to a
  revoked device on their next request (both `/api` and the browser page).
  Cookies minted with the real launch token, and cookies minted before the
  plugin was installed, carry no device mapping and keep working until expiry.
  The session index is a rejection-only cache: losing it degrades to the
  original authentication, never to a bypass.
- Device tokens are stored in plaintext on the client side (secure storage /
  client configuration), mirroring the base product and comparable tools. The
  server side keeps only hashes.
- The plugin depends on two runtime methods of the `connection` service
  (`authorizeConnect`, `authorizeIndex`). A future DSH version that renames them
  makes activation fail with a clear error; it never silently disables
  authentication. Upgrading DSH should therefore be followed by a quick
  `curl` check of `/connect?token=<device token>` (expect 302).
