# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-21

Initial release.

### Added

- Host plugin that wraps `connection.authorizeConnect` / `authorizeIndex` so
  durable `dsh_dev_…` device tokens are exchanged for the process launch token
  and the original 302/303 + signed-cookie flow runs unchanged.
- Device credential store (`$DSH_HOME/remote-auth.json`, `0700`/`0600`): SHA-256
  hashes only, constant-time comparison, atomic writes, cross-process lock for
  mutations; the plugin itself never writes the store.
- `dsh-auth` CLI: `add`, `rotate` (in-place rotation for the same label),
  `revoke` (one or all), `list`, `purge`, with `--store`, `--origin`, `--json`.
- Bundle layer that inserts the plugin and turns off `web-runtime.printUrl`, so
  no usable credential is printed into the log at startup.
- Unit tests (`npm test`) and an isolated sandbox acceptance suite
  (`test/acceptance.sh`, T1–T12) that never touches the production instance.

### Verified

- `dsh 0.2.2-rc.1` on Node 24: unit tests 9/9; sandbox acceptance 29/29
  (lead) and an independent re-run 12/12; production live checks for device
  token exchange, rotation, revocation, browser cookie flow, Host fence, and
  launch-token regression.
