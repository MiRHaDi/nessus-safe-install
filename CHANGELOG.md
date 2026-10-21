# Changelog

## 0.2.1 — 2026-10-22

- Identify the official-package smoke-test downloader with its actual application User-Agent and binary Accept header. A same-network check changed from HTTP 403 / Cloudflare 1010 with the default Python client to HTTP 200 with a Debian archive response.
- Report bounded HTTP/Cloudflare error codes without exposing response bodies, cookies, client IP addresses or signed URLs. Retain the exact official catalog URL and SHA-256 verification.
- Pass a real official Nessus 10.12.5 Ubuntu package download, checksum, installation, repeat-install refusal and restart/preservation test on a disposable runner. All 46 Linux tests pass on Python 3.12 and 3.13; licensed online upgrades remain a separate unverified gate.

## 0.2.0 — 2026-10-22

- Add read-only `versions` discovery using exact official catalog URLs and published package checksums; do not synthesize download routes.
- Add explicit native all-components `upgrade`, expected engine-version readback and mandatory restart acceptance. Require independent host recovery before an upgrade; retain the cross-binary filesystem-rollback refusal.
- Recheck native registration after online updates/upgrades; recognize a strictly parsed informational version banner with exit42 without treating it as service health.
- Reconcile exact directory identities after a lost acknowledgement following either restore rename, including a first-rename fsync failure.
- Recheck owner work after a potentially long restore extraction, before stopping the service.
- Refuse incomplete installed/loaded plugin baselines before backup/service changes.
- Persist an intent/snapshot reference before updates and report the snapshot reference on a refused update.
- Fsync encrypted snapshots and JSON parent directories.
- Add real HTTPS certificate verification, version/upgrade regression tests and an opt-in official-package fresh-install smoke workflow.

## 0.1.0 — 2026-10-22

Initial public alpha: official Debian-package fresh installation, native plugin updates, verified encrypted full-tree snapshots, explicit recovery, English/Persian documentation and 32 fixture/cryptographic tests.
