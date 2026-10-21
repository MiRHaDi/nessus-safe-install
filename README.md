# Nessus Safe Install

[![Tests](https://github.com/MiRHaDi/nessus-safe-install/actions/workflows/ci.yml/badge.svg)](https://github.com/MiRHaDi/nessus-safe-install/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Install official Tenable Nessus packages and perform guarded native plugin updates while retaining recoverable data.**

[فارسی](README.fa.md) · [Engine upgrades](docs/UPGRADES.md) · [Recovery](docs/RECOVERY.md) · [Architecture](docs/ARCHITECTURE.md) · [Testing](docs/TESTING.md) · [Security](SECURITY.md)

An independent, early-stage operations tool for native Debian/Ubuntu hosts. It does not distribute Nessus, plugins, licenses or activation codes. A valid Tenable entitlement and working registration remain necessary for online updates. This project cannot turn an invalid registration into a valid one or guarantee that a vendor feed will be available.

## Why this exists

Startup scripts that overwrite `plugin_feed_info.inc`, reset registration or remove databases can leave a scanner with an empty plugin library. A successful update command also does not establish that the engine finished its deferred reload.

This tool delegates installation and plugin processing to the vendor. It checks the resulting API state, waits for a stable readback, and keeps an encrypted snapshot of the full stopped installation before an update. There is **no cleanup, purge, feed-marker editing, copied activation state, TLS bypass or cache transplant** in its implementation. Vendor operations may replace their own files; the pre-change tree remains recoverable. It does not promise that every future vendor release retains every obsolete plugin.

## Capabilities

| Operation | Behavior |
| --- | --- |
| `install` | Verifies a supplied official `.deb` against an independently trusted SHA-256, checks package name/architecture and refuses an existing installation. Prints a plan unless `--apply` is supplied. |
| `doctor` | Checks the trusted HTTPS API and native registration. Returns an error for a broken registration instead of claiming online updates work. |
| `versions` | Reads the current official Tenable release catalog and published SHA-256 values. Does not require root or install code. |
| `backup` | Stops the service during exclusive maintenance; creates an AES-256 encrypted full-tree snapshot and verifies actual decryption before resuming. |
| `update` | Uses `nessuscli update --plugins-only`, or a supplied licensed local archive. Requires a healthy baseline, verified snapshot, stable post-update API and unchanged owner data. |
| `update --verify-restart` | Additionally restarts the service and verifies that the same plugin library and owner data remain available. |
| `upgrade` | Runs the native all-components updater and verifies an exact expected engine version, owner data and restart. Requires valid registration and independent host recovery. |
| `rollback` | Restores a verified same-installation snapshot. Keeps the displaced current tree in a separate directory; never merges over or deletes it. |

Snapshots and operational receipts are private files under `/var/lib/nessus-safe-install/`. They must never be committed to a repository. Raw native registration output, passwords and session tokens are not included in receipts.

## Requirements and support boundary

- Native Linux with systemd, root access, Python **3.12+**, GnuPG and Debian package tools.
- Initial target platforms: Ubuntu 24.04 and Debian 13 on an architecture supported by the selected official Nessus package. Other distributions, RPM, Windows, macOS, Docker volumes and Kubernetes are outside this release's installer scope.
- An official package downloaded directly from [Tenable Downloads](https://www.tenable.com/downloads/nessus), and its independently verified SHA-256. Matching a user-supplied digest checks integrity; it does not independently prove vendor provenance.
- A supported product registration, administrator credentials, and a certificate matching the HTTPS hostname. Provide your trusted CA file when a private CA is used. Run this tool **on the scanner host**: API connections are pinned to local `127.0.0.1:8834`; the URL hostname supplies TLS identity, not a remote management target. Other ports/proxy-only listeners are outside this release's scope.
- A reserved maintenance window covering **all users and schedules**. Nessus administrator API visibility can be narrower than all users' private work. The flag is an operator declaration of exclusivity, not an automatic system-wide reservation.
- Space for Nessus, a complete encrypted snapshot, local staged archives and a retained displaced tree if restoring. The installer requires 30 GiB free in `/opt`; larger deployments need more. See [Tenable hardware requirements](https://docs.tenable.com/nessus/Content/HardwareRequirements.htm).

The project has automated fixture and cryptographic tests. **The reusable installer has not yet been certified against a licensed end-to-end vendor installation/update matrix.** Use a disposable supported VM first. A fixture test or a registration check is not proof of a real new plugin download. See the exact [validation scope](docs/TESTING.md).

## Quick start

Clone and review the source, or use a reviewed release commit. Do not pipe an unreviewed download into a root shell.

```bash
git clone https://github.com/MiRHaDi/nessus-safe-install.git
cd nessus-safe-install
python3 -m nessus_safe --help
```

### 1. Install a verified official package

Download the correct package and checksum from Tenable using your normal approved process. Substitute the real path and 64-character digest:

```bash
sudo python3 -m nessus_safe install \
  --package /secure-downloads/Nessus-OFFICIAL-PACKAGE.deb \
  --sha256 YOUR_VERIFIED_64_CHARACTER_SHA256
```

Review the plan, then repeat with `--apply` to install and enable `nessusd.service`. The verified package is staged in root-private storage before installation to avoid a source-file replacement race. Already installed scanners are preserved; binary upgrades use the official vendor procedure rather than this fresh-install command.

Complete the [official setup and product registration](https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm) through your secured Nessus interface. This tool does not open a browser, accept activation codes in arguments, set a feed identity, or overwrite registration. Configure appropriate network access and TLS before use; it does not alter firewall rules or deploy a reverse proxy.

### 2. Verify registration and the plugin library

```bash
sudo python3 -m nessus_safe doctor \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem
```

The tool prompts for the administrator username and hides the password. Use a hostname that matches the certificate. There is no `--insecure` option. A self-signed certificate must be provisioned/trusted correctly; bypassing verification is not a repair.

`doctor` exits **3** when online-update eligibility is not healthy, **2** for a refused/failed operation and **0** for successful verification. A failed preference-file validation needs legitimate same-installation registration recovery or Tenable support. The tool does not reset it automatically.

### 3. Update with recoverable data

Reserve an exclusive maintenance window and pause conflicting schedules through your normal operator process:

```bash
sudo python3 -m nessus_safe update \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window \
  --verify-restart
```

You are prompted for a **backup passphrase** as well as the Nessus login. Use a unique password-manager-generated passphrase and retain it securely: losing it makes snapshots unrecoverable. No passphrase is saved by this tool. For managed automation, pass credentials through dedicated already-open file descriptors; see [credential handling](docs/ARCHITECTURE.md#credential-handling).

The tool first checks native registration, then obtains a stopped-tree snapshot. It resumes and verifies the baseline before running the native updater. A stable 60-second API readback accounts for immediate deferred reloads. Plugin counts cannot decrease without a review failure; users, scan metadata and policy metadata must remain unchanged. A legitimate vendor retirement can therefore trigger a conservative review failure.

Expect a large library to take several minutes to initialize. The native update has no forced kill deadline. Readiness waits default to 3600 seconds, configurable using `--wait-seconds`; an expired wait does not kill the engine. With `--verify-restart`, a second stable readback is required after restart. No target scan is launched.

An unchanged plugin-set identifier is reported as `already-current-or-same-set`, not a newly delivered plugin set. Tenable's own automatic update configuration is left intact.

### Licensed offline archive

Use a locally supplied archive obtained for your authorized scanner. Newer vendor workflows may also require a detached signature; supply both files when required:

```bash
sudo python3 -m nessus_safe update \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window --verify-restart \
  --archive /secure-downloads/plugins.tar.gz \
  --sha256 YOUR_VERIFIED_ARCHIVE_SHA256 \
  --signature /secure-downloads/plugins.tar.gz.sig \
  --signature-sha256 YOUR_VERIFIED_SIGNATURE_SHA256
```

The local files are copied into private storage and checked again before use. Only the vendor CLI reads the archive; this project never extracts a vendor plugin bundle or alters its signatures. It cannot make an online scanner an offline-licensed scanner. Check your edition's [offline installation requirements](https://docs.tenable.com/nessus/Content/InstallNessusOffline.htm); in particular, offline registration is not available in Nessus Essentials.

## Engine/software upgrades

`update` handles plugins; `upgrade` handles a native all-components engine/software update. Discover the current vendor release with `python3 -m nessus_safe versions --current-version YOUR_INSTALLED_VERSION`, then follow [engine upgrade and recovery requirements](docs/UPGRADES.md). An update channel may not yet offer the release you request. The tool never silently enables a new channel, installs a guessed version, downgrades a scanner or updates its own source code.

## Failure and recovery

The read-only `doctor` command reports `localReuse`: retain an already loaded compiled library and diagnose online registration independently. It can observe active scans without authorizing a mutation; all maintenance paths retain their strict idle checks. See [local reuse and registration boundaries](docs/LOCAL_REUSE.md). Automatic cache transplantation between installations is not supported.

A failed update does **not** trigger a blind restore over possible new work. The current tree and the verified encrypted snapshot are retained; the command returns a reviewable failure. [Recovery instructions](docs/RECOVERY.md) explain the explicit same-installation restore, preserved-tree location and limits.

This tool does not delete files, prune snapshots, uninstall packages or repair package-manager state by removal. Storage retention is a separate operator decision. It cannot prevent vendor software, another administrator or an external job from deleting data; reserve maintenance and keep independent backups.

## Development

```bash
python3 -m unittest discover -s tests -v
```

No Python runtime dependencies. The Linux suite includes actual GPG encrypt/decrypt/restore, wrong-key/corruption refusal, real TLS certificate checks, lost-acknowledgement rename recovery, deferred reload stability, active-work refusal, engine-upgrade gates and owner-data/plugin-regression checks. GitHub Actions runs Python 3.12 and 3.13. Unit tests use synthetic data and do not download or activate Nessus. The separate opt-in official-package smoke workflow installs a verified vendor package only on a disposable runner; it does not activate the product or prove licensed online updates.

## Vendor references

- [Install on Linux](https://docs.tenable.com/nessus/Content/InstallNessusLinux.htm)
- [Confirm native registration](https://docs.tenable.com/nessus/command-line-reference/Content/ConfirmNessusRegistrationCodes.htm)
- [Native plugin-only updates](https://docs.tenable.com/nessus/command-line-reference/Content/UpdateThePluginsOnly.htm)
- [Native local-archive updates](https://docs.tenable.com/nessus/command-line-reference/Content/UpdateASpecificPluginArchive.htm)
- [Vendor backup scope](https://docs.tenable.com/nessus/Content/BackUpNessus.htm) — the vendor backup does not include scan results; this project's full-tree snapshot is a different, same-host mechanism.

MIT applies only to this project's original code and documentation. Tenable Nessus and its plugins remain subject to Tenable's terms. This project is not affiliated with or endorsed by Tenable.
