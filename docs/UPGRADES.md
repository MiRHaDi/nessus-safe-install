# Engine upgrades and current release discovery

Plugin updates and engine upgrades are separate operations. Version 0.1.0 only exposed native plugin updates. Version 0.2.0 adds release discovery and an explicit guarded native all-components upgrade.

## Discover the current official release

```bash
python3 -m nessus_safe versions --current-version 10.12.4
```

This read-only command requires no root access. It reads the fixed Tenable HTTPS catalog, reports the latest listed Debian/Ubuntu release and its published SHA-256 values, and uses the exact official download URL provided by that catalog. Some vendor URLs contain a `latest` alias: always verify the recorded SHA-256 so an alias changing between lookup and download fails safely. No download URL or release number is invented. The command does not download/install executable code or silently update this tool. The catalog format is vendor-controlled; an unsupported format fails explicitly.

At verification on **2026-10-22 (Asia/Tehran)**, the catalog listed **10.12.5**. We found no Nessus software release **12.7.4** in the official catalog/release notes. Do not substitute a guessed version or confuse a plugin's target-software version with Nessus itself. Run `versions` again for current information instead of treating this dated observation as permanent.

References: [official catalog](https://www.tenable.com/downloads/api/v2/pages/nessus), [2026 release notes](https://docs.tenable.com/release-notes/Content/nessus/2026.htm), [10.12.5 advisory](https://www.tenable.com/security/tns-2026-26).

## Upgrade the Nessus engine

Tenable documents automatic engine/software updates for applicable editions when **Update all components** is enabled, subject to the selected update plan. Changing a plan can also cause a downgrade; this tool does not silently change your plan or automatic-update settings. Edition, standalone/managed status, registration and vendor channel availability determine what the native updater can deliver.

For an operator-initiated upgrade of a standalone scanner on the same host:

```bash
sudo python3 -m nessus_safe upgrade \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window \
  --expected-version 10.12.5 \
  --external-recovery-confirmed
```

Replace the example version with the appropriate supported target from the official catalog and your approved update plan. A version number in this argument is an **acceptance requirement**, not an instruction forcing Tenable to serve that version. The native channel determines delivery. The tool invokes `nessuscli update --all`; it cannot force an unavailable release or bypass registration.

The command requires a healthy library and valid registration, reserves this tool's single-writer lock, records an intent with its snapshot path, obtains a verified encrypted full-tree backup, and verifies the baseline again after resuming. It then uses the native all-components updater, waits for a stable API state, verifies owner data/plugins and always checks a restart. Finally it reads `nessusd -v` and requires the exact expected engine version. An unchanged binary is not reported as a successful engine upgrade. Explicit downgrade requests are refused; a same-version request is reported as a no-op.

## Recovery is different across binary versions

**Create and verify an independent host/VM recovery path before supplying `--external-recovery-confirmed`.** This flag records the operator's declaration; the tool does not create or validate an external VM snapshot. A software upgrade may change package inventory, service units or other files outside `/opt/nessus`. The encrypted tree alone cannot reverse all such changes.

The existing `rollback` command still refuses a changed scanner binary. This guard is deliberate: restoring an older tree over a newer package installation can create an inconsistent system. Use the official supported downgrade/recovery procedure or your independent host snapshot if the engine changed. Both current data and the encrypted pre-change snapshot remain available; no automatic downgrade or deletion is performed.

Engine-upgrade orchestration has regression tests. A successful real licensed online upgrade and subsequent vendor-compatible recovery remain separate integration gates. A fresh official-package smoke test does not establish those gates.

Vendor references: [software and automatic updates](https://docs.tenable.com/nessus/Content/UpdateNessusSoftware.htm), [native all-components update](https://docs.tenable.com/nessus/command-line-reference/Content/ForceThePluginAndCoreComponentsUpdate.htm), [supported downgrade procedure](https://docs.tenable.com/nessus/Content/DowngradeNessusSoftware.htm).
