# Reviewed community NASL sources

The vendor feed and the supplemental community library have separate owners,
versions, counts and acceptance evidence. `update --with-community` coordinates
both paths; it does not merge arbitrary GitHub files into the vendor database.

## Sources included

| Repository | Reviewed commit | Material used | License |
| --- | --- | --- | --- |
| [schubergphilis/custom-nessus-plugins](https://github.com/schubergphilis/custom-nessus-plugins) | `63c53819fa8cbfafaf1418f2d5d70294d2c53b67` | Four header-check adaptations | Apache-2.0 |
| [richkmeli/NASL-Plugins](https://github.com/richkmeli/NASL-Plugins) | `8d966653b042279190fc8920af33cb799fe62dbc` | Bounded TCP-connect adaptation | MIT |

Three companion checks cover CSP, Referrer-Policy and cookie attributes. The
eight local IDs are 1337001–1337008. They belong to this isolated supplemental
profile; they are not reservations in Tenable's global plugin namespace.
Schuberg Philis' repository is archived/read-only as of the review date,
2026-10-22; registering it does not promise future upstream releases.

`nessus_safe/data/community/manifest.json` locks each source file, original
license, adapted check and shared include by SHA-256. Original NASL examples
are retained under `upstream/` as provenance data; they are not executed or
copied into the vendor plugin index.

## Commands

`community check` is read-only, needs no root or Nessus credentials, and checks
the latest GitHub commit against each reviewed pin. A changed upstream commit
returns `reviewRequired: true`. It does not silently edit the lock or download
that changed code for execution. GitHub rate limits, unavailable TLS or malformed
responses produce an explicit failure, never a fabricated current status.

```bash
python3 -m nessus_safe community check
sudo python3 -m nessus_safe update \
  --url https://scanner.example.org:8834 --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window --verify-restart --with-community
sudo python3 -m nessus_safe community status
```

Combined updates first fetch the seven pinned upstream files (five NASL
examples and two licenses), verify their hashes, stage the reviewed local
adaptations, and validate all eight with the installed native interpreter's
no-target load/syntax mode. They then use the existing guarded vendor update,
encrypted snapshot, stable API and owner-data acceptance. Only after vendor
acceptance does an atomic supplemental pointer activate the reviewed bundle.
No target is scanned as part of these commands.

An upstream download/hash/parse failure occurs before the vendor update. A
vendor failure preserves the previous supplemental pointer. If the vendor
update succeeds but supplemental activation fails, the receipt says
`vendorUpdateCompleted: true` and requires review of supplemental state. These
are two coordinated stages, not one transaction capable of undoing a vendor
update automatically. Native failure or lost acknowledgement never causes a
blind full-scanner restore.

For an independent community-only sync:

```bash
sudo python3 -m nessus_safe community sync \
  --url https://scanner.example.org:8834 --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window
```

Add `--offline` to use the exact reviewed originals bundled with the program,
with no network access or claim of fresh upstream delivery. The vendor update
and registration are not invoked. Both sync and rollback require a trusted
local API and the same idle/unknown-work and exclusive-maintenance gates; the
existing product/edition constraints on that API still apply.

## Preservation and rollback

All new files are under `/var/lib/nessus-safe-install/community/`:

- `versions/<manifest-sha256>/`: immutable-by-convention checked file content,
  stored separately from `/opt/nessus` and never pruned by this tool.
- `active.json`: atomic pointer for the supplemental library only.
- `transition-*.json`: retained before/after pointer and provenance evidence.
- Incomplete candidates remain inactive for diagnosis. Existing differing or
  corrupt versions are refused instead of overwritten.

```bash
sudo python3 -m nessus_safe community rollback \
  --bundle-sha256 PREVIOUS_INSTALLED_64_CHARACTER_MANIFEST_SHA256 \
  --url https://scanner.example.org:8834 --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window
```

Rollback revalidates the retained version and native syntax, then selects that
supplemental version. It does not alter vendor feed identity, registration,
scan history, templates, policies or vendor binaries. It is separate from the
full-scanner `rollback` command. Do not restore an old scanner snapshot merely
to undo a supplemental pointer selection. The single operator lock serializes
these commands with vendor maintenance.

## Execution boundary

This release installs a **supplemental native NASL library**, not a Nessus UI
policy/import. It does not advertise UI plugin count growth or a complete
vulnerability database. Native syntax acceptance is not proof that every check
works on every engine or target. The public generic-scope adaptation also needs
its own native fixture acceptance; earlier site-specific evidence is not that
acceptance.

The package intentionally has no automatic target runner. An authorized
external harness must supply these exact KB values and enforce target scope:

| Key | Meaning |
| --- | --- |
| `AEGIS/Community/Enabled` | Explicit `1` opt-in |
| `AEGIS/Host` | Approved HTTP hostname |
| `AEGIS/AuthorizedHost` | The same exact approved hostname; no wildcard grant |
| `AEGIS/ExpectedIP` | The independently approved IP, matched to native `get_host_ip()` |
| `AEGIS/Port` | Only 80 or 443 |
| `AEGIS/TLS` | Whether the selected port uses TLS |
| `AEGIS/Fixture` | Must be `0` for actual targets |

The harness must also validate TLS and hostname independently, select the
correct native target/SNI, preserve scope across DNS changes, and apply an
execution timeout. The reader bounds receive sizes and socket waits, does not
follow redirects or authenticate, and uses a limited GET fallback only for
HEAD 405/501. It reports fixed classifications, not response bodies or cookie
values. A header inventory is not an authenticated application assessment or
exploit finding; absent/disabled legacy X-XSS-Protection is not a vulnerability.

## Updating the reviewed lock

New upstream code is not automatically trusted because its repository is
listed. Review the changed source and licenses, adapt only scoped checks,
retain attribution, update file digests, run native positive/negative and
scope tests on an isolated supported scanner, and publish a reviewed program
revision. `community check` then compares upstream HEAD to those new pins.
No arbitrary repository URL, branch, feed marker or unsigned-plugin bypass is
accepted by the sync command.

## Licenses

Original Python tooling/documentation is MIT. The header adaptations, shared
reader and companion checks carry Apache-2.0 notices; the TCP adaptation and
upstream Port_Checker retain MIT attribution. Complete upstream licenses are
included in `nessus_safe/data/community/upstream/*/LICENSE` and in built wheels.
These are independently licensed community examples, not a redistributed
Tenable feed or a substitute for the vendor's entitlement.
