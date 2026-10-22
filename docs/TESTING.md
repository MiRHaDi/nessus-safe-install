# Validation and release status

Version 0.3.0 is a public alpha. The distinction between tested code and a proven licensed vendor deployment is deliberate.

## Community source integration (0.3.0)

The community tests exercise actual temporary file staging, hash validation,
version retention, pointer failure, idempotent sync and explicit supplemental
rollback. Orchestration tests also prove that failed registration prevents a
combined update, a vendor failure prevents supplemental activation, and a
supplemental activation failure does not hide a completed vendor update.
Upstream commit changes are review-only; tests refuse changed payloads,
traversal, duplicate IDs, redirects, symlinks, active work and state changes.

The Linux CI builds a wheel and verifies every locked resource hash plus all
three license files. The separate official-package smoke workflow now also
opts into `tests/test_native_community.py`: eight native syntax/load checks,
positive/negative fixed-response cases, exact authority/IP refusal and actual
loopback TCP, HEAD and GET fallback. These tests are skipped in ordinary CI
without a native product installation. Opting in requires a disposable Linux
host; absence or failure of its native interpreter is a failure, not a skip.

Native fixture success does not prove a licensed online vendor update or load
the supplemental checks into the Nessus UI. Earlier deployment-specific NASL
results are not acceptance of this generic-scope public revision. Inspect the
workflow result for the exact commit being used.

## Version 0.2.3 validation

On 2026-10-22, the exact candidate source and tests passed **all 59 tests on Linux/Python 3.12.3**, in an unprivileged temporary fixture workspace. GPG encryption/decryption, trusted/untrusted TLS and atomic-rename recovery executed rather than being skipped. The corresponding Windows/Python 3.12 run passed 52 tests and skipped seven Linux-only cases. Both runs used `-W error::ResourceWarning` (or the equivalent `PYTHONWARNINGS` setting).

Seven new tests reproduce the feed-failure diagnostic, prevent raw native messages/owner names from appearing in results, refuse incomplete or malformed readiness details before login, preserve active/unknown scan gates, refuse the same degraded state in maintenance snapshots, retain the healthy snapshot shape, and ensure HTTP503 is still an HTTP failure. The CLI integration case uses the real observation path with a fixture API and proves that even a positive registration check cannot turn a feed outage into healthy online updates or invoke a service mutation.

The installed shared scanner was independently observed with a ready engine/database, failed feed download, matching installed/loaded plugin-set IDs and retained safe narrow-port settings. Existing active processing was left alone. This is observational motivation, not certification of this tool against that container: the installer still supports native systemd deployments only. The observed IP-tracking refusal and real scan acceptance remain unresolved. No production assessment export, internal endpoint, native log, activation code or credential is included in the public test suite.

Reproduce the suite with `python3 -W error::ResourceWarning -m unittest discover -s tests -v`. GitHub Actions repeats it on Python 3.12 and 3.13 for each pushed revision; inspect the exact revision's workflow result separately. See [troubleshooting and acceptance criteria](TROUBLESHOOTING.md).

## Version 0.2.2 review

The suite contains 52 tests. On Windows/Python 3.12, 45 pass and seven Linux-only tests are skipped. New cases cover read-only observations during active/unknown scan states, preserving the strict mutation gate, keeping an already loaded compiled library despite failed registration, refusing to label an incomplete library reusable, and not exporting scan names/targets. These are diagnostic-policy tests; they do not establish a successful registration repair or an automated cache transfer. Check the Linux CI run for the exact deployed revision.

## Version 0.2.0 review

The expanded suite contains 46 tests. On Windows/Python 3.12, 39 pass and seven Linux-only tests are skipped. The Linux CI matrix exercises all tests, including a real trusted/untrusted HTTPS handshake and lost acknowledgement after either restore rename, alongside actual GPG recovery fixtures. Check the workflow result for the precise revision being deployed.

The opt-in **Official package smoke test** workflow downloads a version-pinned official package, checks the vendor's SHA-256, installs it on a disposable Ubuntu runner, verifies its native version/service, verifies that repeat installation refuses while retaining a synthetic sentinel, and checks that sentinel after restart. It does not activate the product or claim a licensed online upgrade. No vendor binary or scanner data is uploaded as a repository artifact.

The `versions` command has also been exercised against the live official catalog: it reported 10.12.5 and its published Debian/Ubuntu package digests on 2026-10-22 (Tehran).

### Actual official-package smoke result

The disposable-runner test was dispatched against the official Ubuntu 10.12.5 package and published SHA-256. Both the explicit version route and the exact canonical URL returned by the vendor catalog received HTTP 403 from the runner. The installation step therefore **did not execute**; this is not a passed installation or upgrade test. No alternate mirror, license bypass or success-by-skipping was introduced. [Canonical-route run](https://github.com/MiRHaDi/nessus-safe-install/actions/runs/39687775561).

### Version 0.2.1 download diagnosis

A bounded check of the same official URL on the same network returned HTTP 403 with `error code: 1010` for the default Python client. Identifying the application honestly in `User-Agent` and requesting `application/octet-stream` returned HTTP 200 with Debian archive magic bytes. This establishes a request-dependent failure; it does not establish a country/IP ban. [Cloudflare documents 1010 as browser-signature blocking](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/). [Tenable documents Nessus downloads as not requiring authentication](https://developer.tenable.com/reference/downloads), consistent with the catalog's `requires_auth: false` for this package.

The smoke workflow now uses those application headers and reports only bounded HTTP/Cloudflare codes on refusal. It does not impersonate a browser, switch proxies or locations, alter TLS verification, or use another download source.

**The corrected official-package test passed** on 2026-10-22 (Tehran), at revision `2e69210183e8010c5e6a653747b9d3d44750935c`: [actual run 39688945737](https://github.com/MiRHaDi/nessus-safe-install/actions/runs/39688945737). It downloaded the complete official Ubuntu amd64 package, verified SHA-256 `37be75d7fac07713a366206f02542c24d234a44b339d786a17945a156c5ae059`, installed Nessus, read native engine version `10.12.5`, checked its systemd service, refused repeat installation with exit 2, and retained the synthetic sentinel through restart. The same revision passed all 46 tests on both Python 3.12 and 3.13: [unit/crypto/TLS CI](https://github.com/MiRHaDi/nessus-safe-install/actions/runs/39688944438).

This clears this one fresh-install integration gate. It does not establish plugin readiness, legitimate activation, a real scan, or an online engine/plugin upgrade. The installer also accepts a locally supplied verified package; the hosted workflow does not upload or redistribute one. Licensed engine upgrades and online delivery remain unverified until legitimate registration is available in an isolated test environment.

## Version 0.1.0 baseline, executed before its publication

- Python 3.12 on Windows: 32 discovered tests; 27 passed and five Linux-only tests were skipped.
- Python 3.12 on Linux, unprivileged temporary fixture workspace: all 32 passed, including actual GPG encrypt/decrypt/restore, corrupted ciphertext, wrong key, exclusive locking and real Linux no-replace rename recovery.
- No production plugin payload, license, credential or service mutation was needed for those tests.

CI repeats the suite on Ubuntu 24.04 with Python 3.12 and 3.13. The badge links to actual workflow results. Tests never download or register Nessus.

## What the tests establish

The tests cover encrypted snapshot roundtrips, preserved file permissions and internal links, failed rename recovery, path traversal/device/link rejection, refusal of changed package hashes, refusal to overwrite an existing installation, owner-data invariants, zero/decreased plugin counts, installed/loaded set mismatch, active/unknown scans, TLS verification/redirect behavior, deferred-reload stability, and service resumption when snapshot creation fails.

Fake API/native-service tests establish orchestration behavior, not vendor compatibility. The GPG and filesystem tests use real operating-system operations on synthetic fixture trees.

## What remains to be established

- Fresh installation of other official packages/platforms; the Ubuntu 24.04 / Ubuntu amd64 10.12.5 case above has passed.
- Product onboarding using a legitimate entitlement, trusted HTTPS and actual native online registration.
- Delivery of a new vendor plugin set, large-library reload timing and persistence after restart.
- The local archive/signature workflow for each supported product/version.
- Full scanner recovery with a real same-installation snapshot and real scan data.
- Power-loss recovery, behavior under disk exhaustion and interaction with other users' private schedules.
- Actual scanning accuracy, target networking, performance and load.

Do not label these pending checks as completed because unit tests passed. Do not run the licensed deployment checks against an active shared scanner. Use a reserved disposable VM with its own legitimate product registration, and keep all vendor artifacts and credentials outside Git.
