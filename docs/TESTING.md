# Validation and release status

Version 0.2.2 is a public alpha. The distinction between tested code and a proven licensed vendor deployment is deliberate.

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
