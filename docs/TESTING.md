# Validation and release status

Version 0.2.0 is a public alpha. The distinction between tested code and a proven licensed vendor deployment is deliberate.

## Version 0.2.0 review

The expanded suite contains 46 tests. On Windows/Python 3.12, 39 pass and seven Linux-only tests are skipped. The Linux CI matrix exercises all tests, including a real trusted/untrusted HTTPS handshake and lost acknowledgement after either restore rename, alongside actual GPG recovery fixtures. Check the workflow result for the precise revision being deployed.

The opt-in **Official package smoke test** workflow downloads a version-pinned official package, checks the vendor's SHA-256, installs it on a disposable Ubuntu runner, verifies its native version/service, verifies that repeat installation refuses while retaining a synthetic sentinel, and checks that sentinel after restart. It does not activate the product or claim a licensed online upgrade. No vendor binary or scanner data is uploaded as a repository artifact.

The `versions` command has also been exercised against the live official catalog: it reported 10.12.5 and its published Debian/Ubuntu package digests on 2026-10-22 (Tehran).

### Actual official-package smoke result

The disposable-runner test was dispatched against the official Ubuntu 10.12.5 package and published SHA-256. Both the explicit version route and the exact canonical URL returned by the vendor catalog received HTTP 403 from the runner. The installation step therefore **did not execute**; this is not a passed installation or upgrade test. No alternate mirror, license bypass or success-by-skipping was introduced. [Canonical-route run](https://github.com/MiRHaDi/nessus-safe-install/actions/runs/39687775561).

The next trigger for that integration gate is approved access to the official package from the test environment. The installer also accepts a locally supplied verified package; the hosted workflow does not upload or redistribute one. Licensed engine upgrades and online delivery remain unverified until legitimate registration is available in an isolated test environment.

## Version 0.1.0 baseline, executed before its publication

- Python 3.12 on Windows: 32 discovered tests; 27 passed and five Linux-only tests were skipped.
- Python 3.12 on Linux, unprivileged temporary fixture workspace: all 32 passed, including actual GPG encrypt/decrypt/restore, corrupted ciphertext, wrong key, exclusive locking and real Linux no-replace rename recovery.
- No production plugin payload, license, credential or service mutation was needed for those tests.

CI repeats the suite on Ubuntu 24.04 with Python 3.12 and 3.13. The badge links to actual workflow results. Tests never download or register Nessus.

## What the tests establish

The tests cover encrypted snapshot roundtrips, preserved file permissions and internal links, failed rename recovery, path traversal/device/link rejection, refusal of changed package hashes, refusal to overwrite an existing installation, owner-data invariants, zero/decreased plugin counts, installed/loaded set mismatch, active/unknown scans, TLS verification/redirect behavior, deferred-reload stability, and service resumption when snapshot creation fails.

Fake API/native-service tests establish orchestration behavior, not vendor compatibility. The GPG and filesystem tests use real operating-system operations on synthetic fixture trees.

## What remains to be established

- Fresh installation of each supported official package on a clean supported VM.
- Product onboarding using a legitimate entitlement, trusted HTTPS and actual native online registration.
- Delivery of a new vendor plugin set, large-library reload timing and persistence after restart.
- The local archive/signature workflow for each supported product/version.
- Full scanner recovery with a real same-installation snapshot and real scan data.
- Power-loss recovery, behavior under disk exhaustion and interaction with other users' private schedules.
- Actual scanning accuracy, target networking, performance and load.

Do not label these pending checks as completed because unit tests passed. Do not run the licensed deployment checks against an active shared scanner. Use a reserved disposable VM with its own legitimate product registration, and keep all vendor artifacts and credentials outside Git.
