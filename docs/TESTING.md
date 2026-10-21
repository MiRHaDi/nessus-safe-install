# Validation and release status

Version 0.1.0 is an initial public alpha. The distinction between tested code and a proven licensed vendor deployment is deliberate.

## Executed before publication

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
