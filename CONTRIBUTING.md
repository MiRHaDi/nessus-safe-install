# Contributing

Use Python 3.12 or newer and run `python -m unittest discover -s tests -v`. Linux with GnuPG is required to exercise every test; skipped tests are not full validation.

For changes to privileged operations, include a failure-path test as well as the successful path. Preserve the same-installation boundary, credential custody, existing data and explicit acceptance gates. Make vendor behavior configurable only when it is documented and tested; do not infer it from an exit code alone.

Use synthetic artifacts. Never commit vendor packages, vendor plugin bundles, copied registration state, live operational evidence or secrets. The explicitly reviewed Apache-2.0/MIT community examples are a separate exception with original licenses, pinned provenance and per-file hashes; see [community review requirements](docs/COMMUNITY.md). Keep runtime dependencies small and reference official vendor documentation for supported workflows.

Pull requests should describe the concrete behavior, affected platforms, test results and remaining vendor integration limitations. Tests that mock the vendor must be described as orchestration tests.
