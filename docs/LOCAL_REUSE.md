# Keep a working compiled library

Plugin payload files, compiled caches and online registration are separate states. A library is currently loaded only when the authenticated API reports positive plugin/family counts and matching, nonempty installed and loaded plugin-set IDs. That observation does not prove scanning accuracy, a valid license, or delivery of a new feed.

## Default decision in code

Run the existing read-only diagnostic on a supported native host:

```bash
sudo python3 -m nessus_safe doctor \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem
```

From version 0.2.2, `localReuse.libraryAction` is `keep-existing-compiled-library` when that library is loaded. The tool reports a failed registration independently rather than recommending another payload download, cache copy or feed-marker rewrite to repair it. `doctor` can now read during scans and reports their nonterminal count; update, backup, upgrade and restore still require the strict idle snapshot and exclusive maintenance. Unknown scan states also block changes. API visibility does not establish that every other user's private schedule is idle.

This decision reports existing state; it does not start a transfer, restart, compilation, update, scan, or registration change. Do not infer actual new delivery from a working local library.

Version 0.2.3 also allows `doctor` to diagnose the specific native `download-failed` state when detailed status allows login and says the engine and database are ready. A failed feed component is required; arbitrary startup failures do not qualify. The diagnostic reports only readiness booleans, not raw native messages. A loaded library can still be retained, but `healthyForOnlineUpdates` stays false and the idle mutation gate is `native-not-ready`. Active/unknown scans take precedence. `API.snapshot()` remains strict and cannot use this exception to authorize maintenance. See [troubleshooting](TROUBLESHOOTING.md) for scan and registration failures.

## When the library is incomplete

The tool reports `review-same-installation-recovery`. The supported routes are an explicitly selected, verified same-installation encrypted snapshot through `rollback`, or an authorized local vendor archive through native `update --archive` (and its signature when required). These routes need maintenance, preserve existing data for recovery, and do not require downloading the same archive again. Review the [recovery limits](RECOVERY.md) before restoring over any work created since the snapshot.

A manually copied cache is not a general recovery format. Compiled artifacts depend on the engine, exact plugin payload, native metadata and installation identity. An installation-specific successful transfer cannot justify always transplanting caches between unrelated installations or engine versions. This project does not implement automatic cache transplantation or copying another installation's registration, users, keys or feed markers.

## Preference validation and registration

Tenable's [migration guide](https://docs.tenable.com/nessus/Content/migrate-nessus-linux-server.htm) documents the “Could not validate this preference file” error after migration and a legitimate license reapplication procedure. Compiled plugin files cannot repair that registration binding. Preserve the loaded library and obtain valid registration for this scanner through the vendor-supported path. A successful offline library load must not be reported as a successful online registration.

The vendor documents [`fetch --register-only`](https://docs.tenable.com/nessus/command-line-reference/Content/RegisterAScannerOnline.htm) for registration without automatically downloading updates. Confirm support for the installed engine and follow its supported registration procedure; this tool does not automatically invoke registration or any reset. Keep activation codes outside Git, logs, reports and chat. A later update still needs its own backup, native completion and real readback.
