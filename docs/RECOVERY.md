# Recovery without deleting the current tree

## If registration is invalid

Run `doctor` and retain its safe receipt. If native registration reports preference-file validation failure, the tool refuses an online update **before stopping the service or changing plugins**. Working compiled plugins do not establish valid online registration.

Use the supported recovery path for that exact installation and your legitimate entitlement, or contact Tenable. Do not copy another scanner's registration database, forge a feed marker, remove the master key or reset registration speculatively. This project never requests your activation code. See [official registration checks](https://docs.tenable.com/nessus/command-line-reference/Content/ConfirmNessusRegistrationCodes.htm).

## If an update fails

Read the reported error code and the private receipt. A native command failure, an empty library, changed owner data or an API readiness deadline is a failure requiring investigation. A readiness timeout leaves native work intact; do not replay an update while it is still running.

The pre-update snapshot is under `/var/lib/nessus-safe-install/snapshot-.../`. It contains encrypted `nessus-tree.tar.gpg`, a private manifest and an empty-purpose GPG home. Retain your passphrase separately. No automated pruning occurs: monitor free space and apply your own reviewed retention policy.

Native update failures are not automatically rolled back over possible new work. Reserve an exclusive maintenance window, inspect all users' work and use explicit recovery only when appropriate.

## Restore a snapshot from this tool

```bash
sudo python3 -m nessus_safe rollback \
  --snapshot /var/lib/nessus-safe-install/snapshot-YOUR_SNAPSHOT_DIRECTORY \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem \
  --maintenance-window
```

Enter your current administrator login and the **snapshot's original passphrase**. Recovery checks:

1. Private snapshot ownership, ciphertext, actual decryption and complete archive path/link safety.
2. Same master-key/UUID binding and scanner binary, with unchanged account identities. Binding values are not printed.
3. A ready current API without visible active or unknown-state scans; sufficient disk space and a native non-mounted installation root.
4. Full extraction into a new directory before the current installation is stopped.
5. Stopped service and absence of Nessus native processes before the directory swap.
6. Ready restored API and the original snapshot's complete metadata/count readback.

The displaced tree remains at `/opt/nessus-preserved-.../`, as recorded in the receipt. It may include work created after the snapshot; retain it for reconciliation. No merge is attempted. Failed intermediate extraction directories also remain for inspection. Restoring historical data intentionally changes which version the service uses; retaining both versions is not an automatic reconciliation of newer work.

If the current API is unavailable, identities differ or the binary has changed, this tool refuses the restore. Do not bypass the guards by editing a manifest. Preserve both trees and use your same-host disaster-recovery procedure or Tenable support. Binary upgrade/downgrade, a missing installation root, OS migration and recovery after loss of the host are outside this command's scope.

## Vendor backups are different

Tenable documents that its configuration backup does not include scan results. This project's full-tree snapshot is a different same-host mechanism and is not accepted as a `nessuscli backup --restore` input. See [vendor backup](https://docs.tenable.com/nessus/Content/BackUpNessus.htm) and [vendor restore](https://docs.tenable.com/nessus/Content/RestoreNessus.htm).

For independent disaster recovery, export/retain the data required by your own policy and keep recoverable encrypted backups off the host. This tool does not upload data or provide a backup-storage service.
