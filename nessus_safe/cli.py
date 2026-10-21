"""Native Linux operator CLI. Credentials stay in active process memory."""
import argparse
import getpass
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from . import __version__
from . import core as c
from . import versions


def secret(fd, prompt):
    if fd is None:
        return getpass.getpass(prompt).encode()
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 8193 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        c.require(total <= 8192, "SECRET_INPUT_TOO_LARGE")
    raw = b"".join(chunks)
    c.require(len(raw) <= 8192, "SECRET_INPUT_TOO_LARGE")
    return raw.rstrip(b"\r\n")


def client(args):
    if args.auth_fd is not None:
        value = json.loads(secret(args.auth_fd, ""))
        username, password = value["username"], value["password"]
    else:
        username = input("Nessus administrator username: ")
        password = getpass.getpass("Nessus administrator password: ")
    return c.API(args.url, args.ca_file, username, password)


def platform_check():
    c.require(sys.version_info >= (3, 12), "PYTHON_3_12_OR_NEWER_REQUIRED")
    c.require(sys.platform == "linux" and os.geteuid() == 0, "LINUX_ROOT_REQUIRED")
    c.require(Path("/run/systemd/system").is_dir(), "NATIVE_SYSTEMD_HOST_REQUIRED")
    c.require(shutil.which("gpg") is not None, "GPG_REQUIRED")
    os.umask(0o077)


def fresh_install(args, fd):
    package = c.verified_file(args.package, args.sha256)
    c.require(not c.ROOT.exists() and not c.ROOT.is_symlink(), "EXISTING_INSTALLATION_PRESERVED_USE_VENDOR_UPGRADE")
    for p in Path("/proc").iterdir():
        if p.name.isdigit():
            try:
                c.require((p / "comm").read_text().strip() not in ("nessusd", "nessus-service", "nessuscli"), "ANOTHER_NESSUS_PROCESS_PRESENT")
            except FileNotFoundError:
                pass
    system = platform.freedesktop_os_release()
    c.require(system.get("ID") in ("ubuntu", "debian"), "DEBIAN_OR_UBUNTU_REQUIRED")
    metadata = subprocess.run(["/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\n${Architecture}\n", str(package)], capture_output=True, check=False)
    c.require(metadata.returncode == 0, "INVALID_DEBIAN_PACKAGE")
    fields = metadata.stdout.decode().splitlines()
    arch = subprocess.run(["/usr/bin/dpkg", "--print-architecture"], capture_output=True, check=True).stdout.decode().strip()
    c.require(len(fields) == 2 and fields[0].lower() == "nessus" and fields[1] == arch, "NESSUS_PACKAGE_OR_ARCHITECTURE_MISMATCH")
    installed = subprocess.run(["/usr/bin/dpkg-query", "--show", "--showformat=${Status}", "nessus"], capture_output=True)
    c.require(installed.returncode != 0 or b"install ok installed" not in installed.stdout, "INSTALLED_PACKAGE_PRESERVED")
    c.require(shutil.disk_usage("/opt").free >= 30 * 1024**3, "MINIMUM_30_GIB_FREE_IN_OPT_REQUIRED")
    if not args.apply:
        return {"planOnly": True, "packageSha256": args.sha256.lower(), "next": "Repeat with --apply to install the verified official package."}
    # Copy a verified package into root-private storage to close user-writable
    # source races before invoking a privileged package manager.
    staged = c.STATE / ("package-" + uuid.uuid4().hex + ".deb")
    with staged.open("xb") as dst, package.open("rb") as src:
        shutil.copyfileobj(src, dst)
        dst.flush()
        os.fsync(dst.fileno())
    c.require(c.digest(staged) == args.sha256.lower(), "STAGED_PACKAGE_CHANGED")
    rc, _ = c.native(["/usr/bin/dpkg", "--install", staged], lock_fd=fd)
    c.require(rc == 0, "PACKAGE_INSTALL_FAILED_PARTIAL_STATE_PRESERVED")
    c.service("enable", fd)
    c.service("start", fd)
    return {"packageInstalled": True, "registrationAndPluginReadinessVerified": False,
            "next": "Complete legitimate product setup at https://YOUR-CERTIFICATE-HOST:8834, then run doctor."}


def parser():
    p = argparse.ArgumentParser(description="Preserve Nessus data while using official installation and native updates.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install", help="Fresh official .deb installation; plan by default")
    install.add_argument("--package", required=True, type=Path)
    install.add_argument("--sha256", required=True)
    install.add_argument("--apply", action="store_true")
    release = sub.add_parser("versions", help="Read official latest-release metadata; no root or installation changes")
    release.add_argument("--current-version")
    for name in ("doctor", "backup", "update", "upgrade", "rollback"):
        s = sub.add_parser(name)
        s.add_argument("--url", required=True, help="HTTPS origin with a trusted matching server certificate")
        s.add_argument("--ca-file", type=Path)
        s.add_argument("--auth-fd", type=int, help="FD containing JSON username/password; otherwise hidden password prompt")
        s.add_argument("--wait-seconds", type=int, default=3600)
        if name != "doctor":
            s.add_argument("--maintenance-window", action="store_true", required=True,
                           help="Operator has reserved exclusive maintenance, including other users' scans")
            s.add_argument("--passphrase-fd", type=int)
        if name == "update":
            s.add_argument("--archive", type=Path, help="Licensed local plugin archive; otherwise native online update")
            s.add_argument("--sha256")
            s.add_argument("--signature", type=Path)
            s.add_argument("--signature-sha256")
            s.add_argument("--verify-restart", action="store_true")
        if name == "rollback":
            s.add_argument("--snapshot", required=True, type=Path)
        if name == "upgrade":
            s.add_argument("--expected-version", required=True, help="Exact expected native engine version")
            s.add_argument("--external-recovery-confirmed", action="store_true", required=True,
                           help="Independent host/VM recovery exists for changes outside /opt/nessus")
    return p


def execute(args, fd):
    if args.command == "install":
        return fresh_install(args, fd)
    c.require(60 <= args.wait_seconds <= 86400, "WAIT_SECONDS_REQUIRES_60_TO_86400")
    api = client(args)
    if args.command == "doctor":
        code, raw = c.native([c.CLI, "fetch", "--check"], lock_fd=fd, capture=True)
        result = {"api": api.snapshot(), "nativeRegistration": c.registration_result(code, raw), "engineVersion": c.engine_version(fd)}
        observed = result["api"]
        result["healthyForOnlineUpdates"] = bool(result["nativeRegistration"]["eligible"] and observed["plugins"] > 0
            and observed["families"] > 0 and observed["pluginSet"] and observed["pluginSet"] == observed["loadedPluginSet"])
        return result
    c.require(c.ROOT.is_dir() and not c.ROOT.is_symlink() and not os.path.ismount(c.ROOT), "NATIVE_NON_MOUNTED_INSTALLATION_REQUIRED")
    passphrase = secret(args.passphrase_fd, "Backup passphrase (at least 16 bytes; retain securely): ")
    if args.command == "rollback":
        # Refuse arbitrary archives or a backup from another scanner/version.
        directory = args.snapshot.absolute()
        c.require(directory.parent == c.STATE and not directory.is_symlink(), "OWN_SNAPSHOT_DIRECTORY_REQUIRED")
        c.private_directory(directory)
        backup = c.Backup(directory, passphrase)
        meta, _, total = backup.inspect()
        c.require(meta["identity"] == c.installation_identity(), "SAME_INSTALLATION_AND_BINARY_REQUIRED")
        current = api.snapshot()  # Active/unknown scans refuse before native stop.
        c.require(current["identities"] == meta["before"]["identities"], "OWNER_IDENTITY_CHANGED_REVIEW_REQUIRED")
        c.require(shutil.disk_usage(c.ROOT.parent).free > total + 2 * 1024**3, "INSUFFICIENT_RESTORE_SPACE")
        incoming = Path(tempfile.mkdtemp(prefix=".nessus-safe-restore-", dir=c.ROOT.parent))
        backup.extract(incoming)
        c.require(api.snapshot() == current, "CURRENT_WORK_CHANGED_DURING_RESTORE_PREPARATION")
        preserved = c.ROOT.parent / ("nessus-preserved-" + uuid.uuid4().hex)
        stopped = False
        try:
            stopped = True
            c.service("stop", fd)
            c.require_idle()
            result = c.promote_restore(incoming, c.ROOT, preserved)
        finally:
            if stopped:
                c.service("start", fd)
        api.wait_ready(args.wait_seconds)
        restored = api.snapshot()
        c.require(restored == meta["before"], "RESTORE_READBACK_REQUIRES_REVIEW_CURRENT_TREE_RETAINED")
        return {**result, "restored": restored}
    directory = c.STATE / ("snapshot-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8])
    backup = c.Backup(directory, passphrase)
    if args.command == "backup":
        before = api.snapshot()
        identity = c.installation_identity()
        stopped = False
        try:
            stopped = True
            c.service("stop", fd)
            c.require_idle()
            backup.create(c.ROOT, before, identity)
            backup.inspect()
        finally:
            if stopped:
                c.service("start", fd)
        api.wait_ready(args.wait_seconds)
        c.require(api.snapshot() == before, "POST_BACKUP_READBACK_CHANGED")
        return {"encryptedSnapshot": str(directory), "decryptionReadbackVerified": True, "api": before}
    command = [c.CLI, "update", "--plugins-only"]
    version_before = None
    if args.command == "upgrade":
        target = versions.version_tuple(args.expected_version)
        version_before = c.engine_version(fd)
        c.require(target >= versions.version_tuple(version_before), "DOWNGRADE_REQUEST_REFUSED")
        code, raw = c.native([c.CLI, "fetch", "--check"], lock_fd=fd, capture=True)
        c.require(c.registration_result(code, raw)["eligible"], "REGISTRATION_CHECK_FAILED_NO_UPGRADE_STARTED")
        if target == versions.version_tuple(version_before):
            baseline = api.snapshot(); c.validate_delivery(baseline, baseline)
            return {"engineVersion": version_before, "delivery": "already-current", "nativeUpgradeStarted": False}
        command = [c.CLI, "update", "--all"]
    elif args.archive:
        c.require(args.sha256, "ARCHIVE_SHA256_REQUIRED")
        c.require(bool(args.signature) == bool(args.signature_sha256), "SIGNATURE_AND_DIGEST_MUST_BE_SUPPLIED_TOGETHER")
        archive = c.verified_file(args.archive, args.sha256)
        stage = c.STATE / ("archive-" + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        target = stage / "plugins.tar.gz"
        with target.open("xb") as dst, archive.open("rb") as src:
            shutil.copyfileobj(src, dst)
        c.verified_file(target, args.sha256)
        # The vendor validates the archive/signature. We never unpack it ourselves.
        command = [c.CLI, "update", target]
        if args.signature:
            c.require(args.signature_sha256, "SIGNATURE_SHA256_REQUIRED")
            signature = c.verified_file(args.signature, args.signature_sha256)
            signed = stage / "plugins.tar.gz.sig"
            with signed.open("xb") as dst, signature.open("rb") as src:
                shutil.copyfileobj(src, dst)
            command.append(c.verified_file(signed, args.signature_sha256))
    else:
        c.require(not args.signature and not args.sha256 and not args.signature_sha256, "ARCHIVE_ARGUMENTS_REQUIRE_ARCHIVE")
        code, raw = c.native([c.CLI, "fetch", "--check"], lock_fd=fd, capture=True)
        c.require(c.registration_result(code, raw)["eligible"], "REGISTRATION_CHECK_FAILED_NO_UPDATE_STARTED")
    c.write_json(c.STATE / ("intent-" + uuid.uuid4().hex + ".json"), {"at": time.time(), "command": args.command,
        "encryptedSnapshot": str(directory), "expectedEngineVersion": getattr(args, "expected_version", None),
        "engineVersionBefore": version_before,
        "externalRecoveryConfirmed": getattr(args, "external_recovery_confirmed", False)})
    try:
        result = c.run_update(api, backup, command, fd, args.wait_seconds, args.command == "upgrade" or args.verify_restart)
        if args.command == "upgrade":
            version_after = c.engine_version(fd)
            c.require(version_after == args.expected_version, "EXPECTED_ENGINE_VERSION_NOT_DELIVERED")
            result.update(engineVersionBefore=version_before, engineVersionAfter=version_after,
                          engineUpgradeVerified=True, filesystemRollbackAcrossBinaryVersionsSupported=False)
    except c.Refused as error:
        error.evidence.update(encryptedSnapshot=str(directory), command=args.command,
                              externalRecoveryRequiredIfBinaryChanged=args.command == "upgrade")
        raise
    delivery = "engine-upgraded" if args.command == "upgrade" else "new-plugin-set" if result["pluginSetChanged"] else "already-current-or-same-set"
    return {**result, "encryptedSnapshot": str(directory), "delivery": delivery}


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "versions":
        try:
            result = versions.fetch_catalog()
            if args.current_version:
                result["upgradeAvailable"] = versions.version_tuple(result["latestVersion"]) > versions.version_tuple(args.current_version)
            print(json.dumps(result, indent=2)); return 0
        except (c.Refused, OSError, ValueError, KeyError) as e:
            print(json.dumps({"error": str(e) if isinstance(e, c.Refused) else type(e).__name__})); return 2
    result, code, receipt = {}, 0, None
    try:
        platform_check()
        with c.locked() as fd:
            receipt = c.STATE / ("receipt-" + uuid.uuid4().hex + ".json")
            try:
                result = execute(args, fd)
                if args.command == "doctor" and not result["healthyForOnlineUpdates"]:
                    code = 3
            except (c.Refused, OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as e:
                result = {"error": str(e) if isinstance(e, c.Refused) else type(e).__name__,
                          "recovery": "Retain current state and snapshots. Inspect the cause before retrying; rollback is explicit."}
                if isinstance(e, c.Refused):
                    result.update(e.evidence)
                code = 2
            c.write_json(receipt, {"at": time.time(), "command": args.command, "exitCode": code, "result": result})
    except (c.Refused, OSError) as e:
        result = {"error": str(e) if isinstance(e, c.Refused) else type(e).__name__}
        code = 2
    print(json.dumps({"exitCode": code, "result": result, "privateReceipt": str(receipt) if receipt else None}, indent=2))
    return code
