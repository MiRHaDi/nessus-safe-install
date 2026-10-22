"""Small, conservative primitives. Never delete a Nessus file or edit a feed marker."""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path("/opt/nessus")
STATE = Path("/var/lib/nessus-safe-install")
CLI = ROOT / "sbin/nessuscli"
TERMINAL = {"completed", "canceled", "cancelled", "aborted", "empty", "imported", "stopped"}


class Refused(RuntimeError):
    """Only fixed, secret-free error codes are exposed to callers."""
    def __init__(self, code, *, evidence=None):
        super().__init__(code)
        self.evidence = evidence or {}


def require(condition, code):
    if not condition:
        raise Refused(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(value) + b"\n")
        f.flush()
        os.fsync(f.fileno())
    if os.name == "posix":
        fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def private_directory(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700)
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700,
            "STATE_DIRECTORY_MUST_BE_ROOT_OWNED_0700")
    return path


@contextlib.contextmanager
def locked():
    import fcntl
    private_directory(STATE)
    fd = os.open(STATE / "operator.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("ANOTHER_OPERATION_IS_RUNNING") from None
        yield fd
    finally:
        os.close(fd)


def native(args, *, lock_fd=None, capture=False):
    """Wait for native completion. Signals do not kill a running native update.

    An inherited flock also protects a native child if the parent is killed.
    Native output is suppressed unless explicitly classified in memory.
    """
    options = {"stdin": subprocess.DEVNULL, "stderr": subprocess.PIPE if capture else subprocess.DEVNULL,
               "stdout": subprocess.PIPE if capture else subprocess.DEVNULL,
               "start_new_session": True}
    if lock_fd is not None:
        options["pass_fds"] = (lock_fd,)
    old = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        old[sig] = signal.signal(sig, lambda *_: None)
    try:
        p = subprocess.Popen([str(x) for x in args], **options)
        while True:
            try:
                stdout, stderr = p.communicate(timeout=60)
                break
            except subprocess.TimeoutExpired:
                print('{"phase":"native-operation-still-running","interrupted":false}', file=sys.stderr, flush=True)
        return p.returncode, (stdout or b"") + (stderr or b"")
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def registration_result(code, output):
    text = output.lower()
    bad = any(x in text for x in (b"not registered", b"not able", b"cannot", b"unable", b"could not", b"expired", b"error", b"failed"))
    return {"exitCode": code, "outputBytes": len(output), "outputSha256": hashlib.sha256(output).hexdigest(),
            "eligible": code == 0 and not bad,
            "preferenceValidationError": b"preference" in text and b"validat" in text,
            "newPluginDownloadProven": False}


def verified_file(path, expected):
    path = Path(path).absolute()
    require(len(expected) == 64 and all(c in "0123456789abcdefABCDEF" for c in expected), "INVALID_SHA256")
    require(path.is_file() and not path.is_symlink(), "REGULAR_INPUT_FILE_REQUIRED")
    require(digest(path) == expected.lower(), "INPUT_SHA256_MISMATCH")
    return path


class API:
    def __init__(self, url, ca_file, username, password):
        u = urlsplit(url)
        require(u.scheme == "https" and u.hostname and not u.username and not u.password
                and u.path in ("", "/") and not u.query and not u.fragment, "HTTPS_ORIGIN_REQUIRED")
        self.host, self.port = u.hostname, u.port or 8834
        require(self.port == 8834, "LOCAL_NATIVE_NESSUS_PORT_8834_REQUIRED")
        self.context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self.username, self.password, self.token = username, password, None

    def call(self, path, method="GET", body=None):
        h = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=30)
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Cookie"] = "token=" + self.token
        try:
            # Match API observations to this host's native installation while
            # retaining certificate/hostname checks for the supplied TLS name.
            h.sock = self.context.wrap_socket(socket.create_connection(("127.0.0.1", self.port), timeout=30), server_hostname=self.host)
            h.request(method, path, None if body is None else canonical(body), headers)
            r = h.getresponse()
            raw = r.read(16 * 1024 * 1024 + 1)
            # No redirects: a session token must never follow a different origin.
            require(r.status in (200, 204), "NESSUS_API_HTTP_ERROR")
            require(len(raw) <= 16 * 1024 * 1024, "NESSUS_API_RESPONSE_TOO_LARGE")
            return json.loads(raw) if raw else {}
        finally:
            h.close()

    @contextlib.contextmanager
    def session(self):
        self.token = self.call("/session", "POST", {"username": self.username, "password": self.password})["token"]
        try:
            yield self
        finally:
            try:
                self.call("/session", "DELETE")
            finally:
                self.token = None

    def observe(self, *, allow_feed_failure=False):
        """Read state even during scans; this observation cannot authorize writes."""
        status = self.call("/server/status")
        ready = status.get("status") == "ready"
        details = status.get("detailed_status") or {}
        feed_failure = (status.get("status") == "download-failed"
                        and details.get("login_status") == "allow"
                        and isinstance(details.get("engine_status"), dict)
                        and details["engine_status"].get("status") == "ready"
                        and isinstance(details.get("db_status"), dict)
                        and details["db_status"].get("status") == "ready"
                        and isinstance(details.get("feed_status"), dict)
                        and details["feed_status"].get("status") in ("downloading-failed", "download-failed")) if isinstance(details, dict) else False
        require(ready or (allow_feed_failure and feed_failure), "NESSUS_NOT_READY")
        with self.session():
            users = self.call("/users").get("users") or []
            scans = self.call("/scans").get("scans") or []
            policies = self.call("/policies").get("policies") or []
            families = self.call("/plugins/families").get("families") or []
            props = self.call("/server/properties")
            nonterminal = sum(str(s.get("status", "unknown")).lower() not in TERMINAL for s in scans)
            require(users, "ADMINISTRATOR_USERS_READBACK_REQUIRED")
            def hash_rows(rows):
                return hashlib.sha256(canonical(sorted(rows, key=canonical))).hexdigest()
            result = {"users": len(users), "identities": hash_rows([(u["id"], u["username"], u.get("permissions")) for u in users]),
                    "scans": len(scans), "scanMetadata": hash_rows(scans), "policies": len(policies), "policyMetadata": hash_rows(policies),
                    "families": len(families), "plugins": sum(f.get("count", 0) for f in families if isinstance(f.get("count"), int)),
                    "pluginSet": props.get("plugin_set"), "loadedPluginSet": props.get("loaded_plugin_set"),
                    "activeOrUnknownScans": nonterminal}
            if allow_feed_failure:
                # Boolean evidence only: native messages may contain private data.
                result["readiness"] = {"maintenanceReady": ready, "feedFailureObserved": feed_failure}
            return result

    def snapshot(self):
        observed = self.observe()
        require(observed.pop("activeOrUnknownScans") == 0, "ACTIVE_OR_UNKNOWN_SCAN_STATE")
        return observed

    def wait_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if self.call("/server/status").get("status") == "ready":
                    return
            except (OSError, http.client.HTTPException, Refused, ValueError):
                pass
            require(time.monotonic() < deadline, "READINESS_TIMEOUT_NATIVE_WORK_NOT_TERMINATED")
            time.sleep(5)

    def wait_stable(self, timeout, stable_seconds=60):
        """Account for a native reload that starts just after CLI completion."""
        deadline, since, last = time.monotonic() + timeout, None, None
        while True:
            try:
                candidate = self.snapshot()
                if candidate == last:
                    if time.monotonic() - since >= stable_seconds:
                        return candidate
                else:
                    last, since = candidate, time.monotonic()
            except Refused as e:
                if str(e) not in ("NESSUS_NOT_READY", "NESSUS_API_HTTP_ERROR"):
                    raise
                since, last = None, None
            except (OSError, http.client.HTTPException):
                since, last = None, None
            require(time.monotonic() < deadline, "STABLE_READBACK_TIMEOUT_NATIVE_WORK_NOT_TERMINATED")
            time.sleep(5)


def reuse_guidance(observed, registration):
    """Preserve a loaded local library; never confuse compiled data with a license."""
    loaded = bool(observed["plugins"] > 0 and observed["families"] > 0
                  and observed["pluginSet"] and observed["pluginSet"] == observed["loadedPluginSet"])
    return {"compiledLibraryLoaded": loaded,
            "libraryAction": "keep-existing-compiled-library" if loaded else "review-same-installation-recovery",
            "registrationAction": "native-online-update-eligible" if registration["eligible"] else "valid-registration-required",
            "mutationGate": ("active-or-unknown-scans" if observed["activeOrUnknownScans"] else
                             "native-not-ready" if not observed.get("readiness", {}).get("maintenanceReady", True) else
                             "exclusive-maintenance-required"),
            "compiledFilesRepairRegistration": False, "automaticCacheTransplantSupported": False,
            "newPluginDownloadProven": False}


def validate_delivery(before, after):
    for key in ("users", "identities", "scans", "scanMetadata", "policies", "policyMetadata"):
        require(before[key] == after[key], "OWNER_DATA_READBACK_CHANGED")
    require(after["plugins"] > 0 and after["families"] > 0, "EMPTY_PLUGIN_LIBRARY")
    require(after["plugins"] >= before["plugins"] and after["families"] >= before["families"], "PLUGIN_COUNT_REGRESSION_REQUIRES_REVIEW")
    require(after["pluginSet"] and after["pluginSet"] == after["loadedPluginSet"], "PLUGIN_SET_NOT_FULLY_LOADED")


def service(action, lock_fd):
    rc, _ = native(["/usr/bin/systemctl", action, "nessusd.service"], lock_fd=lock_fd)
    require(rc == 0, "SYSTEMD_OPERATION_FAILED")


def require_idle():
    require(not ROOT.is_symlink() and ROOT.is_dir() and not os.path.ismount(ROOT), "NATIVE_NON_MOUNTED_INSTALLATION_REQUIRED")
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            comm = (p / "comm").read_text().strip()
            if comm in ("nessusd", "nessus-service", "nessuscli"):
                raise Refused("NESSUS_PROCESS_STILL_RUNNING")
        except (FileNotFoundError, ProcessLookupError):
            continue


def data_size(root):
    size = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = Path(base) / name
            if not p.is_symlink():
                size += p.stat().st_size
    return size


class Backup:
    """Full stopped-tree encrypted snapshots, including plugins and identity.

    This is an independent same-host filesystem snapshot, not a vendor
    nessuscli backup (which intentionally omits some data).
    """
    def __init__(self, directory, passphrase):
        self.directory = Path(directory)
        self.passphrase = passphrase
        require(16 <= len(passphrase) <= 1024 and b"\n" not in passphrase and b"\0" not in passphrase, "BACKUP_PASSPHRASE_REQUIRES_16_TO_1024_BYTES")
        self.archive = self.directory / "nessus-tree.tar.gpg"

    def crypt(self, decrypt=False):
        read, write = os.pipe()
        try:
            os.write(write, self.passphrase + b"\n")
        finally:
            os.close(write)
        args = ["gpg", "--batch", "--no-symkey-cache", "--pinentry-mode", "loopback", "--passphrase-fd", str(read),
                "--homedir", str(self.directory / "gnupg")]
        if decrypt:
            args += ["--decrypt", str(self.archive)]
        else:
            args += ["--symmetric", "--cipher-algo", "AES256", "--compress-algo", "none", "--output", str(self.archive)]
        try:
            return subprocess.Popen(args, pass_fds=(read,), stdin=subprocess.DEVNULL if decrypt else subprocess.PIPE,
                                    stdout=subprocess.PIPE if decrypt else subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.close(read)

    def create(self, source, before, identity=None):
        require(not self.directory.exists(), "SNAPSHOT_DIRECTORY_ALREADY_EXISTS")
        self.directory.mkdir(mode=0o700)
        (self.directory / "gnupg").mkdir(mode=0o700)
        require(shutil.disk_usage(self.directory).free > data_size(source) + 2 * 1024**3, "INSUFFICIENT_BACKUP_DISK_SPACE")
        p = self.crypt()
        h = hashlib.sha256()
        class Writer:
            def write(self, data):
                h.update(data)
                return p.stdin.write(data)
            def flush(self):
                p.stdin.flush()
        try:
            with tarfile.open(fileobj=Writer(), mode="w|") as t:
                t.add(source, arcname=".", recursive=True)
        except BaseException:
            p.stdin.close()
            p.wait()
            raise
        finally:
            if not p.stdin.closed:
                p.stdin.close()
        require(p.wait() == 0, "BACKUP_ENCRYPTION_FAILED")
        self.archive.chmod(0o600)
        with self.archive.open("rb") as durable:
            os.fsync(durable.fileno())
        actual = self.plaintext_digest()
        require(actual == h.hexdigest(), "BACKUP_DECRYPTION_READBACK_FAILED")
        metadata = {"format": 1, "createdAt": time.time(), "ciphertextSha256": digest(self.archive),
                    "plaintextSha256": actual, "before": before, "identity": identity}
        write_json(self.directory / "snapshot.json", metadata)
        return metadata

    def plaintext_digest(self):
        p = self.crypt(True)
        h = hashlib.sha256()
        for block in iter(lambda: p.stdout.read(1024 * 1024), b""):
            h.update(block)
        p.stdout.close()
        require(p.wait() == 0, "BACKUP_DECRYPTION_FAILED")
        return h.hexdigest()

    def inspect(self):
        meta = json.loads((self.directory / "snapshot.json").read_bytes())
        require(meta.get("format") == 1 and digest(self.archive) == meta["ciphertextSha256"], "SNAPSHOT_CIPHERTEXT_MISMATCH")
        require(self.plaintext_digest() == meta["plaintextSha256"], "SNAPSHOT_PLAINTEXT_MISMATCH")
        names, links, count, size = [], set(), 0, 0
        p = self.crypt(True)
        try:
            with tarfile.open(fileobj=p.stdout, mode="r|") as t:
                for member in t:
                    validate_member(member)
                    name = posixpath.normpath(member.name)
                    names.append(name)
                    if member.issym() or member.islnk():
                        links.add(name)
                    count += 1
                    size += member.size
            # Consume authenticated trailing plaintext before checking GPG exit.
            while p.stdout.read(1024 * 1024):
                pass
            p.stdout.close()
            require(p.wait() == 0, "SNAPSHOT_AUTHENTICATION_FAILED")
        finally:
            if p.poll() is None:
                p.stdout.close()
                p.terminate()
                p.wait()
        validate_catalog(names, links)
        return meta, count, size

    def extract(self, target):
        require(target.is_dir() and not any(target.iterdir()), "EMPTY_RESTORE_DIRECTORY_REQUIRED")
        self.inspect()
        p = self.crypt(True)
        try:
            with tarfile.open(fileobj=p.stdout, mode="r|") as t:
                for member in t:
                    validate_member(member)
                    # Entire catalog validated before writing. Only same-host,
                    # same-installation snapshots are accepted by the CLI.
                    t.extract(member, target, numeric_owner=True, filter="fully_trusted")
            while p.stdout.read(1024 * 1024):
                pass
            p.stdout.close()
            require(p.wait() == 0, "RESTORE_AUTHENTICATION_FAILED")
        finally:
            if p.poll() is None:
                p.stdout.close()
                p.terminate()
                p.wait()


def validate_member(member):
    path = PurePosixPath(member.name)
    require(not path.is_absolute() and ".." not in path.parts, "UNSAFE_ARCHIVE_PATH")
    require(member.isfile() or member.isdir() or member.issym() or member.islnk(), "UNSUPPORTED_ARCHIVE_MEMBER")
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        require(not link.is_absolute(), "ABSOLUTE_ARCHIVE_LINK")
        resolved = posixpath.normpath(posixpath.join(str(path.parent) if member.issym() else "", str(link)))
        require(resolved != ".." and not resolved.startswith("../"), "ESCAPING_ARCHIVE_LINK")


def validate_catalog(names, links):
    require(len(names) == len(set(names)), "DUPLICATE_ARCHIVE_PATH")
    for name in names:
        require(not any(str(p) in links for p in PurePosixPath(name).parents), "ARCHIVE_SYMLINK_ANCESTOR")


def installation_identity():
    # Private same-host binding; values never printed to stdout.
    return {str(p.relative_to(ROOT)): digest(p) for p in (ROOT / "var/nessus/uuid", ROOT / "var/nessus/master.key", ROOT / "sbin/nessusd")}


def rename_no_replace(source, target):
    fn = ctypes.CDLL(None, use_errno=True).renameat2
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    if fn(-100, os.fsencode(source), -100, os.fsencode(target), 1):
        raise OSError(ctypes.get_errno(), "ATOMIC_RENAME_FAILED")
    for parent in {source.parent, target.parent}:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def promote_restore(incoming, current, preserved):
    def token(p):
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode), "RESTORE_DIRECTORY_TOKEN_REQUIRED")
        return s.st_dev, s.st_ino
    old, new = token(current), token(incoming)
    require(old[0] == new[0] and not preserved.exists() and not preserved.is_symlink(), "RESTORE_SWAP_TARGET_CONFLICT")
    try:
        rename_no_replace(current, preserved)
        rename_no_replace(incoming, current)
    except BaseException:
        # A rename can succeed even when its subsequent fsync/acknowledgement
        # fails. Reconcile exact inodes rather than assuming no effect occurred.
        if current.exists() and token(current) == new and not incoming.exists() and preserved.exists() and token(preserved) == old:
            rename_no_replace(current, incoming)
        if not current.exists() and preserved.exists() and token(preserved) == old:
            rename_no_replace(preserved, current)
        raise
    return {"previousTreePreserved": True, "preservedPath": str(preserved)}


def run_update(api, backup, command, lock_fd, timeout, restart_check=False):
    before = api.snapshot()
    validate_delivery(before, before)
    identity = installation_identity()
    stopped = False
    try:
        stopped = True
        service("stop", lock_fd)
        require_idle()
        backup.create(ROOT, before, identity)
        backup.inspect()
    finally:
        if stopped:
            service("start", lock_fd)
    require(api.wait_stable(timeout) == before, "PREUPDATE_RESTART_BASELINE_CHANGED")
    # Native updates own all markers. No staged cache copying or feed edits.
    rc, _ = native(command, lock_fd=lock_fd)
    require(rc == 0, "NATIVE_UPDATE_FAILED_SNAPSHOT_PRESERVED")
    after = api.wait_stable(timeout)
    validate_delivery(before, after)
    if restart_check:
        service("restart", lock_fd)
        restarted = api.wait_stable(timeout)
        validate_delivery(after, restarted)
        require(restarted == after, "RESTART_PERSISTENCE_MISMATCH")
    return {"before": before, "after": after, "restartVerified": restart_check,
            "pluginSetChanged": before["pluginSet"] != after["pluginSet"], "nativeUpdateExitCode": rc}


def engine_version(lock_fd):
    rc, raw = native([ROOT / "sbin/nessusd", "-v"], lock_fd=lock_fd, capture=True)
    match = re.search(rb"(?:nessusd\s*(?:\(Nessus\))?|Nessus)\s+(?:version\s+)?v?(\d+\.\d+\.\d+)(?![\d.])", raw, re.I)
    # Some Nessus builds use informational status 42 for -v. A valid banner
    # is still mandatory; this is not a service-health or registration check.
    require(rc in (0, 42) and match is not None, "NATIVE_ENGINE_VERSION_UNRECOGNIZED")
    return match.group(1).decode("ascii")
