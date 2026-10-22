"""Versioned, reviewed community NASL; never write the vendor plugin tree/feed.

Remote repository content is data. Only the locally reviewed adaptations are
eligible for native syntax validation and supplemental activation. A moving
upstream HEAD never becomes executable merely because GitHub serves it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import time
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

from . import core as c

DATA = Path(__file__).parent / "data/community"
REPOSITORIES = {"schubergphilis/custom-nessus-plugins", "richkmeli/NASL-Plugins"}
SHA = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
MAX_FILE = 512 * 1024


def safe_path(value):
    c.require(isinstance(value, str) and bool(value) and "\\" not in value, "COMMUNITY_UNSAFE_PATH")
    path = PurePosixPath(value)
    c.require(not path.is_absolute() and str(path) == value and all(p not in ("", ".", "..") for p in path.parts),
              "COMMUNITY_UNSAFE_PATH")
    c.require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in path.parts), "COMMUNITY_UNSAFE_PATH")
    return path


def read_manifest(root=None):
    root = Path(DATA if root is None else root)
    c.require(root.is_dir() and not root.is_symlink(), "COMMUNITY_BUNDLE_DIRECTORY_REQUIRED")
    raw = (root / "manifest.json").read_bytes()
    c.require(not (root / "manifest.json").is_symlink() and len(raw) <= MAX_FILE, "COMMUNITY_MANIFEST_INVALID")
    value = json.loads(raw)
    c.require(value.get("schemaVersion") == 1 and value.get("mode") == "supplemental-native-nasl-not-vendor-index",
              "COMMUNITY_MANIFEST_SCHEMA_CHANGED")
    c.require(isinstance(value.get("files"), list) and 1 <= len(value["files"]) <= 64, "COMMUNITY_MANIFEST_INVALID")
    paths = set()
    for row in value["files"]:
        rel = safe_path(row["path"])
        c.require(rel.parts[0] in ("plugins", "upstream") or str(rel) == "profile.json", "COMMUNITY_UNSAFE_PATH")
        c.require(row["path"] not in paths and SHA.fullmatch(row["sha256"]) is not None, "COMMUNITY_MANIFEST_INVALID")
        paths.add(row["path"])
        c.require(isinstance(row["bytes"], int) and 0 <= row["bytes"] <= MAX_FILE, "COMMUNITY_FILE_TOO_LARGE")
        p = root.joinpath(*rel.parts)
        c.require(all(not parent.is_symlink() for parent in [p] + list(p.parents)[:len(rel.parts)]), "COMMUNITY_SYMLINK_REFUSED")
        c.require(p.is_file() and p.stat().st_size == row["bytes"] and c.digest(p) == row["sha256"], "COMMUNITY_BUNDLE_HASH_MISMATCH")
    sources = value.get("sources", [])
    c.require(len(sources) == 2 and {s["repository"] for s in sources} == REPOSITORIES, "COMMUNITY_SOURCE_NOT_ALLOWED")
    for source in sources:
        c.require(COMMIT.fullmatch(source["commit"]) is not None and source["license"] in ("MIT", "Apache-2.0"),
                  "COMMUNITY_SOURCE_INVALID")
        c.require(isinstance(source["files"], list) and 1 <= len(source["files"]) <= 16, "COMMUNITY_SOURCE_INVALID")
        for row in source["files"]:
            safe_path(row["path"])
            name = "upstream/" + source["repository"].replace("/", "__") + "/" + row["path"]
            matching = [f for f in value["files"] if f["path"] == name and f["sha256"] == row["sha256"]]
            c.require(len(matching) == 1, "COMMUNITY_SOURCE_HASH_NOT_LOCKED")
    checks = value.get("checks", [])
    c.require(len(checks) == 8 and len({r["pluginId"] for r in checks}) == 8, "COMMUNITY_CHECK_IDS_INVALID")
    for row in checks:
        c.require(isinstance(row["pluginId"], int) and 1337001 <= row["pluginId"] <= 1337008, "COMMUNITY_CHECK_IDS_INVALID")
        c.require("plugins/" + row["file"] in paths and safe_path(row["file"]).suffix == ".nasl", "COMMUNITY_CHECK_FILE_INVALID")
        text = (root / "plugins" / row["file"]).read_text()
        c.require(re.findall(r"script_id\((\d+)\)", text) == [str(row["pluginId"])], "COMMUNITY_CHECK_IDS_INVALID")
    return value, hashlib.sha256(raw).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise c.Refused("COMMUNITY_REDIRECT_REFUSED")


def fetch(url):
    """Only our two public repositories; no credentials, proxies or redirects."""
    allowed = any(url == f"https://api.github.com/repos/{repo}/commits?per_page=1" or
                  re.fullmatch(r"https://raw\.githubusercontent\.com/" + re.escape(repo) + r"/[0-9a-f]{40}/[A-Za-z0-9_./%-]+", url)
                  for repo in REPOSITORIES)
    c.require(allowed, "COMMUNITY_URL_NOT_ALLOWED")
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    try:
        with opener.open(Request(url, headers={"User-Agent": "nessus-safe-install/community", "Accept": "application/vnd.github+json"}), timeout=30) as response:
            raw = response.read(MAX_FILE + 1)
    except URLError:
        raise c.Refused("COMMUNITY_HTTPS_FETCH_FAILED") from None
    c.require(len(raw) <= MAX_FILE, "COMMUNITY_RESPONSE_TOO_LARGE")
    return raw


def check_sources():
    manifest, bundle = read_manifest()
    results = []
    for source in manifest["sources"]:
        data = json.loads(fetch(f"https://api.github.com/repos/{source['repository']}/commits?per_page=1"))
        c.require(isinstance(data, list) and data and isinstance(data[0], dict), "COMMUNITY_UPSTREAM_SCHEMA_CHANGED")
        head = data[0].get("sha")
        c.require(isinstance(head, str) and COMMIT.fullmatch(head) is not None, "COMMUNITY_UPSTREAM_SCHEMA_CHANGED")
        changed = head != source["commit"]
        results.append({"repository": source["repository"], "reviewedCommit": source["commit"], "upstreamCommit": head,
                        "reviewRequired": changed, "automaticExecutionOfUnreviewedCode": False})
    return {"reviewedBundleSha256": bundle, "sources": results, "vendorFeedInspected": False}


def directory():
    return c.private_directory(c.STATE / "community")


def active():
    base = c.STATE / "community"
    path = base / "active.json"
    c.require(not base.is_symlink() and not path.is_symlink(), "COMMUNITY_SYMLINK_REFUSED")
    if not path.exists():
        return None
    c.require(path.stat().st_size <= 8192, "COMMUNITY_POINTER_INVALID")
    value = json.loads(path.read_bytes())
    c.require(isinstance(value, dict) and SHA.fullmatch(value.get("bundleSha256", "")) is not None, "COMMUNITY_POINTER_INVALID")
    return value


def installed(bundle):
    c.require(isinstance(bundle, str) and SHA.fullmatch(bundle) is not None, "COMMUNITY_BUNDLE_SHA256_REQUIRED")
    base = directory()
    versions = c.private_directory(base / "versions")
    target = versions / bundle
    manifest, digest = read_manifest(target)
    c.require(digest == bundle, "COMMUNITY_INSTALLED_MANIFEST_CHANGED")
    # Do not accept a symlink into user-controlled or unrelated data.
    c.private_directory(target)
    return target, manifest


def status():
    pointer = active()
    if pointer is None:
        return {"installed": False, "loadedIntoVendorIndex": False}
    target, manifest = installed(pointer["bundleSha256"])
    return {"installed": True, "bundleSha256": pointer["bundleSha256"], "path": str(target),
            "checks": len(manifest["checks"]), "hashesVerified": True, "loadedIntoVendorIndex": False,
            "onlineRegistrationRepaired": False, "targetsAutomaticallyScanned": False,
            "activation": pointer}


def prepare(*, offline=False):
    """Stage only a complete exact-hash bundle; retain every previous version."""
    manifest, bundle = read_manifest()
    previous = active()
    provenance = {"networkUsed": not offline, "pinnedSourceFilesVerified": 0}
    # Finish all downloads before creating a candidate. No partial activation.
    for source in manifest["sources"]:
        for row in source["files"]:
            path = "upstream/" + source["repository"].replace("/", "__") + "/" + row["path"]
            raw = (DATA / path).read_bytes() if offline else fetch(
                "https://raw.githubusercontent.com/" + source["repository"] + "/" + source["commit"] + "/" + quote(row["path"], safe="/"))
            c.require(hashlib.sha256(raw).hexdigest() == row["sha256"], "COMMUNITY_UPSTREAM_HASH_MISMATCH")
            provenance["pinnedSourceFilesVerified"] += 1
    provenance["upstream"] = {"checked": False, "reason": "offline"} if offline else check_sources()
    base = directory()
    versions = c.private_directory(base / "versions")
    target = versions / bundle
    if target.exists():
        installed(bundle)
    else:
        incoming = c.private_directory(versions / ("candidate-" + uuid.uuid4().hex))
        for row in manifest["files"] + [{"path": "manifest.json"}]:
            rel = safe_path(row["path"])
            dest = incoming.joinpath(*rel.parts)
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = DATA.joinpath(*rel.parts).read_bytes()
            with dest.open("xb") as stream:
                os.chmod(dest, 0o600)
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        _, copied_digest = read_manifest(incoming)
        c.require(copied_digest == bundle, "COMMUNITY_STAGED_BUNDLE_CHANGED")
        c.require(not target.exists(), "COMMUNITY_CONCURRENT_VERSION_EDIT")
        c.rename_no_replace(incoming, target)
        c.require(installed(bundle)[0] == target, "COMMUNITY_STAGED_READBACK_FAILED")
    return {"bundleSha256": bundle, "previous": previous, "provenance": provenance}


def validate_native(bundle, fd):
    target, manifest = installed(bundle)
    nasl = c.ROOT / "bin/nasl"
    c.require(nasl.is_file() and not nasl.is_symlink(), "NATIVE_NASL_REQUIRED")
    for row in manifest["checks"]:
        # -L is the same no-target syntax/load check exercised on the native
        # interpreter. No -X, target, feed reload or daemon restart is used.
        rc, raw = c.native([nasl, "-I", target / "plugins", "-L", target / "plugins" / row["file"]], lock_fd=fd, capture=True)
        c.require(rc == 0 and not any(x in raw.lower() for x in (b"hmac test fail", b"syntax error", b"untrusted")),
                  "COMMUNITY_NATIVE_VALIDATION_FAILED")
    return {"checksParsed": len(manifest["checks"]), "targetExecutionProven": False, "signatureOrFipsBypass": False}


def activate(candidate, validation):
    bundle = candidate["bundleSha256"]
    installed(bundle)
    c.require(active() == candidate["previous"], "COMMUNITY_ACTIVE_VERSION_CHANGED")
    pointer = {"bundleSha256": bundle, "nativeValidation": validation,
               "loadedIntoVendorIndex": False, "at": time.time()}
    base = directory()
    history = base / ("transition-" + uuid.uuid4().hex + ".json")
    c.write_json(history, {"before": candidate["previous"], "after": pointer, "provenance": candidate.get("provenance")})
    temporary = base / (".active-" + uuid.uuid4().hex + ".json")
    c.write_json(temporary, pointer)
    c.require(active() == candidate["previous"], "COMMUNITY_ACTIVE_VERSION_CHANGED")
    os.replace(temporary, base / "active.json")
    if os.name == "posix":
        parent_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    c.require(active() == pointer, "COMMUNITY_POINTER_READBACK_FAILED")
    return {**status(), "delivery": "already-current" if candidate["previous"] and candidate["previous"]["bundleSha256"] == bundle else "reviewed-supplemental-bundle",
            "transitionReceipt": str(history), "provenance": candidate.get("provenance")}


def sync(api, fd, *, offline=False, rollback=None):
    before = api.snapshot()  # Existing idle/unknown/identity gate is retained.
    candidate = ({"bundleSha256": rollback, "previous": active(), "provenance": {"rollback": True}}
                 if rollback else prepare(offline=offline))
    validation = validate_native(candidate["bundleSha256"], fd)
    c.require(api.snapshot() == before, "COMMUNITY_OWNER_OR_SCANNER_STATE_CHANGED")
    return activate(candidate, validation)
