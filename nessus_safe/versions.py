"""Read current vendor metadata; no guessed versions or executable downloads."""
import json
import re
import ssl
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .core import Refused, require

CATALOG = "https://www.tenable.com/downloads/api/v2/pages/nessus"


def version_tuple(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value) is not None, "THREE_PART_VERSION_REQUIRED")
    return tuple(int(n) for n in value.split("."))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise Refused("VENDOR_CATALOG_REDIRECT_REFUSED")


def parse_catalog(data):
    require(isinstance(data, dict) and isinstance(data.get("releases"), dict), "VENDOR_CATALOG_SCHEMA_CHANGED")
    latest = data["releases"].get("latest", {})
    require(isinstance(latest, dict), "VENDOR_CATALOG_SCHEMA_CHANGED")
    candidates = []
    for entries in latest.values():
        if not isinstance(entries, list):
            continue
        for item in entries:
            require(isinstance(item, dict), "VENDOR_CATALOG_SCHEMA_CHANGED")
            name, version, sha = item.get("file", ""), item.get("version", ""), item.get("sha256", "")
            require(all(isinstance(v, str) for v in (name, version, sha)), "VENDOR_CATALOG_SCHEMA_CHANGED")
            match = re.fullmatch(r"Nessus-(\d+\.\d+\.\d+)-(?:ubuntu|debian)[A-Za-z0-9_.-]*\.deb", name)
            if not match or version != match.group(1):
                continue
            require(re.fullmatch(r"[0-9a-fA-F]{64}", sha) is not None, "VENDOR_CATALOG_CHECKSUM_MISSING")
            candidates.append({"version": version, "file": name, "sha256": sha.lower(), "size": item.get("size"),
                               "url": CATALOG + "/files/" + quote(name, safe=""), "requiresAuth": item.get("requires_auth", True)})
    require(candidates, "NO_SUPPORTED_OFFICIAL_DEB_RELEASE_FOUND")
    newest = max(version_tuple(p["version"]) for p in candidates)
    return {"source": CATALOG, "latestVersion": ".".join(map(str, newest)),
            "packages": sorted((p for p in candidates if version_tuple(p["version"]) == newest), key=lambda p: p["file"])}


def fetch_catalog():
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(Request(CATALOG, headers={"User-Agent": "nessus-safe-install/version-check"}), timeout=30) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "VENDOR_CATALOG_TOO_LARGE")
    return parse_catalog(json.loads(raw))
