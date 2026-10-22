"""Opt-in disposable-host native tests, never an active shared scanner job."""
import json
import http.server
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import threading
import unittest
import uuid

from nessus_safe import community as q, core as c


@unittest.skipUnless(os.name == "posix" and os.environ.get("NESSUS_NATIVE_COMMUNITY_TESTS") == "1",
                     "Opt-in disposable Linux host with official native NASL required")
class NativeCommunityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nessus-safe-native-fixture-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.manifest, _ = q.read_manifest()
        cls.checks = {row["kind"]: row for row in cls.manifest["checks"]}
        cls.nasl = c.ROOT / "bin/nasl"
        if not cls.nasl.is_file():
            raise RuntimeError("Official native interpreter missing; do not skip an opted-in test")

    def run_check(self, kind, response=None, **overrides):
        keys = {"Community/Enabled": 1, "Host": "fixture.invalid", "Fixture": 1,
                "Port": 18081, "TLS": 1, "ExpectedIP": "127.0.0.1", **overrides}
        source = ""
        for key, value in keys.items():
            source += 'set_kb_item(name:' + json.dumps("AEGIS/" + key) + ',value:' + json.dumps(value) + ');\n'
        if response is not None:
            source += 'set_kb_item(name:"AEGIS/FixtureResponse",value:raw_string(' + ','.join(str(n) for n in response.encode()) + '));\n'
        source += 'include(' + json.dumps(str(q.DATA / "plugins" / self.checks[kind]["file"])) + ');\n'
        wrapper = self.work / (uuid.uuid4().hex + ".nasl")
        wrapper.write_text(source)
        result = subprocess.run([str(self.nasl), "-I", str(q.DATA / "plugins"), "-s", "-t", "127.0.0.1", str(wrapper)],
                                capture_output=True, timeout=20)
        raw = result.stdout + result.stderr
        self.assertNotIn(b"HMAC test FAIL", raw)
        self.assertNotIn(b"syntax error", raw.lower())
        lines = [line.split("\t") for line in raw.decode(errors="replace").splitlines() if line.startswith("AEGIS_RESULT\t")]
        return result.returncode, lines, raw

    def test_eight_native_no_target_syntax_checks(self):
        for check in self.manifest["checks"]:
            with self.subTest(plugin=check["pluginId"]):
                result = subprocess.run([str(self.nasl), "-I", str(q.DATA / "plugins"), "-L", str(q.DATA / "plugins" / check["file"])],
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0)
                self.assertNotIn(b"HMAC test FAIL", result.stdout + result.stderr)

    def test_positive_negative_header_and_error_classifications(self):
        good = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nsTrIcT-tRaNsPoRt-SeCuRiTy: max-age=31536000\r\n"
                "X-Content-Type-Options: NoSniff\r\nX-Frame-Options: SameOrigin\r\nX-XSS-Protection: 0\r\n"
                "Content-Security-Policy: default-src 'self'\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n"
                "Set-Cookie: synthetic=fixture; Secure; HttpOnly; SameSite=Lax\r\n\r\n")
        missing = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        cases = [(kind, good, expected) for kind, expected in [
            ("hsts", "present_positive_max_age"), ("nosniff", "present"), ("framing", "present_xfo"),
            ("legacy_xss", "legacy_filter_disabled_or_absent"), ("csp", "present_policy_review"),
            ("referrer", "present"), ("cookies", "attributes_observed")]]
        cases += [(kind, missing, expected) for kind, expected in [
            ("hsts", "missing"), ("nosniff", "missing"), ("framing", "missing"),
            ("legacy_xss", "legacy_filter_disabled_or_absent"), ("csp", "missing"),
            ("referrer", "missing_optional"), ("cookies", "no_cookies_observed")]]
        cases += [
            ("hsts", good.replace("max-age=31536000", "max-age=0"), "invalid_or_disabled"),
            ("hsts", good.replace("X-Content-Type", "Strict-Transport-Security: max-age=10\r\nX-Content-Type"), "ambiguous_duplicate"),
            ("nosniff", missing + "X-Content-Type-Options: nosniff\r\n", "missing"),
            ("framing", good.replace("text/html", "application/json"), "not_applicable_non_html_or_unknown"),
            ("framing", good.replace("SameOrigin", "invalid").replace("default-src 'self'", "frame-ancestors 'none'"), "present_csp_frame_ancestors"),
            ("cookies", good.replace("; HttpOnly", ""), "cookie_attributes_review"),
            ("csp", good.replace("default-src 'self'", "script-src 'unsafe-inline'"), "present_unsafe_keyword_review"),
            ("nosniff", good.split("\r\n\r\n")[0], "incomplete_response"),
            ("nosniff", missing.replace("200 OK", "502 Bad Gateway"), "upstream_error"),
        ]
        for kind, response, expected in cases:
            with self.subTest(kind=kind, expected=expected):
                code, lines, _ = self.run_check(kind, response)
                self.assertEqual(code, 0)
                self.assertEqual(len(lines), 1)
                self.assertEqual(lines[0][2], expected)

    def test_exact_authority_and_ip_guards_before_any_target_io(self):
        for values in [
            {"Fixture": 0, "Host": "app.example.org", "AuthorizedHost": "different.example.org", "Port": 443},
            {"Fixture": 0, "Host": "app.example.org", "Port": 443},
            {"Fixture": 0, "Host": "app.example.org", "AuthorizedHost": "app.example.org.evil.invalid", "Port": 443},
            {"Fixture": 0, "Host": "app.example.org", "AuthorizedHost": "app.example.org", "Port": 22},
            {"ExpectedIP": "192.0.2.99"},
        ]:
            with self.subTest(values=values):
                code, lines, raw = self.run_check("nosniff", **values)
                self.assertEqual(code, 1)
                self.assertFalse(lines)
                self.assertIn(b"AEGIS_SCOPE_REFUSED", raw)
        code, lines, _ = self.run_check("nosniff", **{"Community/Enabled": 0})
        self.assertEqual(code, 0)
        self.assertFalse(lines)

    def test_real_loopback_tcp_head_and_bounded_get_fallback(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            reject_head = False
            def do_HEAD(self):
                self.send_response(405 if self.reject_head else 200)
                self.send_header("Content-Length", "0")
                if not self.reject_head:
                    self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Connection", "close")
                self.end_headers()
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Connection", "close")
                self.end_headers()
            def log_message(self, *_):
                pass
        with http.server.HTTPServer(("127.0.0.1", 18081), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                code, lines, _ = self.run_check("tcp", TLS=0)
                self.assertEqual((code, lines[0][2]), (0, "tcp_open"))
                for reject_head, method in [(False, "HEAD"), (True, "GET")]:
                    Handler.reject_head = reject_head
                    code, lines, _ = self.run_check("nosniff", TLS=0)
                    self.assertEqual((code, lines[0][2], lines[0][4]), (0, "present", method))
            finally:
                server.shutdown(); worker.join(timeout=5)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 18082))
            code, lines, _ = self.run_check("tcp", Port=18082, TLS=0)
            self.assertEqual((code, lines[0][2]), (0, "unreachable"))


if __name__ == "__main__":
    unittest.main()
