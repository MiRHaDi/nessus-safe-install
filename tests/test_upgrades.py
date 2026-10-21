import copy
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from nessus_safe import core as c, cli, versions
from test_core import healthy


class VersionTests(unittest.TestCase):
    def test_numeric_order_not_string_order(self):
        self.assertGreater(versions.version_tuple("10.12.5"), versions.version_tuple("10.9.9"))

    def test_malformed_version_refused(self):
        for value in ("latest", "12.7", "1.2.3;run", None):
            with self.assertRaises(c.Refused): versions.version_tuple(value)

    def test_official_nested_catalog_uses_vendor_url_and_pinned_digest(self):
        url=versions.CATALOG+"/files/Nessus-latest-ubuntu1604_amd64.deb"
        items = [{"file": "Nessus-10.12.5-ubuntu1604_amd64.deb", "version": "10.12.5", "sha256": "a"*64, "requires_auth": False,"file_url":url}]
        result = versions.parse_catalog({"releases": {"latest": {"Nessus - 10.12.5": items}}})
        self.assertEqual(result["latestVersion"], "10.12.5")
        self.assertEqual(result["packages"][0]["url"],url)
        self.assertEqual(result["packages"][0]["sha256"],"a"*64)

    def test_catalog_cannot_inject_file_path_or_missing_checksum(self):
        for filename, sha in (("../Nessus-10.12.5-ubuntu.deb", "a"*64), ("Nessus-10.12.5-ubuntu.deb", "")):
            with self.assertRaises(c.Refused):
                versions.parse_catalog({"releases": {"latest": {"x": [{"file": filename, "version": "10.12.5", "sha256": sha}]}}})

    def test_native_version_not_api_banner(self):
        for code in (0,42):
            with patch.object(c, "native", return_value=(code, b"nessusd (Nessus) 10.12.5 [build 20057]")):
                self.assertEqual(c.engine_version(5), "10.12.5")
        with patch.object(c, "native", return_value=(0, b"unrecognized banner 10.12.5")):
            with self.assertRaises(c.Refused): c.engine_version(5)


class UpgradeTests(unittest.TestCase):
    def args(self):
        return cli.parser().parse_args(["upgrade", "--url", "https://localhost:8834", "--maintenance-window", "--expected-version", "10.12.5", "--external-recovery-confirmed"])

    def run_upgrade(self, before="10.12.4", after="10.12.5", registration=0, post_registration=0):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); api = Mock(); api.snapshot.return_value = healthy()
            result = {"pluginSetChanged": False, "restartVerified": True}
            with patch.object(c, "ROOT", root), patch.object(c, "STATE", root), patch.object(c.os.path, "ismount", return_value=False), \
                 patch.object(cli, "client", return_value=api), patch.object(cli, "secret", return_value=b"synthetic-backup-passphrase"), \
                 patch.object(c, "engine_version", side_effect=[before, after]), patch.object(c, "native", side_effect=[(registration,b"registered"),(post_registration,b"registered")]), \
                 patch.object(c, "run_update", return_value=result) as updater:
                try: outcome = cli.execute(self.args(), 5)
                except c.Refused as e: outcome = str(e)
                return outcome, updater.call_args, updater.call_count

    def test_upgrade_uses_all_and_forces_restart_acceptance(self):
        result, call, count = self.run_upgrade()
        self.assertEqual(count, 1)
        self.assertEqual(call.args[2][-1], "--all")
        self.assertTrue(call.args[-1])
        self.assertEqual(result["delivery"], "engine-upgraded")

    def test_unchanged_engine_is_not_reported_as_upgraded(self):
        result, _, _ = self.run_upgrade(after="10.12.4")
        self.assertEqual(result, "EXPECTED_ENGINE_VERSION_NOT_DELIVERED")

    def test_no_downgrade_and_no_unregistered_upgrade(self):
        result, _, count = self.run_upgrade(before="10.13.0")
        self.assertEqual(result, "DOWNGRADE_REQUEST_REFUSED"); self.assertEqual(count, 0)
        result, _, count = self.run_upgrade(registration=1)
        self.assertEqual(result, "REGISTRATION_CHECK_FAILED_NO_UPGRADE_STARTED"); self.assertEqual(count, 0)

    def test_same_version_is_noop(self):
        result, _, count = self.run_upgrade(before="10.12.5")
        self.assertEqual(result["delivery"], "already-current"); self.assertEqual(count, 0)

    def test_registration_regression_after_upgrade_is_not_success(self):
        result, _, count = self.run_upgrade(post_registration=1)
        self.assertEqual(result,"POST_UPDATE_REGISTRATION_CHECK_FAILED")
        self.assertEqual(count,1)


class RecoveryRegressionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Linux atomic rename required")
    def test_lost_ack_after_either_rename_restores_both_exact_trees(self):
        for lost_step in (1, 2):
            with self.subTest(step=lost_step), tempfile.TemporaryDirectory() as d:
                b=Path(d); incoming=b/"incoming"; current=b/"current"; preserved=b/"old"
                incoming.mkdir(); current.mkdir(); (incoming/"new").write_text("new"); (current/"owner").write_text("keep")
                real=c.rename_no_replace; calls=[0]
                def rename(src, dst):
                    real(src, dst); calls[0]+=1
                    if calls[0] == lost_step: raise OSError("synthetic-lost-ack")
                with patch.object(c, "rename_no_replace", side_effect=rename), self.assertRaises(OSError):
                    c.promote_restore(incoming, current, preserved)
                self.assertEqual((current/"owner").read_text(), "keep")
                self.assertEqual((incoming/"new").read_text(), "new")
                self.assertFalse(preserved.exists())

    def test_incomplete_baseline_refuses_before_service_stop(self):
        api=Mock(); before=healthy(); before["loadedPluginSet"]="old"; api.snapshot.return_value=before
        with patch.object(c, "service") as service, self.assertRaisesRegex(c.Refused, "NOT_FULLY_LOADED"):
            c.run_update(api, Mock(), ["native"], 5, 60)
        service.assert_not_called()

    def test_new_work_during_restore_preparation_refuses_before_stop(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); live=root/"live"; live.mkdir(); state=root/"state"; state.mkdir(); snap=state/"snapshot-test"; snap.mkdir()
            args=cli.parser().parse_args(["rollback","--url","https://localhost:8834","--maintenance-window","--snapshot",str(snap)])
            api=Mock(); before=healthy(); changed=healthy(); changed["scanMetadata"]="new-work"; api.snapshot.side_effect=[before,changed]
            backup=Mock(); backup.inspect.return_value=({"identity":{},"before":before},1,100)
            with patch.object(c,"ROOT",live),patch.object(c,"STATE",state),patch.object(c.os.path,"ismount",return_value=False), \
                 patch.object(cli,"client",return_value=api),patch.object(cli,"secret",return_value=b"synthetic-passphrase"), \
                 patch.object(c,"private_directory"),patch.object(c,"Backup",return_value=backup),patch.object(c,"installation_identity",return_value={}),patch.object(c,"service") as service:
                with self.assertRaisesRegex(c.Refused,"CURRENT_WORK_CHANGED"):
                    cli.execute(args,5)
            service.assert_not_called()


@unittest.skipUnless(os.name == "posix" and shutil.which("openssl"), "Linux OpenSSL HTTPS fixture required")
class RealTlsTests(unittest.TestCase):
    def test_real_tls_accepts_trusted_cert_and_rejects_unknown_ca(self):
        with tempfile.TemporaryDirectory() as d:
            b=Path(d); cert=b/"cert.pem"; key=b/"key.pem"
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-keyout",str(key),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body=b'{"status":"ready"}'; self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
                def log_message(self,*args): pass
            server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key); server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                api=c.API("https://localhost:8834",cert,"fixture","fixture");api.port=server.server_port
                self.assertEqual(api.call("/server/status"),{"status":"ready"})
                bad=c.API("https://localhost:8834",None,"fixture","fixture");bad.port=server.server_port
                with self.assertRaises(ssl.SSLCertVerificationError):bad.call("/server/status")
            finally:
                server.shutdown();thread.join();server.server_close()
