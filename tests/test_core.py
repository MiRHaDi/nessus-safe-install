import copy
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from nessus_safe import core as c
from nessus_safe import cli


def healthy():
    return {"users": 2, "identities": "identity-hash", "scans": 0, "scanMetadata": "scans-hash",
            "policies": 0, "policyMetadata": "policy-hash", "families": 65, "plugins": 1000,
            "pluginSet": "202610200000", "loadedPluginSet": "202610200000"}


class DeliveryTests(unittest.TestCase):
    def test_zero_plugins_rejected(self):
        after = healthy(); after["plugins"] = 0
        with self.assertRaisesRegex(c.Refused, "EMPTY_PLUGIN"):
            c.validate_delivery(healthy(), after)

    def test_nonzero_regression_rejected(self):
        after = healthy(); after["plugins"] = 999
        with self.assertRaisesRegex(c.Refused, "COUNT_REGRESSION"):
            c.validate_delivery(healthy(), after)

    def test_identity_or_policy_changes_rejected(self):
        for key in ("identities", "scanMetadata", "policyMetadata"):
            after = healthy(); after[key] = "changed"
            with self.assertRaisesRegex(c.Refused, "OWNER_DATA"):
                c.validate_delivery(healthy(), after)

    def test_pending_plugin_set_rejected(self):
        after = healthy(); after["loadedPluginSet"] = "old"
        with self.assertRaisesRegex(c.Refused, "NOT_FULLY_LOADED"):
            c.validate_delivery(healthy(), after)

    def test_healthy_growth_accepted(self):
        after = healthy(); after["plugins"] += 5
        c.validate_delivery(healthy(), after)

    def test_same_set_is_not_new_delivery(self):
        c.validate_delivery(healthy(), healthy())
        self.assertEqual(healthy()["pluginSet"], healthy()["loadedPluginSet"])


class RegistrationTests(unittest.TestCase):
    def test_singular_preference_validation_error(self):
        r = c.registration_result(1, b"Could not validate preference file")
        self.assertTrue(r["preferenceValidationError"])
        self.assertFalse(r["eligible"])

    def test_negative_ability_is_not_positive(self):
        self.assertFalse(c.registration_result(0, b"Not registered, not able to receive updates")["eligible"])

    def test_exit_failure_is_never_eligible(self):
        self.assertFalse(c.registration_result(1, b"can receive updates")["eligible"])

    def test_diagnostics_never_include_raw_output(self):
        r = c.registration_result(1, b"SYNTHETIC_PRIVATE_DIAGNOSTIC")
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(r))
        self.assertFalse(r["newPluginDownloadProven"])


class ArchiveTests(unittest.TestCase):
    def test_relative_file_and_internal_symlink(self):
        c.validate_member(tarfile.TarInfo("./var/nessus/test.db"))
        m = tarfile.TarInfo("lib/a.so"); m.type = tarfile.SYMTYPE; m.linkname = "a.so.1"
        c.validate_member(m)

    def test_path_traversal_and_absolute_paths(self):
        for name in ("/etc/passwd", "../outside", "x/../../outside"):
            with self.assertRaises(c.Refused):
                c.validate_member(tarfile.TarInfo(name))

    def test_link_escape_and_absolute_link(self):
        for target in ("../../outside", "/etc/passwd"):
            m = tarfile.TarInfo("lib/a"); m.type = tarfile.SYMTYPE; m.linkname = target
            with self.assertRaises(c.Refused):
                c.validate_member(m)

    def test_devices_rejected(self):
        m = tarfile.TarInfo("device"); m.type = tarfile.CHRTYPE
        with self.assertRaises(c.Refused):
            c.validate_member(m)

    def test_symlink_ancestor_and_duplicate_rejected(self):
        with self.assertRaises(c.Refused):
            c.validate_catalog(["a", "a/child"], {"a"})
        with self.assertRaises(c.Refused):
            c.validate_catalog(["a", "a"], set())


class ApiTests(unittest.TestCase):
    def test_https_origin_only(self):
        for url in ("http://localhost", "https://user:password@host", "https://host/path", "https://host?token=a"):
            with self.assertRaises(c.Refused):
                c.API(url, None, "fixture", "fixture")

    def test_redirect_does_not_forward_session(self):
        api = c.API("https://localhost:8834", None, "fixture", "fixture")
        api.token = "synthetic-session"
        connection = Mock(); response = connection.getresponse.return_value
        response.status = 302; response.read.return_value = b""
        with patch.object(c.http.client, "HTTPSConnection", return_value=connection) as constructor, \
             patch.object(c.socket, "create_connection", return_value=Mock()) as connect, \
             patch.object(c.ssl.SSLContext, "wrap_socket", return_value=Mock()):
            with self.assertRaises(c.Refused):
                api.call("/users")
        self.assertEqual(constructor.call_count, 1)
        connect.assert_called_once_with(("127.0.0.1", 8834), timeout=30)
        self.assertTrue(api.context.check_hostname)
        self.assertEqual(api.context.verify_mode, c.ssl.CERT_REQUIRED)

    def test_unknown_or_active_scan_refuses(self):
        api = c.API("https://localhost:8834", None, "fixture", "fixture")
        base = {"/server/status": {"status": "ready"}, "/session": {"token": "synthetic"},
                "/users": {"users": [{"id": 1, "username": "fixture", "permissions": 128}]},
                "/scans": {"scans": [{"status": "running"}]}, "/policies": {}, "/plugins/families": {}, "/server/properties": {}}
        for state in ("running", "pending", "processing", "unknown"):
            base["/scans"]["scans"][0]["status"] = state
            with patch.object(api, "call", side_effect=lambda path, *a: base[path]):
                with self.assertRaisesRegex(c.Refused, "ACTIVE_OR_UNKNOWN"):
                    api.snapshot()
            self.assertIsNone(api.token)

    def test_deferred_reload_resets_stability_window(self):
        api = c.API("https://localhost:8834", None, "fixture", "fixture")
        clock = [0]
        responses = [healthy(), c.Refused("NESSUS_NOT_READY"), healthy(), healthy(), healthy()]
        def snap():
            item = responses.pop(0)
            if isinstance(item, Exception): raise item
            return item
        def sleep(seconds): clock[0] += seconds
        with patch.object(api, "snapshot", side_effect=snap), patch.object(c.time, "monotonic", side_effect=lambda: clock[0]), patch.object(c.time, "sleep", side_effect=sleep):
            self.assertEqual(api.wait_stable(60, stable_seconds=10), healthy())
        self.assertEqual(clock[0], 20)


class TransactionTests(unittest.TestCase):
    def run_fixture(self, *, fail_backup=False, fail_native=False, restart=False):
        api = Mock(); api.snapshot.return_value = healthy(); api.wait_stable.return_value = healthy()
        backup = Mock()
        if fail_backup: backup.create.side_effect = c.Refused("TEST_BACKUP_FAILURE")
        events = []
        backup.create.side_effect = c.Refused("TEST_BACKUP_FAILURE") if fail_backup else lambda *a: events.append("backup")
        def native(*args, **kwargs): events.append("update"); return (1 if fail_native else 0), b""
        with patch.object(c, "service", side_effect=lambda action, fd: events.append(action)), patch.object(c, "require_idle"), patch.object(c, "installation_identity", return_value={}), patch.object(c, "native", side_effect=native):
            try:
                result = c.run_update(api, backup, ["native", "update"], 5, 300, restart)
            except c.Refused as e:
                result = str(e)
        return result, events, backup

    def test_backup_failure_resumes_service_without_update(self):
        result, events, backup = self.run_fixture(fail_backup=True)
        self.assertIn("TEST_BACKUP_FAILURE", result)
        self.assertEqual(events, ["stop", "start"])

    def test_native_failure_retains_verified_snapshot(self):
        result, events, backup = self.run_fixture(fail_native=True)
        self.assertIn("NATIVE_UPDATE_FAILED", result)
        self.assertEqual(events, ["stop", "backup", "start", "update"])
        backup.inspect.assert_called_once()

    def test_success_checks_restart_when_requested(self):
        result, events, _ = self.run_fixture(restart=True)
        self.assertTrue(result["restartVerified"])
        self.assertFalse(result["pluginSetChanged"])
        self.assertEqual(events[-1], "restart")

    def test_existing_install_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); sentinel = root / "owner-data"; sentinel.write_text("keep")
            args = Mock(); args.package = root / "fixture.deb"; args.package.write_bytes(b"fixture")
            args.sha256 = c.digest(args.package)
            with patch.object(c, "ROOT", root), self.assertRaisesRegex(c.Refused, "EXISTING_INSTALLATION"):
                cli.fresh_install(args, 5)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_input_digest_refuses_changed_payload(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a"; p.write_bytes(b"fixture")
            with self.assertRaisesRegex(c.Refused, "SHA256_MISMATCH"):
                c.verified_file(p, "0" * 64)

    @unittest.skipUnless(os.name == "posix", "Linux atomic rename required")
    def test_failed_second_rename_restores_original(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d); current = b / "current"; incoming = b / "incoming"; old = b / "preserved"
            current.mkdir(); incoming.mkdir(); (current / "owner-data").write_text("keep")
            real = c.rename_no_replace
            def rename(src, dst):
                if src == incoming: raise OSError("injected")
                return real(src, dst)
            with patch.object(c, "rename_no_replace", side_effect=rename), self.assertRaises(OSError):
                c.promote_restore(incoming, current, old)
            self.assertEqual((current / "owner-data").read_text(), "keep")
            self.assertTrue(incoming.is_dir())


@unittest.skipUnless(os.name == "posix" and shutil.which("gpg"), "Linux GPG integration required")
class EncryptedBackupTests(unittest.TestCase):
    def test_real_encrypt_verify_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d); src = b / "source"; src.mkdir(); (src / "plugins").mkdir()
            (src / "plugins/test.nasl").write_bytes(b"synthetic-test-plugin")
            (src / "registration").write_bytes(b"synthetic-private-test-data")
            (src / "registration").chmod(0o600)
            (src / "plugins/alias").symlink_to("test.nasl")
            backup = c.Backup(b / "snapshot", b"synthetic-backup-passphrase-for-tests")
            backup.create(src, healthy(), {"fixture": True})
            meta, count, size = backup.inspect()
            self.assertGreater(count, 2)
            self.assertEqual(stat.S_IMODE(backup.archive.stat().st_mode), 0o600)
            self.assertNotIn(b"synthetic-private-test-data", backup.archive.read_bytes())
            target = b / "restore"; target.mkdir()
            backup.extract(target)
            self.assertEqual((target / "registration").read_bytes(), (src / "registration").read_bytes())
            self.assertTrue((target / "plugins/alias").is_symlink())
            self.assertEqual(stat.S_IMODE((target / "registration").stat().st_mode), 0o600)

    def test_corruption_refuses_before_restore(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d); src = b / "source"; src.mkdir(); (src / "a").write_bytes(b"fixture")
            backup = c.Backup(b / "snapshot", b"synthetic-backup-passphrase-for-tests")
            backup.create(src, healthy())
            with backup.archive.open("ab") as f: f.write(b"corruption")
            with self.assertRaisesRegex(c.Refused, "CIPHERTEXT_MISMATCH"):
                backup.inspect()
            self.assertEqual((src / "a").read_bytes(), b"fixture")

    def test_wrong_key_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d); src = b / "source"; src.mkdir(); (src / "a").write_bytes(b"fixture")
            backup = c.Backup(b / "snapshot", b"synthetic-backup-passphrase-for-tests")
            backup.create(src, healthy())
            other = c.Backup(backup.directory, b"different-synthetic-test-passphrase")
            with self.assertRaisesRegex(c.Refused, "DECRYPTION_FAILED"):
                other.inspect()


if __name__ == "__main__":
    unittest.main()
