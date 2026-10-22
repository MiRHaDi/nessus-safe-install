import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from nessus_safe import cli, community as q, core as c


class CommunityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.data = self.root / "data"
        shutil.copytree(q.DATA, self.data)
        for obj, name, value in [(q, "DATA", self.data), (c, "STATE", self.state), (c, "private_directory", self.private)]:
            p = patch.object(obj, name, value); p.start(); self.addCleanup(p.stop)
        if os.name != "posix":
            p = patch.object(c, "rename_no_replace", lambda a, b: a.rename(b))
            p.start(); self.addCleanup(p.stop)

    @staticmethod
    def private(path):
        path = Path(path)
        path.mkdir(mode=0o700, exist_ok=True)
        return path

    def change_manifest(self, callback):
        path = self.data / "manifest.json"
        value = json.loads(path.read_text())
        callback(value)
        path.write_text(json.dumps(value))

    def test_bundled_licenses_and_all_eight_unique_ids_are_hash_verified(self):
        value, bundle = q.read_manifest()
        self.assertEqual(len(value["checks"]), 8)
        self.assertEqual(len(bundle), 64)
        self.assertEqual({s["license"] for s in value["sources"]}, {"Apache-2.0", "MIT"})
        common = (self.data / "plugins/aegis_http_common.inc").read_text()
        self.assertIn('AEGIS/AuthorizedHost', common)
        self.assertIn('host != authorized_host', common)
        self.assertNotIn('bulutsoc', common)

    def test_corrupt_payload_refused_before_any_installation(self):
        (self.data / "plugins/aegis_hsts.nasl").write_text("changed")
        with self.assertRaisesRegex(c.Refused, "BUNDLE_HASH_MISMATCH"):
            q.prepare(offline=True)
        self.assertFalse((self.state / "community").exists())

    def test_traversal_and_duplicate_ids_refused(self):
        original = (self.data / "manifest.json").read_bytes()
        self.change_manifest(lambda m: m["files"][0].update(path="plugins/../../activity.db"))
        with self.assertRaisesRegex(c.Refused, "UNSAFE_PATH"):
            q.read_manifest()
        (self.data / "manifest.json").write_bytes(original)
        self.change_manifest(lambda m: m["checks"][1].update(pluginId=m["checks"][0]["pluginId"]))
        with self.assertRaisesRegex(c.Refused, "CHECK_IDS_INVALID"):
            q.read_manifest()

    def test_changed_download_never_activates_or_overwrites_old_version(self):
        candidate = q.prepare(offline=True)
        q.activate(candidate, {"checksParsed": 8})
        old = q.active()
        with patch.object(q, "fetch", return_value=b"changed remote NASL"):
            with self.assertRaisesRegex(c.Refused, "UPSTREAM_HASH_MISMATCH"):
                q.prepare()
        self.assertEqual(q.active(), old)
        self.assertTrue(q.status()["hashesVerified"])

    def test_upstream_new_commit_is_review_only_downloads_remain_pinned(self):
        manifest, _ = q.read_manifest()
        urls = []
        def fetch(url):
            urls.append(url)
            if "api.github.com" in url:
                return json.dumps([{"sha": "f" * 40}]).encode()
            for source in manifest["sources"]:
                prefix = f"https://raw.githubusercontent.com/{source['repository']}/{source['commit']}/"
                if url.startswith(prefix):
                    path = self.data / "upstream" / source["repository"].replace("/", "__") / url[len(prefix):]
                    return path.read_bytes()
            self.fail("Non-pinned download attempted")
        with patch.object(q, "fetch", side_effect=fetch):
            candidate = q.prepare()
        self.assertTrue(all(s["reviewRequired"] for s in candidate["provenance"]["upstream"]["sources"]))
        self.assertFalse(any("/" + "f" * 40 + "/" in u for u in urls))
        self.assertIsNone(q.active())

    def test_real_files_atomic_switch_idempotent_and_explicit_rollback(self):
        first = q.prepare(offline=True)
        result = q.activate(first, {"checksParsed": 8})
        first_path, _ = q.installed(first["bundleSha256"])
        original = (first_path / "plugins/aegis_hsts.nasl").read_bytes()
        again = q.activate(q.prepare(offline=True), {"checksParsed": 8})
        self.assertEqual(again["delivery"], "already-current")
        self.change_manifest(lambda m: m.update(bundleVersion="reviewed-fixture-2"))
        second = q.prepare(offline=True)
        self.assertNotEqual(first["bundleSha256"], second["bundleSha256"])
        q.activate(second, {"checksParsed": 8})
        self.assertEqual((first_path / "plugins/aegis_hsts.nasl").read_bytes(), original)
        api = Mock(); api.snapshot.return_value = {"synthetic": "unchanged-owner"}
        with patch.object(q, "validate_native", return_value={"checksParsed": 8}):
            back = q.sync(api, 4, rollback=first["bundleSha256"])
        self.assertEqual(back["bundleSha256"], first["bundleSha256"])
        self.assertFalse(result["loadedIntoVendorIndex"])
        self.assertEqual(len(list((self.state / "community/versions").iterdir())), 2)

    def test_pointer_failure_retains_previous_and_both_versions(self):
        q.activate(q.prepare(offline=True), {"checksParsed": 8})
        old = q.active()
        self.change_manifest(lambda m: m.update(bundleVersion="reviewed-fixture-2"))
        candidate = q.prepare(offline=True)
        with patch.object(q.os, "replace", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                q.activate(candidate, {"checksParsed": 8})
        self.assertEqual(q.active(), old)
        self.assertEqual(len(list((self.state / "community/versions").iterdir())), 2)

    def test_concurrent_pointer_edit_is_preserved(self):
        candidate = q.prepare(offline=True)
        q.activate(candidate, {"checksParsed": 8})
        old = q.active()
        with self.assertRaisesRegex(c.Refused, "ACTIVE_VERSION_CHANGED"):
            q.activate(candidate, {"checksParsed": 8})
        self.assertEqual(q.active(), old)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink fixture")
    def test_symlinked_payload_and_version_root_refused(self):
        p = self.data / "plugins/aegis_hsts.nasl"
        external = self.root / "outside.nasl"
        p.rename(external); p.symlink_to(external)
        with self.assertRaisesRegex(c.Refused, "SYMLINK_REFUSED"):
            q.read_manifest()
        # A pointer must never traverse a community-directory symlink.
        (self.state / "community").symlink_to(self.data)
        with self.assertRaisesRegex(c.Refused, "SYMLINK_REFUSED"):
            q.active()

    def test_https_redirect_and_unlisted_source_refused(self):
        with self.assertRaisesRegex(c.Refused, "REDIRECT_REFUSED"):
            q.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid/")
        with self.assertRaisesRegex(c.Refused, "URL_NOT_ALLOWED"):
            q.fetch("http://raw.githubusercontent.com/unreviewed/repo/main/a.nasl")

    def test_offline_sync_does_not_contact_upstream(self):
        with patch.object(q, "fetch") as fetch:
            candidate = q.prepare(offline=True)
        fetch.assert_not_called()
        self.assertFalse(candidate["provenance"]["networkUsed"])
        self.assertEqual(candidate["provenance"]["pinnedSourceFilesVerified"], 7)

    def test_no_active_pointer_on_active_work_or_native_validation_failure(self):
        api = Mock(); api.snapshot.side_effect = c.Refused("ACTIVE_OR_UNKNOWN_SCAN_STATE")
        with patch.object(q, "prepare") as prepare:
            with self.assertRaisesRegex(c.Refused, "ACTIVE_OR_UNKNOWN"):
                q.sync(api, 4)
        prepare.assert_not_called()
        api.snapshot.side_effect = None
        api.snapshot.return_value = {"synthetic": "baseline"}
        with patch.object(q, "validate_native", side_effect=c.Refused("COMMUNITY_NATIVE_VALIDATION_FAILED")):
            with self.assertRaisesRegex(c.Refused, "NATIVE_VALIDATION_FAILED"):
                q.sync(api, 4, offline=True)
        self.assertIsNone(q.active())

    def test_new_work_during_download_prevents_activation(self):
        api = Mock(); api.snapshot.side_effect = [{"synthetic": "before"}, {"synthetic": "new-work"}]
        with patch.object(q, "validate_native", return_value={"checksParsed": 8}):
            with self.assertRaisesRegex(c.Refused, "OWNER_OR_SCANNER_STATE_CHANGED"):
                q.sync(api, 4, offline=True)
        self.assertIsNone(q.active())

    def test_real_native_command_does_not_have_target_or_bypass(self):
        candidate = q.prepare(offline=True)
        scanner = self.root / "scanner"
        (scanner / "bin").mkdir(parents=True)
        (scanner / "bin/nasl").write_text("synthetic fixture, never executed")
        with patch.object(c, "ROOT", scanner), patch.object(c, "native", return_value=(0, b"")) as native:
            result = q.validate_native(candidate["bundleSha256"], 9)
        self.assertEqual(result["checksParsed"], 8)
        for call in native.call_args_list:
            args = list(map(str, call.args[0]))
            self.assertIn("-L", args)
            self.assertNotIn("-X", args)
            self.assertNotIn("-t", args)

    def test_status_detects_tampered_installed_payload(self):
        candidate = q.prepare(offline=True)
        q.activate(candidate, {"checksParsed": 8})
        path, _ = q.installed(candidate["bundleSha256"])
        (path / "plugins/aegis_hsts.nasl").write_text("tampered")
        with self.assertRaisesRegex(c.Refused, "BUNDLE_HASH_MISMATCH"):
            q.status()


class PairedUpdateTests(unittest.TestCase):
    def args(self):
        return cli.parser().parse_args(["update", "--url", "https://scanner.example.org:8834", "--maintenance-window", "--with-community"])

    def update(self, *, vendor_error=False, activation_error=False, registration_ok=True):
        api = Mock(); api.snapshot.return_value = {"synthetic": "owner"}
        candidate = {"bundleSha256": "a" * 64, "previous": None}
        vendor = {"pluginSetChanged": False, "after": {"synthetic": "owner"}}
        with contextlib.ExitStack() as stack:
            for obj, name, kwargs in [
                (cli, "client", {"return_value": api}), (cli, "secret", {"return_value": b"synthetic-test-passphrase"}),
                (c, "native", {"return_value": (0, b"registered") if registration_ok else (1, b"invalid")}),
                (c, "write_json", {}), (c, "Backup", {}),
                (c, "run_update", {"side_effect": c.Refused("SYNTHETIC_VENDOR_FAILURE")} if vendor_error else {"return_value": vendor}),
                (q, "prepare", {"return_value": candidate}), (q, "validate_native", {"return_value": {"checksParsed": 8}}),
                (q, "activate", {"side_effect": c.Refused("SYNTHETIC_ACTIVATION_FAILURE")} if activation_error else {"return_value": {"delivery": "reviewed-supplemental-bundle"}}),
            ]:
                stack.enter_context(patch.object(obj, name, **kwargs))
            stack.enter_context(patch.object(c, "ROOT", Path(tempfile.gettempdir())))
            stack.enter_context(patch.object(c.os.path, "ismount", return_value=False))
            if vendor_error or activation_error or not registration_ok:
                with self.assertRaises(c.Refused) as caught:
                    cli.execute(self.args(), 4)
                return caught.exception, q.activate.call_count, q.prepare.call_count
            return cli.execute(self.args(), 4), q.activate.call_count, q.prepare.call_count

    def test_pairing_keeps_results_separate_and_same_vendor_set_honest(self):
        result, activated, prepared = self.update()
        self.assertEqual(result["delivery"], "already-current-or-same-set")
        self.assertEqual(result["community"]["delivery"], "reviewed-supplemental-bundle")
        self.assertEqual((activated, prepared), (1, 1))

    def test_vendor_failure_never_activates_community_candidate(self):
        _, activated, prepared = self.update(vendor_error=True)
        self.assertEqual((activated, prepared), (0, 1))

    def test_invalid_registration_does_not_fetch_or_activate_a_workaround(self):
        _, activated, prepared = self.update(registration_ok=False)
        self.assertEqual((activated, prepared), (0, 0))

    def test_failed_supplemental_stage_does_not_hide_completed_vendor_update(self):
        error, _, _ = self.update(activation_error=True)
        self.assertEqual(str(error), "VENDOR_UPDATE_COMPLETED_COMMUNITY_REQUIRES_REVIEW")
        self.assertTrue(error.evidence["vendorUpdateCompleted"])

    def test_mutation_needs_local_api_and_exclusive_window(self):
        args = cli.parser().parse_args(["community", "sync"])
        with patch.object(cli, "client") as client:
            with self.assertRaisesRegex(c.Refused, "EXCLUSIVE_MAINTENANCE_REQUIRED"):
                cli.execute(args, 4)
        client.assert_not_called()

    def test_check_is_read_only_without_root_or_credentials(self):
        with patch.object(q, "check_sources", return_value={"sources": []}), patch.object(cli, "platform_check") as platform, \
             patch.object(cli, "client") as client, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["community", "check"]), 0)
        platform.assert_not_called(); client.assert_not_called()
