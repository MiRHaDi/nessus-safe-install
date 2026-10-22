"""A feed outage must remain diagnosable without opening maintenance gates."""
import copy
import json
import unittest
from unittest.mock import Mock, patch

from nessus_safe import core as c, cli


def responses():
    return {
        "/server/status": {"status": "download-failed", "detailed_status": {
            "login_status": "allow", "engine_status": {"status": "ready"},
            "db_status": {"status": "ready"}, "feed_status": {"status": "downloading-failed",
                "message": "SYNTHETIC_PRIVATE_NATIVE_MESSAGE"}}},
        "/session": {"token": "synthetic-session"},
        "/users": {"users": [{"id": 1, "username": "synthetic-owner", "permissions": 128}]},
        "/scans": {"scans": []}, "/policies": {},
        "/plugins/families": {"families": [{"count": 20}]},
        "/server/properties": {"plugin_set": "same", "loaded_plugin_set": "same"}}


class DegradedDoctorTests(unittest.TestCase):
    def api(self):
        return c.API("https://localhost:8834", None, "fixture", "fixture")

    def test_loaded_library_can_be_observed_without_exporting_native_messages(self):
        api = self.api(); data = responses()
        with patch.object(api, "call", side_effect=lambda path, *a: data[path]):
            result = api.observe(allow_feed_failure=True)
        self.assertEqual(result["plugins"], 20)
        self.assertEqual(result["readiness"], {"maintenanceReady": False, "feedFailureObserved": True})
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))
        self.assertNotIn("synthetic-owner", json.dumps(result))
        self.assertIsNone(api.token)
        self.assertEqual(c.reuse_guidance(result, {"eligible": True})["mutationGate"], "native-not-ready")

    def test_default_observe_and_maintenance_snapshot_refuse_before_login(self):
        for method in ("observe", "snapshot"):
            api = self.api(); data = responses()
            with patch.object(api, "call", side_effect=lambda path, *a: data[path]) as call:
                with self.assertRaisesRegex(c.Refused, "NESSUS_NOT_READY"):
                    getattr(api, method)()
            call.assert_called_once_with("/server/status")

    def test_other_unready_or_malformed_states_are_not_diagnostic_exceptions(self):
        base = responses()["/server/status"]
        bad_states = [{"status": "loading"}, {"status": "download-failed"},
                      {"status": "download-failed", "detailed_status": "invalid"}]
        for key, value in (("login_status", "deny"), ("engine_status", {"status": "loading"}),
                           ("db_status", {"status": "loading"}), ("feed_status", {"status": "ready"}),
                           ("engine_status", None)):
            changed = copy.deepcopy(base); changed["detailed_status"][key] = value; bad_states.append(changed)
        for status in bad_states:
            with self.subTest(status=status):
                api = self.api()
                with patch.object(api, "call", return_value=status) as call:
                    with self.assertRaisesRegex(c.Refused, "NESSUS_NOT_READY"):
                        api.observe(allow_feed_failure=True)
                call.assert_called_once_with("/server/status")

    def test_active_work_remains_the_first_mutation_gate(self):
        api = self.api(); data = responses()
        data["/scans"]["scans"] = [{"status": "processing"}, {"status": "future-status"}]
        with patch.object(api, "call", side_effect=lambda path, *a: data[path]):
            result = api.observe(allow_feed_failure=True)
        self.assertEqual(result["activeOrUnknownScans"], 2)
        self.assertEqual(c.reuse_guidance(result, {"eligible": False})["mutationGate"], "active-or-unknown-scans")

    def test_doctor_does_not_call_a_feed_outage_healthy_or_mutate_service(self):
        api = self.api(); data = responses()
        args = cli.parser().parse_args(["doctor", "--url", "https://localhost:8834"])
        with patch.object(cli, "client", return_value=api), \
             patch.object(api, "call", side_effect=lambda path, *a: data[path]), \
             patch.object(c, "native", return_value=(0, b"registered")), \
             patch.object(c, "engine_version", return_value="10.12.5"), \
             patch.object(c, "service") as service, patch.object(c, "run_update") as update:
            result = cli.execute(args, 5)
        self.assertTrue(result["nativeRegistration"]["eligible"])
        self.assertTrue(result["localReuse"]["compiledLibraryLoaded"])
        self.assertFalse(result["healthyForOnlineUpdates"])
        self.assertFalse(result["targetScanAcceptanceProven"])
        service.assert_not_called(); update.assert_not_called()

    def test_healthy_observation_keeps_maintenance_snapshot_shape(self):
        api = self.api(); data = responses(); data["/server/status"] = {"status": "ready"}
        with patch.object(api, "call", side_effect=lambda path, *a: data[path]):
            strict = api.snapshot(); diagnostic = api.observe(allow_feed_failure=True)
        self.assertNotIn("readiness", strict)
        self.assertTrue(diagnostic["readiness"]["maintenanceReady"])
        self.assertFalse(diagnostic["readiness"]["feedFailureObserved"])

    def test_http_failure_is_not_reclassified_as_usable_native_status(self):
        api = self.api(); connection = Mock(); response = connection.getresponse.return_value
        response.status = 503; response.read.return_value = json.dumps(responses()["/server/status"]).encode()
        with patch.object(c.http.client, "HTTPSConnection", return_value=connection), \
             patch.object(c.socket, "create_connection", return_value=Mock()), \
             patch.object(c.ssl.SSLContext, "wrap_socket", return_value=Mock()):
            with self.assertRaisesRegex(c.Refused, "NESSUS_API_HTTP_ERROR"):
                api.observe(allow_feed_failure=True)
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
