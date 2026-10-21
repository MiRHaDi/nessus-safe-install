import contextlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nessus_safe import cli, core as c


class CommandGateTests(unittest.TestCase):
    def args(self, command):
        values = [command, "--url", "https://localhost:8834"]
        if command != "doctor": values += ["--maintenance-window"]
        return cli.parser().parse_args(values)

    def test_failed_registration_never_stops_service_or_starts_update(self):
        with patch.object(cli, "client", return_value=Mock()), patch.object(cli, "secret", return_value=b"synthetic-test-passphrase"), \
             patch.object(c, "native", return_value=(1, b"Could not validate preference file")), \
             patch.object(c, "ROOT", Path(tempfile.gettempdir())), patch.object(c.os.path, "ismount", return_value=False), \
             patch.object(c, "run_update") as update, patch.object(c, "service") as service:
            with self.assertRaisesRegex(c.Refused, "REGISTRATION_CHECK_FAILED"):
                cli.execute(self.args("update"), 5)
        update.assert_not_called()
        service.assert_not_called()

    def test_doctor_does_not_accept_unloaded_set(self):
        api = Mock(); api.snapshot.return_value = {"plugins": 20, "families": 2, "pluginSet": "new", "loadedPluginSet": "old"}
        with patch.object(cli, "client", return_value=api), patch.object(c, "native", return_value=(0, b"registered")):
            result = cli.execute(self.args("doctor"), 5)
        self.assertFalse(result["healthyForOnlineUpdates"])

    def test_password_is_not_a_supported_argument(self):
        with contextlib.redirect_stderr(__import__("io").StringIO()):
            with self.assertRaises(SystemExit):
                cli.parser().parse_args(["doctor", "--url", "https://localhost", "--password", "synthetic"])

    @unittest.skipUnless(os.name == "posix", "Linux flock required")
    def test_single_writer_lock_refuses_second_operation(self):
        with tempfile.TemporaryDirectory() as d, patch.object(c, "STATE", Path(d)), \
             patch.object(c, "private_directory", return_value=Path(d)):
            with c.locked():
                with self.assertRaisesRegex(c.Refused, "ANOTHER_OPERATION"):
                    with c.locked(): pass


if __name__ == "__main__":
    unittest.main()
