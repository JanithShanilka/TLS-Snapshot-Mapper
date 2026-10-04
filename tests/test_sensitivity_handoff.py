"""The one-time handoff must gate on complete audits and a mounted volume."""

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))

from tls13_sensitivity_handoff import checked_audit, check_volume, wait_for_primary


class HandoffTests(unittest.TestCase):
    def test_refuses_plain_directory_in_place_of_volume(self):
        with tempfile.TemporaryDirectory() as directory:
            volume = Path(directory) / "volume"
            volume.mkdir()
            with self.assertRaisesRegex(ValueError, "Separate comparison volume"):
                check_volume(volume, volume / "study")

    def test_audit_must_have_every_setting_scored(self):
        passed = {"counts": {"scored": 100, "failed_unscored": 0,
                             "partial_unscored": 0, "not_attempted": 0}}
        with patch("tls13_sensitivity_handoff.command",
                   return_value=types.SimpleNamespace(stdout=json.dumps(passed))):
            self.assertEqual(checked_audit(Path("auditor.py"), [], 100), passed)
        passed["counts"]["failed_unscored"] = 1
        passed["counts"]["scored"] = 99
        with patch("tls13_sensitivity_handoff.command",
                   return_value=types.SimpleNamespace(stdout=json.dumps(passed))):
            with self.assertRaisesRegex(ValueError, "every predeclared"):
                checked_audit(Path("auditor.py"), [], 100)

    def test_waits_for_running_service_and_checks_mount(self):
        with patch("tls13_sensitivity_handoff.service_state",
                   side_effect=["active", "inactive"]), \
             patch("tls13_sensitivity_handoff.check_volume") as mounted, \
             patch("tls13_sensitivity_handoff.time.sleep") as slept:
            wait_for_primary("primary.service", Path("/volume"), Path("/volume/study"), 30)
        self.assertEqual(mounted.call_count, 2)
        slept.assert_called_once_with(30)


if __name__ == "__main__":
    unittest.main()
