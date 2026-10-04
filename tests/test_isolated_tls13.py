"""Evidence integrity and sandbox command tests; the live sandbox is checked on Linux."""

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/isolated_tls13"))

from sandbox import comparison_command, probe_command, recovery_command
from comparison_study import (campaign_ids, compare, freeze_comparison,
                              require_separate_volume)
from replay import prepare_case_folder
from seals import (INPUT_NAMES, OUTPUT_NAMES, file_hashes, key_at, seal_record,
                   tool_hashes, verify_evidence, verify_record, TOOL_NAMES)


class IsolatedTLS13Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.tools = base / "tools"
        self.inputs = base / "inputs"
        self.output = base / "output"
        for path in (self.inputs, self.output, self.tools / "blind_tls13",
                     self.tools / "offline_memory"):
            path.mkdir(parents=True)
        for name in INPUT_NAMES:
            (self.inputs / name).write_bytes(name.encode())
        for directory, names in TOOL_NAMES.items():
            for name in names:
                (self.tools / directory / name).write_bytes(name.encode())

    def test_sandbox_exposes_only_named_inputs_and_private_output(self):
        command = recovery_command(self.tools, self.inputs, self.output, "structured")
        self.assertIn("--unshare-all", command)
        self.assertIn("--clear-groups", command)
        self.assertNotIn("--share-net", command)
        self.assertIn("/input/memory.core", command)
        self.assertIn("/out/result", command)
        self.assertNotIn("/root", command)
        controller = Path(self.temp.name) / "controller"
        controller.mkdir(mode=0o755)
        (controller / "probe.py").write_text("pass\n")
        probe = probe_command(self.tools, self.inputs, self.output, controller, 18443)
        self.assertEqual(probe[-2:], ["/controller/probe.py", "18443"])
        self.assertIn("--unshare-all", probe)
        self.assertIn("/controller", probe)

    def test_tampering_inputs_outputs_or_seal_rejects_before_scoring(self):
        result = self.output / "result"
        result.mkdir()
        for name in OUTPUT_NAMES:
            (result / name).write_bytes(name.encode())
        record = {"inputs": file_hashes(self.inputs, INPUT_NAMES),
                  "outputs": file_hashes(result, OUTPUT_NAMES),
                  "tools": tool_hashes(self.tools)}
        key = bytes(range(32))
        seal = self.output / "controller-seal.json"
        seal.write_text(json.dumps(seal_record(key, record)))
        verify_evidence(key, seal, self.inputs, result, self.tools)
        for path in (self.inputs / "target.json", result / "decisions.json", seal):
            original = path.read_bytes()
            path.write_bytes(original + b"x")
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                verify_evidence(key, seal, self.inputs, result, self.tools)
            path.write_bytes(original)
        verify_evidence(key, seal, self.inputs, result, self.tools)

    def test_probe_mount_requires_unprivileged_read_access(self):
        controller = Path(self.temp.name) / "controller"
        controller.mkdir(mode=0o700)
        (controller / "probe.py").write_text("pass\n")
        with self.assertRaisesRegex(ValueError, "not readable"):
            probe_command(self.tools, self.inputs, self.output, controller, 18443)

    def test_comparison_uses_same_isolation_boundary_and_declared_budgets(self):
        comparison = Path(self.temp.name) / "comparison"
        comparison.mkdir()
        (comparison / "compare_recovery.py").write_text("pass\n")
        command = comparison_command(self.tools, comparison, self.inputs, self.output,
                                     "anderson_nss_adjacent", 180, 100)
        self.assertIn("--unshare-all", command)
        self.assertIn("/comparison/compare_recovery.py", command)
        self.assertNotIn("/root", command)
        with self.assertRaisesRegex(ValueError, "predeclared grid"):
            comparison_command(self.tools, comparison, self.inputs, self.output,
                               "structure_only", 181, 100)

    def test_comparison_rejects_unmounted_volume_and_destination_outside_it(self):
        volume = Path(self.temp.name) / "unmounted-volume"
        volume.mkdir()
        with self.assertRaisesRegex(ValueError, "not a separate mounted filesystem"):
            require_separate_volume(volume / "comparison", volume)
        with self.assertRaisesRegex(ValueError, "must be inside"):
            require_separate_volume(Path(self.temp.name) / "elsewhere", volume)

    def test_comparison_freeze_can_be_verified_after_json_round_trip(self):
        base = Path(self.temp.name)
        study = base / "study"
        replay = base / "replay"
        destination = base / "comparison"
        for directory in (study, replay, destination):
            directory.mkdir()
        (study / "manifest.json").write_text("{}\n")
        (study / "state.json").write_text("{}\n")
        (replay / "controller-manifest.json").write_text("{}\n")
        key = bytes(range(32))
        first = freeze_comparison(study, replay, destination, key, 180, 100, ("B123",))
        second = freeze_comparison(study, replay, destination, key, 180, 100, ("B123",))
        self.assertEqual(first, second)
        self.assertIsInstance(first["methods"], list)
        self.assertEqual(first["case_ids"], ["B123"])

    def test_campaign_requires_exactly_100_distinct_scored_cases(self):
        study = Path(self.temp.name) / "study"
        study.mkdir()
        state = study / "state.json"
        rows = [{"case_id": f"B{number:03d}", "status": "scored"}
                for number in range(100)]
        state.write_text(json.dumps({"cases": rows}))
        self.assertEqual(len(campaign_ids(study)), 100)
        rows[-1]["case_id"] = rows[0]["case_id"]
        state.write_text(json.dumps({"cases": rows}))
        with self.assertRaisesRegex(ValueError, "100 distinct scored"):
            campaign_ids(study)

    def test_case_preflight_failure_is_preserved_as_signed_evidence(self):
        base = Path(self.temp.name)
        study = base / "study"
        replay = base / "replay"
        destination = base / "comparison"
        study.mkdir()
        replay.mkdir()
        (study / "state.json").write_text(json.dumps({"cases": [{"case_id": "B123"}]}))
        (study / "manifest.json").write_text("{}\n")
        (replay / "controller-manifest.json").write_text("{}\n")
        with patch("comparison_study.os.geteuid", return_value=0), \
             patch("comparison_study.require_separate_volume"), \
             patch("comparison_study.require_free_space"), \
             patch("comparison_study.frozen_tools", return_value=({}, self.tools)), \
             patch("comparison_study.verify_replayed_case", side_effect=ValueError("bad replay seal")):
            with self.assertRaisesRegex(ValueError, "bad replay seal"):
                compare(study, replay, destination, base, "B123", 180, 100)
        failure = destination / "cases/B123/failure.json"
        record = verify_record(key_at(destination / "controller.key"),
                               json.loads(failure.read_text()))
        self.assertEqual(record["status"], "failed_unscored")
        self.assertEqual(record["stage_error"], "ValueError")

    def test_rejects_symlinks_and_hardlinks(self):
        path = self.inputs / "traffic.pcap"
        target = self.inputs / "alias"
        target.hardlink_to(path)
        with self.assertRaises(ValueError):
            file_hashes(self.inputs, INPUT_NAMES)
        target.unlink()
        path.unlink()
        path.symlink_to(self.inputs / "memory.core")
        with self.assertRaises(ValueError):
            file_hashes(self.inputs, INPUT_NAMES)

    def test_case_directories_allow_unprivileged_traversal_even_with_private_umask(self):
        base = Path(self.temp.name) / "replay"
        base.mkdir()
        previous = os.umask(0o077)
        try:
            case = prepare_case_folder(base, "B123")
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(case.parent.stat().st_mode), 0o711)
        self.assertEqual(stat.S_IMODE(case.stat().st_mode), 0o711)


if __name__ == "__main__":
    unittest.main()
