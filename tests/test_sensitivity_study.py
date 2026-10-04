"""Resource-grid selection and budget adapter checks."""

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab/isolated_tls13"))

from budget_recovery import run as budget_run
from sandbox import budget_command
from seals import sha256, verify_record
from sensitivity_study import (CANDIDATE_LIMITS, METHODS, SEARCH_SECONDS,
                               freeze, selected_cases, settings)


class SensitivityStudyTests(unittest.TestCase):
    def test_design_selects_exactly_20_scored_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            study = base / "study"
            study.mkdir()
            (study / "manifest.json").write_text("{}\n")
            rows = [{"case_id": f"B{i:03d}", "status": "scored"} for i in range(100)]
            (study / "state.json").write_text(json.dumps({"cases": rows}))
            selection = base / "selection.json"
            design = {"historical_manifest_sha256": sha256(study / "manifest.json"),
                      "methods": list(METHODS), "search_seconds": list(SEARCH_SECONDS),
                      "candidate_limits": list(CANDIDATE_LIMITS),
                      "strata": {"positive": [f"B{i:03d}" for i in range(20)]}}
            selection.write_text(json.dumps(design))
            self.assertEqual(len(selected_cases(study, selection)), 20)
            design["strata"]["positive"][-1] = "B000"
            selection.write_text(json.dumps(design))
            with self.assertRaisesRegex(ValueError, "20 distinct"):
                selected_cases(study, selection)

    def test_grid_and_pilot_budgets_are_predeclared(self):
        self.assertEqual(len(settings(None, None)), 9)
        self.assertEqual(settings(30, 25), ((30, 25),))
        with self.assertRaisesRegex(ValueError, "outside"):
            settings(31, 25)

    def test_budget_adapter_changes_parameters_only(self):
        calls = []
        fake = types.SimpleNamespace(SEARCH_SECONDS=180, MAX_CANDIDATES=100)

        def original_entropy(image, deadline, maximum=100):
            calls.append((image, deadline, maximum))
            return [], {}

        def historical_run(*args):
            fake.entropy_rank("image", 30)
            calls.append(args)
            return "done"

        fake.entropy_rank = original_entropy
        fake.run = historical_run
        original_path = list(sys.path)
        try:
            with patch.dict(sys.modules, {"recover": fake}):
                result = budget_run(Path("core"), Path("pcap"), Path("metadata"),
                                    Path("tools"), "entropy", 600, 1000, Path("output"))
        finally:
            sys.path[:] = original_path
        self.assertEqual(result, "done")
        self.assertEqual((fake.SEARCH_SECONDS, fake.MAX_CANDIDATES), (600, 1000))
        self.assertEqual(calls[0], ("image", 30, 1000))
        self.assertEqual(calls[1][-2:], ("entropy", Path("output")))

    def test_budget_method_uses_same_sandbox_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tools = base / "tools"
            inputs = base / "inputs"
            output = base / "output"
            controller = base / "controller"
            for path in (tools / "blind_tls13", inputs, output, controller):
                path.mkdir(parents=True)
            (tools / "blind_tls13/recover.py").write_text("pass\n")
            (controller / "budget_recovery.py").write_text("pass\n")
            for name in ("memory.core", "traffic.pcap", "target.json"):
                (inputs / name).write_text(name)
            command = budget_command(tools, controller, inputs, output,
                                     "structured", 600, 1000)
            self.assertIn("--unshare-all", command)
            self.assertNotIn("--share-net", command)
            self.assertIn("/controller/budget_recovery.py", command)
            self.assertEqual(command[-2:], ["--output", "/out/result"])

    def test_grid_freeze_rejects_changed_case_set(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            study = base / "study"
            replay = base / "replay"
            destination = base / "destination"
            for path in (study, replay, destination):
                path.mkdir()
            (study / "manifest.json").write_text("{}\n")
            (study / "state.json").write_text("{}\n")
            (replay / "controller-manifest.json").write_text("{}\n")
            selection = base / "selection.json"
            selection.write_text("{}\n")
            key = bytes(range(32))
            first = freeze(study, replay, destination, selection, key, ("B001",), ((30, 25),))
            saved = verify_record(key, json.loads((destination / "sensitivity-manifest.json").read_text()))
            self.assertEqual(saved, first)
            with self.assertRaisesRegex(ValueError, "changed after freeze"):
                freeze(study, replay, destination, selection, key, ("B002",), ((30, 25),))


if __name__ == "__main__":
    unittest.main()
