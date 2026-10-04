#!/usr/bin/env python3
"""Read-only verification and accounting for an isolated replay directory."""

import argparse
import json
from pathlib import Path

from replay import compare_original, MIN_FREE_BYTES
from seals import (file_hashes, sha256, verify_evidence,
                   verify_record)


def audit(study: Path, destination: Path):
    key = (destination / "controller.key").read_bytes()
    frozen = verify_record(key, json.loads((destination / "controller-manifest.json").read_text()))
    if frozen["historical_manifest_sha256"] != sha256(study / "manifest.json") or \
            frozen["historical_state_sha256"] != sha256(study / "state.json"):
        raise ValueError("Historical study changed after replay freeze")
    controller = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    if frozen["controller"] != file_hashes(controller, names) or \
            frozen["minimum_free_bytes"] != MIN_FREE_BYTES:
        raise ValueError("Controller code changed after replay freeze")
    state = json.loads((study / "state.json").read_text())
    tools = study / "tools"
    rows = []
    for original in state["cases"]:
        case_id = original["case_id"]
        case = destination / "cases" / case_id
        status = "not_attempted"
        if case.exists():
            reconciliation = case / "reconciliation.json"
            failure = case / "failure.json"
            if reconciliation.exists():
                if failure.exists():
                    raise ValueError(f"Case has both success and failure: {case_id}")
                report = verify_record(key, json.loads(reconciliation.read_text()))
                if report["case_id"] != case_id or report["score_sha256"] != sha256(case / "score.json"):
                    raise ValueError(f"Reconciliation changed: {case_id}")
                expected_order = ("structured", "entropy") if len(rows) % 2 == 0 else ("entropy", "structured")
                if tuple(report["method_order"]) != expected_order:
                    raise ValueError(f"Method order changed: {case_id}")
                for method in ("structured", "entropy"):
                    seal = case / (method + "-controller-seal.json")
                    detail = verify_evidence(key, seal, case / "inputs", case / method / "result", tools)
                    if detail["case_id"] != case_id or detail["method"] != method:
                        raise ValueError(f"Sealed method identity changed: {case_id}")
                if report["assignment_differences"] != compare_original(study, case, original):
                    raise ValueError(f"Assignment reconciliation changed: {case_id}")
                status = report["status"]
            elif failure.exists():
                failure_record = verify_record(key, json.loads(failure.read_text()))
                if failure_record["case_id"] != case_id:
                    raise ValueError(f"Failure case identity changed: {case_id}")
                status = "failed_unscored"
            else:
                status = "partial_unscored"
        rows.append({"case_id": case_id, "status": status})
    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("matched", "different", "failed_unscored", "partial_unscored", "not_attempted")}
    return {"historical_study": study.name, "replay_cases": rows, "counts": counts,
            "total_accounted_for": sum(counts.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.study, args.destination), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
