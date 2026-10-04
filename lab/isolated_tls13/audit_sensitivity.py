#!/usr/bin/env python3
"""Read-only seal verification and accounting for the sensitivity study."""

import argparse
import json
from pathlib import Path

from seals import file_hashes, sha256, verify_record
from sensitivity_study import (CANDIDATE_LIMITS, METHODS, SEARCH_SECONDS,
                               selected_cases, setting_name, verify_completed)


def audit(study: Path, replay: Path, destination: Path, selection: Path,
          controller: Path):
    key = (destination / "controller.key").read_bytes()
    frozen = verify_record(key, json.loads((destination / "sensitivity-manifest.json").read_text()))
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    if frozen["controller"] != file_hashes(controller, names) or \
            frozen["historical_manifest_sha256"] != sha256(study / "manifest.json") or \
            frozen["historical_state_sha256"] != sha256(study / "state.json") or \
            frozen["source_replay_manifest_sha256"] != sha256(replay / "controller-manifest.json") or \
            frozen["selection_sha256"] != sha256(selection) or \
            tuple(frozen["methods"]) != METHODS:
        raise ValueError("Sensitivity design or software changed after freeze")
    preselected = selected_cases(study, selection)
    ids = tuple(frozen["case_ids"])
    budgets = tuple((item["search_seconds"], item["candidate_limit"])
                    for item in frozen["budgets"])
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Sensitivity case selection changed")
    if not budgets or len(budgets) != len(set(budgets)) or \
            any(seconds not in SEARCH_SECONDS or cap not in CANDIDATE_LIMITS
                for seconds, cap in budgets):
        raise ValueError("Sensitivity budget selection changed")
    if len(ids) == 1:
        scored = {row["case_id"] for row in json.loads((study / "state.json").read_text())["cases"]
                  if row["status"] == "scored"}
        if ids[0] not in scored or len(budgets) != 1:
            raise ValueError("Invalid sensitivity pilot selection")
    elif ids != preselected or budgets != tuple((seconds, cap)
                                                for seconds in SEARCH_SECONDS
                                                for cap in CANDIDATE_LIMITS):
        raise ValueError("Full sensitivity design changed")
    cases_root = destination / "cases"
    actual_ids = {path.name for path in cases_root.iterdir()} if cases_root.exists() else set()
    if actual_ids - set(ids):
        raise ValueError("Unexpected sensitivity case directory")
    tools = study / "tools"
    rows = []
    hashes = {}
    for case_id in ids:
        parent = cases_root / case_id
        if parent.exists():
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError("Unsafe sensitivity case directory")
            actual_settings = {path.name for path in parent.iterdir()}
            expected_settings = {setting_name(seconds, cap) for seconds, cap in budgets}
            if actual_settings - expected_settings:
                raise ValueError("Unexpected sensitivity setting directory")
        for seconds, cap in budgets:
            case = parent / setting_name(seconds, cap)
            status = "not_attempted"
            if case.exists():
                if case.is_symlink() or not case.is_dir():
                    raise ValueError("Unsafe sensitivity setting directory")
                if (case / "reconciliation.json").exists():
                    report = verify_completed(case, replay / "cases" / case_id / "inputs",
                                              tools, key, controller, case_id, seconds, cap)
                    hashes[f"{case_id}/{setting_name(seconds, cap)}"] = report["score_sha256"]
                    status = "scored"
                elif (case / "failure.json").exists():
                    failure = verify_record(key, json.loads((case / "failure.json").read_text()))
                    if failure["case_id"] != case_id or failure["status"] != "failed_unscored" or \
                            failure["search_seconds"] != seconds or failure["candidate_limit"] != cap:
                        raise ValueError("Sensitivity failure changed")
                    status = "failed_unscored"
                else:
                    status = "partial_unscored"
            rows.append({"case_id": case_id, "search_seconds": seconds,
                         "candidate_limit": cap, "status": status})
    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("scored", "failed_unscored", "partial_unscored", "not_attempted")}
    summary = destination / "sensitivity-summary.json"
    if summary.exists():
        record = verify_record(key, json.loads(summary.read_text()))
        if record["status"] != "scored" or tuple(record["case_ids"]) != ids or \
                tuple((item["search_seconds"], item["candidate_limit"])
                      for item in record["budgets"]) != budgets or \
                record["score_sha256"] != hashes or counts["scored"] != len(ids) * len(budgets):
            raise ValueError("Sensitivity summary disagrees with case evidence")
    return {"selected_cases": len(ids), "settings_per_case": len(budgets),
            "total_settings": len(rows), "counts": counts,
            "summary_present": summary.exists(), "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.study, args.replay, args.destination,
                          args.selection, args.controller), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
