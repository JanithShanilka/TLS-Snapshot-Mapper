#!/usr/bin/env python3
"""Read-only accounting and seal verification for a comparison campaign."""

import argparse
import json
from pathlib import Path

from seals import (INPUT_NAMES, file_hashes, sha256, tool_hashes,
                   verify_evidence, verify_record)


METHODS = ("structure_only", "anderson_nss_adjacent", "xray_full_snapshot_entropy")


def audit(study: Path, replay: Path, destination: Path, controller: Path):
    key = (destination / "controller.key").read_bytes()
    frozen = verify_record(key, json.loads((destination / "comparison-manifest.json").read_text()))
    if frozen["historical_manifest_sha256"] != sha256(study / "manifest.json") or \
            frozen["historical_state_sha256"] != sha256(study / "state.json") or \
            frozen["source_replay_manifest_sha256"] != sha256(replay / "controller-manifest.json"):
        raise ValueError("Comparison source changed after freeze")
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    software = file_hashes(controller, names)
    if frozen["controller"] != software or tuple(frozen["methods"]) != METHODS:
        raise ValueError("Comparison software or method list changed")
    if frozen["search_seconds"] not in {30, 180, 600} or \
            frozen["candidate_limit"] not in {25, 100, 1000}:
        raise ValueError("Comparison budget changed")
    state = json.loads((study / "state.json").read_text())
    expected = tuple(row["case_id"] for row in state["cases"])
    selected = tuple(frozen["case_ids"])
    if len(selected) != len(set(selected)) or any(case_id not in expected for case_id in selected):
        raise ValueError("Comparison case selection changed")
    cases_root = destination / "cases"
    actual = {path.name for path in cases_root.iterdir()} if cases_root.exists() else set()
    if actual - set(selected):
        raise ValueError("Unexpected comparison case directory")
    tools = study / "tools"
    source_key = (replay / "controller.key").read_bytes()
    source = verify_record(source_key, json.loads((replay / "controller-manifest.json").read_text()))
    if source["historical_manifest_sha256"] != frozen["historical_manifest_sha256"] or \
            source["historical_state_sha256"] != frozen["historical_state_sha256"]:
        raise ValueError("Source replay is not for this retained study")
    tool_hash = tool_hashes(tools)
    rows = []
    for case_id in selected:
        case = cases_root / case_id
        status = "not_attempted"
        if case.exists():
            if case.is_symlink() or not case.is_dir():
                raise ValueError(f"Unsafe comparison case directory: {case_id}")
            reconciliation = case / "reconciliation.json"
            failure = case / "failure.json"
            if reconciliation.exists() and failure.exists():
                raise ValueError(f"Case has success and failure records: {case_id}")
            if reconciliation.exists():
                report = verify_record(key, json.loads(reconciliation.read_text()))
                if report["case_id"] != case_id or report["status"] != "scored" or \
                        report["score_sha256"] != sha256(case / "score.json"):
                    raise ValueError(f"Comparison score changed: {case_id}")
                inputs = replay / "cases" / case_id / "inputs"
                input_hashes = file_hashes(inputs, INPUT_NAMES)
                source_report = verify_record(source_key, json.loads(
                    (replay / "cases" / case_id / "reconciliation.json").read_text()))
                if source_report["case_id"] != case_id or \
                        source_report["score_sha256"] != sha256(replay / "cases" / case_id / "score.json") or \
                        source_report["status"] not in {"matched", "different"} or \
                        report["source_replay_status"] != source_report["status"]:
                    raise ValueError(f"Source replay status changed: {case_id}")
                score = json.loads((case / "score.json").read_text())
                if set(score) != set(METHODS):
                    raise ValueError(f"Comparison score methods changed: {case_id}")
                for method in METHODS:
                    detail = verify_evidence(key, case / (method + "-controller-seal.json"),
                                             inputs, case / method / "result", tools)
                    if detail["method"] != method or detail["inputs"] != input_hashes or \
                            detail["tools"] != tool_hash or detail["comparison_software"] != software:
                        raise ValueError(f"Comparison method identity changed: {case_id}/{method}")
                    if report["correct_targets"][method] != score[method]["correct_targets"] or \
                            report["false_assignments"][method] != score[method]["false_assignments"]:
                        raise ValueError(f"Comparison reconciliation changed: {case_id}/{method}")
                status = "scored"
            elif failure.exists():
                failed = verify_record(key, json.loads(failure.read_text()))
                if failed["case_id"] != case_id or failed["status"] != "failed_unscored":
                    raise ValueError(f"Comparison failure changed: {case_id}")
                status = "failed_unscored"
            else:
                status = "partial_unscored"
        rows.append({"case_id": case_id, "status": status})
    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("scored", "failed_unscored", "partial_unscored", "not_attempted")}
    summary = destination / "campaign-summary.json"
    if summary.exists():
        record = verify_record(key, json.loads(summary.read_text()))
        if record["status"] != "scored" or tuple(record["case_ids"]) != selected or \
                counts != {"scored": len(selected), "failed_unscored": 0,
                           "partial_unscored": 0, "not_attempted": 0}:
            raise ValueError("Campaign summary disagrees with case accounting")
        if set(record["score_sha256"]) != set(selected):
            raise ValueError("Campaign summary case set changed")
        for case_id in selected:
            if record["score_sha256"][case_id] != sha256(cases_root / case_id / "score.json"):
                raise ValueError(f"Campaign summary score changed: {case_id}")
    return {"historical_study": study.name, "selected_cases": len(selected),
            "search_seconds": frozen["search_seconds"],
            "candidate_limit": frozen["candidate_limit"], "counts": counts,
            "campaign_summary_present": summary.exists(), "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.study, args.replay, args.destination, args.controller),
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
