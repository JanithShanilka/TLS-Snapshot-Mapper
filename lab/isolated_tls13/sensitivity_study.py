#!/usr/bin/env python3
"""Sealed resource-sensitivity study on preselected retained cases."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import socket
import sys

from comparison_study import (require_free_space, require_separate_volume,
                              run_method as run_comparator, verify_replayed_case)
from replay import (frozen_tools, own_outputs, prepare_case_folder, run_command,
                    source_paths, write_json)
from sandbox import budget_command, probe_command
from seals import (INPUT_NAMES, file_hashes, key_at, seal_record, sha256,
                   tool_hashes, verify_evidence, verify_record)


METHODS = ("structured", "entropy", "structure_only", "anderson_nss_adjacent",
           "xray_full_snapshot_entropy")
SEARCH_SECONDS = (30, 180, 600)
CANDIDATE_LIMITS = (25, 100, 1000)


def selected_cases(study: Path, selection: Path):
    manifest = json.loads(selection.read_text())
    if manifest["historical_manifest_sha256"] != sha256(study / "manifest.json") or \
            tuple(manifest["methods"]) != METHODS or \
            tuple(manifest["search_seconds"]) != SEARCH_SECONDS or \
            tuple(manifest["candidate_limits"]) != CANDIDATE_LIMITS:
        raise ValueError("Sensitivity design no longer matches the retained study")
    ids = tuple(case_id for stratum in manifest["strata"].values() for case_id in stratum)
    state = json.loads((study / "state.json").read_text())
    scored = {row["case_id"] for row in state["cases"] if row["status"] == "scored"}
    if len(ids) != 20 or len(set(ids)) != 20 or not set(ids) <= scored:
        raise ValueError("Sensitivity selection is not 20 distinct scored cases")
    return ids


def settings(search_seconds: int | None, candidate_limit: int | None):
    if search_seconds is None and candidate_limit is None:
        return tuple((seconds, cap) for seconds in SEARCH_SECONDS for cap in CANDIDATE_LIMITS)
    if search_seconds not in SEARCH_SECONDS or candidate_limit not in CANDIDATE_LIMITS:
        raise ValueError("Sensitivity budget is outside the predeclared grid")
    return ((search_seconds, candidate_limit),)


def setting_name(seconds: int, cap: int):
    return f"t{seconds}-c{cap}"


def freeze(study: Path, replay: Path, destination: Path, selection: Path,
           key: bytes, ids, budgets):
    controller = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    record = {"schema": 1, "historical_study": study.name,
              "historical_manifest_sha256": sha256(study / "manifest.json"),
              "historical_state_sha256": sha256(study / "state.json"),
              "source_replay_manifest_sha256": sha256(replay / "controller-manifest.json"),
              "selection_sha256": sha256(selection), "controller": file_hashes(controller, names),
              "methods": list(METHODS), "case_ids": list(ids),
              "budgets": [{"search_seconds": seconds, "candidate_limit": cap}
                          for seconds, cap in budgets], "authentication_seconds": 300}
    path = destination / "sensitivity-manifest.json"
    if path.exists():
        if verify_record(key, json.loads(path.read_text())) != record:
            raise ValueError("Sensitivity software or design changed after freeze")
    else:
        write_json(path, seal_record(key, record))
    return record


def run_historical(case: Path, inputs: Path, tools: Path, method: str,
                   key: bytes, seconds: int, cap: int):
    controller = Path(__file__).resolve().parent
    folder = case / method
    folder.mkdir(mode=0o700)
    account = pwd.getpwnam("researcher")
    os.chown(folder, account.pw_uid, account.pw_gid)
    before = file_hashes(inputs, INPUT_NAMES)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        if run_command(probe_command(tools, inputs, folder, controller,
                                     listener.getsockname()[1]),
                       case / (method + "-probe.log"), 30) != 0:
            raise RuntimeError(f"Historical sensitivity access probe failed: {method}")
    if file_hashes(inputs, INPUT_NAMES) != before:
        raise ValueError("Access probe changed sensitivity input")
    command = budget_command(tools, controller, inputs, folder, method, seconds, cap)
    if run_command(command, case / (method + ".log"), seconds + 360,
                   cpu_limit=seconds + 360) != 0:
        raise RuntimeError(f"Historical sensitivity method failed: {method}")
    if file_hashes(inputs, INPUT_NAMES) != before:
        raise ValueError("Historical sensitivity method changed input")
    result = folder / "result"
    outputs = own_outputs(result)
    os.chown(folder, 0, 0)
    folder.chmod(0o500)
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    record = {"schema": 1, "method": method, "search_seconds": seconds,
              "candidate_limit": cap, "inputs": before, "outputs": outputs,
              "tools": tool_hashes(tools), "comparison_software": file_hashes(controller, names),
              "sealed_utc": datetime.now(timezone.utc).isoformat()}
    write_json(case / (method + "-controller-seal.json"), seal_record(key, record))
    verify_evidence(key, case / (method + "-controller-seal.json"), inputs, result, tools)


def score_all(study: Path, case: Path, inputs: Path, row: dict, tools: Path, key: bytes):
    controller = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    code = file_hashes(controller, names)
    for method in METHODS:
        seal = verify_evidence(key, case / (method + "-controller-seal.json"),
                               inputs, case / method / "result", tools)
        if seal["method"] != method or seal["comparison_software"] != code:
            raise ValueError("Sensitivity software or method identity changed")
    sys.path.insert(0, str(tools / "blind_tls13"))
    sys.path.insert(0, str(tools / "offline_memory"))
    from evaluate import flow_truth, score_method, verify_seal

    _, _, reference = source_paths(study, row)
    targets = flow_truth(inputs / "traffic.pcap", reference / "workload-reference.json",
                         reference / "server-reference.keys")
    withheld = tuple(row["withheld"]) if row["kind"] == "withheld" else None
    scores = {}
    for method in METHODS:
        report, candidates = verify_seal(case / method / "result")
        if report["method"] != method or report["candidate_count"] != len(candidates):
            raise ValueError("Sensitivity method report changed")
        scores[method] = score_method(report, candidates, targets, row["kind"], withheld)
    write_json(case / "score.json", scores)
    return scores


def verify_completed(case: Path, inputs: Path, tools: Path, key: bytes,
                     controller: Path, case_id: str, seconds: int, cap: int):
    if (case / "failure.json").exists() or not (case / "reconciliation.json").exists():
        raise ValueError(f"Incomplete sensitivity attempt needs inspection: {case_id}/{setting_name(seconds, cap)}")
    report = verify_record(key, json.loads((case / "reconciliation.json").read_text()))
    if report["case_id"] != case_id or report["status"] != "scored" or \
            report["search_seconds"] != seconds or report["candidate_limit"] != cap or \
            report["score_sha256"] != sha256(case / "score.json"):
        raise ValueError("Sensitivity reconciliation changed")
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    code = file_hashes(controller, names)
    for method in METHODS:
        detail = verify_evidence(key, case / (method + "-controller-seal.json"),
                                 inputs, case / method / "result", tools)
        if detail["method"] != method or detail["comparison_software"] != code:
            raise ValueError("Sensitivity method evidence changed")
    return report


def run_setting(study: Path, replay: Path, destination: Path, volume: Path,
                case_id: str, seconds: int, cap: int, row: dict, tools: Path, key: bytes):
    require_separate_volume(destination, volume)
    require_free_space(volume)
    parent = prepare_case_folder(destination, case_id)
    case = parent / setting_name(seconds, cap)
    inputs = replay / "cases" / case_id / "inputs"
    controller = Path(__file__).resolve().parent
    if case.exists():
        return verify_completed(case, inputs, tools, key, controller, case_id, seconds, cap)
    case.mkdir(mode=0o711)
    case.chmod(0o711)
    try:
        _, source = verify_replayed_case(study, replay, case_id, tools)
        for method in METHODS:
            if method in {"structured", "entropy"}:
                run_historical(case, inputs, tools, method, key, seconds, cap)
            else:
                run_comparator(case, inputs, tools, method, key, seconds, cap)
        scores = score_all(study, case, inputs, row, tools, key)
        report = {"case_id": case_id, "status": "scored",
                  "source_replay_status": source["status"],
                  "search_seconds": seconds, "candidate_limit": cap,
                  "score_sha256": sha256(case / "score.json"),
                  "correct_targets": {method: scores[method]["correct_targets"] for method in METHODS},
                  "false_assignments": {method: scores[method]["false_assignments"] for method in METHODS}}
        write_json(case / "reconciliation.json", seal_record(key, report))
        return report
    except Exception as error:
        write_json(case / "failure.json", seal_record(key, {
            "case_id": case_id, "status": "failed_unscored",
            "search_seconds": seconds, "candidate_limit": cap,
            "stage_error": type(error).__name__, "message": str(error),
            "recorded_utc": datetime.now(timezone.utc).isoformat()}))
        raise


def run(study: Path, replay: Path, destination: Path, volume: Path,
        selection: Path, case_id: str | None, seconds: int | None, cap: int | None):
    if os.geteuid() != 0:
        raise PermissionError("Sensitivity controller requires root")
    require_separate_volume(destination, volume)
    require_free_space(volume)
    selected = selected_cases(study, selection)
    if case_id is None:
        ids = selected
        budgets = settings(None, None)
    else:
        state = json.loads((study / "state.json").read_text())
        if case_id not in {row["case_id"] for row in state["cases"] if row["status"] == "scored"}:
            raise ValueError("Unknown sensitivity pilot case")
        ids = (case_id,)
        budgets = settings(seconds, cap)
    _, tools = frozen_tools(study)
    rows = {row["case_id"]: row for row in json.loads((study / "state.json").read_text())["cases"]}
    destination.mkdir(mode=0o711, parents=True, exist_ok=True)
    destination.chmod(0o711)
    key = key_at(destination / "controller.key")
    freeze(study, replay, destination, selection, key, ids, budgets)
    hashes = {}
    for selected_id in ids:
        for selected_seconds, selected_cap in budgets:
            report = run_setting(study, replay, destination, volume, selected_id,
                                 selected_seconds, selected_cap, rows[selected_id], tools, key)
            hashes[f"{selected_id}/{setting_name(selected_seconds, selected_cap)}"] = report["score_sha256"]
    summary = {"schema": 1, "status": "scored", "case_ids": list(ids),
               "budgets": [{"search_seconds": s, "candidate_limit": c} for s, c in budgets],
               "score_sha256": hashes, "completed_utc": datetime.now(timezone.utc).isoformat()}
    path = destination / "sensitivity-summary.json"
    if path.exists():
        previous = verify_record(key, json.loads(path.read_text()))
        if previous["case_ids"] != summary["case_ids"] or \
                previous["budgets"] != summary["budgets"] or \
                previous["score_sha256"] != summary["score_sha256"]:
            raise ValueError("Sensitivity summary changed")
    else:
        write_json(path, seal_record(key, summary))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--volume", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--case-id")
    parser.add_argument("--search-seconds", type=int)
    parser.add_argument("--candidate-limit", type=int)
    args = parser.parse_args()
    if (args.case_id is None) != (args.search_seconds is None) or \
            (args.case_id is None) != (args.candidate_limit is None):
        parser.error("Pilot requires case ID, search seconds, and candidate limit together")
    run(args.study, args.replay, args.destination, args.volume, args.selection,
        args.case_id, args.search_seconds, args.candidate_limit)


if __name__ == "__main__":
    main()
