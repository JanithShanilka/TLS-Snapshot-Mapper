#!/usr/bin/env python3
"""Controller for separate, sealed saved-image comparison experiments."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import socket
import sys

from replay import (MIN_FREE_BYTES, frozen_tools, own_outputs, prepare_case_folder, run_command,
                    source_paths, write_json)
from sandbox import comparison_command, probe_command
from seals import (INPUT_NAMES, file_hashes, key_at, seal_record,
                   sha256, tool_hashes, verify_evidence, verify_record)


METHODS = ("structure_only", "anderson_nss_adjacent", "xray_full_snapshot_entropy")


def require_separate_volume(destination: Path, volume: Path):
    """Refuse to stage evidence on the server disk if the volume is unmounted."""
    volume = volume.resolve()
    destination = destination.resolve()
    if not destination.is_relative_to(volume) or destination == volume:
        raise ValueError("Comparison destination must be inside the declared volume")
    if not volume.is_mount() or volume.stat().st_dev == volume.parent.stat().st_dev:
        raise ValueError("Declared comparison volume is not a separate mounted filesystem")
    return volume


def require_free_space(volume: Path):
    available = os.statvfs(volume).f_bavail * os.statvfs(volume).f_frsize
    if available < MIN_FREE_BYTES:
        raise ValueError("Comparison volume has less than 20 GiB free")


def verify_replayed_case(study: Path, replay: Path, case_id: str, tools: Path):
    root_key = (replay / "controller.key").read_bytes()
    frozen = verify_record(root_key, json.loads((replay / "controller-manifest.json").read_text()))
    if frozen["historical_manifest_sha256"] != sha256(study / "manifest.json") or \
            frozen["historical_state_sha256"] != sha256(study / "state.json"):
        raise ValueError("Source replay was not sealed against this historical study")
    case = replay / "cases" / case_id
    report = verify_record(root_key, json.loads((case / "reconciliation.json").read_text()))
    if report["case_id"] != case_id or report["status"] not in {"matched", "different"}:
        raise ValueError("Source replay case has no completed reconciliation")
    if report["score_sha256"] != sha256(case / "score.json"):
        raise ValueError("Source replay score changed")
    for method in ("structured", "entropy"):
        verify_evidence(root_key, case / (method + "-controller-seal.json"),
                        case / "inputs", case / method / "result", tools)
    return case / "inputs", report


def freeze_comparison(study: Path, replay: Path, destination: Path, key: bytes,
                      search_seconds: int, candidate_limit: int, case_ids):
    code = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in code.glob("*.py")))
    record = {"schema": 1, "historical_study": study.name,
              "historical_manifest_sha256": sha256(study / "manifest.json"),
              "historical_state_sha256": sha256(study / "state.json"),
              "source_replay_manifest_sha256": sha256(replay / "controller-manifest.json"),
              "controller": file_hashes(code, names), "methods": list(METHODS),
              "search_seconds": search_seconds, "candidate_limit": candidate_limit,
              "authentication_seconds": 300, "case_ids": list(case_ids)}
    path = destination / "comparison-manifest.json"
    if path.exists():
        if verify_record(key, json.loads(path.read_text())) != record:
            raise ValueError("Comparison controller or inputs changed after freeze")
    else:
        write_json(path, seal_record(key, record))
    return record


def run_method(case: Path, inputs: Path, tools: Path, method: str, key: bytes,
               search_seconds: int, candidate_limit: int):
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
            raise RuntimeError(f"Comparison access probe failed: {method}")
    if file_hashes(inputs, INPUT_NAMES) != before:
        raise ValueError("Comparison access probe changed an input")
    command = comparison_command(tools, controller, inputs, folder, method,
                                 search_seconds, candidate_limit)
    if run_command(command, case / (method + ".log"), search_seconds + 360,
                   cpu_limit=search_seconds + 360) != 0:
        raise RuntimeError(f"Comparison method failed: {method}")
    if file_hashes(inputs, INPUT_NAMES) != before:
        raise ValueError("Comparison method changed an input")
    result = folder / "result"
    outputs = own_outputs(result)
    os.chown(folder, 0, 0)
    folder.chmod(0o500)
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    record = {"schema": 1, "method": method, "inputs": before,
              "outputs": outputs, "tools": tool_hashes(tools),
              "comparison_software": file_hashes(controller, names),
              "sealed_utc": datetime.now(timezone.utc).isoformat()}
    write_json(case / (method + "-controller-seal.json"), seal_record(key, record))
    verify_evidence(key, case / (method + "-controller-seal.json"), inputs, result, tools)


def score(study: Path, case: Path, inputs: Path, row: dict, tools: Path, key: bytes):
    controller = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    for method in METHODS:
        seal = case / (method + "-controller-seal.json")
        record = verify_evidence(key, seal, inputs, case / method / "result", tools)
        if record["comparison_software"] != file_hashes(controller, names):
            raise ValueError("Comparison software changed after method exit")

    sys.path.insert(0, str(tools / "blind_tls13"))
    sys.path.insert(0, str(tools / "offline_memory"))
    from evaluate import flow_truth, score_method, verify_seal

    _, _, reference = source_paths(study, row)
    targets = flow_truth(inputs / "traffic.pcap", reference / "workload-reference.json",
                         reference / "server-reference.keys")
    withheld = tuple(row["withheld"]) if row["kind"] == "withheld" else None
    result = {}
    for method in METHODS:
        report, candidates = verify_seal(case / method / "result")
        if report["method"] != method or report["candidate_count"] != len(candidates):
            raise ValueError("Comparator identity or candidate count changed")
        result[method] = score_method(report, candidates, targets, row["kind"], withheld)
    write_json(case / "score.json", result)
    return result


def compare(study: Path, replay: Path, destination: Path, volume: Path,
            case_id: str, search_seconds: int, candidate_limit: int,
            campaign_case_ids=None):
    if os.geteuid() != 0:
        raise PermissionError("Comparison controller requires root")
    if search_seconds not in {30, 180, 600} or candidate_limit not in {25, 100, 1000}:
        raise ValueError("Comparison budget is outside the declared grid")
    require_separate_volume(destination, volume)
    require_free_space(volume)
    _, tools = frozen_tools(study)
    state = json.loads((study / "state.json").read_text())
    matching = [row for row in state["cases"] if row["case_id"] == case_id]
    if len(matching) != 1:
        raise ValueError("Unknown retained case")
    selected = tuple(campaign_case_ids) if campaign_case_ids is not None else (case_id,)
    if case_id not in selected or len(selected) != len(set(selected)):
        raise ValueError("Comparison case selection is inconsistent")
    row = matching[0]
    destination.mkdir(mode=0o711, parents=True, exist_ok=True)
    destination.chmod(0o711)
    key = key_at(destination / "controller.key")
    case = prepare_case_folder(destination, case_id)
    if any(case.iterdir()):
        raise ValueError("Comparison case already attempted; preserve its evidence")
    try:
        freeze_comparison(study, replay, destination, key, search_seconds,
                          candidate_limit, selected)
        inputs, source_report = verify_replayed_case(study, replay, case_id, tools)
        for method in METHODS:
            run_method(case, inputs, tools, method, key, search_seconds, candidate_limit)
        results = score(study, case, inputs, row, tools, key)
        write_json(case / "reconciliation.json", seal_record(key, {
            "case_id": case_id, "source_replay_status": source_report["status"],
            "score_sha256": sha256(case / "score.json"),
            "correct_targets": {method: results[method]["correct_targets"] for method in METHODS},
            "false_assignments": {method: results[method]["false_assignments"] for method in METHODS},
            "status": "scored"}))
    except Exception as error:
        write_json(case / "failure.json", seal_record(key, {
            "case_id": case_id, "status": "failed_unscored", "stage_error": type(error).__name__,
            "message": str(error), "recorded_utc": datetime.now(timezone.utc).isoformat()}))
        raise


def campaign_ids(study: Path):
    state = json.loads((study / "state.json").read_text())
    rows = state["cases"]
    ids = tuple(row["case_id"] for row in rows)
    if len(ids) != 100 or len(set(ids)) != 100 or any(row["status"] != "scored" for row in rows):
        raise ValueError("Primary comparison requires exactly 100 distinct scored cases")
    return ids


def compare_campaign(study: Path, replay: Path, destination: Path, volume: Path,
                     search_seconds: int, candidate_limit: int):
    if os.geteuid() != 0:
        raise PermissionError("Comparison controller requires root")
    if search_seconds not in {30, 180, 600} or candidate_limit not in {25, 100, 1000}:
        raise ValueError("Comparison budget is outside the declared grid")
    require_separate_volume(destination, volume)
    require_free_space(volume)
    ids = campaign_ids(study)
    destination.mkdir(mode=0o711, parents=True, exist_ok=True)
    destination.chmod(0o711)
    key = key_at(destination / "controller.key")
    freeze_comparison(study, replay, destination, key, search_seconds,
                      candidate_limit, ids)
    _, tools = frozen_tools(study)
    controller = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in controller.glob("*.py")))
    results = {}
    for case_id in ids:
        require_separate_volume(destination, volume)
        require_free_space(volume)
        case = destination / "cases" / case_id
        if case.exists():
            path = case / "reconciliation.json"
            if not path.exists() or (case / "failure.json").exists():
                raise ValueError(f"Existing incomplete comparison attempt needs inspection: {case_id}")
            report = verify_record(key, json.loads(path.read_text()))
            if report["case_id"] != case_id or report["status"] != "scored" or \
                    report["score_sha256"] != sha256(case / "score.json"):
                raise ValueError(f"Existing comparison result changed: {case_id}")
            inputs = replay / "cases" / case_id / "inputs"
            for method in METHODS:
                seal = verify_evidence(key, case / (method + "-controller-seal.json"),
                                       inputs, case / method / "result", tools)
                if seal["method"] != method or \
                        seal["comparison_software"] != file_hashes(controller, names):
                    raise ValueError(f"Existing comparison method changed: {case_id}/{method}")
        else:
            compare(study, replay, destination, volume, case_id,
                    search_seconds, candidate_limit, ids)
            report = verify_record(key, json.loads((case / "reconciliation.json").read_text()))
        results[case_id] = report["score_sha256"]
    summary = {"schema": 1, "status": "scored", "case_ids": list(ids),
               "score_sha256": results, "completed_utc": datetime.now(timezone.utc).isoformat()}
    path = destination / "campaign-summary.json"
    if path.exists():
        previous = verify_record(key, json.loads(path.read_text()))
        if previous["case_ids"] != summary["case_ids"] or \
                previous["score_sha256"] != summary["score_sha256"]:
            raise ValueError("Existing comparison campaign summary changed")
    else:
        write_json(path, seal_record(key, summary))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--volume", type=Path, required=True,
                        help="Expected separate mounted volume containing destination")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--case-id")
    selection.add_argument("--all-cases", action="store_true")
    parser.add_argument("--search-seconds", type=int, default=180)
    parser.add_argument("--candidate-limit", type=int, default=100)
    args = parser.parse_args()
    if args.all_cases:
        compare_campaign(args.study, args.replay, args.destination, args.volume,
                         args.search_seconds, args.candidate_limit)
    else:
        compare(args.study, args.replay, args.destination, args.volume, args.case_id,
                args.search_seconds, args.candidate_limit)


if __name__ == "__main__":
    main()
