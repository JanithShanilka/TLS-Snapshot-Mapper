#!/usr/bin/env python3
"""Evaluator-controlled transfer study on preselected Firefox/NSS builds.

Only acquisition paths and declared build metadata differ from the historical
study. Recovery candidate discovery, authentication, and scoring are copied
from the retained 100-case study and run behind the existing sandbox boundary.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import random
import shutil
import socket
import subprocess
import sys

from comparison_study import require_free_space, require_separate_volume
from replay import own_outputs, run_command, write_json
from sandbox import probe_command, recovery_command
from seals import (INPUT_NAMES, file_hashes, key_at, seal_record, sha256,
                   tool_hashes, verify_evidence, verify_record)

METHODS = ("structured", "entropy")
SOURCE_STUDY = "BLIND-FINAL-20260930-A"
REFERENCE_ROOT = Path("/root/tlkh-unseen-reference")


def utc():
    return datetime.now(timezone.utc).isoformat()


def controller_hashes():
    folder = Path(__file__).resolve().parent
    return file_hashes(folder, tuple(sorted(path.name for path in folder.glob("*.py"))))


def design(selection, pilot, seed):
    rng = random.Random(int(seed, 16))
    rows = []
    for build in selection["builds"]:
        version = build["firefox_version"]
        if pilot:
            kinds = [("positive", 2)]
        else:
            kinds = ([("positive", 2)] * build["positive_two_flow"] +
                     [("positive", 3)] * build["positive_three_flow"] +
                     [("mismatch", 2), ("mismatch", 3)] +
                     [("unrelated", 2), ("unrelated", 3)] +
                     [("withheld", 2), ("withheld", 3)])
            if (build["mismatch_controls"], build["unrelated_controls"],
                    build["withheld_controls"]) != (2, 2, 2):
                raise ValueError("Frozen control allocation differs from controller")
            rng.shuffle(kinds)
        group = []
        for kind, count in kinds:
            group.append({"case_id": "U" + f"{rng.getrandbits(64):016x}",
                          "build": version, "kind": kind, "connections": count})
        mismatch = [row for row in group if row["kind"] == "mismatch"]
        if mismatch:
            mismatch[0]["donor"] = mismatch[1]["case_id"]
            mismatch[1]["donor"] = mismatch[0]["case_id"]
        rows.extend(group)
    if len({row["case_id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate generated case ID")
    if len(rows) != (2 if pilot else 40):
        raise ValueError("Frozen case count differs from controller")
    return rows


def replace_exact(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Declared metadata token missing or duplicated")
    return source.replace(before, after)


def prepare_tools(study, source_study, build):
    version = build["firefox_version"]
    target = study / "tools" / version
    source = source_study / "tools"
    shutil.copytree(source, target)
    expected = {
        "firefox": build["firefox_sha256"],
        "libssl3.so": build["libssl3_so_sha256"],
        "libsoftokn3.so": build["libsoftokn3_so_sha256"],
    }
    historical = json.loads((source_study / "manifest.json").read_text())["target_hashes"]
    for relative in ("blind_tls13/capture_blind.py", "blind_tls13/recover.py"):
        path = target / relative
        content = path.read_text()
        content = replace_exact(content, '"136.0.2"', json.dumps(version))
        for name, old_hash in historical.items():
            content = replace_exact(content, json.dumps(old_hash), json.dumps(expected[name]))
        path.chmod(0o644)
        path.write_text(content)
        path.chmod(0o444)
    return {"source_tool_hashes": {name: sha256(source / name) for name in
             json.loads((source_study / "manifest.json").read_text())["script_sha256"]},
            "adapted_tool_hashes": tool_hashes(target)}


def prepare(study, source_study, selection_path, builds_root, volume, pilot, seed):
    require_separate_volume(study, volume)
    require_free_space(volume)
    selection = json.loads(selection_path.read_text())
    source_manifest = json.loads((source_study / "manifest.json").read_text())
    if (source_study.name != SOURCE_STUDY or
            sha256(source_study / "manifest.json") != selection["historical_manifest_sha256"] or
            len(selection["builds"]) != 2):
        raise ValueError("Frozen selection does not match historical study")
    for name, expected in source_manifest["script_sha256"].items():
        if sha256(source_study / "tools" / name) != expected:
            raise ValueError("Historical source tool changed")
    for build in selection["builds"]:
        root = builds_root / build["firefox_version"]
        if sha256(root / f"firefox-{build['firefox_version']}.tar.xz") != build["archive_sha256"]:
            raise ValueError("Pinned Firefox archive changed")
        executable = root / "unpacked/firefox/firefox"
        for name, field in (("firefox", "firefox_sha256"),
                            ("libnss3.so", "libnss3_so_sha256"),
                            ("libssl3.so", "libssl3_so_sha256"),
                            ("libsoftokn3.so", "libsoftokn3_so_sha256")):
            if sha256(executable.parent / name) != build[field]:
                raise ValueError(f"Pinned {name} changed for {build['firefox_version']}")
    rows = design(selection, pilot, seed)
    study.mkdir(mode=0o711, parents=True, exist_ok=False)
    study.chmod(0o711)
    (study / "cases").mkdir(mode=0o711)
    (study / "cases").chmod(0o711)
    (study / "tools").mkdir(mode=0o755)
    (study / "tools").chmod(0o755)
    key = key_at(study / "controller.key")
    tool_records = {build["firefox_version"]: prepare_tools(study, source_study, build)
                    for build in selection["builds"]}
    record = {"schema": 1, "phase": "unseen_build_pilot" if pilot else "unseen_build_transfer",
              "frozen_utc": utc(), "selection_sha256": sha256(selection_path),
              "historical_manifest_sha256": sha256(source_study / "manifest.json"),
              "historical_state_sha256": sha256(source_study / "state.json"),
              "controller": controller_hashes(), "builds": selection["builds"],
              "tools": tool_records, "case_rows": rows, "search_seconds": 180,
              "candidate_limit": 100, "authentication_seconds": 300,
              "minimum_free_bytes": 20 * 1024 ** 3,
              "policy": "Preserve every attempted failure; no replacement or quiet exclusion"}
    write_json(study / "manifest.json", seal_record(key, record))
    write_json(study / "state.json", {"state": "frozen", "cases": [
        {**row, "status": "planned"} for row in rows]})
    return record


def verify_frozen(study, source_study, selection_path, builds_root, volume):
    require_separate_volume(study, volume)
    require_free_space(volume)
    key = key_at(study / "controller.key")
    record = verify_record(key, json.loads((study / "manifest.json").read_text()))
    if (record["controller"] != controller_hashes() or
            record["selection_sha256"] != sha256(selection_path) or
            record["historical_manifest_sha256"] != sha256(source_study / "manifest.json") or
            record["historical_state_sha256"] != sha256(source_study / "state.json")):
        raise ValueError("Unseen-build controller or preregistration changed")
    for build in record["builds"]:
        version = build["firefox_version"]
        if tool_hashes(study / "tools" / version) != record["tools"][version]["adapted_tool_hashes"]:
            raise ValueError("Frozen recovery software changed")
        executable = builds_root / version / "unpacked/firefox/firefox"
        for name, field in (("firefox", "firefox_sha256"), ("libnss3.so", "libnss3_so_sha256"),
                            ("libssl3.so", "libssl3_so_sha256"),
                            ("libsoftokn3.so", "libsoftokn3_so_sha256")):
            if sha256(executable.parent / name) != build[field]:
                raise ValueError("Declared Firefox/NSS build changed")
    return record, key


def sources(study, row):
    own = study / "cases" / row["case_id"]
    reference = REFERENCE_ROOT / study.name / row["case_id"]
    if row["kind"] == "mismatch":
        donor = row["donor"]
        return own / "firefox.core", study / "cases" / donor / "traffic.pcap", \
            REFERENCE_ROOT / study.name / donor
    if row["kind"] == "unrelated":
        decoy = row["case_id"] + "-decoy"
        return own / "firefox.core", study / "cases" / decoy / "traffic.pcap", \
            REFERENCE_ROOT / study.name / decoy
    if row["kind"] == "withheld":
        return own / "redacted.core", own / "traffic.pcap", reference
    return own / "firefox.core", own / "traffic.pcap", reference


def acquisition_command(argv, log, timeout):
    """Capture needs Firefox's normal process/thread count; recovery remains bounded."""
    with log.open("wb") as stream:
        result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
    return result.returncode


def capture_case(study, row, builds_root):
    case_id, version = row["case_id"], row["build"]
    root = REFERENCE_ROOT / study.name
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    tools = study / "tools" / version
    command = ["/home/researcher/.venv/bin/python",
               str(tools / "blind_tls13/capture_blind.py"), "--case",
               str(study / "cases" / case_id), "--reference", str(root / case_id),
               "--connections", str(row["connections"]), "--firefox",
               str(builds_root / version / "unpacked/firefox/firefox"),
               "--lab-disable-socket-sandbox", "--lab-accept-insecure-certs"]
    log = study / "cases" / (case_id + "-capture.log")
    if acquisition_command(command, log, 330) != 0:
        raise RuntimeError("Unseen-build acquisition failed; preserved attempt")
    acquired = json.loads((study / "cases" / case_id / "acquisition.json").read_text())
    if acquired["status"] != "captured":
        raise ValueError("Acquisition did not complete")
    if row["kind"] == "unrelated":
        decoy = ["/home/researcher/.venv/bin/python",
                 str(tools / "blind_tls13/capture_decoy.py"), "--case",
                 str(study / "cases" / (case_id + "-decoy")), "--reference",
                 str(root / (case_id + "-decoy")), "--port", "18453",
                 "--connections", str(row["connections"])]
        if acquisition_command(decoy, study / "cases" / (case_id + "-decoy.log"), 180) != 0:
            raise RuntimeError("Unrelated-control capture failed; preserved attempt")
    return {"core_sha256": acquired["core_sha256"],
            "pcap_sha256": acquired["pcap_sha256"],
            "core_allocated_bytes": acquired["core_allocated_bytes"]}


def stage_case(study, row, build, key):
    case = study / "cases" / row["case_id"]
    core, pcap, reference = sources(study, row)
    if row["kind"] == "withheld":
        from importlib.util import spec_from_file_location, module_from_spec
        evaluator = study / "tools" / row["build"] / "blind_tls13/evaluate.py"
        sys.path.insert(0, str(evaluator.parent))
        spec = spec_from_file_location("frozen_evaluate", evaluator)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        truth = module.flow_truth(pcap, reference / "workload-reference.json",
                                  reference / "server-reference.keys")
        withheld = sorted(truth)[0]
        module.redact_core(case / "firefox.core", core, truth[withheld])
        row["withheld"] = list(withheld)
    # The capture leaves its case directory private. Allow UID 1000 to traverse
    # to the staged input directory; the sandbox mounts only that directory.
    case.chmod(0o711)
    inputs = case / "inputs"
    inputs.mkdir(mode=0o755)
    inputs.chmod(0o755)
    for name, source in (("memory.core", core), ("traffic.pcap", pcap)):
        subprocess.run(["cp", "--sparse=always", "--reflink=auto", str(source),
                        str(inputs / name)], check=True)
        (inputs / name).chmod(0o444)
        if sha256(source) != sha256(inputs / name):
            raise ValueError("Staged input changed")
    metadata = {"architecture": "linux-x86_64", "firefox_version": row["build"],
                "cipher_suite": "0x1302", "target_hashes": {
                    "firefox": build["firefox_sha256"],
                    "libssl3.so": build["libssl3_so_sha256"],
                    "libsoftokn3.so": build["libsoftokn3_so_sha256"]}}
    (inputs / "target.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    (inputs / "target.json").chmod(0o444)
    return inputs


def run_method(study, case, inputs, tools, method, key):
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
            raise RuntimeError("Isolation access probe failed")
    if before != file_hashes(inputs, INPUT_NAMES):
        raise ValueError("Access probe changed recovery input")
    if run_command(recovery_command(tools, inputs, folder, method),
                   case / (method + ".log"), 570) != 0:
        raise RuntimeError("Frozen recovery method failed")
    if before != file_hashes(inputs, INPUT_NAMES):
        raise ValueError("Recovery input changed")
    outputs = own_outputs(folder / "result")
    os.chown(folder, 0, 0)
    folder.chmod(0o500)
    write_json(case / (method + "-controller-seal.json"), seal_record(key, {
        "schema": 1, "method": method, "inputs": before, "outputs": outputs,
        "tools": tool_hashes(tools), "controller": controller_hashes(),
        "sealed_utc": utc()}))
    verify_evidence(key, case / (method + "-controller-seal.json"), inputs,
                    folder / "result", tools)


def score_case(study, row, inputs, tools, key):
    case = study / "cases" / row["case_id"]
    for method in METHODS:
        record = verify_evidence(key, case / (method + "-controller-seal.json"),
                                 inputs, case / method / "result", tools)
        if record["controller"] != controller_hashes():
            raise ValueError("Controller changed after sealing")
    from importlib.util import spec_from_file_location, module_from_spec
    evaluator = tools / "blind_tls13/evaluate.py"
    sys.path.insert(0, str(evaluator.parent))
    spec = spec_from_file_location("frozen_evaluate", evaluator)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    _, _, reference = sources(study, row)
    targets = module.flow_truth(inputs / "traffic.pcap",
                                reference / "workload-reference.json",
                                reference / "server-reference.keys")
    withheld = tuple(row["withheld"]) if row.get("withheld") else None
    score = {}
    for method in METHODS:
        report, candidates = module.verify_seal(case / method / "result")
        score[method] = module.score_method(report, candidates, targets,
                                            row["kind"], withheld)
    write_json(case / "score.json", score)
    write_json(case / "reconciliation.json", seal_record(key, {
        "case_id": row["case_id"], "build": row["build"], "kind": row["kind"],
        "status": "scored", "score_sha256": sha256(case / "score.json"),
        "methods": {method: {"case_success": score[method]["case_success"],
                             "correct_targets": score[method]["correct_targets"],
                             "false_assignments": score[method]["false_assignments"]}
                    for method in METHODS}, "completed_utc": utc()}))


def run(study, source_study, selection_path, builds_root, volume):
    record, key = verify_frozen(study, source_study, selection_path, builds_root, volume)
    state = json.loads((study / "state.json").read_text())
    if [row["case_id"] for row in state["cases"]] != [row["case_id"] for row in record["case_rows"]]:
        raise ValueError("Case allocation changed")
    by_version = {build["firefox_version"]: build for build in record["builds"]}
    for row in state["cases"]:
        if row["status"] != "planned":
            continue
        require_separate_volume(study, volume)
        require_free_space(volume)
        row["status"] = "attempted"
        row["started_utc"] = utc()
        write_json(study / "state.json", state)
        try:
            row["acquisition"] = capture_case(study, row, builds_root)
            row["status"] = "captured"
            write_json(study / "state.json", state)
            if row["kind"] != "mismatch":
                case = study / "cases" / row["case_id"]
                inputs = stage_case(study, row, by_version[row["build"]], key)
                tools = study / "tools" / row["build"]
                for method in METHODS:
                    run_method(study, case, inputs, tools, method, key)
                score_case(study, row, inputs, tools, key)
                row["status"] = "scored"
                row["ended_utc"] = utc()
                write_json(study / "state.json", state)
        except Exception as error:
            row.update(status="failed", failure_type=type(error).__name__,
                       failure=str(error), ended_utc=utc())
            write_json(study / "state.json", state)
            case = study / "cases" / row["case_id"]
            case.mkdir(mode=0o711, exist_ok=True)
            write_json(case / "failure.json", seal_record(key, {
                "case_id": row["case_id"], "status": "failed", "stage": "capture_or_recovery",
                "failure_type": type(error).__name__, "message": str(error),
                "recorded_utc": utc()}))
            raise
    for row in state["cases"]:
        if row["kind"] != "mismatch" or row["status"] != "captured":
            continue
        require_separate_volume(study, volume)
        require_free_space(volume)
        try:
            case = study / "cases" / row["case_id"]
            inputs = stage_case(study, row, by_version[row["build"]], key)
            tools = study / "tools" / row["build"]
            for method in METHODS:
                run_method(study, case, inputs, tools, method, key)
            score_case(study, row, inputs, tools, key)
            row["status"] = "scored"
            row["ended_utc"] = utc()
            write_json(study / "state.json", state)
        except Exception as error:
            row.update(status="failed", failure_type=type(error).__name__,
                       failure=str(error), ended_utc=utc())
            write_json(study / "state.json", state)
            case = study / "cases" / row["case_id"]
            write_json(case / "failure.json", seal_record(key, {
                "case_id": row["case_id"], "status": "failed", "stage": "mismatch_recovery",
                "failure_type": type(error).__name__, "message": str(error),
                "recorded_utc": utc()}))
            raise
    counts = {status: sum(row["status"] == status for row in state["cases"])
              for status in ("scored", "failed", "captured", "attempted", "planned")}
    summary = {"schema": 1, "case_count": len(state["cases"]), "counts": counts,
               "scored_hashes": {row["case_id"]: sha256(study / "cases" / row["case_id"] / "score.json")
                                 for row in state["cases"] if row["status"] == "scored"},
               "completed_utc": utc()}
    write_json(study / "campaign-summary.json", seal_record(key, summary))
    state["state"] = "completed" if counts["scored"] == len(state["cases"]) else "incomplete"
    write_json(study / "state.json", state)
    return summary


def main():
    if os.geteuid() != 0:
        raise PermissionError("Unseen-build evaluator requires root")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--builds", type=Path, required=True)
    parser.add_argument("--volume", type=Path, required=True)
    parser.add_argument("--prepare", choices=("pilot", "full"))
    parser.add_argument("--seed")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        import secrets
        record = prepare(args.study, args.historical, args.selection, args.builds,
                         args.volume, args.prepare == "pilot", args.seed or secrets.token_hex(16))
        print(json.dumps({"phase": record["phase"], "cases": len(record["case_rows"])}))
    if args.run:
        result = run(args.study, args.historical, args.selection, args.builds, args.volume)
        print(json.dumps({"case_count": result["case_count"], "counts": result["counts"]}))
    if not args.prepare and not args.run:
        parser.error("Choose --prepare and/or --run")


if __name__ == "__main__":
    main()
