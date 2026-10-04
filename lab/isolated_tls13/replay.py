#!/usr/bin/env python3
"""Replay retained blind-study cases in new sandboxes without changing methods."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import uuid

from sandbox import probe_command, recovery_command
from seals import (INPUT_NAMES, OUTPUT_NAMES, file_hashes, key_at, seal_record,
                   sha256, tool_hashes, verify_evidence, verify_record)

MIN_FREE_BYTES = 20 * 1024 ** 3


def write_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    path.chmod(0o600)


def frozen_tools(study: Path):
    manifest = json.loads((study / "manifest.json").read_text())
    tools = study / "tools"
    for name, expected in manifest["script_sha256"].items():
        if sha256(tools / name) != expected:
            raise ValueError(f"Historical script changed: {name}")
    if manifest["mode"] != "final" or len(manifest["cases"]) != 100:
        raise ValueError("Expected the retained 100-case final study")
    return manifest, tools


def freeze_controller(study: Path, destination: Path, key: bytes):
    source = Path(__file__).resolve().parent
    names = tuple(sorted(path.name for path in source.glob("*.py")))
    record = {"schema": 1, "historical_study": study.name,
              "historical_manifest_sha256": sha256(study / "manifest.json"),
              "historical_state_sha256": sha256(study / "state.json"),
              "controller": file_hashes(source, names),
              "minimum_free_bytes": MIN_FREE_BYTES}
    path = destination / "controller-manifest.json"
    if path.exists():
        saved = verify_record(key, json.loads(path.read_text()))
        if saved != record:
            raise ValueError("Replay controller or retained study changed after freeze")
    else:
        write_json(path, seal_record(key, record))


def source_paths(study: Path, row: dict):
    cases = study / "cases"
    references = Path("/root/tlkh-blind-reference") / study.name
    own = cases / row["case_id"]
    if row["kind"] == "mismatch":
        return own / "firefox.core", cases / row["donor"] / "traffic.pcap", references / row["donor"]
    if row["kind"] == "unrelated":
        name = row["case_id"] + "-decoy"
        return own / "firefox.core", cases / name / "traffic.pcap", references / name
    if row["kind"] == "withheld":
        return own / "redacted.core", own / "traffic.pcap", references / row["case_id"]
    return own / "firefox.core", own / "traffic.pcap", references / row["case_id"]


def prepare_case_folder(destination: Path, case_id: str):
    case = destination / "cases" / case_id
    case.parent.mkdir(mode=0o711, exist_ok=True)
    case.parent.chmod(0o711)
    if case.exists():
        return case
    case.mkdir(mode=0o711)
    case.chmod(0o711)
    return case


def stage(study: Path, row: dict, manifest: dict, destination: Path):
    core, pcap, reference = source_paths(study, row)
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    values = {"memory.core": core, "traffic.pcap": pcap}
    for name, source in values.items():
        target = destination / name
        subprocess.run(["cp", "--sparse=always", "--reflink=auto", str(source), str(target)], check=True)
        target.chmod(0o444)
        if sha256(source) != sha256(target):
            raise ValueError(f"Sparse staging changed {name}")
    metadata = {"architecture": "linux-x86_64", "firefox_version": "136.0.2",
                "cipher_suite": "0x1302", "target_hashes": manifest["target_hashes"]}
    (destination / "target.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    (destination / "target.json").chmod(0o444)
    expected = json.loads((study / "results" / row["case_id"] / "structured" / "decisions.json").read_text())[
        "input_sha256"]
    actual = file_hashes(destination, INPUT_NAMES)
    if actual["memory.core"]["sha256"] != expected["core"] or actual["traffic.pcap"]["sha256"] != expected["pcap"] or actual["target.json"]["sha256"] != expected["metadata"]:
        raise ValueError("Retained input differs from its original recovery record")
    return actual, reference


def run_command(argv, log: Path, timeout: int, cpu_limit: int = 540):
    unit = "tlkh-isolated-" + uuid.uuid4().hex + ".service"
    bounded = ["systemd-run", "--unit=" + unit, "--wait", "--collect", "--pipe",
               "-p", "MemoryMax=14G", "-p", "MemorySwapMax=0",
               "-p", "TasksMax=64", "-p", "LimitAS=17179869184",
               "-p", f"LimitCPU={cpu_limit}", "-p", f"RuntimeMaxSec={timeout}s", *argv]
    with log.open("wb") as stream:
        process = subprocess.Popen(bounded, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
        try:
            return process.wait(timeout=timeout + 30)
        except subprocess.TimeoutExpired:
            subprocess.run(["systemctl", "stop", unit], check=False, timeout=30)
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise TimeoutError(f"Recovery exceeded {timeout} seconds")


def own_outputs(path: Path):
    expected = set(OUTPUT_NAMES)
    if set(p.name for p in path.iterdir()) != expected:
        raise ValueError("Unexpected or missing recovery output files")
    files = file_hashes(path, OUTPUT_NAMES)
    for name in OUTPUT_NAMES:
        os.chown(path / name, 0, 0)
        (path / name).chmod(0o400)
    os.chown(path, 0, 0)
    path.chmod(0o500)
    return files


def run_method(case: Path, method: str, tools: Path, key: bytes, case_id: str, controller: Path):
    folder = case / method
    folder.mkdir(mode=0o700)
    account = pwd.getpwnam("researcher")
    os.chown(folder, account.pw_uid, account.pw_gid)
    inputs = case / "inputs"
    before = file_hashes(inputs, INPUT_NAMES)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        probe = probe_command(tools, inputs, folder, controller, listener.getsockname()[1])
        if run_command(probe, case / (method + "-probe.log"), 30) != 0:
            raise RuntimeError(f"Sandbox access probe failed for {method}")
    after_probe = file_hashes(inputs, INPUT_NAMES)
    if before != after_probe:
        raise ValueError("Access probe modified recovery input")
    command = recovery_command(tools, inputs, folder, method)
    status = run_command(command, case / (method + ".log"), 570)
    if status != 0:
        raise RuntimeError(f"Frozen {method} exited with status {status}")
    if file_hashes(inputs, INPUT_NAMES) != before:
        raise ValueError("Recovery input changed while method ran")
    result = folder / "result"
    output_hashes = own_outputs(result)
    os.chown(folder, 0, 0)
    folder.chmod(0o500)
    record = {"schema": 1, "case_id": case_id, "method": method,
              "sealed_utc": datetime.now(timezone.utc).isoformat(),
              "inputs": before, "outputs": output_hashes, "tools": tool_hashes(tools)}
    write_json(case / (method + "-controller-seal.json"), seal_record(key, record))
    verify_evidence(key, case / (method + "-controller-seal.json"), inputs, result, tools)


def compare_original(study: Path, case: Path, row: dict):
    def indexed(report):
        return {(item["client_random"], item["direction"]):
                (item["status"], item["candidate_id"], item["reason"])
                for item in report["decisions"]}

    differences = []
    for method in ("structured", "entropy"):
        old = study / "results" / row["case_id"] / method
        new = case / method / "result"
        old_report = json.loads((old / "decisions.json").read_text())
        new_report = json.loads((new / "decisions.json").read_text())
        old_decisions, new_decisions = indexed(old_report), indexed(new_report)
        for target in sorted(set(old_decisions) | set(new_decisions)):
            if old_decisions.get(target) != new_decisions.get(target):
                differences.append({"method": method, "target": target,
                                    "old": old_decisions.get(target),
                                    "new": new_decisions.get(target)})
    return differences


def score(study: Path, case: Path, row: dict, reference: Path, tools: Path):
    _, pcap, _ = source_paths(study, row)
    command = ["/usr/bin/python3", str(tools / "blind_tls13/evaluate.py"),
               "--structured", str(case / "structured/result"),
               "--entropy", str(case / "entropy/result"),
               "--core", str(case / "inputs/memory.core"),
               "--pcap", str(case / "inputs/traffic.pcap"),
               "--workload", str(reference / "workload-reference.json"),
               "--keylog", str(reference / "server-reference.keys"),
               "--kind", row["kind"], "--output", str(case / "score.json")]
    if row["kind"] == "withheld":
        command += ["--withheld-random", row["withheld"][0],
                    "--withheld-direction", row["withheld"][1]]
    if run_command(command, case / "score.log", 120) != 0:
        raise RuntimeError("Frozen evaluator failed after verified seals")
    return json.loads((case / "score.json").read_text())


def replay(study: Path, destination: Path, case_id: str | None = None, limit: int | None = None):
    if os.geteuid() != 0:
        raise PermissionError("Controller requires root to isolate references and own seals")
    manifest, tools = frozen_tools(study)
    state = json.loads((study / "state.json").read_text())
    rows = state["cases"]
    if len(rows) != 100 or any(row["status"] != "scored" for row in rows):
        raise ValueError("Historical campaign is incomplete")
    destination.mkdir(mode=0o711, parents=True, exist_ok=True)
    destination.chmod(0o711)
    key = key_at(destination / "controller.key")
    freeze_controller(study, destination, key)
    chosen = [(index, row) for index, row in enumerate(rows)
              if case_id is None or row["case_id"] == case_id]
    if case_id and not chosen:
        raise ValueError("Unknown retained case")
    failures = []
    for index, row in chosen[:limit]:
        if shutil.disk_usage(destination).free < MIN_FREE_BYTES:
            raise OSError("Replay paused at the 20 GiB free-space reserve")
        case = destination / "cases" / row["case_id"]
        if case.exists():
            if (case / "reconciliation.json").exists():
                continue
            raise ValueError(f"Existing partial replay needs inspection: {case}")
        case = prepare_case_folder(destination, row["case_id"])
        try:
            _, reference = stage(study, row, manifest, case / "inputs")
            controller = Path(__file__).resolve().parent
            order = ("structured", "entropy") if index % 2 == 0 else ("entropy", "structured")
            for method in order:
                run_method(case, method, tools, key, row["case_id"], controller)
            for method in ("structured", "entropy"):
                verify_evidence(key, case / (method + "-controller-seal.json"),
                                case / "inputs", case / method / "result", tools)
            scored = score(study, case, row, reference, tools)
            differences = compare_original(study, case, row)
            original = row["score"]
            score_changes = {method: {name: [original[method][name], scored[method][name]]
                                      for name in ("case_success", "correct_targets", "false_assignments", "abstentions")
                                      if original[method][name] != scored[method][name]}
                             for method in ("structured", "entropy")}
            write_json(case / "reconciliation.json", seal_record(key, {"case_id": row["case_id"],
                "original_kind": row["kind"], "method_order": order,
                "assignment_differences": differences,
                "score_differences": score_changes,
                "score_sha256": sha256(case / "score.json"),
                "status": "matched" if not differences and not any(score_changes.values()) else "different"}))
        except Exception as error:
            failure = {"case_id": row["case_id"], "status": "failed_unscored",
                       "stage_error": type(error).__name__, "message": str(error),
                       "recorded_utc": datetime.now(timezone.utc).isoformat()}
            write_json(case / "failure.json", seal_record(key, failure))
            failures.append(f"{row['case_id']}: {type(error).__name__}: {error}")
    if failures:
        raise RuntimeError(f"{len(failures)} replay case(s) failed; see sealed failure records: "
                           + "; ".join(failures))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--case-id")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    replay(args.study, args.destination, args.case_id, args.limit)


if __name__ == "__main__":
    main()
