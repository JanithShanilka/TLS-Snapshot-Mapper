#!/usr/bin/env python3
"""One-time, gated handoff from the primary comparison to sensitivity runs."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def command(argv, *, capture=False, timeout=None):
    return subprocess.run(argv, check=True, text=True, timeout=timeout,
                          capture_output=capture)


def check_volume(volume: Path, destination: Path):
    if not volume.is_mount() or volume.stat().st_dev == volume.parent.stat().st_dev or \
            not destination.resolve().is_relative_to(volume.resolve()):
        raise ValueError("Separate comparison volume is missing")
    if os.statvfs(volume).f_bavail * os.statvfs(volume).f_frsize < 20 * 1024 ** 3:
        raise ValueError("Comparison volume has less than 20 GiB free")


def service_state(unit: str):
    result = subprocess.run(["systemctl", "show", unit, "-p", "ActiveState", "--value"],
                            text=True, capture_output=True, check=False)
    return result.stdout.strip()


def wait_for_primary(unit: str, volume: Path, destination: Path, deadline_seconds: int):
    deadline = time.monotonic() + deadline_seconds
    while service_state(unit) in {"active", "activating", "reloading"}:
        try:
            check_volume(volume, destination)
        except ValueError:
            subprocess.run(["systemctl", "stop", unit], check=False)
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError("Primary comparison did not finish before the handoff deadline")
        time.sleep(30)
    check_volume(volume, destination)


def checked_audit(script: Path, args, expected: int):
    result = command([sys.executable, "-B", str(script), *args], capture=True,
                     timeout=max(3600, expected * 120))
    record = json.loads(result.stdout)
    if record["counts"] != {"scored": expected, "failed_unscored": 0,
                            "partial_unscored": 0, "not_attempted": 0}:
        raise ValueError("Audit did not score every predeclared setting")
    return record


def handoff(args):
    if os.geteuid() != 0:
        raise PermissionError("Handoff requires root")
    sys.path.insert(0, str(args.next_controller))
    from replay import write_json
    from seals import key_at, seal_record, sha256, verify_record

    check_volume(args.volume, args.primary)
    wait_for_primary(args.primary_unit, args.volume, args.primary,
                     args.wait_hours * 3600)
    primary_audit = checked_audit(args.next_controller / "audit_comparison.py", [
        "--study", str(args.study), "--replay", str(args.replay),
        "--destination", str(args.primary), "--controller", str(args.primary_controller)
    ], 100)
    if not primary_audit["campaign_summary_present"] or primary_audit["selected_cases"] != 100:
        raise ValueError("Primary comparison has no complete signed campaign summary")
    audit_path = args.primary / "audit-handoff.json"
    audit_record = {"schema": 1, "status": "verified", "counts": primary_audit["counts"],
                    "auditor_sha256": sha256(args.next_controller / "audit_comparison.py"),
                    "recorded_utc": datetime.now(timezone.utc).isoformat()}
    key = key_at(args.primary / "controller.key")
    if audit_path.exists():
        previous = verify_record(key, json.loads(audit_path.read_text()))
        if previous["status"] != "verified" or previous["counts"] != audit_record["counts"] or \
                previous["auditor_sha256"] != audit_record["auditor_sha256"]:
            raise ValueError("Existing primary handoff audit changed")
    else:
        write_json(audit_path, seal_record(key, audit_record))

    check_volume(args.volume, args.pilot)
    command([sys.executable, "-B", str(args.next_controller / "sensitivity_study.py"),
             "--study", str(args.study), "--replay", str(args.replay),
             "--destination", str(args.pilot), "--volume", str(args.volume),
             "--selection", str(args.selection), "--case-id", args.pilot_case_id,
             "--search-seconds", "30", "--candidate-limit", "25"], timeout=3600)
    pilot_audit = checked_audit(args.next_controller / "audit_sensitivity.py", [
        "--study", str(args.study), "--replay", str(args.replay),
        "--destination", str(args.pilot), "--selection", str(args.selection),
        "--controller", str(args.next_controller)
    ], 1)
    if not pilot_audit["summary_present"] or pilot_audit["total_settings"] != 1:
        raise ValueError("Sensitivity pilot is not completely sealed")

    check_volume(args.volume, args.full)
    if args.full.exists():
        if service_state(args.full_unit) == "active":
            return
        raise ValueError("Sensitivity destination exists without an active service")
    command(["systemd-run", "--unit=" + args.full_unit, "--collect",
             "-p", "RuntimeMaxSec=604800",
             "/usr/bin/flock", "-n", "/run/lock/" + args.full_unit + ".lock",
             "/usr/bin/python3", "-B", str(args.next_controller / "sensitivity_study.py"),
             "--study", str(args.study), "--replay", str(args.replay),
             "--destination", str(args.full), "--volume", str(args.volume),
             "--selection", str(args.selection)])
    for _ in range(10):
        if service_state(args.full_unit) == "active" and \
                (args.full / "sensitivity-manifest.json").exists():
            print("Primary audit and sensitivity pilot passed; full sensitivity study started")
            return
        time.sleep(1)
    raise RuntimeError("Sensitivity service did not stay active after launch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--volume", type=Path, required=True)
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--primary-controller", type=Path, required=True)
    parser.add_argument("--primary-unit", required=True)
    parser.add_argument("--next-controller", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--pilot", type=Path, required=True)
    parser.add_argument("--pilot-case-id", required=True)
    parser.add_argument("--full", type=Path, required=True)
    parser.add_argument("--full-unit", required=True)
    parser.add_argument("--wait-hours", type=int, default=72)
    handoff(parser.parse_args())


if __name__ == "__main__":
    main()
