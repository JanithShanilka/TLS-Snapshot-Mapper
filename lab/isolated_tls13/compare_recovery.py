#!/usr/bin/env python3
"""Saved-image comparator arms with the historical common assignment stage.

This is a new experiment. It is not part of the frozen 100-case replay.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time

from comparators import anderson_nss_adjacent, structure_only, xray_full_snapshot_entropy
from seals import sha256


METHODS = {"structure_only": structure_only,
           "anderson_nss_adjacent": anderson_nss_adjacent,
           "xray_full_snapshot_entropy": xray_full_snapshot_entropy}


def run(core_path: Path, pcap_path: Path, metadata_path: Path, tools: Path,
        method: str, search_seconds: int, candidate_limit: int,
        auth_seconds: int, output: Path):
    if method not in METHODS:
        raise ValueError("Unknown comparison method")
    if search_seconds <= 0 or auth_seconds <= 0 or not 1 <= candidate_limit <= 10_000:
        raise ValueError("Invalid predeclared resource budget")
    for directory in ("blind_tls13", "offline_memory"):
        sys.path.insert(0, str(tools / directory))
    from core_memory import CoreMemory
    from recover import PINNED_HASHES, assign
    from tls13_packets import inspect_connections

    metadata = json.loads(metadata_path.read_text())
    if metadata != {"architecture": "linux-x86_64", "firefox_version": "136.0.2",
                    "cipher_suite": "0x1302", "target_hashes": PINNED_HASHES}:
        raise ValueError("Comparison input metadata differs from the pinned retained build")

    def expired(_signum, _frame):
        raise TimeoutError("Comparison search reached its declared time budget")

    start = time.monotonic()
    cpu_start = time.process_time()
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        with CoreMemory(core_path) as core:
            signal.setitimer(signal.ITIMER_REAL, search_seconds)
            try:
                rows, search = METHODS[method](core, candidate_limit)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous)
    search_elapsed = time.monotonic() - start
    if search_elapsed > search_seconds:
        search["search_exhausted"] = False
        search["search_timed_out"] = True
    connections = inspect_connections(pcap_path)
    if not connections or any(row["cipher_suite"] != "0x1302" for row in connections):
        raise ValueError("PCAP has no compatible completed TLS 1.3 handshake")
    auth_start = time.monotonic()
    decisions, authentication = assign(rows, connections, pcap_path, auth_start + auth_seconds)
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    candidates = output / "candidates.private.json"
    candidates.write_text(json.dumps(rows, sort_keys=True) + "\n")
    candidates.chmod(0o400)
    report = {"method": method,
              "input_sha256": {"core": sha256(core_path), "pcap": sha256(pcap_path),
                               "metadata": sha256(metadata_path)},
              "input_contract": ["core", "pcap", "target_metadata"],
              "candidate_count": len(rows), "search": search,
              "search_seconds": search_seconds, "search_elapsed_seconds": search_elapsed,
              "candidate_limit": candidate_limit, "authentication": authentication,
              "authentication_seconds": auth_seconds, "connections": connections,
              "decisions": decisions, "wall_seconds": time.monotonic() - start,
              "cpu_seconds": time.process_time() - cpu_start,
              "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    decision_file = output / "decisions.json"
    decision_file.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    (output / "seal.json").write_text(json.dumps({
        "candidates_sha256": sha256(candidates),
        "decisions_sha256": sha256(decision_file),
        "sealed_at_utc": datetime.now(timezone.utc).isoformat()}, sort_keys=True, indent=2) + "\n")
    return report


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--method", choices=sorted(METHODS), required=True)
    parser.add_argument("--search-seconds", type=int, required=True)
    parser.add_argument("--candidate-limit", type=int, required=True)
    parser.add_argument("--auth-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.core, args.pcap, args.metadata, args.tools, args.method,
                 args.search_seconds, args.candidate_limit, args.auth_seconds, args.output)
    print(json.dumps({"method": report["method"], "candidate_count": report["candidate_count"],
                      "search": report["search"], "decisions": report["decisions"]}))


if __name__ == "__main__":
    main()
