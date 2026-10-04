#!/usr/bin/env python3
"""Independently check sealed recovered traffic with TShark's TLS dissector."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from seals import seal_record, verify_evidence


def verify(case: Path, tools: Path, workload: Path, reference_keylog: Path | None):
    destination = case.parents[1]
    key = (destination / "controller.key").read_bytes()
    inputs = case / "inputs"
    for method in ("structured", "entropy"):
        verify_evidence(key, case / (method + "-controller-seal.json"),
                        inputs, case / method / "result", tools)

    result = case / "structured" / "result"
    rows = {row["id"]: row["hex"] for row in json.loads(
        (result / "candidates.private.json").read_text())}
    decisions = json.loads((result / "decisions.json").read_text())["decisions"]
    application = []
    for decision in decisions:
        if decision["status"] != "selected":
            continue
        value = rows.get(decision["candidate_id"])
        if value is None:
            raise ValueError("Selected recovered secret is missing")
        label = ("CLIENT_TRAFFIC_SECRET_0" if decision["direction"] == "client"
                 else "SERVER_TRAFFIC_SECRET_0")
        application.append(f"{label} {decision['client_random']} {value}")
    if not application:
        raise ValueError("No recovered application secrets to check")

    # X-Ray-TLS supplies dummy handshake secrets to its patched TShark. Try
    # the same with stock TShark when no reference key log is supplied; this
    # uses no reference secret at all. If it does not decode a build, the
    # separate reference-handshake-only mode remains available.
    if reference_keylog is None:
        randoms = sorted({decision["client_random"] for decision in decisions
                          if decision["status"] == "selected"})
        handshake = [f"{label} {random} {'0' * 96}" for random in randoms
                     for label in ("CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                                   "SERVER_HANDSHAKE_TRAFFIC_SECRET")]
        handshake_mode = "dummy_zero"
    else:
        # Reference application secrets are deliberately excluded.
        handshake = [line for line in reference_keylog.read_text().splitlines()
                     if line.startswith(("CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
                                         "SERVER_HANDSHAKE_TRAFFIC_SECRET "))]
        handshake_mode = "reference_handshake_only"
    if not handshake:
        raise ValueError("No handshake-only decoder support")

    with tempfile.TemporaryDirectory(prefix="tlkh-tshark-", dir="/tmp") as temporary:
        folder = Path(temporary)
        capture = folder / "traffic.pcap"
        keylog = folder / "selected.keys"
        shutil.copyfile(inputs / "traffic.pcap", capture)
        keylog.write_text("\n".join(application + handshake) + "\n")
        keylog.chmod(0o600)
        command = ["tshark", "-r", str(capture), "-o", "tls.keylog_file:" + str(keylog),
                   "-T", "fields", "-E", "separator=|", "-E", "occurrence=a",
                   "-E", "aggregator=,", "-e", "websocket.payload"]
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True)

    observed = Counter()
    for line in output.splitlines():
        for token in line.split(","):
            token = token.strip().replace(":", "")
            if not token:
                continue
            value = bytes.fromhex(token)
            observed[(len(value), hashlib.sha256(value).hexdigest())] += 1
    expected = Counter()
    for flow in json.loads(workload.read_text())["flows"]:
        for direction in ("client_messages", "server_messages"):
            for message in flow[direction]:
                expected[(message["length"], message["sha256"])] += 1
    matched = sum((expected & observed).values())
    version = subprocess.check_output(["tshark", "-v"], stderr=subprocess.DEVNULL,
                                      text=True).splitlines()[0]
    return {"schema": 1, "case_id": case.name, "verifier": version,
            "decoder_handshake_mode": handshake_mode,
            "recovered_application_secrets": len(application),
            "expected_payloads": sum(expected.values()),
            "observed_payloads": sum(observed.values()),
            "exact_payload_hash_matches": matched,
            "all_expected_payloads_match": matched == sum(expected.values())}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    handshake = parser.add_mutually_exclusive_group(required=True)
    handshake.add_argument("--reference-keylog", type=Path)
    handshake.add_argument("--dummy-handshake", action="store_true",
                           help="Diagnostic only; stock TShark 4.6.4 failed on the pilot")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = verify(args.case, args.tools, args.workload, args.reference_keylog)
    key = (args.case.parents[1] / "controller.key").read_bytes()
    with args.output.open("x") as stream:
        json.dump(seal_record(key, record), stream, sort_keys=True, indent=2)
        stream.write("\n")
    args.output.chmod(0o600)
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
