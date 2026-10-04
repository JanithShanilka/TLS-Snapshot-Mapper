#!/usr/bin/env python3
"""Read-only audit of sealed unseen-build cases and their frozen allocation."""

import argparse
import json
from pathlib import Path

from seals import INPUT_NAMES, file_hashes, sha256, tool_hashes, verify_evidence, verify_record
from unseen_build import METHODS, replace_exact, sources


def audit(study: Path, historical: Path, selection: Path, controller: Path):
    key = (study / "controller.key").read_bytes()
    frozen = verify_record(key, json.loads((study / "manifest.json").read_text()))
    if (frozen["controller"] != file_hashes(controller, tuple(sorted(
            path.name for path in controller.glob("*.py")))) or
            frozen["selection_sha256"] != sha256(selection) or
            frozen["historical_manifest_sha256"] != sha256(historical / "manifest.json") or
            frozen["historical_state_sha256"] != sha256(historical / "state.json")):
        raise ValueError("Transfer preregistration or controller changed")
    historic_manifest = json.loads((historical / "manifest.json").read_text())
    for build in frozen["builds"]:
        version = build["firefox_version"]
        source = historical / "tools"
        tools = study / "tools" / version
        for name, expected in historic_manifest["script_sha256"].items():
            if sha256(source / name) != expected:
                raise ValueError("Historical method changed")
            text = (source / name).read_text()
            if name in ("blind_tls13/capture_blind.py", "blind_tls13/recover.py"):
                text = replace_exact(text, '"136.0.2"', json.dumps(version))
                for target_name, old_hash in historic_manifest["target_hashes"].items():
                    new_hash = build[{"firefox": "firefox_sha256",
                                      "libssl3.so": "libssl3_so_sha256",
                                      "libsoftokn3.so": "libsoftokn3_so_sha256"}[target_name]]
                    text = replace_exact(text, json.dumps(old_hash), json.dumps(new_hash))
            if (tools / name).read_text() != text:
                raise ValueError("Transfer tool has a non-metadata change")
        if tool_hashes(tools) != frozen["tools"][version]["adapted_tool_hashes"]:
            raise ValueError("Adapted tool hashes changed")
    state = json.loads((study / "state.json").read_text())
    rows = state["cases"]
    registered = frozen["case_rows"]
    if len(rows) != len(registered) or any(
            {k: row.get(k) for k in ("case_id", "build", "kind", "connections", "donor")}
            != {k: fixed.get(k) for k in ("case_id", "build", "kind", "connections", "donor")}
            for row, fixed in zip(rows, registered)):
        raise ValueError("Case allocation changed")
    counts = {status: 0 for status in ("scored", "failed", "captured", "attempted", "planned")}
    score_hashes = {}
    results = []
    for row in rows:
        status = row["status"]
        if status not in counts:
            raise ValueError("Unknown transfer status")
        counts[status] += 1
        case = study / "cases" / row["case_id"]
        if status == "scored":
            tools = study / "tools" / row["build"]
            inputs = case / "inputs"
            core, pcap, _ = sources(study, row)
            hashes = file_hashes(inputs, INPUT_NAMES)
            if hashes["memory.core"]["sha256"] != sha256(core) or \
                    hashes["traffic.pcap"]["sha256"] != sha256(pcap):
                raise ValueError("Staged transfer input changed")
            for method in METHODS:
                seal = verify_evidence(key, case / (method + "-controller-seal.json"),
                                       inputs, case / method / "result", tools)
                if seal["method"] != method or seal["controller"] != frozen["controller"]:
                    raise ValueError("Sealed transfer method or controller changed")
            report = verify_record(key, json.loads((case / "reconciliation.json").read_text()))
            if report["case_id"] != row["case_id"] or report["status"] != "scored" or \
                    report["score_sha256"] != sha256(case / "score.json"):
                raise ValueError("Transfer reconciliation changed")
            score_hashes[row["case_id"]] = report["score_sha256"]
            results.append({"case_id": row["case_id"], "build": row["build"],
                            "kind": row["kind"], "status": "scored",
                            "methods": report["methods"]})
        elif status == "failed":
            failure = verify_record(key, json.loads((case / "failure.json").read_text()))
            if failure["case_id"] != row["case_id"] or failure["status"] != "failed":
                raise ValueError("Transfer failure evidence changed")
            results.append({"case_id": row["case_id"], "build": row["build"],
                            "kind": row["kind"], "status": "failed",
                            "failure_type": failure["failure_type"]})
        else:
            results.append({"case_id": row["case_id"], "build": row["build"],
                            "kind": row["kind"], "status": status})
    summary = study / "campaign-summary.json"
    if summary.exists():
        sealed = verify_record(key, json.loads(summary.read_text()))
        if sealed["case_count"] != len(rows) or sealed["counts"] != counts or \
                sealed["scored_hashes"] != score_hashes:
            raise ValueError("Transfer campaign summary disagrees with evidence")
    return {"case_count": len(rows), "counts": counts,
            "summary_present": summary.exists(), "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.study, args.historical, args.selection,
                           args.controller), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
