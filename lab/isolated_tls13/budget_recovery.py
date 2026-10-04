#!/usr/bin/env python3
"""Run the frozen historical recovery algorithm with declared resource limits."""

import argparse
from pathlib import Path
import sys


def run(core: Path, pcap: Path, metadata: Path, tools: Path, method: str,
        search_seconds: int, candidate_limit: int, output: Path):
    if method not in {"structured", "entropy"}:
        raise ValueError("Unknown historical method")
    if search_seconds not in {30, 180, 600} or candidate_limit not in {25, 100, 1000}:
        raise ValueError("Budget is outside the predeclared grid")
    sys.path.insert(0, str(tools / "offline_memory"))
    sys.path.insert(0, str(tools / "blind_tls13"))
    import recover

    # These are resource parameters. Candidate discovery and assignment remain
    # the exact functions in the historical tools snapshot.
    recover.SEARCH_SECONDS = search_seconds
    recover.MAX_CANDIDATES = candidate_limit
    original_entropy_rank = recover.entropy_rank

    def limited_entropy_rank(image, deadline):
        return original_entropy_rank(image, deadline, maximum=candidate_limit)

    recover.entropy_rank = limited_entropy_rank
    return recover.run(core, pcap, metadata, method, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--method", choices=("structured", "entropy"), required=True)
    parser.add_argument("--search-seconds", type=int, required=True)
    parser.add_argument("--candidate-limit", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.core, args.pcap, args.metadata, args.tools, args.method,
        args.search_seconds, args.candidate_limit, args.output)


if __name__ == "__main__":
    main()
