# Isolated replay controller

This directory holds the new evaluator-side execution boundary for the retained
`BLIND-FINAL-20260930-A` study. The historical `tools/` snapshot is not edited.
The old study and its answers remain on the original disk. Replay inputs,
method outputs, failure records, controller seals, and reconciliation records
go to a new study directory on the attached volume.

Run as root on the controlled Linux host after inspecting its source and
recording its hashes:

```text
python3 replay.py --study HISTORICAL_STUDY --destination NEW_REPLAY_DIRECTORY
```

`--case-id` runs one named case for an integration check. `--limit` restricts
the number of cases processed. A complete replay can resume in the same
destination; reconciled cases are skipped. A failed or partially processed
case is not retried in place. Preserve it and use a new diagnostic study
directory for a changed controller or another attempt.

Every recovery process uses a new filesystem, network, process, IPC, user and
cgroup namespace. Only its staged core, PCAP, pinned metadata, frozen software,
and own output are mounted. `setpriv` drops supplementary groups and privileges
before `bwrap`; `systemd-run` enforces memory, process and CPU limits and
terminates descendants. The probe checks visible inputs, forbidden paths,
symlink traversal, identity, and loopback denial before recovery starts.

The controller stages sparse copies and checks their hashes against the original
input hashes. It waits for method exit before taking root ownership of outputs
and signing a seal with a controller-only key. References are opened by the
frozen evaluator only after both controller seals verify. An input, output,
software, controller or historical-study change causes verification failure.
Failed setup and recovery attempts are retained as signed, unscored records.

The controller manifest fixes the controller code and historical study state
for a replay directory. The original study contains the results to compare;
the new reconciliation record distinguishes a matched assignment and score
from a changed or failed replay. This is replication on the same 100 retained
cases, not new independent evidence.

Check with `python3 -m unittest discover -s tests -p test_isolated_tls13.py`
and `ruff check lab/isolated_tls13 tests/test_isolated_tls13.py`. The real
Bubblewrap and systemd path must also pass a one-case integration run on the
controlled host before launching a full replay.
