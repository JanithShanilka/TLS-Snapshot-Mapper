# Isolated replay controller

This directory holds the new evaluator-side execution boundary for the retained
`BLIND-FINAL-20260930-A` study. The historical `tools/` snapshot is not edited.
The old study and its answers remain on the original disk. Replay inputs,
method outputs, failure records, controller seals, and reconciliation records
go to a new study directory on the attached volume.

Run as root on the controlled Linux host after inspecting its source and
recording its hashes. The deployed controller directory must be readable and
traversable by UID 1000 because the isolated access probe is mounted from it;
the signing key belongs in the separate, root-owned replay destination.

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
controlled host from the **same deployed directory** before launching a full
replay. A failed launch or probe must remain in a separate diagnostic replay
directory; do not overwrite its signed records.

`comparison_study.py` is a separate, later experiment. It accepts a completed
and verified source replay case, then runs structure-only, adapted Anderson
NSS adjacency, and X-Ray-TLS full-snapshot entropy-baseline arms with the
same record-authentication assignment stage. The X-Ray-TLS arm is an adaptation
of its full-snapshot *baseline*, not its live memory-difference method. Its
time and candidate budgets must be in the predeclared grid in the
validation plan. Pass `--volume` as the expected separate mounted filesystem;
the controller refuses to write results if it is unmounted or the destination
is outside it. All three added arms receive the same staged inputs in separate
namespaces and are controller-sealed before references are opened. Deploy this
code to its own frozen directory, run one case under real Bubblewrap/systemd,
inspect its signed output, and only then expand to more cases. It has not yet
been fully scored on the retained corpus; a separate frozen 100-case primary
comparison is running and its results must pass `audit_comparison.py`.

`audit_comparison.py` is a read-only, separate completion check. It verifies
the frozen source hashes, every completed case's signed score and three method
seals, and the signed campaign summary. It accounts for failed, partial and
unattempted cases, so a downstream study can require exactly 100 scored cases.

`sensitivity_study.py` runs the preselected 20-case, nine-setting resource
grid. Its `budget_recovery.py` adapter calls the historical `recover.py`
functions with only the declared search time and candidate cap changed; the
historical snapshot is not edited. The three added comparison arms share the
same inputs, isolation, assignment and scoring. Each five-method setting is
sealed before the controller opens references. A pilot uses an already-known
development case outside the 20 selected cases. The full grid begins only
after the primary comparison and pilot pass their read-only audits. A failed
or interrupted setting remains in place and is never overwritten.

`independent_verify.py` runs only after the replay controller seals verify.
It gives TShark the selected application secrets and reference handshake
secrets, never reference application secrets, then compares decrypted
WebSocket payload lengths and SHA-256 hashes with private workload records.
Its temporary key log and PCAP live in a private `/tmp` directory and are
removed automatically. The output is a signed, nonsecret count report in a
separate path. A positive integration case passed with 12/12 payload hashes;
a representative subset across success, partial recovery and controls is
still required for the final report.
The supplied X-Ray-TLS source uses dummy zero handshake values with a patched
TShark; a diagnostic with stock TShark 4.6.4 yielded zero decrypted payloads
with that technique. The successful check used reference handshake secrets
only, after controller sealing. The verifier exposes dummy mode solely as an
explicit diagnostic and records which decoder support it used.

`unseen_build.py` creates separate pilot and 40-case transfer studies for the
two Firefox builds fixed in `TLS13_UNSEEN_BUILD_MANIFEST.json`. It copies the
historical method snapshot and changes only the pinned Firefox version and
executable/NSS hash literals used by acquisition and metadata validation;
candidate discovery, authentication, and scoring source stay identical. Its
evaluator captures each core and PCAP, stages only those inputs plus declared
metadata, runs the same two methods behind the access probe, takes ownership
and signs the outputs, then opens the root-private references. Failed and
partial cases stay in the frozen denominator. `audit_unseen.py` independently
checks method seals, metadata-only adaptation, case allocation, and the
campaign summary. `unseen_handoff.sh` is a one-time gate from the two-build
pilot to the 40-case campaign; it starts the full run only if the pilot's
case accounting and read-only audit pass. The destination must remain on the
separate mounted volume with at least 20 GiB free.
