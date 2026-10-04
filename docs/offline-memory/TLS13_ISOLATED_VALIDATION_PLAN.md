# TLS 1.3 saved-image validation: execution plan

Status: implementation in progress, 2026-10-04. This plan extends the retained
`BLIND-FINAL-20260930-A` study. Its 100 cases and original outputs are preserved.
An isolated replay of those same cases has passed its final audit; it is **replication on
existing data**, not another independent sample.

## Evidence boundary and storage

The recovery input contract is one Firefox ELF core, its PCAP, and declared
target metadata. The independent reference, case type, donor pairing, old
results, and other methods' outputs stay with the controller. The existing
study occupies about 36 GiB allocated on the server. The new Hetzner volume
has about 465 GiB available after formatting; the original 100 cores occupy
about 30 GiB allocated despite roughly 859 GiB of logical sparse-file sizes.
Keep sparse copies sparse and check free space before each case, reserving at
least 20 GiB. Do not move or remove the original study during replication.
Storage projections for new builds and fresh cases must use *allocated* bytes
from a pilot plus headroom, as well as logical sizes and expected I/O time.
The 2026-10-02 measurement is substantially below the conservative 500 GB
volume allowance: the volume uses about 36.8 GB and has about 463.6 GB
available (432 GiB). The completed replay occupies about 32.6 GB; the
100-case primary comparison occupies about 18 MB, and the sensitivity grid
reuses the replay images. The 100 retained cores allocate 32.3 GB in total
despite 922 GB of logical file sizes. If new captures have the same sparse
allocation, another 100 images would need roughly 32 GB before copies and
headroom, not 500 GB. This is a projection to verify with new-build and fresh
pilots; dense images or changed workloads could use much more space. Each
controller must verify the actual separate mount and retain the 20 GiB free
space stop threshold so a missing mount cannot redirect data to the root disk.

## Phase 1 — isolated replication of the retained 100

Freeze a controller and historical study hashes in a signed manifest. Stage
each case's three inputs into its own directory and compare their hashes with
the original recovery records. Run the unchanged structured and entropy
algorithms separately in Bubblewrap namespaces, with a private output mount,
no host network, dropped credentials, and systemd resource limits. Run an
access probe before every method. After exit, the controller takes ownership
of the three output files, hashes them and signs its own seal. Verify both
seals before the old evaluator can open references. Preserve a signed failure
record for an unsuccessful case. Compare every role's selected candidate or
abstention and reason, then compare the original and replayed scores. Audit
all 100 case IDs, including partial and failed cases.

The full replay uses a separate directory on the attached volume and runs
immediately as a service so terminal disconnection cannot interrupt it. It is
not a recurring or scheduled task. A positive-case pilot and a mismatch-case
pilot passed, including access checks, controller seals, scoring and exact
assignment reconciliation. Completion gate: 100/100 accounted for, with all
differences explained and signed evidence independently rechecked. A setup
or method failure is a reported result, not silently replaced.

## Phase 2 — comparison arms and resource sensitivity

Keep the historical algorithms frozen. In a *separate* experiment, compare:

1. The historical structure plus entropy filter.
2. Structure-only enumeration of valid NSS `CKA_VALUE` pointers (ablation).
3. An explicit TLS 1.3, 48-byte adaptation of Anderson et al.'s published NSS
   adjacency pattern, followed by the same record-authentication assignment.
4. An adaptation of the *full-snapshot entropy baseline* in the X-Ray-TLS
   source: writable captured memory, 48-byte windows at 8-byte steps, entropy of hexadecimal characters
   at threshold 3.6, bounded top candidates, then the same assignment. This
   is not the full X-Ray-TLS live memory-difference method.
5. The historical entropy-only arm as a weak context baseline.

The Anderson pattern was published for TLS master-secret extraction, primarily
TLS 1.2; label the 48-byte TLS 1.3 use as an adaptation, never as a reproduced
published TLS 1.3 result. [X-Ray-TLS](https://www.eurecom.edu/publication/7588/download/data-publi-7588.pdf)
and [Keys in Flux](https://github.com/fkie-cad/keys-in-flux-paper-material)
need an input-by-input review. Where a prior method requires timed snapshots
or other inputs unavailable in a single saved core, report that difference
and do not manufacture an equal-input result. Select any further executable
baseline before inspecting its study scores.

Use the identical PCAP parser, role assignment, authentication threshold,
false-assignment rule, and evaluator for all saved-image arms. Candidate
generation must remain blind to PCAP content and references. Run each arm in
the isolation boundary, seal outputs and record exact input/software hashes.
Predeclare search-time budgets of 30, 180 and 600 seconds and candidate caps
of 25, 100 and 1000 for the sensitivity grid. The 180-second, 100-candidate
primary comparison uses all 100 retained cases. The full resource grid uses
the 20 case IDs frozen in `TLS13_SENSITIVITY_MANIFEST.json`: seven cases from
each positive flow-count stratum and two from each control stratum, selected
by a case-ID hash without looking at method outcomes. If a cap or time budget is
exhausted, retain the partial result and flag it. Measure candidate recall
against references only after sealing; record bytes of captured PT_LOAD data
examined, unique candidates, authenticated trials, wall/CPU time, peak RSS,
correct/false assignments, abstentions and timeouts. Attribute differences
to discovery, ordering, filtering or cost instead of treating all failures
as equivalent. Explicitly count reference secrets found by structure-only
and discarded by entropy filtering.

The active primary comparison executes one case and one method at a time, so
its timed search runs use roughly one of the server's eight CPU cores. Keep
that frozen execution unchanged. Before later campaigns, benchmark a separate
controller with two concurrent case workers on development cases, recording
per-method wall and CPU time, timeout changes, memory pressure, and volume I/O.
Increase worker count only while the 15 GiB server avoids memory or I/O
contention and timed-search outcomes remain comparable. Freeze the selected
worker count for each later campaign; report it alongside method costs.

Gate: a comparison that supports a named advantage beyond beating the
historical 180-second, 100-candidate entropy arm, or a candid result that no
such advantage is established. Do not tune the comparison on confirmation
cases.

## Phase 3 — unseen-build transfer

Before reading results, register additional Firefox/NSS build identities,
their executable/library hashes, acquisition setup and case allocation. The
build choice and allocation are now frozen in `TLS13_UNSEEN_BUILD_MANIFEST.json`:
Firefox 135.0.1 and 137.0.2, 20 cases per build (14 positives and six
controls). Both official archives have been downloaded to the attached
volume, checked against Mozilla's SHA256SUMS, extracted and verified to report
their declared versions; archive and executable/NSS library hashes are pinned
in that manifest before any transfer result was inspected. Permit only
declared metadata/hash updates while discovery and
assignment rules stay fixed. Record unsupported layouts, unavailable builds,
capture failures and incomplete traffic in the denominator. Any change to a
discovery rule becomes a new adapted method evaluated in a later, separate
set. Gate: case-level transfer and failure rates by build, with no quiet
exclusions.

## Phase 4 — fresh confirmation

Freeze source hashes, environment image, workload generator, acquisition
timing, case counts, controls, budgets, scoring and analysis before generating
new secrets. The proposed design is 100 fresh cases: 70 positives (35 with
two flows and 35 with three), ten mismatched PCAPs, ten unrelated-traffic
controls and ten redacted-memory controls, matching the retained design for
paired interpretation. Use new independent secrets and undisclosed varied
payloads; retain attempted failures. Run all recovery arms under the tested
isolation and sealing workflow. Keep development, transfer and confirmation
cases separate in every report. Gate: complete case accounting and per-case
sealed evidence; never substitute a failed attempt with a clean rerun.

## Phase 5 — independent verification and claims

The primary evaluator checks exact 48-byte secret equality by role and
authenticated TLS 1.3 records. A separate verifier, with a distinct parsing
or decryption implementation, rechecks a preselected representative subset
across success, partial recovery and controls. Report positive complete-case
success, per-target recall, false assignments, correct abstentions, partial
recovery, unsupported cases, processing cost and uncertainty separately.
Avoid treating a bootstrap interval whose endpoints coincide as the sole
evidence of advantage; present raw paired counts and a suitable paired
uncertainty analysis.

Finish a contribution matrix against Anderson et al., X-Ray-TLS, Keys in
Flux and relevant structural memory methods. For each, state required input,
target secret/protocol, candidate discovery, assignment evidence, isolation,
evaluation population and cost. Package frozen code, dependency and build
hashes, controller and case manifests, nonsecret case-level results, audit
instructions and a description of restricted evidence access. Keep raw cores,
reference secrets and key logs private unless their release is separately
authorized. Gate: each novelty and performance statement maps to a specific
result and states where it does not generalize.

## Current execution record

- Original retained study: `BLIND-FINAL-20260930-A`; 70 positives and 30
  controls; 100 original case outputs retained.
- Successful isolated positive integration case: `B3be2c1df57873d90`;
  assignments and score matched. This was a setup diagnostic on an earlier
  controller revision.
- Successful isolated mismatch integration case: `Bf4a5af96f3482163`;
  signed auditor verified both controller seals, score hash and exact
  reconciliation. It matched the original.
- Initial full-replay launch into `tls13-isolated-replay-100-20261001` stopped
  after the deployment directory was found to be inaccessible to the probe's
  unprivileged identity. The signed failed attempts remain. The directory
  permission was corrected, and `tls13-isolated-pilot-f` passed with the exact
  frozen deployment and a signed, matched audit. The new full replay runs in
  `tls13-isolated-replay-100-b-20261001`.
  Controller manifests and per-case records, rather than this document, are
  the evidence of the eventual outcome.
- On 2026-10-01 at 06:33 UTC, the full replay stopped after 23 signed,
  matching cases. Case `B961831d7f6a97c3c` had an unsealed partial attempt;
  the controller refused to overwrite it. The exact cause of the overlapping
  partial state is not established. Its files and SHA-256 hashes were preserved
  under `interrupted-attempts/` with a controller-signed archive record. The
  unchanged frozen controller was then resumed under
  `tlkh-isolated-replay-100-resume.service` with a nonblocking run lock.
  The archive is additional evidence outside the 100-case auditor's standard
  `cases/` count and must be retained and checked separately in the final
  evidence package.
- The resumed replay completed all 100 cases without a case failure or
  difference. The exact frozen auditor verified the controller manifest,
  input and output hashes, method seals, score hashes, assignments and case
  accounting. Its signed `audit-final-20261002.json` records 100 matched,
  zero different, zero failed, zero partial and zero unattempted cases. The
  prior interrupted attempt was also verified separately against its signed
  archive record. These are the same retained 100 cases, not fresh cases.
- A one-case comparison integration pilot began on 2026-10-02 in
  `tls13-comparison-pilot-20261002`, using a separately frozen controller and
  the replay's audited inputs. It failed unscored after its first two method
  outputs were sealed: the controller serialized its method tuple to a JSON
  list, then rejected the list when checking its frozen manifest. The attempt,
  including the third method's unsealed partial output, was preserved with a
  signed failure record. A regression test and controller-only fix were made;
  a fresh one-case pilot in `tls13-comparison-pilot-20261002-b` used a separate
  frozen deployment and completed with all three methods controller-sealed and
  scored. On this one positive case, structure-only and the adapted Anderson
  adjacency method each assigned six of six targets with no false assignment;
  the adapted X-Ray full-snapshot entropy baseline assigned none and abstained
  on all six. This integration result is not a corpus-level performance claim.
  No primary comparison or sensitivity-grid results are claimed yet.
- A batch-capable comparison controller was committed as `812eee9` and deployed
  without subsequent edits to `tls13-comparison-controller-frozen-20261002-c`.
  Its new pilot in `tls13-comparison-pilot-20261002-c` finished successfully:
  the independent check verified the frozen controller hashes, all three
  method input/output seals, and the signed score. The 100-case primary
  comparison then started as `tlkh-comparison-primary-20261002.service`, with
  destination `tls13-comparison-primary-20261002` on the separate volume.
  Its manifest predeclares all 100 retained case IDs, 180 seconds and 100
  candidates. At launch, the service was active, the volume was mounted from
  `/dev/sdb` with about 432 GiB free, and no failure was recorded. Its results
  are pending; the one-case pilot is not evidence of a corpus-level advantage.
- The resource-grid controller was committed as `e9cab01` and deployed to the
  separate, read-only `tls13-sensitivity-controller-frozen-20261002` directory.
  Its 20 case IDs and nine search-time/candidate-cap settings are checked
  against `TLS13_SENSITIVITY_MANIFEST.json`. The historical recovery source
  remains unchanged; a budget adapter supplies the declared limits. The new
  controller raises the per-process CPU cap for the 600-second search setting
  so that the cap cannot terminate a valid 600-second search plus its separate
  authentication stage. This fix applies only to the future controller and
  does not alter the active primary comparison.
- A one-time `tlkh-sensitivity-handoff-20261002.service` is active. It waits
  for the primary comparison to finish, verifies all 100 cases and the signed
  campaign summary with the read-only comparison auditor, runs one
  development-case sensitivity pilot, verifies that pilot's five method seals,
  and only then starts `tlkh-sensitivity-grid-20261002.service`. The pilot and
  grid destinations are `tls13-sensitivity-pilot-20261002` and
  `tls13-sensitivity-grid-20x9-20261002` on the attached volume. At handoff
  launch the primary had four scored cases and no failures; the pilot and grid
  had not started. A failed gate leaves the evidence intact and prevents the
  full grid from starting.
- The primary comparison subsequently completed 100/100 cases without a
  failure. Its signed campaign summary and read-only handoff audit passed.
  The sensitivity pilot then passed its five-method seal audit, and the
  20-case, nine-setting grid started as `tlkh-sensitivity-grid-20261002.service`.
  The first grid setting was signed and scored with no failure; the next was
  running at the check. The separate [primary comparison results](TLS13_PRIMARY_COMPARISON_RESULTS.md)
  report paired, nonsecret aggregates. These remain retained-case results;
  resource-grid, unseen-build and fresh-confirmation conclusions are pending.
- An independent TShark 4.6.4 check of the first completed positive replay
  case (`B3be2c1df57873d90`) used the six recovered application secrets and
  reference **handshake-only** secrets for TLS 1.3 epoch decoding. It matched
  all 12 private workload payload hashes. The root-private scratch key log was
  removed after the check; the signed nonsecret verification result remains
  on the attached volume.
- A diagnostic following X-Ray-TLS's dummy-handshake technique yielded zero
  decrypted payloads with stock TShark 4.6.4. X-Ray-TLS uses a patched TShark;
  our independent verifier therefore declares reference handshake-only
  decoder support rather than silently treating dummy values as equivalent.
- The 20-case × nine-setting sensitivity grid completed all 180 settings on
  2026-10-04. The frozen read-only auditor verified its manifest, controller,
  method seals, reconciliations and signed campaign summary: 180 scored, zero
  failed, zero partial and zero unattempted. The separate
  [resource-sensitivity results](TLS13_SENSITIVITY_RESULTS.md) give nonsecret
  recall, assignment, timeout and cost aggregates. This remains sensitivity on
  selected retained cases, not fresh independent confirmation. Unseen-build
  transfer and the fresh campaign have not started.
- The unseen-build transfer was initiated on 2026-10-04 using the preregistered
  Firefox 135.0.1 and 137.0.2 archives. The first pilot controller `-a`
  stopped during browser startup because its capture process inherited the
  recovery worker's 64-task limit. Both failed startup attempts are retained.
  Controller `-b` corrected the capture limit and preserved both recovery
  algorithms, but its first pilot reached the sandbox access probe with a
  case directory left non-traversable by the recovery UID. That failed,
  captured attempt is also retained. Controller `-c` corrects this staging
  permission. Its fresh two-build pilot at `tls13-unseen-pilot-20261004-c`
  completed two of two scored cases. The frozen read-only auditor verified
  both method seals and all case evidence. Historical structured recovery
  passed both positive pilots without a false assignment; the audit report
  SHA-256 is `07b3be4b71edefd07e8906dc4c7cf7791fb02b2e8ec04185eac3915cc689f28f`.
  The one-time `tlkh-unseen-handoff-20261004-c.service` passed and launched
  `tlkh-unseen-builds-40-20261004-c.service` at 04:31 UTC on 2026-10-04.
  Its signed, frozen allocation has 40 cases (20 per build; 14 positives and
  six controls each), and its manifest SHA-256 is
  `e521bf99f80c833812bfafa069a39610786c3e6933cf0e425a38212c6b425d2c`.
  At launch the mounted `/dev/sdb` ext4 volume had about 430 GiB free and
  the first full case had been captured. Full transfer results are pending.
  The earlier unstarted `-a` and `-b` allocations and all failed attempts
  remain intact. A controller revision is a setup change, never a silent
  replacement for a scored transfer result.
