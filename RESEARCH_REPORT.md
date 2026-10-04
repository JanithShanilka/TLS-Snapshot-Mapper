# Consolidated Research Report: Firefox/NSS Saved-Memory TLS Secret Recovery

**Project:** Improving the Robustness of Static-to-Dynamic TLS Key Extraction

**Researcher:** Janith Shanilka Geekiyanage Don, UCSC

**Report date:** 4 October 2026 (Asia/Colombo)

**Evidence cut-off:** the latest records available in this workspace, including the completed resource-sensitivity audit and the launch record for the unseen-build study on 4 October 2026
**Status:** consolidated account of the active saved-memory research; historical live-hook work is identified only as retired project history

## 1. Executive summary

The active thesis investigates whether TLS secrets can be recovered from a **saved Firefox process-memory image**, selected without access to a server reference secret, and used to authenticate and decrypt the corresponding saved network traffic. The work targets controlled, researcher-operated Firefox/NSS sessions. It does not attack TLS cryptography: it examines secrets held at an endpoint after cryptographic negotiation.

The study moved from a single TLS 1.2 feasibility case to repeatability campaigns, more demanding TLS 1.3 connection states, a blind multiconnection study, isolated replay, and method comparisons. The most important recorded findings are:

| Study | Recorded outcome | Interpretation |
| --- | --- | --- |
| TLS 1.2 saved-memory repeatability | 19/20 initial unattended completions; the original failed attempt later recovered from its **same** dump, giving 20/20 eventual exact recoveries | Packet-assisted selection was repeatable under the fixed laboratory conditions; memory-only ranking did not uniquely choose a secret. |
| TLS 1.3 single-connection repeatability | 20/20 complete fresh sessions | Both generation-zero application traffic-secret directions matched independent references and decrypted the intended traffic. |
| TLS 1.3 extended scenarios | 100/100 complete cases, 20 each for before-response capture, delayed capture, resumption, KeyUpdate and two overlapping connections | The scenario-specific conditions and target secret generations were validated separately. |
| Blind TLS 1.3 multiconnection study | Structured search: 70/70 complete positive cases, 350/350 positive targets, 30/30 controls, zero false assignments | This was the first separately frozen blind comparison; the entropy-only arm completed 0/70 positives under the same declared limits. |
| Isolated replay of blind study | 100/100 retained cases matched the original decisions and scores | Strengthened the access boundary and reproducibility on **the same data**; it does not add 100 independent cases. |
| Five-method retained-case comparison | Structured, structure-only: 70/70 positives; adapted Anderson adjacency: 69/70; two full-snapshot entropy arms: 0/70 | A paired comparison on the 100 retained images, with shared authentication and scoring. |
| Resource-sensitivity grid | 180/180 settings scored; five methods per setting, 900 sealed method outputs | The structural methods retained their observed target recall across nine resource settings on 20 selected retained cases. |

All fractions describe observed performance on the named controlled datasets. The public workspace contains source, plans, manifests and nonsecret summaries; the raw memory images, full packet captures, candidate values and reference secrets are restricted to the laboratory. The checkout alone cannot independently reconstruct every private result.

## 2. Research scope and provenance

### 2.1 Active question

The governing [saved-memory thesis scope](docs/governance/THESIS_SCOPE.md) asks four related questions: whether the correct secret is present among structured candidates in a saved image; whether memory-only ranking can uniquely identify it; whether the saved PCAP can resolve ambiguity without a reference secret; and whether independent verification establishes exact equality and intended traffic recovery. TLS 1.2 and TLS 1.3 are treated as separate experiments because their secret types, labels and validation requirements differ.

The input boundary is central. Candidate discovery reads saved memory and public build metadata. Packet-assisted assignment adds the saved PCAP and public handshake data. The protected server reference is read only after selection has been recorded and sealed. Later blind recovery also withholds message markers, case types, donor pairing, target-flow assignments and prior answers from the recovery process.

### 2.2 Relationship to TLSKeyHunter and the retired phase

The upstream [TLSKeyHunter project](https://github.com/monkeywave/TLSKeyHunter) supplied the original static-to-dynamic TLS extraction foundation. The thesis originally explored live runtime hooks and argument ranking, but the researcher retired that entire method on 28 September 2026. The old hooks, A/D benchmarks, Firefox live campaigns, frozen baselines and visual evidence are preserved in the separately retained workspace archive for provenance. They are **not** active thesis results, baselines, comparisons or contribution claims. This report gives them no result table and does not transfer any live-hook percentage to saved-memory recovery.

The active contribution is the bounded implementation and evaluation of saved-image candidate enumeration, explicit abstention, packet-assisted assignment, post-selection reference verification, controlled negative cases, and progressively stronger experimental isolation. Prior work on finding TLS secrets in memory and using traffic to test candidates must still be credited; the study's novelty cannot be stated as inventing those general ideas. The [contribution boundaries](docs/governance/CONTRIBUTION_BOUNDARIES.md) and [prior-work matrix](docs/offline-memory/TLS13_PRIOR_WORK_MATRIX.md) record this distinction.

### 2.3 Tested environment

The principal saved-memory studies used Firefox **136.0.2** with pinned NSS binaries on Linux x86-64 and researcher-controlled localhost services. The TLS 1.2 study used `ECDHE-RSA-AES128-GCM-SHA256` and a 48-byte master secret. The TLS 1.3 studies used `TLS_AES_256_GCM_SHA384` and 48-byte application traffic secrets for each required direction and generation. Disposable Firefox profiles were used for fresh sessions. Explicit laboratory socket-sandbox and certificate-validation exceptions were part of some runs; their use limits external validity and does not establish ordinary browser certificate authentication.

## 3. End-to-end methodology

### 3.1 Acquisition

The controlled server and packet capture are started before the Firefox workload. The acquisition code identifies the Firefox process that owns the connection and has the relevant NSS libraries, then uses GDB to save an ELF core. Process selection matters because Firefox has multiple processes and the visible browser PID need not own the TLS state. The core is a **saved** memory image: the extractor does not require a live Frida hook, does not call NSS secret-export APIs, and does not use a target key log. GDB may pause the process and may omit unreadable mappings, so the image is neither an instantaneous snapshot nor a guarantee of complete address-space coverage. These constraints are recorded in the [offline workflow](lab/offline_memory/README.md).

The core reader translates virtual addresses through readable ELF64 `PT_LOAD` segments to file offsets and rejects missing or truncated ranges. Sparse core files can have very large logical sizes while consuming much less allocated disk space; the campaigns monitor allocated storage and free-space reserves. Private cores and disposable profiles from the early repeatability campaigns were deleted only after durable per-case results were saved. The later blind study retained its cores for replay and comparison.

### 3.2 Memory-only candidate discovery

The successful Firefox/NSS path scans for a fixed-shape `CKA_VALUE` attribute pattern in captured memory. For the TLS 1.2 pilot it enumerates readable 48-byte values. For TLS 1.3 it enumerates NSS attribute-shaped values and retains the 48-byte values required by the negotiated SHA-384 suite. It deduplicates identical values and records candidate locations and nonsecret statistics. Structure, readability, length, entropy and zero count are **candidate filters**, not proof that a buffer is the right secret.

The distinction between *candidate inclusion* and *unique memory-only selection* is important. In the TLS 1.2 pilot and continuation campaign, several candidate values tied at the top. The memory-only method abstained; the reported recovery therefore depends on the separate saved-PCAP stage. In the blind TLS 1.3 study, structural enumeration was followed by record-authentication assignment. The report does not describe the latter as memory-only role identification.

### 3.3 Saved-traffic assignment

For TLS 1.2, packet validation tries each sealed candidate with the public ClientHello random against the saved connection and accepts a unique candidate only when controlled request and response traffic decrypt correctly. This stage does not read the private reference. For TLS 1.3, the selector discovers completed handshakes and TCP directions in the PCAP, derives normal traffic keys and IVs from each candidate for the relevant epoch, and requires authenticated TLS application records. In the blind study, selection requires a unique candidate authenticating at least two application records in a consecutive sequence-zero epoch. Ambiguity, timeout, no authenticated candidate and reuse of one candidate across incompatible roles lead to an unresolved output rather than a guessed assignment. Payload text is not used to choose the candidate.

Extended-scenario validation adds explicit flow and generation checks. Resumption is established by a full connection followed by packet and server evidence of a PSK-resumed second connection. The second connection is the recovery target. KeyUpdate recovery targets generation-one client and server application secrets **directly observed in saved memory**; deriving them from a generation-zero selection is not counted. Packet evidence must authenticate the bidirectional update. Concurrent flows require distinct flow/random associations, overlap in lifetime and rejection of cross-flow secret substitutions.

### 3.4 Sealing and independent verification

The output is fixed before the evaluator opens the server-held reference. The verifier checks byte-for-byte equality for every selected TLS secret and authenticates the intended request and response. A one-bit-corrupted secret must fail the relevant direction. Additional negative cases test wrong connections, mismatched PCAPs, unrelated traffic, redacted memory and wrong secret generation. Exact equality means zero differing bits; an entropy score or a near match is never reported as partial cryptographic recovery.

In the later blind study, per-method candidate and decision outputs are hashed and sealed. Its original run separated the unprivileged recovery account from root-only answers using Unix permissions, though it did **not** technically prevent the second method from seeing the first method's output directory. The subsequent replay addressed that limitation by using separate Bubblewrap namespaces, staged declared inputs, dropped privileges, no host network, systemd resource limits, access probes, root-owned output seals and a separate read-only audit. Replay references were opened only after both method seals passed. This stronger isolation was demonstrated on the retained images; it does not retroactively change the original run's access boundary.

### 3.5 Outcome definitions

A complete positive case requires all required target secrets to be assigned to their correct connection, direction and generation, followed by exact independent equality and authenticated recovery of the intended traffic. A control passes only when its declared available targets are recovered and unavailable or mismatched targets remain unresolved. Failed acquisition, no candidate, ambiguity, false assignment and processing failures remain separately counted. Candidate tests within a case are not independent sessions. Replays and alternate methods on retained images are not new case samples.

## 4. TLS 1.2 saved-memory programme

### 4.1 Pilot and method selection

Early development established which Firefox process to capture and which NSS memory layout was useful. A generic `SECItem` scan on a development core generated many plausible values but failed unique selection. A reference-guided *presence audit* found the literal master-secret bytes in the saved image; that audit demonstrated capture feasibility, not blind extraction. The subsequently fixed `CKA_VALUE` method was tested on development case 008 and then fresh case 009. Each returned five tied candidates including the correct secret. Saved-PCAP testing selected exactly one; independent verification found zero differing bits, recovered both application markers and rejected a one-bit wrong-secret control. The fresh case is a feasibility result, not a population-rate estimate. See the [pilot result](docs/offline-memory/SAVED_MEMORY_RESULT.md) and [work log](docs/offline-memory/SAVED_MEMORY_WORK_LOG.md).

### 4.2 Twenty fresh captures

The fixed repeatability design scheduled 20 fresh Firefox sessions with at least ten minutes between starts. The first attempt stopped at the orchestration stage because the frozen script directory lacked traversal permission for the unprivileged researcher. Its failure was kept. The remaining 19 sessions then completed automatically. The failed first attempt was later reanalyzed **using its original saved dump**, without a replacement capture, and recovered successfully after the permission repair. These are distinct outcome measures:

| TLS 1.2 measure | Result |
| --- | ---: |
| Initial unattended completion among all attempted captures | 19/20 |
| Automatic completion in the continuation campaign | 19/19 |
| Subsequent recovery of the original failed capture | 1/1 |
| Eventual exact recovery across the 20 captured sessions | 20/20 |
| Unique selection by memory-only ranking in the 19 continuation cases | 0/19 |
| Correct secret present among memory candidates in the continuation | 19/19 |
| Unique packet-validation winner in the continuation | 19/19 |

The continuation generated 91 candidate checks: 19 packet-validating selections and 72 candidates that failed the required traffic test. Including the repaired first attempt yields 96 checks, 20 passes and 76 failures. These checks are nested within 20 sessions, not 96 independent experiments. Every eventually selected master secret matched its isolated reference with zero differing bits out of 384, and the intended request and response decrypted. A one-bit-corrupted reference was rejected in every continuation case. Median continuation runtime was 47.62 seconds. The [repeatability record](docs/offline-memory/REPEATABILITY_RESULTS.md) preserves the initial failure and separate repair.

The result applies to one controlled connection per fresh profile, captured while a response connection remained open. It does not establish success for different timing, multiple connections, other browser builds or other TLS 1.2 suites.

## 5. TLS 1.3 saved-memory programme

### 5.1 Development and fresh validation

The TLS 1.3 implementation extended candidate discovery to directional application traffic secrets and derived the correct key/IV for the negotiated SHA-384 suite. One development case and one later fresh validation case each yielded a unique packet-validating client secret and server secret. Both secrets matched their isolated references exactly and recovered the controlled request/response. One-bit corruption of either direction blocked that direction while the other remained decryptable. These cases established feasibility for the fixed method, not a campaign rate. The [offline workflow](lab/offline_memory/README.md#tls-13-implementation) records the implementation boundary.

### 5.2 Twenty-session baseline repeatability

The subsequent baseline campaign captured 20 fresh, single-connection TLS 1.3 sessions at ten-minute spacing. All 20 completed automatically. Both generation-zero application traffic-secret directions were selected uniquely from saved-memory candidates by PCAP validation, matched the independent reference exactly, and decrypted the intended request and response. Candidate discovery yielded 196 values across the campaign: nine values in four sessions and ten in sixteen. Every case had one client-direction winner and one server-direction winner. Directional one-bit controls passed in 20/20 cases. Median end-to-end case time was 51.01 seconds. Raw-core/profile cleanup was recorded in 20/20 cases. The [TLS 1.3 repeatability result](docs/offline-memory/TLS13_REPEATABILITY_RESULTS.md) limits this dataset to full handshakes, no resumption, no intentional KeyUpdate and no 0-RTT.

### 5.3 Extended connection states and capture times

Five separately piloted, frozen campaigns tested conditions beyond the baseline. Each campaign contained 20 fresh cases with starts spaced at least 600 seconds apart. Every repeat case passed its scenario condition, structured extraction, unique packet assignment, exact reference equality, intended marker authentication and negative controls.

| Scenario | What the image had to support | Complete cases |
| --- | --- | ---: |
| Before response | Both generation-zero directions while the response was held behind a gate | 20/20 |
| Delayed capture | Both generation-zero directions at least 30 monotonic seconds after the response | 20/20 |
| Resumption | Both generation-zero directions of the second, PSK-resumed connection | 20/20 |
| KeyUpdate | Both generation-one directions after a bidirectional update | 20/20 |
| Concurrency | Both directions for each of two overlapping connections | 20/20 |
| **Total** | Two targets in the first four groups; four in concurrency | **100/100** |

The campaigns had 9–20 candidates per case, with a median of 10. Case execution ranged from 42.194 to 105.939 seconds, median 50.541 seconds, excluding the scheduled spacing. Cross-flow controls failed as expected in concurrency cases and generation-zero controls failed against generation-one targets in KeyUpdate cases. Earlier unsuccessful development pilots remain separate and are not counted in these 100 repeats. The [extended results](docs/offline-memory/TLS13_EXTENDED_RESULTS.md) and [work log](docs/offline-memory/TLS13_EXTENDED_WORK_LOG.md) specify the condition and target for each scenario.

These results broaden the tested states of the pinned build. They do not establish 0-RTT, all resumption patterns, arbitrary key-update schedules, different cipher suites or unbounded secret lifetime.

## 6. Blind TLS 1.3 multiconnection study

### 6.1 Design and information boundary

The later blind study used two or three overlapping WebSocket/TLS connections and undisclosed, varied payloads. Each direction carried at least two application messages before capture. Recovery received one saved core, its complete PCAP and pinned metadata, but no expected markers, server event log, key log, case label or supplied connection map. A root-only evaluator kept the answers. A ten-case development pilot preceded the frozen final manifest. The 100 final neutral case IDs comprised 35 two-flow positives, 35 three-flow positives, ten mismatched core/PCAP pairs, ten unrelated-traffic PCAPs and ten cores with one target secret deliberately redacted. The final had 100/100 attempted and scored cases. See the [blind-study report](docs/offline-memory/TLS13_BLIND_STUDY_RESULTS.md) and [manifest](docs/offline-memory/campaigns/BLIND-FINAL-20260930-A/manifest.json).

The structural arm reused the NSS `CKA_VALUE` candidate enumeration and selected secrets by shared TLS 1.3 record authentication. The original comparator was an entropy-only scan across readable 48-byte windows. Both received a 180-second search budget, a 100-candidate cap, a 300-second authentication budget and the same final evaluator. Their order alternated across cases. The entropy scanner reached its search time limit in every final case; the structured search exhausted its enumeration in every case.

### 6.2 Final findings

| Declared outcome | Structured candidate search | Entropy-only search |
| --- | ---: | ---: |
| Complete positive cases | 70/70 | 0/70 |
| Correct positive connection/direction targets | 350/350 | 1/350 |
| All controls meeting their declared outcome | 30/30 | 20/30 |
| False assignments across all cases | 0 | 0 |
| Reference secrets included among 390 available targets | 390/390 | 1/390 |
| Median wall time per case | 23.0 s | 187.7 s |

In the ten redacted-memory controls, the structured method recovered 40 still-available directions while leaving the ten removed directions unresolved. It abstained completely on the ten mismatched and ten unrelated controls. The entropy arm also abstained correctly on the mismatched and unrelated controls but missed the required available directions in the redacted cases. The 390 available targets consist of 350 positive-case targets and 40 still-present targets in redacted controls; they should not be confused with all scored target slots.

Every one of the 70 positive pairs favored the structured arm on complete-case recovery. The predeclared paired difference was 1.0, with a paired bootstrap interval of `[1.0, 1.0]` across 20,000 resamples. This extreme interval reflects the uniform outcomes on this generated dataset, not a universal accuracy bound. The supported comparison is against this particular entropy-only method at the declared resource limits.

### 6.3 Retention and audit

All 100 original cores, paired and decoy PCAPs, redacted derivatives, protected references, logs and sealed outputs were retained on the controlled host, allowing later replay. A post-run audit checked all 200 method seals, the frozen script hashes and an exact recomputation of the aggregate summary. The versioned [aggregate summary](docs/offline-memory/campaigns/BLIND-FINAL-20260930-A/summary.json) is nonsecret. The original account permissions protected reference answers, but the same-run cross-method visibility caveat led to the stricter isolated replay described next.

## 7. Isolation, replication and method comparison on retained cases

### 7.1 Isolated replay

The retained 100 cases were replayed with the historical methods unchanged inside separate filesystem, network, process, IPC, user and cgroup namespaces. An access probe checked that the recovery process could see only its staged core, PCAP, metadata, frozen software and own output; it also checked forbidden paths and loopback denial. The controller verified input hashes, took ownership of outputs after exit, sealed them, and opened references only after seal verification. The separate read-only auditor found **100 matched, zero different, zero failed, zero partial and zero unattempted** cases. This is a reproducibility and isolation result on existing data, not a second 100-case trial. See the [isolated validation plan](docs/offline-memory/TLS13_ISOLATED_VALIDATION_PLAN.md) and [controller documentation](lab/isolated_tls13/README.md).

### 7.2 Primary five-method comparison

The subsequent 180-second/100-candidate primary comparison ran five discovery methods on the same retained 100 images and PCAPs. All used the same TLS record-authentication assignment and evaluator. The added methods were: structure-only enumeration without entropy admission; a declared 48-byte TLS 1.3 adaptation of Anderson and colleagues' NSS adjacency pattern; and an adaptation of the **full-snapshot entropy baseline** from X-Ray-TLS. The latter is not X-Ray-TLS's complete live before/after memory-difference method. The fifth arm was the historical entropy-only scanner.

| Candidate discovery | Complete positive cases | Correct positive targets | Mismatch + unrelated controls abstained | Withheld controls passed | Median positive wall time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Historical structure + entropy | 70/70 | 350/350 | 20/20 | 10/10 | 22.7 s |
| Structure only | 70/70 | 350/350 | 20/20 | 10/10 | 17.3 s |
| Adapted Anderson NSS adjacency | 69/70 | 347/350 | 20/20 | 10/10 | 20.3 s |
| Historical entropy only | 0/70 | 1/350 | 20/20 | 0/10 | 187.7 s |
| Adapted X-Ray full-snapshot entropy baseline | 0/70 | 0/350 | 20/20 | 0/10 | 187.4 s |

Every method recorded zero false assignments. The signed campaign summary and independent handoff audit reported 100 scored cases, no failure, no partial case and no unattempted case. These are **paired reanalyses**, not 500 new acquisitions or independent cases. The structure-only arm matching the historical structured arm is evidence that the entropy admission filter did not improve observed complete-case recovery on this retained corpus; it is not proof that entropy is useless for every build or workload. The [primary comparison result](docs/offline-memory/TLS13_PRIMARY_COMPARISON_RESULTS.md) records the frozen evidence hashes and comparison limits.

### 7.3 Resource sensitivity

Before inspecting grid outcomes, 20 retained cases were selected by a case-ID hash: seven from each positive flow-count stratum and two from each control stratum. Five methods were run at each combination of search budgets **30, 180 and 600 seconds** and candidate caps **25, 100 and 1,000**. The 20 × 9 grid produced 180 scored settings and 900 sealed method outputs. The exact frozen read-only audit found zero failed, partial or unattempted settings. These are repeated measurements on 20 selected cases, not 180 independent cases.

At the primary 180-second/100-candidate setting, the structured, structure-only and adapted Anderson arms each included and correctly assigned **78/98** declared target slots with **20 abstentions** and no false assignment. The 98 slots include control targets deliberately absent from certain images; the 20 abstentions were correct. The historical entropy-only and adapted X-Ray full-snapshot arms scored 0/98 at this setting, with search timeouts in 20/20 and 13/20 cases respectively. The structural arms had no search timeout. Across all nine settings, historical structured and structure-only each remained at 78/98 with zero false assignments; the adapted Anderson arm was 74/98 at cap 25 and 78/98 at caps 100 and 1,000. At the largest setting the adapted X-Ray full-snapshot baseline reached 3/98, while historical entropy-only reached 0/98. The [sensitivity result](docs/offline-memory/TLS13_SENSITIVITY_RESULTS.md) gives the full interpretation.

The grid supports an advantage from NSS structure in these selected images and shows a candidate-cap effect for the adapted adjacency arm. It also shows that the historical entropy filter discarded no observed valid structural candidate in this grid while adding about seven seconds to the median run at the primary setting. The structural and entropy implementations count different work units, so an equal-unit “memory bytes searched” comparison is not established. Nor is this a direct comparison with the complete X-Ray-TLS system, whose live timed snapshots supply different inputs.

### 7.4 Independent traffic check

An additional post-seal TShark 4.6.4 integration check on one completed positive replay case matched **12/12 private workload payload hashes** using the recovered application secrets and reference **handshake-only** secrets needed for decoding. It did not use reference application secrets. A larger representative subset across success, partial and control outcomes is still required by the plan. The diagnostic also showed that the dummy-handshake method used by a patched X-Ray-TLS TShark build did not work with the laboratory's stock TShark; the report records the actual decoder support used.

## 8. Evidence management and reproducibility

The project separates development, pilot, fresh campaign, retained-case replay and planned confirmation evidence. Campaign identifiers, frozen scripts, input hashes, output seals, signed controller records and read-only audits allow an outcome to be traced without publishing secret bytes. Failures and amendments are preserved as chronology rather than overwritten. Negative and withheld controls test both incorrect assignment and appropriate abstention.

| Evidence area | Principal versioned location | Private evidence boundary |
| --- | --- | --- |
| TLS 1.2 pilot and repeatability | [`docs/offline-memory/` in active publication](docs/offline-memory/) and [workspace output](docs/offline-memory/) | Candidate secrets, isolated references, PCAPs and retained small case artifacts on lab host; campaign cores removed after durable result storage. |
| TLS 1.3 baseline and extended campaigns | [Extended validation documents](docs/offline-memory/) and campaign JSON/CSV | Raw secret-bearing artifacts and full per-case logs on lab host. |
| Blind final | [Manifest](docs/offline-memory/campaigns/BLIND-FINAL-20260930-A/manifest.json) and [summary](docs/offline-memory/campaigns/BLIND-FINAL-20260930-A/summary.json) | Original cores, PCAPs, references and sealed outputs retained privately. |
| Isolated replay, primary comparison and grid | [Plan and audit chronology](docs/offline-memory/TLS13_ISOLATED_VALIDATION_PLAN.md), [comparison](docs/offline-memory/TLS13_PRIMARY_COMPARISON_RESULTS.md), [sensitivity](docs/offline-memory/TLS13_SENSITIVITY_RESULTS.md) | Signed case-level records and private inputs on the separate laboratory volume. |

The source used to assemble this repository was an imported, partial research snapshot; its [snapshot note](docs/REPOSITORY_PROVENANCE.md) says the complete original remote laboratory, private references and Git history are not included. Historical commit IDs and absolute paths in older reports are provenance references, not objects necessarily present in this checkout. Local source/tests and public aggregate JSON are useful audit inputs, but they do not replace independent access to the protected evidence. The newer isolated results are documented in Markdown, while their signed detailed audits remain on the server.

## 9. Current work and open research questions

The completed retained-case programme does **not** yet demonstrate transfer to unseen Firefox builds or confirmation on a fresh, independently generated multiconnection cohort. A transfer design froze Firefox **135.0.1** and **137.0.2**, 20 cases per build: 14 positives and six controls each. Official archives, build/NSS hashes and the permitted metadata-only changes were recorded before transfer results. By the latest available work log, the two-build positive pilot scored **2/2** for the historical structured method with no false assignment and passed its read-only audit. The 40-case campaign was launched at **04:31 UTC on 4 October 2026**; its full outcome was **pending in the available record**. This report does not infer a completion result from launch. See the [unseen-build manifest](docs/offline-memory/TLS13_UNSEEN_BUILD_MANIFEST.json) and the [execution chronology](docs/offline-memory/TLS13_ISOLATED_VALIDATION_PLAN.md).

A separate proposed fresh confirmation design has 100 new cases matching the blind study's 70-positive/30-control allocation, with new secrets and varied undisclosed payloads. No completed fresh-confirmation outcome is present in this workspace. The proposed independent TShark check also needs a representative prespecified subset rather than only one positive integration case. Literature-grounded novelty analysis remains to be completed before stating a broad originality claim.

A public-handshake audit of the blind study's 100 cases found negotiated group `X25519MLKEM768` and `TLS_AES_256_GCM_SHA384` in every saved PCAP. This is public handshake metadata, **not** evidence that an ephemeral private key was recovered from memory. Recovering only an X25519 scalar would not supply the hybrid shared secret; the ML-KEM component or an equivalent later secret would also be needed. The [feasibility note](docs/offline-memory/TLS13_EPHEMERAL_KEY_FEASIBILITY.md) proposes a bounded future probe and explicitly reports no memory-residue recovery result.

## 10. Limitations and defensible conclusion

The successful experiments used privileged memory acquisition on a controlled endpoint, complete saved traffic, pinned Firefox/NSS versions, fixed cipher policy and designed workloads. Memory capture may omit unreadable regions and changes browser timing by pausing the process. Many early cases used one connection and deliberate capture gates; the blind study broadened connection count and payload variation but excluded resumption and KeyUpdate from **that** 100-case comparison. The extended scenario campaigns tested resumption and KeyUpdate separately. Different versions, operating systems, cipher suites, packet loss, endpoint lifetimes, allocator states and uncontrolled concurrent activity remain open questions.

The strongest present claim is specific: in the pinned Firefox 136.0.2/NSS controlled datasets, structured saved-memory discovery supplied candidates that could be assigned by authenticated saved-traffic testing and then independently verified as exact TLS secrets. The blind study demonstrated complete recovery for its 70 positive multiconnection cases with correct behavior in 30 declared controls; isolated replay reproduced those decisions on the same retained cases, and retained-case comparisons associated the observed advantage with NSS structure under the measured limits. The work does **not** establish a network-only attack, a break of TLS 1.2/1.3, universal browser transfer, production readiness, or a population-level success probability.

## 11. Source index

- [Active thesis scope](docs/governance/THESIS_SCOPE.md) and [contribution boundaries](docs/governance/CONTRIBUTION_BOUNDARIES.md).
- [Saved-memory pilot result](docs/offline-memory/SAVED_MEMORY_RESULT.md), [TLS 1.2 repeatability](docs/offline-memory/REPEATABILITY_RESULTS.md) and [TLS 1.3 repeatability](docs/offline-memory/TLS13_REPEATABILITY_RESULTS.md).
- [TLS 1.3 extended campaigns](docs/offline-memory/TLS13_EXTENDED_RESULTS.md), [blind study](docs/offline-memory/TLS13_BLIND_STUDY_RESULTS.md), [primary comparison](docs/offline-memory/TLS13_PRIMARY_COMPARISON_RESULTS.md) and [resource sensitivity](docs/offline-memory/TLS13_SENSITIVITY_RESULTS.md).
- [Isolated validation plan and chronology](docs/offline-memory/TLS13_ISOLATED_VALIDATION_PLAN.md), [prior-work comparison](docs/offline-memory/TLS13_PRIOR_WORK_MATRIX.md), and [unseen-build manifest](docs/offline-memory/TLS13_UNSEEN_BUILD_MANIFEST.json).
- [Offline memory code](lab/offline_memory/), [blind study code](lab/blind_tls13/) and [isolated replay/comparison code](lab/isolated_tls13/).
