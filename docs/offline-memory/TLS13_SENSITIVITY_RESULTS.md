# TLS 1.3 saved-image resource sensitivity: retained cases

The frozen 20-case × nine-setting grid completed on 2026-10-04 at 01:06:47 UTC. Its controller-signed summary has SHA-256 `e8449146ed19ee4b779502d46502878f7ee5391928b516bbdd9ea1ee88734e29`. The exact frozen, read-only auditor passed on the separate Hetzner volume; its report has SHA-256 `241706f9514d20baf339a4fc6e0e925ecfb7cfed31393631dc36f6e9214d8b51` and accounts for 180/180 scored settings, zero failed, zero partial, and zero unattempted. Each setting ran five methods, yielding 900 sealed method outputs. This is **resource sensitivity on 20 selected retained cases**, not 180 independent cases or a fresh confirmation campaign.

The selection and design were fixed before the grid: 20 retained cases, search budgets of 30, 180, and 600 seconds, candidate limits of 25, 100, and 1,000, identical record-authentication assignment, and the historical structured and entropy methods plus structure-only, adapted Anderson NSS adjacency, and adapted X-Ray full-snapshot entropy arms. The auditor verified the frozen controller hashes, inputs, method seals, reconciliations, case selection, settings, and campaign summary.

At the primary 180-second/100-candidate setting, the nonsecret aggregate is:

| Candidate discovery | Reference targets in candidates | Correct assignments | Abstentions | False assignments | Search timeouts | Median method wall time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Historical structure + entropy | 78/98 | 78/98 | 20 | 0 | 0/20 | 21.9 s |
| Structure only | 78/98 | 78/98 | 20 | 0 | 0/20 | 14.7 s |
| Adapted Anderson adjacency | 78/98 | 78/98 | 20 | 0 | 0/20 | 20.5 s |
| Adapted X-Ray full-snapshot entropy baseline | 0/98 | 0/98 | 98 | 0 | 13/20 | 187.5 s |
| Historical entropy only | 0/98 | 0/98 | 98 | 0 | 20/20 | 187.7 s |

The 98 target slots include controls, including targets intentionally absent from some memory images; the 20 abstentions for the structural arms are not false assignments. At this setting, every target that entered a method's candidate set was assigned correctly. Authentication did not time out in any of the 900 method runs. The adapted Anderson search hit the 100-candidate cap in three cases, although all its reference targets remained in the set.

Across all nine settings, the structured and structure-only arms each retained and correctly assigned 78/98 target slots every time, with zero false assignments and zero search timeouts. The entropy admission filter therefore discarded **no observed valid secret in this selected grid**; it also did not improve recovery over structure-only and added about seven seconds to the median method run at the primary setting. The adapted Anderson arm scored 74/98 at cap 25 and 78/98 at caps 100 and 1,000, independent of the search-time setting. This shows a candidate-limit effect in that arm. The two entropy scans were far more sensitive to time and ranking: at 600 seconds/1,000 candidates, the adapted X-Ray full-snapshot baseline scored 3/98 and the historical entropy-only arm scored 0/98. Historical entropy-only briefly scored 1/98 at 180 seconds/1,000 candidates; its top-candidate ranking can replace an earlier candidate during a longer scan, so outcome is not necessarily monotonic in time.

The full-snapshot X-Ray arm is only an adaptation of that paper's baseline. It does not reproduce X-Ray-TLS's live before/after memory differencing, which cannot be run from one saved image. These results support a discovery advantage from NSS structure in this pinned Firefox build and selected retained cases; they do not establish transfer to unseen builds or superiority over the complete published X-Ray-TLS method.

Cost fields in every method report include wall time, CPU time, peak RSS, candidate count, and authentication trials. The entropy methods additionally record windows scanned; the structure-based methods enumerate memory patterns and do not expose a directly comparable byte or window count. Thus the grid establishes differences in candidate recall and observed processing time, while an equal-unit **memory-bytes-searched** comparison remains unavailable from these frozen reports. Timeouts above are actual search-time expirations, not `search_exhausted=true` (which means the search completed).

Private case-level records, candidate bytes, and reference answers remain on the server. The nonsecret audit report is at `/mnt/HC_Volume_106994092/tls13-sensitivity-grid-20x9-20261002/audit-final-20261004.json` on the mounted volume.
