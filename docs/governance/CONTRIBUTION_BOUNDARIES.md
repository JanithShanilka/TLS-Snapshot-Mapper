# Active thesis contribution boundaries

**Effective:** 2026-09-28. This replaces the retired live-hook contribution contract.

The active work implements and evaluates a bounded saved-memory recovery workflow: structured candidate enumeration, explicit ambiguity/abstention, saved-PCAP candidate validation, and independent post-selection verification for controlled Firefox/NSS sessions.

| Area | Permitted bounded claim | Evidence |
| --- | --- | --- |
| Memory extraction | Implemented enumeration of structured candidates from captured process memory | Offline source, synthetic tests, named offline cases |
| Memory-only ranking | Measured candidate inclusion and unique selection/abstention | Offline per-case results; ties remain failures of unique selection |
| Packet-assisted selection | Tested sealed candidates using saved traffic without reference-secret input | Offline validator outputs and selected-candidate records |
| Independent verification | Checked exact equality, controlled traffic recovery and corrupted-secret controls after selection | Offline verification records |
| TLS 1.2 repeatability | Evaluated fresh sessions under fixed conditions, retaining failures and separate reanalysis | Campaigns A/B and the separate A repair record |
| TLS 1.3 feasibility | Recovered directional application traffic secrets in development and one fresh validation case | Separate TLS 1.3 summaries; no campaign-rate claim |

The retired argument ranker, A/D benchmark improvements, runtime hooks, static fingerprints and historical hook campaigns are not active contributions or evidence. No results from those experiments may appear in thesis tables, figures, comparisons or conclusions.

Attribute prior TLSKeyHunter concepts to their authors. Do not claim invention of TLSKeyHunter, secret-to-client-random association, or TLS secret validation through decryption. Implementation alone does not establish novelty; any novelty claim requires a literature-grounded assessment.

Do not equate entropy scores with secret accuracy, reference-only decryption with blind extraction, packet-assisted success with memory-only success, or eventual recovery after repair with unattended reliability. Results apply only to the named versions, cipher suites, capture conditions and controlled workloads. Public summaries do not constitute complete private evidence.

The governing scope is [THESIS_SCOPE.md](THESIS_SCOPE.md). Original attribution is retained in [UPSTREAM_PROVENANCE.md](UPSTREAM_PROVENANCE.md).
