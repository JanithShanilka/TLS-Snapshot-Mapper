# Thesis scope: saved-memory TLS secret recovery

**Scope version:** 2.0
**Effective date:** 2026-09-28
**Status:** Governing active thesis scope; supersedes the 2026-08-30 live-hook contract.

## Researcher decision

The earlier live-hook method observed running software calls. That method, its argument ranker, native ABI benchmark, OpenSSL/wolfSSL A/D studies, Firefox/NSS hook campaigns, reports, frozen baselines and visual evidence are retired completely from the active thesis. They must not be used as results, baselines, comparisons, contribution claims, validation, or completion requirements. They are preserved only in an archive and a local archive branch.

This is a scope change made after the historical live-hook results and existing offline results were available. It is not a preregistered decision or a new experiment. No old result is relabelled as saved-memory evidence, and no offline denominator is changed.

## Active objective and inputs

Evaluate whether structured candidates recovered from saved Firefox/NSS process memory can produce exact TLS secret recovery and decrypt the corresponding saved controlled traffic. The tested environment is pinned Firefox 136.0.2/NSS on Linux x86-64, using researcher-controlled localhost sessions.

Candidate enumeration receives saved memory only. Packet-assisted validation additionally receives the saved PCAP and public handshake values. The isolated server reference is opened only after candidate selection is sealed. Runtime call hooks, argument-position observation and secret-export instrumentation are excluded from the extraction method.

## Research questions

1. Does saved-memory candidate enumeration include the required secret in fresh controlled sessions?
2. Can memory-only ranking select it uniquely, and how often does it abstain?
3. Can saved traffic resolve candidate ambiguity without reference-secret access?
4. Does independent verification establish exact equality, controlled request/response recovery and rejection of corrupted secrets?

TLS 1.2 and TLS 1.3 are separate experiments. TLS 1.3 reports client and server application traffic-secret roles independently and does not imply coverage of resumption, key updates or 0-RTT.

## Current evidence boundary

Use only `docs/offline-memory/` records and the associated private offline case evidence. TLS 1.2 repeatability comprises campaign A's one failed initial attempt and B's 19 continuation attempts; report the separate repair of A without hiding its original failure. TLS 1.3 currently has separate development and fresh validation summaries. A campaign runner's existence is not campaign evidence.

Historical offline plans and development logs are dated records, not current completion gates. Future evaluations must freeze method, inputs, capture timing, target versions and attempted-session count before execution, preserve failures, and record amendments separately.

## Acceptance and limitations

Recovery requires reference-independent candidate selection, exact independent equality and intended traffic decryption. Report memory-only abstention separately from packet-assisted success. Preserve every attempted session in its denominator, including acquisition and orchestration failures.

Report disposable-profile compatibility exceptions, incomplete memory mappings, fixed cipher/version/workload conditions, and deleted-dump retention limits. No claim of universal reliability, production readiness, breaking TLS cryptography, or measured analyst-effort improvement is supported.

## Archive location

Local branch: `codex/archive-live-hook-20260928`, commit `b3c86697bd60fa27224b0cc1ec3ab17903434f50`. Loose files and retired repository files: workspace `archive/retired-live-hook-20260928/`. The archive preserves provenance only and is outside active thesis evidence.
