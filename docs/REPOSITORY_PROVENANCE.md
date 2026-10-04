# Repository provenance and publication boundary

**Prepared:** 4 October 2026. This is a curated publication of the active saved-memory project into `TLS-Snapshot-Mapper`, not a Git-history-preserving fork of the older `TLK-Key-Hunter-v2` repository.

## Included sources

- `lab/offline_memory/`, `lab/blind_tls13/`, `lab/isolated_tls13/`, `ops/` and the matching offline tests were copied from the local `tls13-extended-validation` research checkout as present at publication time.
- `docs/offline-memory/` contains that checkout's dated plans, work logs, result reports, frozen manifests and nonsecret campaign JSON/CSV. Historical plans retain the status they had when written; later result reports and `RESEARCH_REPORT.md` state what was completed.
- `docs/governance/` contains the saved-memory scope decision and attribution record from the active `TLK-Key-Hunter-v2-publish` checkout. Its 28 September evidence-status examples predate the later TLS 1.3 campaigns and should be read as dated governance, not as a current result inventory.
- `RESEARCH_REPORT.md` consolidates the active findings in this new layout. `presentations/` contains the final research-pathway deck and its speaker notes prepared from records available on 3 October; it predates the completed sensitivity audit and the unseen-build launch.

## Deliberately excluded

The retired runtime-hook code, argument-ranker benchmarks, Ghidra analyzer files, old report versions, visual hook evidence, and their result tables are not part of this saved-memory repository. Duplicate older snapshots of current offline code, Python caches, scratch files, raw cores, PCAPs, candidate values, private references, HTML evidence views, key logs and credentials are also excluded. The Markdown reports and nonsecret campaign summaries provide the public result record.

## Verification boundary

This checkout preserves source and nonsecret summaries. It does not contain the full remote laboratory, complete private case manifests, protected evaluator answers or original source Git history. Historical file hashes in experiment manifests refer to frozen laboratory snapshots and are not expected to match this reorganized checkout. The signed detailed audits for isolated replay, comparison, sensitivity and the unseen-build pilot remain on the controlled server. No experiment was rerun merely by assembling this repository.
