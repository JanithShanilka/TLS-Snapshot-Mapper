# TLS Snapshot Mapper

Saved-memory TLS secret recovery and role assignment for controlled Firefox/NSS experiments.

This repository contains the **active saved-memory research code and nonsecret documentation**. It is a clean project layout assembled from the current local research sources. It does not contain the retired TLSKeyHunter live-hook implementation, its benchmarks, or upstream Ghidra/Frida source files.

Start with the [consolidated research report](RESEARCH_REPORT.md). It brings together the experimental methods, completed results, limitations, evidence boundaries and current work through the available records of 4 October 2026.

## What the software does

1. A controlled laboratory session saves a Firefox process core and its corresponding encrypted traffic capture.
2. Offline code enumerates candidate secret values from the saved image, without reading the independent server reference.
3. A separate assignment step tests candidates against authenticated records in the saved PCAP. It reports ambiguity or abstains when evidence is insufficient.
4. After decisions are sealed, an evaluator checks exact secret equality, recovered traffic and negative controls against protected references.

The method requires privileged access to endpoint memory. It does not break TLS encryption or recover secrets from network traffic alone. The recorded results apply to the specific pinned builds, cipher suites and workloads described in the report.

## Repository map

| Path | Contents |
| --- | --- |
| [Research report](RESEARCH_REPORT.md) | One detailed account of the active work and its evidence. |
| [Offline memory laboratory](lab/offline_memory/) | Firefox acquisition, ELF core reader, TLS 1.2/1.3 candidate discovery, packet validation, verification and repeatability runners. |
| [Blind TLS 1.3 study](lab/blind_tls13/) | Multiconnection generator, reference-blind recovery, evaluator and study runner. |
| [Isolated validation](lab/isolated_tls13/) | Namespace-isolated replay, comparison arms, sensitivity grid, audits, independent traffic check and unseen-build transfer code. |
| [Study documents](docs/offline-memory/) | Protocols, work logs, result reports, frozen manifests and nonsecret campaign summaries. |
| [Governance](docs/governance/) | The dated scope decision, contribution boundaries and upstream attribution. |
| [Repository provenance](docs/REPOSITORY_PROVENANCE.md) | Source selection, excluded material and what this publication can verify. |
| [Tests](tests/) | Offline, blind-study, comparison and isolation checks. |
| [Presentation](presentations/) | The final research-pathway deck and speaker notes prepared before the later sensitivity result. |

## Evidence status

The versioned results record TLS 1.2 and TLS 1.3 repeatability, five extended TLS 1.3 scenarios, a 100-case blind study, an isolated replay of those same 100 cases, a five-method retained-case comparison and a 20-case resource-sensitivity grid. The unseen Firefox build campaign was launched after a passing two-build pilot; its full outcome is **not** available in this snapshot. See the report for the exact denominators and study boundaries.

Raw cores, candidate values, reference secrets, private key logs, PCAPs and full signed case evidence are not included. Some historical records refer to the original laboratory paths and script hashes. Publishing this source does not rerun the experiments or reproduce their private evidence.

## Local checks

The Python code targets the controlled Linux x86-64 laboratory. Unit checks can be run from the repository root with Python 3 and `cryptography` installed:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

These checks exercise local logic. Full acquisition and replay require the recorded Firefox/NSS builds, GDB, packet tools, the laboratory Python dependencies and the private evidence environment. Follow the relevant `lab/` README and frozen protocol before any new run. A new run must use new case IDs and keep private outputs outside Git.

## Attribution and scope

TLSKeyHunter is prior work and is credited in [third-party notices](THIRD_PARTY_NOTICES.md). The active thesis scope retired the earlier live-hook method on 28 September 2026; its files and results are held separately for provenance and are not included in this repository's evidence tables. The MIT [license](LICENSE) applies to original contributions that the named copyright holder can license; it does not relabel third-party research as original.
