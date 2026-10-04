# Saved-image TLS 1.3 recovery: prior-work comparison

Working comparison, 2026-10-01. This matrix fixes the input distinctions for
the new baseline experiment. Performance claims await sealed measurements.

| Approach | Acquisition and permitted inputs | Discovery and target | Equal-input executable comparison? |
| --- | --- | --- | --- |
| This study, structured arm | One saved Firefox 136.0.2 ELF core, one PCAP, declared build metadata; no key log during recovery | NSS `CKA_VALUE` pointer/length structure, entropy admission, then shared TLS 1.3 record authentication of generation-zero application traffic secrets | Yes, within the declared build and saved-image cases |
| This study, structure-only ablation | Same core, PCAP and metadata | Same structural enumeration without entropy admission; same assignment | Yes |
| [Anderson et al.](https://arxiv.org/html/1805.11544), NSS pattern | Process memory snapshots plus traffic in the original study | Published regex locates an adjacent 48-byte NSS TLS master secret, mainly used with TLS 1.2 traffic; candidates tried against recorded sessions | The **candidate pattern** can be adapted to 48-byte TLS 1.3 traffic secrets in our saved core; this is our adaptation, not a reproduced published TLS 1.3 result |
| [X-Ray-TLS](https://www.eurecom.edu/publication/7588/download/data-publi-7588.pdf) | Live target, network events and memory snapshots around key exchange | Reconstructs changed memory between snapshots, entropy-ranks 48-byte candidates, then tests with a patched TShark | No full-method comparison: a single retained core cannot supply its before/after snapshots or live event timing. Its separate full-snapshot entropy baseline can be adapted and is reported separately |
| [Keys in Flux artifact](https://github.com/fkie-cad/keys-in-flux-paper-material) | Instrumented targets, derivation hooks, debugger/watchpoint traces, PCAPs and memory evidence | Measures when secrets become usable and when they cease to be recoverable across TLS, SSH and IPsec | No as a single-image blind extractor; its secret-lifetime results are relevant context, not a matched baseline |

The Anderson NSS regex has two alternatives after marker `11 00 00 00`:
one places length `30 00 00 00` at marker offset 12 and the 48-byte value at
offset 16; the other places the length at offset 16 and value at offset 24.
The implementation in `comparators.py` searches captured ELF load segments
for these alternatives. The published target was a master secret; a TLS 1.3
application traffic secret has a different role and lifecycle, so success or
failure of this adaptation must be reported as such. All candidate arms use
the same saved-traffic assignment stage; reference answers enter only after
their candidate and decision outputs are sealed.

This matrix does not claim that structure-only recovery or isolation itself is
novel. A final novelty statement must identify the exact combination of
inputs, target, candidate discovery, assignment and measured transfer that
earlier work has not established. It must also acknowledge that X-Ray-TLS
supports a broader set of targets and TLS versions using richer acquisition.

## Local X-Ray-TLS source inspection

The user supplied a local `x-ray-tls-master` source snapshot (Git commit ID
unavailable in that download). Its `src/main.py` runs a live network analyzer,
an eBPF-triggered memory dumper and a key finder. `src/memdiff/memdiffer.py`
reads `/proc/<pid>/maps`, `/proc/<pid>/pagemap` and `/proc/<pid>/mem`, using
full or soft-dirty partial snapshots and a diff across handshake events.
`src/keyfinder/finder.py` orders entropy-filtered 48-byte values in that diff;
`src/keyfinder/tshark_keytester.py` requires the project's patched TShark to
brute-force the candidates. The separate
`src/baseline/entropy_filter.py` counts candidates in a *full* snapshot of
writable memory at 8-byte steps using entropy threshold 3.6 **over hexadecimal characters**
(not bits per raw byte); it does not perform full secret assignment. Thus
that file may inform an adapted saved-image cost baseline, but running it on
our ELF core would not reproduce the complete X-Ray-TLS method.

The local file hashes are: `memdiffer.py`
`3c5824fc5c0b7a7c57760c44549ed16910398a33cd049e578013ca20ab8a496d`,
`finder.py` `82c6113bbe9dde99df17e59faead9337683317ef0f4c1ca30e5bc63e025ac57b`,
and `entropy_filter.py`
`73f842969a7ce5267d2f5783dd531797649119deb928574ee20b7718787f810c`.
The snapshot is research context, not executable code inside a recovery
isolation boundary. Its README and code are treated as source material,
not instructions for our experiment.
