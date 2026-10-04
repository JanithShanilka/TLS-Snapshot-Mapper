# Ephemeral-key recovery from the retained TLS 1.3 images

This is an exploratory feasibility note on **existing data**, separate from the frozen replay, comparison, and resource-limit grid. It does not score a new recovery method or add independent cases.

## Public-handshake audit (2026-10-03)

The saved study manifest has SHA-256 `a75a7c2fda8ac17c7fba29523158a4ec74cd756a5016d172f686ce502ab57660`. For each of its 100 declared cases, TShark 4.6.4 read the saved PCAP's ServerHello and reported the negotiated key-share group and cipher suite. The audit parsed 100/100 cases with no missing or ambiguous group:

| Negotiated value | Cases |
| --- | ---: |
| Group 4588 (`0x11ec`, X25519MLKEM768) | 100/100 |
| Cipher suite `0x1302` (TLS_AES_256_GCM_SHA384) | 100/100 |

The audit read only public handshake metadata. It copied each small PCAP into a temporary private directory for TShark and removed the copy immediately. It did not open memory images, candidate outputs, or reference answers. The study directory also contains PCAPs outside the manifest; these were excluded from the 100-case result.

## Consequence for the proposed `r`/private-key approach

`ClientHello.random` and the key-share public values in the PCAP are not private keys. Group 4588 combines an X25519 exchange with ML-KEM-768. Recovering just the client's X25519 private scalar would supply only the X25519 component; deriving this study's TLS secrets from the handshake also requires the client's ML-KEM decapsulation key or the corresponding ML-KEM shared secret (or an already-derived later secret). The Firefox and local server were separate processes; the saved core is from Firefox's socket-owning process only.

The capture occurs after application messages have already crossed the connection. NSS's TLS 1.3 completion path calls the general handshake-finish routine, which frees its ephemeral key pairs. This makes a live private-key structure unlikely at capture time, although a saved core could still contain stale bytes from freed allocations. Source behavior is a reason to test carefully, not proof of absence in these exact images.

## Bounded saved-image test after the active timing grid

Use one retained positive case as a **development probe**, without changing the frozen grid or its results. Pin the image and PCAP hashes, source revision, parser, candidate limits, and a maximum scan time. Read only that case's saved Firefox core, its PCAP, and declared metadata. Do not give the probe access to reference key logs, other cases, or prior method outputs.

First compare any proposed private-key material with the PCAP's client public key shares. A public-share match alone is not evidence that private material survived. If both private components or their equivalent shared secrets are found, derive the hybrid shared secret and TLS 1.3 key schedule from the complete recorded handshake, authenticate captured encrypted records, then seal outputs before the evaluator opens reference answers. Include wrong-key and wrong-case negative controls. Record an abstention if either component is absent or cannot be validated, and retain failed attempts and cost measurements.

Do not start the full-core scan while the frozen resource-limit grid is measuring runtimes: competing disk reads or CPU use could contaminate those timing results. No memory-residue result has been obtained yet, and this note must not be cited as a successful ephemeral-key recovery.

Primary sources: [IANA TLS supported-group registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8), [RFC 10024 hybrid group construction](https://www.rfc-editor.org/rfc/rfc10024.html), [Mozilla NSS TLS 1.3 key-share handling](https://searchfox.org/nss/rev/9028b604112bc4a797d9fa4824670bc686e3891a/lib/ssl/tls13con.c), [Mozilla NSS handshake cleanup](https://github.com/mozilla/gecko-dev/blob/master/security/nss/lib/ssl/sslsecur.c), and [TLS 1.3 key schedule](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1).
