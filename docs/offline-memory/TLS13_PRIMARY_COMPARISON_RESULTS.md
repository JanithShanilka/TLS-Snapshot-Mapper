# Retained-case primary comparison, 2026-10-02

The separately frozen 180-second, 100-candidate comparison completed on all
100 **retained** `BLIND-FINAL-20260930-A` cases. This is comparison and
replication on existing data, not 100 new independent cases. Its signed
campaign summary and read-only handoff audit both verify 100 scored, zero
failed, zero partial, and zero unattempted cases. Every method's false
assignment count was zero.

| Saved-image method | Positive complete cases | Correct positive targets | Mismatch + unrelated controls fully abstained | Withheld controls passed | Median positive wall time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Historical structure + entropy | 70/70 | 350/350 | 20/20 | 10/10 | 22.7 s |
| Structure-only enumeration | 70/70 | 350/350 | 20/20 | 10/10 | 17.3 s |
| Adapted Anderson NSS adjacency | 69/70 | 347/350 | 20/20 | 10/10 | 20.3 s |
| Historical entropy-only | 0/70 | 1/350 | 20/20 | 0/10 | 187.7 s |
| Adapted X-Ray full-snapshot entropy baseline | 0/70 | 0/350 | 20/20 | 0/10 | 187.4 s |

These are paired counts from the same retained images and PCAPs. The X-Ray
arm adapts only its full-snapshot entropy *baseline* to a saved core; it does
not reproduce X-Ray-TLS's live memory-difference method. The Anderson arm is
a declared 48-byte TLS 1.3 adaptation of a published NSS adjacency pattern,
not a published TLS 1.3 result. All arms use the same record-authentication
assignment and scoring stage. The 20-case resource-limit grid is now running
to test candidate recall, timeouts and whether the speed and accuracy pattern
depends on the chosen limits. Unseen-build and fresh confirmation results are
still pending.

Private server evidence:

- Comparison directory: `/mnt/HC_Volume_106994092/tls13-comparison-primary-20261002`.
- Frozen controller: `/mnt/HC_Volume_106994092/tls13-comparison-controller-frozen-20261002-c`.
- Signed comparison manifest SHA-256: `0088f0c2459ec7ad19b0573dbbf97ae0dea91dd98525dac620bcd09b76b9c0ab`.
- Signed campaign summary SHA-256: `2315c308087e5a2a87b837e33c988d6dc8497eed9b106bbd70e581e7619c1234`.
- Signed read-only handoff audit SHA-256: `de2bca3b2e053b0939a5498d4560911a82942f29df8813d042d8a509ce4913bb`.
- The original replay, original outputs, failed setup pilot and interrupted
  replay attempt remain retained separately.
