# VERIFICATIONS.md — independent verification reports

Reports by parties other than the operator, recorded as received. A durable independent verifier publishes under its
own stable key in a log it controls; entries here are the operator's transcription and carry no more weight than that.

## 2026-09-12 — point-in-time independent verifier (via Bill), checkpoint `c7daba71606ea841bac32390c723beb35789f7dd`

**Verdict:** ACCEPT host-isolated pairs **0020/0021** and **0022/0023**. REJECT under current rules **0018/0019** (as
documented by ERR-007: signatures intact, witness health assertions fail).

| check | result |
|---|---|
| pulse hashes | 23/23 |
| chain links | 22/22 |
| Ed25519 signatures | 78 pass |
| distinct drand BLS rounds | 13 pass |
| RFC 3161 tokens | 16 pass |
| minimum current commit margin | 223 s |
| mutation/rejection tests (altered entropy, witness health, output value, drand round, predecessor link, missing statement, unknown statement, missing TSA token) | 8/8 rejected |
| state transitions | pass |

Accepted outputs: 0021 `d9312a0402cd1bd9250dfbf2fea26ce347ec4a348847f36b3cbc92f7aa20bbc9`;
0023 `603144ebdba4be65d8608ae9f9dae0c12aac5ce17ac9427d1b5e43faec7042db`.

**Findings raised (all accepted and fixed the same day, see `hosts/ISOLATION.md` "Hardening"):** fresh-install shell
broke forced commands (P1); commit not recoverable after the entropy host held `E` (P1); abandoned `E` retained (P1);
"green must mean fully verified" wording (P2).

**What the verifier could not certify — still true:** unique public pre-round publication (no external watcher key
yet; only pre-round TSA existence of the exact bytes); the live hosts' forced-command configuration from pulse data
alone (now partially addressed by the signed `execution` self-report); capture-time provenance for ERR-006 blocks;
live GitHub/drand refetch (blocked in that environment; BLS verified offline).

**Follow-up, same verifier, checkpoint `81d8a93`:** all four findings closed. The signed `execution` self-report
"materially strengthens evidence, while correctly remaining short of hardware/remote attestation." Remaining open
boundaries, in the verifier's words: (1) independent pre-round watcher identity/publication; (2) the ERR-006
recomputed-byte manifest; (3) verification of the first unattended hardened cycle. Assessment: "moved from credible
design to an exercised, auditable implementation beginning with the hardened pulses."
