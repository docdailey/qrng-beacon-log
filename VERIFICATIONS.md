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

## 2026-09-12 — Grok Bot (separate system, own sandbox), checkpoint `1d62321`

A second verifier on a different vendor's system: cloned the repo, installed `cryptography` + `py_ecc` itself, and
checked the published objects independently of the operator's tooling.

**Verdict:** accept as a published commit-reveal log **0014/15, 0016/17** (pre-isolation, digest signatures) and
**0020/21, 0022/23** (v0.5, host-isolated). Reject under current rules **0018/0019**. "Do not treat as a number to
build on, and do not treat the 4.5 TB archive root as verified provenance."

| check | result |
|---|---|
| `REQUIRE_BLS=1 REFETCH=1 ci/verify_chain.py` | 23 pulses, 0 unexpected failures; 0018/0019 fail exactly per ERR-007; 22/22 links; 15 BLS verified, 0 skipped; 15 live drand refetches matched; 16 RFC 3161 tokens, min v0.5 commit margin 223 s; Merkle root + sample proof recompute; 0 state-machine violations |
| independent recomputation, four pairs, not trusting `attested_value` | `SHA256(canon(core)) == pulse_hash`; reveal `prev_hash == commit`; `SHA256(domain‖E) == commitment`; mix recomputed from E, R, chain hash, round: **0014/15 `f14bd4d9…`, 0016/17 `b43a9c9a…`, 0020/21 `d9312a04…`, 0022/23 `603144eb…` — all match** |
| drand group key | identical from api.drand.sh, api2, api3 (Cloudflare relay 403); scheme, genesis, period, chain hash agree |
| BLS with **live** signatures from api.drand.sh (not the pulse's copy) | rounds 32123921, 32125121, 32126100, 32126321 — all True; `SHA256(sig) == randomness` |
| RFC 3161 vs git committer time | match to the second on 0014, 0016, 0020, 0022; "existence of those exact bytes at T, not uniqueness" |
| git ordering of timer fires | 0014/15 and 0016/17 on the hour; 0020/21 cut-over (off-hour); 0022/23 first unattended isolated hour |

**Not certified, in the verifier's words:** 0018/0019; ERR-005 on 0001–0017 ("three machines signed a digest the
aggregator chose"); host isolation as a live property (statements and signatures verified; `think`'s SSH config not
visible from the sandbox); ERR-006 archive; uniqueness ("TSA + git prove these bytes existed before the round, not that
no other E was timestamped privately"); independent watcher key — "not yet attested by a second operator I control";
"quantum" — "not a property verify.py checks."

Reproduction given by the verifier:
```bash
git clone https://github.com/docdailey/qrng-beacon-log.git && cd qrng-beacon-log
pip install cryptography py_ecc
REQUIRE_BLS=1 REFETCH=1 python3 ci/verify_chain.py
python3 tsa.py verify chain/pulse-0022.json
python3 verify.py chain/pulse-0023.json --prev chain/pulse-0022.json --pin keys --refetch
```
