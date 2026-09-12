# PROTOCOL.md — pulse format and verification, normative

Version **0.4** (commit-then-reveal). This document is the specification; `verify.py` is the reference
implementation. Where they disagree, this document wins and `verify.py` has a bug.

## 1. Objects

A **pulse** is a JSON document `{ core, pulse_hash, signatures, disclosure }`.

- `core` — the signed content. `core.type ∈ {commit, reveal}` (pulses ≤ 0009 are `legacy`).
- `pulse_hash` = `SHA256(canonical(core))` as lowercase hex.
- `signatures` — a map `name → {signer, role, alg:"ed25519", key_id, public_key_b64, sig_b64}`; every
  signature is over the **32 raw bytes of `pulse_hash`**. Required names: `entropy` (role
  `entropy_signer`), `time` (`time_attester`), `time_witness` (`time_witness`).
- `disclosure` — human-readable notes; **not signed, not normative**.

**Canonical JSON** = `json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
encoded as UTF-8. Integers are JSON integers; no floats are introduced by canonicalisation.

`key_id` = first 16 hex chars of `SHA256(raw 32-byte public key)`. Pinned keys are published in `keys/`.

## 2. Chain

`core.seq` is a strictly increasing integer. `core.prev_hash` is the `pulse_hash` of pulse `seq−1`
(`"0"*64` for genesis). Files are `chain/pulse-NNNN.json`. A file `chain/pulse-NNNN.FAILED.json`
records that pulse `NNNN` breached §5 and MUST be treated as failed by consumers.

## 3. Commit pulse

```
core.commitment.entropy_commitment = SHA256( "grok_antics/commit/v1" || E )      E = 32 bytes
core.commitment.target_round       = R          (drand quicknet round, strictly > drand_at_commit.round)
core.commitment.target_release_unix_s = 1692803367 + 3·R
core.drand_at_commit               = the latest drand round at mint (proves "not earlier than")
core.time                          = §6 time block; core.time.anchor.utc_unix_s MUST be < target_release
```
The entropy `E` MUST NOT appear anywhere in a commit pulse. The publisher MUST publish the commit pulse
before `target_release`; the evidence is (a) RFC 3161 tokens `pulse-NNNN.json.<tsa>.tsr` over the exact
file bytes, taken at mint, and (b) the public log's history.

## 4. Reveal pulse

```
core.reveals.commit_seq / commit_pulse_hash   identify the commit; core.prev_hash MUST equal commit_pulse_hash
core.reveals.entropy_hex                      E
core.external_anchor                          drand round == R exactly; randomness == SHA256(signature)
core.attested_value = SHA256( "grok_antics/pulse-mix/v1" || E || randomness(32) || chain_hash(32) || R as uint64 big-endian )
```
`chain_hash` = `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` (drand quicknet). All
fields are fixed-length, so the preimage is unambiguous without separators. **Consumers use
`attested_value`; `entropy_hex` alone is not the output.**

## 5. Timing contract (CADENCE.md)

commit pushed ≥ 120 s before `target_release`; reveal pushed ≤ 600 s after. Breach → FAILED marker. A
commit with neither a reveal nor a FAILED marker after the deadline is a **withheld reveal**; an
independent watcher (`watcher.py`) publishes a signed NON-REVEAL record under its own key.

## 6. Time block

`core.time.anchor` is a GNSS epoch (`gps_week`, `gps_tow_ms`, `tow_time_base`) whose TP1 **falling,
on-time** edge was captured in i210 hardware. Uncertainty terms are published as measured, with their
windows and sample counts; a statistic with fewer than 3 samples is `null`, never a guess. Software read
latency is reported under `orchestration` and is a freshness limit, not part of the anchor.

## 7. Verification algorithm (what `verify.py` does)

1. `SHA256(canonical(core)) == pulse_hash`; every signature verifies over that **recomputed** digest;
   keys match pins if provided.
2. commit: `target_round > drand_at_commit.round`; `anchor.utc_unix_s < target_release`; drand fields
   self-consistent (`randomness == SHA256(signature)`).
3. reveal (with its commit as `--prev`): `SHA256(domain||E) == entropy_commitment`; `prev_hash ==
   commit_pulse_hash`; `external_anchor.round == target_round`; `randomness == SHA256(signature)`;
   `attested_value` recomputes; `commit.anchor < round release ≤ reveal.anchor`.
4. `--refetch`: fetch `https://api.drand.sh/<chain>/public/<round>` and compare randomness + signature.
5. RFC 3161: `openssl ts -verify -data <pulse> -in <tsr> -CAfile …` for each token (`tsa.py verify`).

**Not performed:** BLS threshold verification of the drand signature. Do it with the official drand
client and the chain's public key from `/<chain>/info` if you need it.

## 8. What a valid reveal proves, and what it assumes

Proves: the attested value was not computable by anyone before `target_release`, and `E` was fixed
before `R` existed, so `E` was not chosen with knowledge of `R`.
Assumes: the commit was published before `R` (check the TSA tokens and log history); drand's threshold
is honest; SHA-256 preimage resistance; Ed25519 keys are the operator's.
Does not claim: fitness for gambling, certification by any body, or absolute UTC accuracy (L1-only GNSS).
