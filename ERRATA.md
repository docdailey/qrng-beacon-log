# ERRATA.md — known defects in published pulses, and their fixes

Pulses are signed and hash-chained, so a published pulse is **never edited**. A defect is corrected in
the tooling, takes effect from a stated seq onward, and is recorded here permanently. Consumers of the
affected pulses should read the affected field as described below. Newest first.

---

## ERR-008 — the entropy host accepted a second commit at an already-resolved seq; operator equivocation was neither prevented nor documented (2026-09-12)

**Affected:** `hosts/entropy_host.py` before hash `d2eaa923b7ac817f…`; `PROTOCOL.md`, `CLAIMS.md`, `THESIS.md`
through commit `75c0366`, none of which stated the split-view limitation. `hosts/beacon-cmd` is unchanged: its
`seq < last` guard is a *backdating* guard by design (an unpublished commit legitimately reuses its seq).

**What was wrong.** After a commit at seq N had been published and resolved (revealed or abandoned),
`entropy_host.py commit N` would mint a fresh commitment at the same seq. With the aggregator assembling pulses,
the operator could produce two different valid pulse-Ns on one `prev_hash` — a fork — and show each to a different
audience. Nothing published said so; a reader could not have known the log was equivocation-*detectable* only by
comparing independent observations, of which there was exactly one (ours).

**Not a stranger's capability, and not retroactive.** Every pulse carries five signatures under pinned keys, so a
fork by anyone but the key holders fails verification; and a commit's RFC 3161 tokens must predate its drand round,
so both branches of a fork would have to be made live inside the same publication window.

**Fix.** (1) `entropy_host.py` refuses `commit N` when seq N has a record in state `revealing`/`abandoning`/`revealed`,
or `abandoned` with a real resolver hash (an abandonment bound to the all-zero hash means the commit never entered
the published chain, and the seq may be reused). Deployed on protectli 2026-09-12 12:45 UTC and exercised through
the forced command. Defence in depth only — root on the host can delete the record. (2) **Publication anchors:**
every published pulse is entered, under the pinned key `keys/anchor.pub`, into Rekor (the public Sigstore
transparency log) and OpenTimestamps (Bitcoin block headers); `ci/verify_anchors.py` verifies each anchor offline
against the pinned Rekor key and **enumerates every Rekor entry ever made under the anchor key** — an anchored
hidden branch is publicly visible, and a published pulse with no anchor fails CI after 25 minutes. (3) PROTOCOL,
CLAIMS and THESIS now state the single-writer split-view limitation and what bounds it.

**Retroactive anchors.** Pulses 0001–0041 were anchored 2026-09-12 12:47 UTC, after the fact (Rekor log indices
2807717612–2807718704). Their Rekor times prove existence *from then*, not from minting; the TSA tokens remain the
commit-time proof. From 0042 on, the workflow anchors each pulse within minutes of its push, so a commit's Rekor
`integratedTime` precedes its drand release — a third clock on the commit.

**Found by:** Bill's question "so anyone could branch this pulse chain?" (2026-09-12), answered by reading the guard
code instead of the design intent.

## ERR-007 — required witness statements in pulses 0018/0019 report "invalid" while the pulses verify

**Affected:** pulses **0018, 0019** (the first v0.5 pair), `core.statements.witness.statement.measurement.epoch_guard`.
**What was wrong:** the witness (k3) statement carries `epoch_ok: false`, `chrony_selects_iphc: false` and an ALERT
text saying timestamps from this clock are invalid — yet the strict verifier passed the pulses, because it checked the
witness's **signature** and never its **content**. Two defects: (1) the epoch guard was written for p550 and misfires on
k3: k3's chrony disciplines from its PHC with `offset -37` rather than the `tai` option, so its kernel TAI offset is
**0** and the guard computed a 37 s "epoch error"; and k3's refclock id is `PHC`, not `IPHC`; (2) the verifier treated
required clock statements as attested-if-signed.
**Was k3's clock actually bad?** No, on live evidence taken 2026-09-12 02:3x UTC: PHC − CLOCK_REALTIME = 36.999985 s
(PHC holds TAI, system UTC — exactly right), chrony stratum 1 selecting `PHC` at RMS 15 ns, ptp4l offset to the BMC
grandmaster −6 ns. The guard's verdict was wrong; the pulses' *timestamps* were fine. That does not excuse a pulse that
says "invalid" and passes.
**Fix (2026-09-12):** the probe is host-aware (expected refclock id passed per host; when the kernel TAI offset is
unset it uses the IERS constant and says so); the **aggregator refuses to mint** if a required clock statement reports
an unhealthy clock; **the verifier now fails a pulse whose required time or witness statement reports
`epoch_ok != true`, an unselected hardware refclock, or any ALERT** — pulses 0018/0019 therefore now **fail** the current
verifier, as they should, and are recorded here as valid-in-content but formally non-compliant. **The first fully
compliant pair is 0020/0021** (2026-09-12 02:50–02:55 UTC). Latent issue also
logged: k3's `offset -37` is the hardcoded leap-second form; it should be the `tai` option (gap #10).
**Found by:** external reviewer, 2026-09-12 (review #3, finding 4).

## ERR-006 — archive manifest hashes do not match the bytes on disk for 2.835 % of blocks (FINAL, 2026-09-12)

**Affected:** the sidecar-based commitment root **`c88c4320…2738`** (`merkle/manifest.json`) and any capture-time
provenance claim for the 1,217 blocks listed in `merkle/mismatch.json`.

**Final result of the full re-hash (every one of 42,935 blocks, 4.50 TB, read on macstu 2026-09-12):**
**1,217 blocks (2.835 % of the archive) do not match the SHA-256 in their capture-time sidecar; 41,718 do.** No block
was missing or unreadable. (The preliminary entry's "5.6 %" was the rate within the first third scanned, where the
failures are concentrated; the archive-wide figure is 2.835 %.)

**Where they are.** Mismatches begin on **2025-08-15** and run through **2025-09-02** (worst days 08-25 at 38.1 % and
08-26 at 37.7 %), with three isolated later blocks (09-05, 09-06, 09-28). **62 of 83 capture days have zero
mismatches**, including the entire first four weeks (07-18 → 08-14). Sizes: 815 exactly 100 MiB; 401 between 16 and
48 KiB over 100 MiB; one truncated at 85,573,632 bytes.

**What was tested and rejected:** the sidecar hash is not the hash of the first 100 MiB, of the first `size_bytes`
bytes, or of any of 25 offset/length windows of the file — it bears no verifiable relation to the written bytes. mtimes
are consistent with a single original write, which argues against (does not prove) later modification. The one
mismatching sidecar examined in detail belongs to a collector session started 2025-08-15T09:00:41Z, coinciding with
the onset; a session-level attribution across all 1,217 blocks was **not** established (the August collector logs do
not exist). **The bytes themselves are statistically intact**: a mismatching block from 08-25 is indistinguishable from
a good block (Shannon 7.999983 vs 7.999983, all SP 800-22 pass, MCV 7.962 vs 7.962). This is a **broken provenance
record, not corrupted data** — with the caveat that passing randomness tests cannot prove the bytes came from the
Quantis; only the sidecar could, and for these blocks it does not.

**The correction — a new archive root over the recomputed bytes of every block:**

| | sidecar manifest (superseded, kept for the record) | **archive manifest (cite this)** |
|---|---|---|
| file | `merkle/manifest.json`, `leaves.tsv` | **`merkle/manifest-rehashed.json`, `leaves-rehashed.tsv`** |
| leaf hash | capture-time sidecar SHA-256 | **SHA-256 of the bytes as re-read 2026-09-12** |
| root | `c88c4320dff421400744abb36e65ecfc6f185b1a0e9ead5ddb0e10920b7a2738` | **`4e93d4be9ff5355d40e7e2c1d0ea599a62326aa09a651c9fa0b584764ccd95c4`** |
| leaves | 42,935 | 42,935 (**41,718 concordant, 1,217 discordant**) |
| per-leaf `sidecar_concordance` | — | `true` = provenance chain intact from 2025; `false` = provenance dated 2026-09-12 only |

`merkle_proof.py --rehashed` produces and verifies inclusion proofs that carry the concordance flag; a proof for a
discordant block says so in its `provenance` field, and a proof that claims concordance falsely does not verify.
Discordant blocks are usable as random data with provenance dated 2026-09-12 and are **excluded from any claim that
rests on capture-time provenance**. This is an archive root, not a subset root: every readable block is in it.

**Found by:** our own full re-hash, started 2026-09-11 after the sidecar-based manifest was built; headline math
corrected after external review (review #3, finding 5); final numbers 2026-09-12 12:05 UTC.

## ERR-005 — role signatures were digest signatures, not role attestations (architecture)

**Affected:** every pulse to date (**0001–0015** and any minted before the v0.5 cut-over).
**What was wrong:** the orchestrator computed `pulse_hash` and asked each host to sign that digest.
The entropy host never checked that the commitment was over bytes it produced; the time host never
checked that the timestamp in `core` was its own measurement; the witness signed without seeing the
observation. A dishonest orchestrator could fabricate `core` and still collect all three signatures.
**How to read the affected signatures:** "three named machines signed this digest" — evidence that the
record was not altered after signing and that three hosts participated; **not** independent attestation
by each host of the fact its role names.
**Fix (v0.5, in progress):** each host produces and signs its own statement (entropy host generates and
holds `E` and signs `{commitment, target_round}`; time host signs its own measurement object; witness signs
its own observation); the aggregator assembles the already-signed statements and signs the assembly with a
fourth key. Host-side scripts are published and version-bound into each pulse by hash. **Architecture effective from pulse 0018** (first v0.5 commit; 0016/0017 are the last v0.4 pair). **Host isolation
(the part that makes the aggregator unable to fabricate host facts) effective from pulse 0020.**
**Found by:** external reviewer, 2026-09-12.

## ERR-004 — every drand release time was computed 3 s late

**Affected:** pulses **0009–0015**: `commitment.target_release_unix_s` / `target_release_utc` (commits),
`external_anchor.round_release_unix_s` and `drand_at_commit.round_release_unix_s` (all), `timeline.*`
(reveals), `commitment.next_target_round_release_unix_s` (0009).
**What was wrong:** `drand_anchor.round_time()`, `watcher.py` and `PROTOCOL.md` used
`genesis + round × period`. drand defines **round 1 as occurring at genesis**, so the correct expression is
`genesis + (round − 1) × period`. Verified empirically 2026-09-12: under the old formula the live round's
"release time" sat up to 2 s in the future while the round was already being served.
**Consequences:** every published release time is **+3 s**; every "commit before round" margin was
overstated by 3 s and every "reveal after round" margin understated by 3 s; the verifier compared against
the published (late) value, so it could in principle have accepted a commitment made up to 3 s after the
round existed; the watcher waited 3 s too long. **All published claims survive** — the smallest true
commit-before-round margin is 171 s.
**Recomputed interpretation of every affected pulse:**

| seq | type | round | published release | true release | recomputed margin |
|---|---|---|---|---|---|
| 9 | legacy | 32122254 | 1789170129 | 1789170126 | single-phase |
| 10 | commit | 32122604 | 1789171179 | 1789171176 | commit precedes round by 171 s (published 174) |
| 11 | reveal | 32122604 | 1789171179 | 1789171176 | reveal follows round by 49 s (published 46) |
| 12 | commit | 32123484 | 1789173819 | 1789173816 | commit precedes round by 296 s (published 299) |
| 13 | reveal | 32123484 | 1789173819 | 1789173816 | reveal follows round by 4 s (published 1) |
| 14 | commit | 32123921 | 1789175130 | 1789175127 | commit precedes round by 297 s (published 300) |
| 15 | reveal | 32123921 | 1789175130 | 1789175127 | reveal follows round by 3 s (published 0) |

**Fix (commit on 2026-09-12, before pulse 0016):** formula corrected in `drand_anchor.py`, `watcher.py`,
`PROTOCOL.md`; **`verify.py` now computes release times itself from the round number and never trusts the
pulse's field** — for the affected pulses it prints a `[WARN] ERR-004` naming the +3 s and runs every
ordering check against the true time.
**Found by:** external reviewer, 2026-09-12, citing the drand specification ("round 1 starts at genesis time").

## ERR-003 — verifying pulses 0001–0002 with `--pin` failed after the time key rotated

**Affected:** verification of pulses **0001, 0002** with `verify.py --pin keys/` (the pulses themselves are correct).
**Symptom:** `[FAIL] time key matches pinned time_attester.pub`. The `time_attester` role moved from f9t
(key `4687aa55eff780e4`, pulses 1–2) to p550 (`6dae96e8faa9678a`, pulse 3 →), and pinning was a single
file per role, so the retired key had no standing.
**Fix (commit `590f46f`, 2026-09-12):** `keys/KEYS.json` — a key history with `valid_from_seq` /
`valid_to_seq`. `verify.py --pin` now checks the signing key is listed for its role **at that seq**.
Retired keys remain listed so old pulses stay verifiable and are never valid for new ones.
**Found by:** CI (`ci/verify_chain.py`) on its first full-chain run.

## ERR-002 — anchor text said "rising-to-on-time edge"; the on-time edge is FALLING

**Affected:** `core.time.anchor.what` in pulses **0007–0015**. Wording only; no number is affected.
**Facts:** the ZED-F9T is configured `TP-POL_TP1=0` (falling edge on the second) because the i210/igb
driver latches **only** falling edges and ignores edge-select flags; ts2phc runs `extts_polarity both`
and discards the edge that is 100 ms off the second. So the hardware-captured, on-time edge is the
**falling** edge.
**Fix (commit `590f46f`):** `gnss_probe.py` text corrected; effective from pulse **0016**.
**Found by:** external reviewer, 2026-09-12 ("some edge/anchor wording deserves reconciliation").

## ERR-001 — a signed, single ts2phc offset was published under an RMS label

**Affected:** pulses **0004–0015**. Field `core.time.precision.anchor_uncertainty.i210_servo_residual_ns_rms`
(pulses 0007–0015) or `core.time.precision.primary_discipline_rms_ns` (0004–0006).

| seq | published "RMS" | seq | published "RMS" | seq | published "RMS" |
|---|---|---|---|---|---|
| 0004 | 10 | 0008 | −6 | 0012 | −11 |
| 0005 | −12 | 0009 | −21 | 0013 | −8 |
| 0006 | −12 | 0010 | 1 | 0014 | 8 |
| 0007 | 1 | 0011 | 10 | 0015 | −8 |

**How to read the affected field:** it is **`last_offset_ns`** — the *signed, instantaneous* ts2phc offset
at the moment of the probe — **not** an RMS. An RMS cannot be negative; the sign is the giveaway. The true
servo residual over a window on this hardware is ~8 ns RMS (measured 8.27 ns over 45 s on 2026-09-11 and
8.25 ns over 12 s on 2026-09-12), and the instantaneous values above are consistent with that.
**Root cause:** the p550 probe's ts2phc branch read `/run/ts2phc-f9t.status` **once**, yielding only
`last_offset_ns`; the pulse builder used `offset_ns_rms or last_offset_ns` as a fallback and kept the RMS
label. The same defect produced 1-sample "RMS" values in the BMC cross-check block of some pulses.
**Fix (commit `590f46f`, 2026-09-12):** the probe now samples the servo over a 12 s window and reports
`last_offset_ns`, `offset_ns_rms`, `samples`, `offset_ns_min/max` as **distinct** fields; `offset_ns_rms`
is `null` when fewer than 3 samples fell in the window; the pulse never substitutes one for the other.
Effective from pulse **0016** (first cycle after the fix, 2026-09-12 02:00 UTC).
**Found by:** external reviewer, 2026-09-12 ("pulse 0015 reports an impossible negative RMS value").
**Why it matters here:** this project's claims discipline rests on publishing measured quantities with
their windows. A mislabelled statistic is exactly the failure `CLAIMS.md` exists to prevent. Recorded
here so the record of being wrong is as public as the record of being right.
