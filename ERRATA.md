# ERRATA.md — known defects in published pulses, and their fixes

Pulses are signed and hash-chained, so a published pulse is **never edited**. A defect is corrected in
the tooling, takes effect from a stated seq onward, and is recorded here permanently. Consumers of the
affected pulses should read the affected field as described below. Newest first.

---

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

## ERR-006 — archive manifest hashes do not match the bytes on disk for at least 1.9 % of blocks (PRELIMINARY)

**Affected:** the archive commitment root **`c88c4320…2738`** (`merkle/manifest.json`), the claim "committed to
capture-time sidecars", and any block not individually re-verified.
**What was found (2026-09-12, full re-hash 34 % complete):** of **14,651** blocks re-hashed so far, **823** do **not**
match the SHA-256 recorded in their capture-time sidecar. That is **5.62 % of the checked subset** and a demonstrated
**archive-wide lower bound of 1.92 %** (823 / 42,935). Because the scan is chronological and the failures cluster by
day, **no extrapolation to the unscanned remainder is justified** in either direction; the final figure will replace
this one. (An earlier revision of this entry wrote "≥ 5.6 %" — that was the subset rate misstated as an archive bound;
corrected 2026-09-12 after external review.) Distribution by capture day is not random:
**zero** mismatches in the first 15 days (2025-07-18 → 08-14), then 0.5 % (08-15) rising to **38 %** (08-25, 08-26),
still elevated on 08-29 (the job's current position). 272 of the 823 files are 16–48 KiB **larger** than 100 MiB.
**Tested and rejected:** the sidecar hash is **not** the hash of the first 100 MiB, nor of the first `size_bytes` bytes
(12/12 sampled), **nor of any of 25 offset/length windows of the file** (drop 16–64 KiB head, drop 16–48 KiB tail,
8/8 sampled) — the recorded hash has **no verifiable relationship to the written bytes** for these blocks. File mtimes
are consistent with the original write (filenames are local time; mtime − name ≈ the ~200 s write duration), which
**argues against** later modification but does not prove it. **The sidecars name the culprit window:** every mismatching block belongs to
a collector session whose `collection_stats.start_time` is **2025-08-15T09:00:41Z** — the exact onset of mismatches —
whereas the clean blocks belong to earlier sessions (e.g. 2025-08-09T16:40:03Z). No collector logs exist for August
(the `logs/` directory covers only 2025-07-16). Working conclusion: the collector started on 2025-08-15 hashed
something other than the bytes it wrote (mutated or interleaved buffer), intermittently and load-dependently
(0.5 % → 38 %). Collector source is being located to confirm. **The bytes themselves are intact.** A 10 MB slice of a
mismatching block from the worst day (2025-08-25) is statistically indistinguishable from a matching block from
2025-08-10: Shannon 7.999983 vs 7.999983 bits/byte, χ² p = 0.79 vs 0.73, serial correlation +4e-4 vs +2.5e-4, SP 800-22
subset all pass on both, 90B MCV 7.962 vs 7.962. So this is a **broken provenance record, not corrupted data** — but
note that passing randomness tests cannot by itself prove the bytes came from the Quantis; only the sidecar could have,
and for these blocks it does not.
**Salvage, honestly tiered:** the corrected manifest will carry two classes of leaf — **(A) capture-verified**: bytes
match the capture-time sidecar (provenance chain intact from 2025); **(B) re-hashed-only**: bytes hashed on
2026-09-12, no capture-time corroboration. Class B blocks are usable as random data with provenance dated 2026-09-12,
and are **excluded** from any claim that rests on capture-time provenance.
**What the root means now:** `c88c4320…` commits to the **manifest**, and the manifest is wrong for at least these
blocks. **Do not rely on it for any block that has not been individually re-hashed.** The sample verification of
3/3 published on 2026-09-11 was true and was a sample; it did not license the word "verified" for the archive, and
`CLAIMS.md` said so — this entry is the reason that rule exists.
**Plan (revised after external review):** (1) the full re-hash continues (resumable, read-only) — final numbers replace
the preliminary ones here; (2) a **new archive manifest over the recomputed bytes of every readable block** —
an archive root, not a subset root — with a per-leaf `sidecar_concordance` field (`true` = bytes match the capture-time
sidecar; `false` = recorded hash unrelated to the bytes) and the mismatch list; (3) cause analysis; (4) leaves with
`sidecar_concordance: false` carry provenance dated 2026-09-12 only and are excluded from any capture-time claim. The
original root stays published, labelled, for the record.
**Found by:** our own full re-hash job, started 2026-09-11 after the manifest was built from sidecars.

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
