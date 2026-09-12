# ERRATA.md — known defects in published pulses, and their fixes

Pulses are signed and hash-chained, so a published pulse is **never edited**. A defect is corrected in
the tooling, takes effect from a stated seq onward, and is recorded here permanently. Consumers of the
affected pulses should read the affected field as described below. Newest first.

---

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
