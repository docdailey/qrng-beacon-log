# HARDWARE.md — verified entropy and timing assets

> **Thesis: exact timing is trust.** The timing stack below is not supporting infrastructure for the
> entropy — it is half the product. A value bound to a verifiable instant can be ordered, audited
> and bounded; the same value with a vague timestamp can only be believed. Everything here is
> measured, with its window stated, because a trust layer that cannot be checked is not one.
>
> Since v0.3 every pulse also mixes an external **drand** round, so the value carries a checkable
> lower bound on its age. How *tight* that bound is, is a timing claim — which is the thesis doing
> real work rather than decorating it. See `THESIS.md`.
>
> The lab notebook proved the sharp corollary: **a clock that fails silently is a trust failure, not
> a precision failure.** See "What the lab notebook corrected".

All facts below were **measured on 2026-09-11**, not assumed. Commands were read-only except the
Gate 1a byte pull (a normal API read) and a 28 KB copy of a SQLite file to /tmp for read-only query.

## protectli — 192.168.70.1 (live source)

SSH as `willy@` (root key auth is refused). Ubuntu 6.8.0-124, up 94 days.

**Device** — `lsusb 0aba:0102`, iManufacturer `id Quantique`, iProduct `Quantis USB`, vendor-specific
class. Reported by the server's own `/api/v1/info`:

| field | value |
|---|---|
| serial_number | `246578A410` |
| board_version | `0x060B1C01` |
| module_count | 4 (modules_enabled 15) |
| data_rate | **4,000,000 bit/s = 500 KB/s** |

**Software stack — already built, was simply never used for anything.**

| unit | what | port |
|---|---|---|
| `quantis-qrng.service` | Rust `quantis-server`, `~/qrng/rust-quantis` | **:8080** |
| `quantum-api.service` | FastAPI/uvicorn `~/quantum-api/api_wrapper.py`, redis-backed, has a `StripeManager` | :8000 |
| redis | backing store for the API layer | 127.0.0.1:6379 |

`/etc/udev/rules.d/99-quantis.rules` sets `MODE="0666"` on the device. Note `rng_current=none` and
`rngd` inactive — the QRNG is deliberately **not** feeding the kernel pool; it is served over HTTP.

**Ring buffer** — `src/ring_buffer.rs`: `BUFFER_SIZE = 4 MiB` raw, `REFILL_THRESHOLD = 25%`,
`READ_CHUNK_SIZE = 64 KiB` from USB. Separate von-Neumann (2 MiB) and matrix buffers. Sibling
modules: `streaming_buffer.rs`, `buffer_consumers.rs`, `data_distributor.rs`.

**API** — `GET /api/v1/random/bytes?count=&format=&correction=`
- `format`: `hex` | `base64` only. **`binary` is rejected** (HTTP 400) — the docs imply otherwise.
- `count` max 1,000,000 per request.
- `correction`: `none` (raw, ~488 KB/s) · `von_neumann` (~244 KB/s) · `matrix` (~390 KB/s) ·
  `sampled` (~122 KB/s).
- Also present: `/api/v1/ais31/status`, `/api/v1/quality/entropy`, `/api/v1/crypto/*`.
  ⚠️ The `crypto/key` endpoints exist but **we do not sell key generation** — see CLAIMS.md.

## p550 — 192.168.68.44 — **the authoritative timer**

Measured 2026-09-11. This, not f9t, is the clock the beacon stamps with.

**Hardware** — `01:00.0 Intel Corporation I210 Gigabit Network Connection (rev 03)`, interface
`enp1s0` (MAC `a0:36:9f:37:b8:e7`). `ethtool -T enp1s0` reports `hardware-transmit`,
`hardware-receive`, `hardware-raw-clock`, **PTP Hardware Clock: 0**. The PHC is `/dev/ptp0` and its
`clock_name` is `a0369f37b8e7` — the i210's own MAC, which is how we know ptp0 *is* the i210.

⚠️ The SoC MACs `end0`/`end1` report **`PTP Hardware Clock: none`** — no 1588 timestamping. The i210
in the PCIe slot is the only real clock on this box. Kernel `6.6.138-rt74+` (PREEMPT_RT).

**Since 2026-09-13 this clock also starts the beacon's hour.** `beacon-cadence.service` (`hosts/beacon-cadence.py`,
user `beacon`) wakes at :00:00.000 UTC with `clock_nanosleep(TIMER_ABSTIME)` on `CLOCK_REALTIME` — which chrony holds
to the i210 PHC (refid IPHC, RMS a few ns) — reads the PHC, signs a cadence trigger with the `time_attester` key and
starts the aggregator's cycle on think over a forced-command-only SSH key. Measured wake lateness 0.1–0.4 ms; every
trigger records it. The clock evidence a statement quotes now comes from `beacon-clocklog@time` (`hosts/clocklog.py`):
ts2phc offsets per PPS, the i210's observation of the BMC GM, and the epoch guard, logged at source rate to
`/run/beacon-clocklog` and the timehat DB. See CADENCE.md §2.

**Discipline chain — verified, not assumed.** `ts2phc-f9t.service` is active; `/run/ts2phc-f9t.status`
states the source verbatim: *"ZED-F9T TP1 (falling edge on the second) -> i210 SDP0, ts2phc generic"*.

```
GPS -> u-blox ZED-F9T (receiver hosted on f9t) -> TP1 PPS, FALLING edge -> coax
     -> i210 SDP0 -> ts2phc -> /dev/ptp0 (PHC) -> chrony refclock IPHC -> system clock
```

**f9t's role is the GNSS receiver host, nothing more.** Its own Pi PHC is disciplined by PTP from the
BMC — a different path that does **not** feed p550. Signing time on f9t (pulses 0001–0002) was
stamping with the wrong clock.

**Measured quality (2026-09-11, sampled live):**

| quantity | measured | how |
|---|---|---|
| i210 PHC ↔ ZED-F9T PPS | **RMS 8.27 ns**, min −11 / max +19 ns, servo `s2` locked | 45 s, 45 samples of `/run/ts2phc-f9t.status` |
| chrony system ↔ PHC | RMS 8–10 ns, root delay 1 ns, root dispersion 2.2–2.8 µs, Leap Normal | `chronyc tracking`, RefID `IPHC`, stratum 1 |
| PHC − UTC | **+36.999999354 s** → the PHC holds **TAI** | interleaved `clock_gettime` |
| TAI − UTC | **37 s**, from `adjtimex` (ret=0) — read, never hardcoded | kernel |
| kernel error bounds | maxerror ~500 µs, esterror 0 µs | `adjtimex` |

⚠️ **The nanoseconds describe the clock and the hardware-captured anchor, not any software timestamp.** A pulse's
time comes from the GNSS epoch of an edge latched in i210 silicon (SDP0 EXTTS) and disciplined by `ts2phc`; no
`clock_gettime` is in that path. The `CLOCK_REALTIME` fields a statement also carries are freshness and ordering
only. (Earlier copies of this file presented userspace clock-read latency as the stamp bound — removed, ERR-012.)

⚠️ **Precision is not accuracy.** Everything above is how tightly the PHC *tracks the PPS*. Absolute
accuracy versus UTC(k) is **uncalibrated**: antenna cable delay (69 ns is configured in the F9T but
unverified by us), the PPS coax run to SDP0, i210 SDP0 input latency, and the receiver's own UTC
error. We claim precision and a traceable discipline chain — not calibrated absolute accuracy.

Other services on the box: `bmc-phc-monitor` is active but **free-running** — it observes the BMC and never steers the i210; the loop is nonetheless closed through the BMC's `ptptgt` trim, so say "measure and trim" (an instrument,
not a servo). `extts-f9t` and `iphc-f9t-servo` are disabled and must stay disabled — any other EXTTS
opener steals events from ts2phc.

## k3 / Milk-V — 192.168.68.24 — **the low-jitter stamper**

SpacemiT **K3 Pico ITX**, riscv64, kernel **6.18.3-generic**. SSH as `willy@` or `root@` (`sudo`
needs a password; use `root@` for privileged probes).

Two PHCs: `/dev/ptp1` = `stmmac ptp` on the live NIC `end0` (**this is the one that matters**), and
`/dev/ptp0` = `500a520b8408` on `enP2p1s0`, which is **DOWN** and reads a constant 0 — ignore it.

**A different receiver, but the same closed loop — and the BMC actively STEERS k3.** `ptp4l-bmc.service`
disciplines `end0`'s PHC to the **P550-BMC GPS grandmaster** (domain 44, UDPv4) at 41 ns RMS, a chain
fed by the **LEA-6T** rather than the ZED-F9T. That grandmaster is **continuously measured by p550's i210**
(25 ns RMS) and trimmed via `ptptgt`. Bill's point (2026-09-12): the steering is what matters. Because k3
is *driven by* a clock the primary continuously audits, the witness timestamp is **transitively audited
by the primary** — the chain i210 ↔ BMC → k3 is closed. A witness signature from k3 therefore attests
"a second, independently-steered clock inside the audited mesh agreed", which is a stronger statement
than either "independent" (it is not) or "merely adjacent" (it is not that either).

```
GPS -> LEA-6T -> P550-BMC GM -> PTP dom44 -> ptp4l -> /dev/ptp1 -> chrony (RefID PHC) -> CLOCK_REALTIME
```

⚠️ k3's chrony uses `refclock PHC /dev/ptp1 ... offset -37` — a **hardcoded leap-second offset**.
That is the exact landmine the fleet notes warn about; it goes stale at the next leap second. p550
does this correctly. Worth fixing on k3, tracked as a gap.

## timehat DB — the ZED-F9T telemetry behind the i210 stamper (verified 2026-09-11)

**Database**: MySQL on **nas1 `192.168.69.133:3309`**, schema **`timehat`**, user `timehat`,
credentials in `/home/willy/timehat-db.env` on f9t. 21 tables; two matter here.

| table | columns | f9t rows | span | rate |
|---|---|---|---|---|
| `qerr_stream` | `ts, src, week, tow_ms, qerr_ps, flags` | **358,232** | 2026-09-07 01:45 → now | **0.848 Hz** lifetime |
| `rawx_stream` | `ts, src, kind, week, tow_ms, frame` (mediumblob) | **2,989,865** | 2026-09-08 01:22 → now | 8.86 rows/s |

`rawx_stream` splits by `kind`: **`rawx` 326,609 rows @ 0.968 Hz** (avg 846 B — the 1 Hz raw
measurement epoch) and **`sfrbx` 2,663,256 rows @ ~7.9 Hz** (avg 51 B — navigation subframes).
Total f9t frame payload: **394.3 MiB**.

⚠️ An earlier note in this project said RAWX was M8T-only. **That was stale** — f9t is now the
dominant RAWX source (2.99 M rows vs the M8T's 901 k).

### qErr — is the "~2 ns" real?

Measured over the f9t stream's own window (not a padded 21 days):

| | value |
|---|---|
| n | 358,232 over 422,264 s |
| mean | −0.1176 ns |
| **sd / RMS** | **2.2548 / 2.2579 ns** |
| min / max | −4.05 / +3.81 ns |
| last 60 min | n=3,596, sd 2.276 ns |
| gaps > 5 s in last 24 h | **0** |

**Yes, ~2.26 ns is real and current.** The 0.848 Hz lifetime figure is *not* ongoing loss — the last
24 h shows zero gaps over 5 s and a 15-minute window returns 897–900 of 900 expected samples
(99.7–100 %). The shortfall is entirely the Sipeed UART wedge on 2026-09-07.

⚠️ **What it measures.** qErr is the **sawtooth quantisation error**: how far the TP1 edge fell from
its ideal instant, which the receiver reports per pulse. It is a jitter/granularity figure, **not**
accuracy versus UTC(k).

### RAWX — decoded, not assumed

A live `UBX-RXM-RAWX` frame (920 B) decodes to: week **2435**, rcvTow 515078.998,
**numMeas 28**, recStat 0x01, version 1, constellations **GPS 7–8, Galileo 7–8, BeiDou 11, SBAS 2**.
Over the last hour: numMeas min 26, p50 29, max 31, mean 28.5 — a steady multi-constellation fix.

**`leapS = 18`**, which is **GPS−UTC**, not TAI−UTC. TAI−GPS is a fixed 19 s, so the satellites are
broadcasting **TAI−UTC = 18 + 19 = 37 s** — independently confirming the value p550's kernel reports
via `adjtimex`. That is a genuine second source for the leap offset, from the constellation rather
than the OS.

### How this couples to the i210 — and the part that surprised me

```
  u-blox ZED-F9T (RCB-F9T on the f9t Pi)
     |                                    \
     | TP1 PPS, falling edge, 100 ms       \  UBX over UART (Sipeed bridge)
     v                                      v
  coax -> i210 SDP0 -> ts2phc -> /dev/ptp0   qerr_logger.py -> nas1:3309 timehat
         [8.3 ns RMS]                          qerr_stream (sawtooth, 1 Hz)
                                               rawx_stream (RAWX 1 Hz + SFRBX ~8 Hz)
```

⚠️ **The sawtooth is logged but NOT applied.** `ts2phc-f9t.conf` uses a generic PPS source
(`ts2phc.pulsewidth 100000000`, `extts_polarity both`, `first_step_threshold 0.00002`) and a grep
across `/etc/linuxptp/` and the wrapper finds **no sawtooth or qErr handling at all**. Nothing reads
qErr back to correct the PHC. So the 2.26 ns is an **uncorrected residual inside the i210's error
budget**, not a correction already in effect.

⚠️ **And correcting it would barely help — say this before anyone calls it a 2 ns system.** The
receiver's sawtooth sd is 2.26 ns while the delivered i210 discipline is 8.3 ns RMS. Removing the
sawtooth in quadrature leaves √(8.3² − 2.26²) ≈ **8.0 ns**. **The receiver is not the dominant term.**
Roughly 8 ns of the budget lives in the PPS cable, the SDP0 latch and the servo. A sawtooth-corrected
ts2phc is worth doing for correctness, not for a headline number.

## Applying qErr — what was done, what was not, and why (2026-09-11)

**Done in the record.** Every pulse now carries `precision.anchor_uncertainty.sawtooth_this_epoch_ns`
and the sign convention (`corrected = raw + qErr`, notebook 212), so a consumer can correct the
anchor themselves. The servo is untouched.

**Not done in the servo, deliberately, this session.** Applying the sawtooth at the discipline point
is cross-host and has no clean hook today:

- the qErr arrives as UBX-TIM-TP on **f9t's** UART; the servo (`ts2phc`) runs on **p550** and reads
  only the electrical edge on SDP0;
- stock `ts2phc` has **no runtime input for a per-edge offset** — no socket, no FIFO, no pmc verb;
- the notebook's own recommendation (212) is to correct **at the capture**, i.e. in the BMC firmware
  for the 6T chain, not in chrony on p550.

Three honest options, in order of preference: **(a)** patch `ts2phc` to accept a per-pulse
correction over a UDS from a small forwarder on f9t (the qErr for second *N* is known ~0.7 s before
the *next* edge, so it can be applied to the right edge); **(b)** apply it downstream in chrony via a
dynamically-updated `refclock … offset` — crude, and chrony filters it; **(c)** for the BMC chain,
firmware-side per notebook 212. **Scheduled as (a)**; it touches a production timing service and
belongs in its own change with a rollback, not at the end of this session. Expected gain per the
notebook's measurement: roughly 6 → 1.7 ns class on the receiver term.

## Archive Merkle commitment (built 2026-09-11)

Root **`c88c4320dff421400744abb36e65ecfc6f185b1a0e9ead5ddb0e10920b7a2738`** over **42,935** leaves,
**4,501,833,711,616 bytes** (4.50 TB), depth 16. Leaf = `SHA256(0x00‖filename‖0x00‖sha256_hex)`,
node = `SHA256(0x01‖left‖right)`, odd node promoted, leaves sorted by filename. Built read-only on
macstu from the capture-time sidecars in 486 s; `leaves.tsv`, `manifest.json`, `orphans.json`,
`merkle_proof.py` and a sample proof are in `entropy/merkle/` and in the public repo.

**Reconciling the counts** — three different numbers exist and only one is committed:

| number | what | committed? |
|---|---|---|
| 43,421 | sidecar JSON files | — |
| 57 | sidecars that do not parse | no |
| 429 | parseable sidecars whose `.bin` is missing | no (listed in `orphans.json`) |
| **42,935** | sidecars with a present file | **yes — the leaves** |
| 43,010 | `.bin` files on disk | 75 have no valid sidecar → **not committed** |

**Verification status — ERR-006 FINAL (2026-09-12).** The full re-hash of all 42,935 blocks found **1,217 (2.835 %) whose bytes do
not match their sidecar** (window 2025-08-15 → 09-02 plus three later singletons; 62 of 83 days clean). The archive root to cite is now
**`4e93d4be9ff5355d40e7e2c1d0ea599a62326aa09a651c9fa0b584764ccd95c4`** over the recomputed bytes (`manifest-rehashed.json`, per-leaf
`sidecar_concordance`). The sidecar root below is retained, labelled, for the record.
Sample 3/3 on 2026-09-11; a **full re-hash of every leaf** against its
sidecar started 2026-09-11 (`~/fullverify.py` on macstu, nice 19, resumable, ~234 MB/s ⇒ ≈5.3 h);
status in `macstu:~/beacon-merkle/fullverify.status`. Until `final: true` with `mismatch: 0`, the
claim is "committed to the manifest; sample-verified; full verification in progress".

## What the lab notebook corrected (read 2026-09-11)

The lab notebook is **`timehat.notebook`** on nas1:3309 — 221 entries, `author='claude'`, columns
`ts, author, entry_type, tags, title, body, data, ref_id`. Found via graphquery: domain **40
"P550 PPS Timing Calibration"** (8,305 nodes, conversation-heavy) plus `:Document` hits in
`memory/p550_pps_21us_decomposition.md`, `project_bmc_18us_resolved.md` and
`project_milkv_on_bmc_phc.md`. The notebook itself is a DB table, not files, so it is not in the
graph — the graph pointed at the work, the DB holds the record.

Four things it fixes in this document.

### 1. ⚠️ The i210 PHC epoch is wiped by ANY link bounce — and every metric we publish stays green

**Notebook entry 220 (2026-09-10).** `ethtool --set-eee`, a cable pull, a switch reboot, a port flap
or a driver reset restarts autonegotiation, which **resets the i210 SYSTIM registers and destroys
the PHC's integer second**.

`ts2phc -s generic` disciplines only the **sub-second phase** from a bare PPS. After the bounce it
re-locks and keeps reporting `offset 12 ns s2` — a textbook-healthy servo — **while the seconds
label is gone**. The integer second is seeded exactly once, by `iphc-epoch-seed.py` as ts2phc's
`ExecStartPre`; nothing re-runs it on link recovery.

```
/run/ts2phc-f9t.status   offset 12 ns s2          <- perfect
systemctl is-active      active, never restarted  <- fine
chronyc sources          #x IPHC ... +37.0s       <- THE ONLY SYMPTOM
```

**This was the most serious gap in our pulse design**: every number a pulse published — servo state
`s2`, ts2phc RMS, chrony RMS — stays healthy through this failure, and none of them detects it.
A pulse could have carried a timestamp wrong by 37 seconds while looking flawless.

**Fixed.** `stamp_probe.py` now carries an `epoch_guard` that checks **PHC − CLOCK_REALTIME == TAI−UTC
within 0.5 s** and that chrony still shows `#*` on IPHC; `make_pulse.py` **refuses to mint** if either
fails. The fleet already self-heals via `iphc-epoch-check.service` fired by
`/etc/udev/rules.d/99-iphc-epoch.rules` on every `ACTION=="change"` for `enp1s0`.

Also from 220, confirming a caution raised earlier here: **`phc_ctl /dev/ptp0 cmp` reports the
OPPOSITE SIGN to (PHC − REALTIME)**. Read both clocks directly.

### 2. The 69 ns antenna delay is MEASURED, not assumed — our claim was wrong

**Entry 215** is an explicit correction of entry 214 on exactly this point: 69 ns is the **measured**
antenna-cable term carried by every receiver on the feed (Furys ADELay 69; 6T/8T/F9T
`antCableDelay` 69). Our `CLAIMS.md` and pulses called it "configured… unverified by us". Corrected —
it now appears under `calibrated_terms`.

### 3. The quadrature argument was wrong — the sawtooth is coherent, not white

This document previously argued that removing the sawtooth would take 8.3 ns to ~8.0 ns in
quadrature, so it was not worth doing. **That reasoning is invalid.** Entry 212 measured the
sawtooth's structure: **LEA-6T lag-1 autocorrelation +0.839, decaying over ~7 s**. It is not white,
so it does not add in quadrature and **no disciplining loop can average it away** — 32 s of averaging
buys 2× where white noise would buy 5.7×. Measured on the bench, subtracting qErr took a receiver
from **6.13 → 1.68 ns sd (r²=0.970)**; the GFS-8A went 6.17 → 1.33 ns. Sign: **corrected = raw + qErr**.
The quantisation clock is ~48.5 MHz (one period = 20.8 ns, hence the ±10.4 ns span).

Because the 6T feeds the BMC PHC, its sawtooth propagates into IPHC and everything on PTP domain 44 —
which is the argument for correcting **at the capture**, not in chrony on p550.

### 4. The monitor is read-only, but the loop IS closed — through `ptptgt`

Entry 214: `bmc-phc-monitor` (ptp4l `free_running`) never steers anything, which this document had
right. But its measurement **is** used: the BMC's console `ptptgt` knob is the trim. The ~950 ns
offset was root-caused to the BMC's own **EXTI interrupt-entry + PHC-read latency (~900 ns** on a
168 MHz STM32 running lwIP), baked in as lateness because the servo parks the CPU-read phase at
target 0. `ptptgt 900` calibrates it out; the i210 then reads the GM at 0/+29/+37/+9/−24 ns.
`ptptgt` is RAM-only, re-asserted by `bmc-tai-seed.py` at boot+120 s and 6-hourly.

Entry 214 also explains the polarity config this document could not: **falling edge because the
i210/igb latches ONLY the falling edge**, and ts2phc's `both` mode discards edges 100 ms off the
second — `igb` ignores edge-select flags entirely. ts2phc holds ±7.5 ns there, consistent with the
8.3 ns RMS measured independently here.

### 5. The real limit on ABSOLUTE time is L1-only, and that is the L2 roadmap

Entry 214's error budget: the bench is internally coherent to tens of ns, but **absolute UTC/TAI
rests on the F9T, which is L1-ONLY on the current antenna path** (33 signals on L1, **0 on L2**;
MON-SPAN shows the L2 block hunting at +12 dB PGA). So there is an **uncorrected ionospheric term**
in absolute time. The roadmap is an L1/L2 antenna (TW3972, DigiKey 1526-33-3972-01-10-ND) → the F9T
goes dual-band iono-free → "the whole fleet lands on real UTC/TAI". Remaining systematics named
there: the ±445 ns monitor path asymmetry (calibrate via BMC PD2 ← i210 SDP1 perout) and the
6T-vs-F9T receiver difference (SDP1 extts when the fanout SMAs arrive).

**This is the honest ceiling on "accuracy" claims, and it is a roadmap item, not a current property.**

### 6. Independent confirmation of Bill's anchoring point

Entry 189 (2026-09-01) states it a week before this session: un-threading p550's `pps-gpio` IRQ cut
I210-vs-CLOCK_REALTIME from **18 µs → 5 µs**, gpio-PPS StdDev 871 → 303 ns, **IPHC StdDev 13 ns** —
and the residual 5 µs hard-IRQ floor is *"eliminated by the SDP0 EXTTS fanout (i210 hardware-stamps
the pulse, no IRQ → ~ns)"*. That is precisely the hardware-anchored model. Our independently measured
chrony `sourcestats` StdDev of **13 ns** matches the notebook's figure exactly.

## How the i210 hands time to chrony (verified 2026-09-11)

**One line does it, and there is no phc2sys anywhere.**

`/etc/chrony/conf.d/40-i210-phc.conf`:
```
refclock PHC /dev/ptp0 tai poll 0 dpoll -2 refid IPHC prefer
```

chrony's **built-in PHC refclock driver** reads `/dev/ptp0` directly. There is **no `phc2sys`**
(service inactive, no process), **no SHM**, and **no SOCK** in the i210 path. Decoding the options:

| option | meaning |
|---|---|
| `PHC /dev/ptp0` | read the i210 PHC through the kernel's dynamic-POSIX-clock interface |
| `tai` | the PHC holds **TAI**; chrony converts using the kernel/leapsectz offset rather than a hardcoded constant — this is what k3 gets wrong with `offset -37` |
| `dpoll -2` | driver samples the PHC every 2⁻² s = **4 Hz**, then reduces |
| `poll 0` | chrony consumes one filtered sample per **1 s** |
| `refid IPHC` | the label seen in `chronyc` |
| `prefer` | favour it over every other source |

Other refclocks exist for **monitoring only**: `refclock SOCK /run/chrony.6t.sock refid GPS6`
(6T NMEA, coarse date) and `refclock PPS /dev/pps0 refid PPS ... noselect` (direct PPS, software
timestamped through a PREEMPT_RT threaded IRQ, sitting ~+16 µs out). `hwtimestamp enp1s0` in
`50-hwts.conf` is for NTP **packet** timestamping when p550 serves time; it is not part of the
PHC→system path.

### Measured handoff quality

```
chronyc sources      #* IPHC   reach 377   -22ns[-28ns]  +/- 1000ns     <- selected
chronyc sourcestats  IPHC  NP=17 NR=11 Span=16s  Offset -0ns  StdDev 13ns  FreqSkew 0.003ppm
chronyc tracking     RMS offset 9 ns | Root delay 1 ns | Root dispersion 2.447 us
                     Update interval 1.0 s | Leap status Normal | Stratum 1
```

### What this means for each way of stamping a pulse

| stamping method | error bound you can defend | why |
|---|---|---|
| **GNSS epoch anchor** (what pulses use) | **ns-class**: sawtooth 2.24 ns sd ⊕ ts2phc residual ~8 ns ⊕ uncalibrated path | chrony is **not involved at all** — the edge was latched in i210 silicon and exists whether or not chronyd is running |
| `CLOCK_REALTIME` | **µs-class — 2.447 µs** | the 9 ns RMS is chrony's *internal* residual; the defensible published bound is **root dispersion**, which grows between updates |

⚠️ **The important consequence.** A `CLOCK_REALTIME` stamp is only
defensible to chrony's **root dispersion (~2.4 µs)**, because that is the error bound chrony itself
publishes. The GNSS-epoch anchor bypasses chrony completely and stays ns-class. **chrony is a
consumer of the i210 PHC, not a link in the anchor chain** — which is exactly why the anchored stamp
is independent of anything happening in userspace.

⚠️ **Stale comment in that config file — flagged, not edited.** The header of
`40-i210-phc.conf` still says *"the i210 PHC is now disciplined by the BMC grandmaster (domain 44)
via bmc-phc-monitor (converted from read-only to steering slave)"* and mentions `noselect`. All
three are now false: the directive carries **`prefer`, not `noselect`** (and `chronyc` shows `#*`,
selected); `bmc-phc-monitor` is back to **`free_running 1`**, read-only; and the i210 is disciplined
by **ts2phc from the F9T PPS**, not by the BMC. Anyone reading that comment would conclude the
i210 is BMC-disciplined, which would make the "i210 cross-checks the BMC" story circular. **It is
not circular in reality** — ts2phc drives the i210 from the F9T, and the BMC monitor only measures.
Worth correcting on the box; I have not touched a production config.

## The timing mesh — i210 continuously measures the BMC (verified 2026-09-11)

**Correction to an earlier draft of this file: p550 and k3 are NOT two unrelated reference trees.**
The i210 continuously cross-checks the BMC PHC, so the witness chain is watched, not foreign.

```
                          GPS constellation (one sky, one antenna feed: the two paths are NOT independent against a GNSS-common failure)
                                   |
             +---------------------+----------------------+
             |                                            |
      u-blox ZED-F9T (L1-only today)                u-blox LEA-6T
      qErr sd 2.26 ns, logged not applied           qErr core sd 6.02 ns; 3 excursions > 1 us / 21 d
             |                                            |
      TP1 PPS, FALLING edge                          PPS -> STM32 PD3 (EXTI interrupt, CPU read)
             |  HARDWARE capture: i210 SDP0 EXTTS            |  software-latched capture inside the BMC
             v  (~8-10 ns RMS servo residual)                 v
   ts2phc ==disciplines==> i210 PHC /dev/ptp0        P550-BMC PHC == PTP grandmaster, domain 44 ==disciplines==> k3 stmmac PHC
                              |                            ^   ^                                           (~41 ns RMS, 60 s)
                              |   bmc-phc-monitor          |   |
                              +-- OBSERVES (ptp4l          |   |  ptptgt trim (RAM-only; re-asserted by bmc-tai-seed.py)
                                  free_running=1,          |   +---- a separate CONTROL path: the operator trims the BMC's
                                  slaveOnly=1) ------------+         phase target so the GM reads ~0 against the i210.
                                  measures the BMC PHC;              The i210 itself is never steered by anything but ts2phc.
                                  ~8-30 ns RMS per pulse window, path delay ~442 ns
```

Read the arrows literally. **Discipline** flows F9T→i210 (hardware EXTTS, ts2phc) and LEA-6T→BMC→k3 (PTP). **Observation**
flows i210→BMC only: the monitor's endpoint is the **BMC grandmaster**, not k3; k3 is downstream of the BMC and signs its own
discipline figures. **Trim** is a third, human-configured path (`ptptgt`) on the BMC — so the honest phrase for the pair is
"measure and trim", not "read-only" and not "independent". The F9T edge is captured in hardware by the i210 timestamping unit;
the BMC's edge is latched by an interrupt and a CPU read, which is why its target needed the ~900 ns trim.


**`bmc-phc-monitor.service`** on p550 runs `ptp4l -f /run/bmc-monitor.runtime.conf -i enp1s0 -m -q`
with `free_running 1` + `slaveOnly 1`. Those two settings are the whole point: it **measures the BMC
grandmaster against the i210 and never disciplines anything**. Because p550's stdout is not captured
by systemd here, the wrapper parses ptp4l into world-readable **`/run/bmc-phc.status`**.

Measured cross-check (2026-09-11): **offset RMS 24.8 ns** over 75 s (n=22, min −41, max +47,
mean +7.4), path delay 442 ns, servo state `s0` — `s0` is expected and correct for a free-running
monitor, not a fault. The BMC's own Announce reports **clockClass 6 (GPS-locked), accuracy 100 ns,
source GPS, UTC offset 37**.

### The "~2 ns source" — verified, and it is the ZED-F9T

From `timehat.qerr_stream`, 21 days, UBX-TIM-TP sawtooth quantisation error:

| receiver | n | mean | sd (all) | sd (core, |qErr|≤50 ns) | excursions >1 µs |
|---|---|---|---|---|---|
| **ZED-F9T** (disciplines the i210) | 357,982 | −0.118 ns | **2.255 ns** | **2.255 ns** | **0** |
| LEA-M8T | 468,087 | −0.124 ns | 6.01 ns | 6.01 ns | 0 |
| LEA-6T (feeds the BMC) | 468,631 | +5.773 ns | 2,328 ns | **6.02 ns** | **3** (max 925 µs) |

⚠️ **Read that table carefully.** The 6T's headline sd of 2.3 µs is an artefact of **three** samples
out of 468,631 (0.0006 %); its core is 6.02 ns, statistically the same as the M8T. The honest
statement is not "the 6T is bad" but "**the 6T is normally 6 ns and occasionally excursions past a
microsecond — which is exactly what the continuous i210-vs-BMC measurement exists to catch.**"

⚠️ **What "2 ns" is and is not.** 2.255 ns is the **standard deviation of the sawtooth quantisation
error** the receiver itself reports. It is a jitter/granularity figure, **not** an accuracy figure
versus UTC(k). Never quote it as "accurate to 2 ns".

## Clock read latency

Removed 2026-09-12 (ERR-012): the beacon never stamps a pulse with a software clock read, so read latency is not a
precision term. The 2026-09-11 k3-vs-p550 read-latency comparison lives in the notebook and in this file's git history.

## Clock *quality* runs the other way

| | p550 (i210) | k3 (Milk-V) |
|---|---|---|
| PHC ↔ its reference | **8.3 ns RMS** (ts2phc ← ZED-F9T PPS, direct) | 41.4 ns RMS (ptp4l ← BMC GM over Ethernet) |
| system ↔ PHC (chrony) | 8–10 ns RMS | 26 ns RMS |
| PTP path delay | n/a — direct electrical PPS | ~893 ns, one-way symmetry **assumed** |

So **p550 has the better-disciplined clock (≈5×); k3 is the cheaper clock to read (≈2.5×).**

## What actually bounds a pulse's time

```
anchor uncertainty  ≈  receiver epoch error (sawtooth 2.2 ns sd, logged)  ⊕  ts2phc discipline (~8 ns RMS)  ⊕  uncalibrated fixed delays (antenna, coax, SDP0 input)
```

The edge is captured in hardware; software touches the record afterwards, not the time. `CLOCK_REALTIME` values in
statements bound *freshness* (chrony's root dispersion, ~2.4 µs) and are labelled as such.

## macstu — 192.168.71.75 (archive)

macOS 15.7.8, up 77 days. External volume `/Volumes/Expansion` (25 TiB, 13 TiB used).

**Two corpora, and they are NOT the same thing:**

| path | size | files | span | source |
|---|---|---|---|---|
| `/Volumes/Expansion/quantum_cache/raw/2025/` | **4.1 TB** | 43,010 `.bin` | 2025-07-18 → 2025-11-15 | **the Quantis**, via `http://192.168.70.1:8080` |
| `/Volumes/Expansion/dev_random_raw/` | **159 GB** | 2,385 `.bin` | 2025-07-21 | **Linux `/dev/random`** — a CSPRNG |

`dev_random_raw/mirror_service.log` states the intent outright: it mirrored the quantum corpus with
`/dev/random` bytes, *"Collecting 151.70 GiB to reach parity"*. This is a deliberate **matched-pair
control experiment**, and it is scientifically the most valuable thing here.

⚠️ **`dev_random_raw` is not quantum and must never be sold or labelled as such.** It is the control
arm. Mislabelling it would be the single worst mistake available to us.

Capture cadence (files/month): 2025/07 1,222 · 08 14,996 · 09 17,937 · 10 8,852 · 11 3.
Capture effectively stopped early November 2025.

Mostly-empty siblings: `quantum_backup/` (12 K), `random/` and `/Volumes/MySSD/random` are *code*
projects (analysis tooling, venvs), not byte stores.
