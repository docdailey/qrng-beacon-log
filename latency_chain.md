# latency_chain.md — the beacon's chain, step by step, before and after (2026-09-13)

Bill: *"if anyone is going to take the timing aspect seriously we need a fast chain."* This document records the chain's
latency as measured on three configurations in one day, every figure taken from timestamps a verifier can read back out
of the pulses, the aggregator's logs, git, and the Rekor anchors. It is a record, not a claim: the numbers are for the
hours named, and the floors at the end are stated as floors.

## 1. Four budgets, defined

| budget | from | to | what limits it |
|---|---|---|---|
| **trigger response** | the scheduled instant (a drand round boundary, :00:00.000 UTC) | the aggregator's cycle running | the clock that fires the instant and how the aggregator learns of it |
| **commitment public** | the instant | the commit pulse pushed to `main` (TSA-stamped) | the chain: entropy host, three clock statements, two TSAs, seal, checkpoint, push |
| **externally anchored** | the instant | the commit's Rekor entry (`integratedTime`) | today a CI workflow after the push |
| **usable randomness** | the instant | the reveal pulse pushed | the lead (100 rounds = 300 s through 0101; **20 rounds = 60 s from 0102**, a policy) + the relays' publication delay + the reveal chain |

## 2. The same chain, three times

Instant → commit public. Times are relative to the scheduled instant. Column 1 is think on its systemd timer (pulse
0086/0087, 11:00Z); column 2 is think after the first trigger work (0092/0093, 13:00Z: p550 slept to the tick and
delivered a signed trigger over SSH); column 3 is k3 on the finished path (staging run 7, 15:15Z, real hosts, throwaway
clone, secret retired afterwards — see CADENCE.md §2 for the staging method).

| step | think, timer (11:00Z) | think, SSH trigger (13:00Z) | k3, hardware event + daemon (run 7) |
|---|---|---|---|
| trigger origin | systemd timer, +26 s | p550 `clock_nanosleep`, woke +114 µs | i210 PHC's own second event, kernel stamp **+23 µs**; p550 process running **+170 µs** |
| trigger delivered | — | SSH session + forced command, +682 ms | signed UDP datagram, **+3.0 ms** |
| aggregator cycle started | +26 s | +0.80 s | **+3.9 ms** (on the datagram) |
| git pull + recover | after the tick, 3.8 s | after the tick, 3.8 s | before the tick (prepare −40 s, last fetch −10 s) |
| commit process started | ~+30 s | +4.67 s | +0.24 s |
| entropy statement (protectli) | — | +8.76 s | +0.30 s |
| gnss / witness / time statements | sequential, 12–35 s of live sampling each | +10.4 / +10.5 / +12.6 s | +0.51 / +0.54 / +0.65 s |
| TSA tokens (FreeTSA, DigiCert) | | +13 s | within the same second |
| **commit pushed** | ~+80 s | **+14.8 s** | **+1.5 s** |
| Rekor entry (CI) | | +33 s | unchanged (CI); see §5 |

Round release → reveal public. Times are relative to the drand round's release.

| step | think, timer (11:05Z) | think (13:05Z) | k3 (run 7) |
|---|---|---|---|
| round first served by a relay | polled every 3 s | +1.2 s | +1.13 s (all relays raced over pre-opened connections) |
| aggregator reveal started | +6 s | +1.29 s | +1.37 s |
| four reveal statements | +11 / +13 / +49 / +84 s | +8 to +13 s | +1.62 to +1.75 s |
| **reveal pushed** | **+86 s** | **+15 s** | **+2.0 s** |

**Live pair 0098/0099 (16:00Z, the first minted by k3, verified from the published pulses):** i210 second event stamped
+267 µs, p550 process +317 µs, first datagram +1.65 ms, received on k3 +2.0 ms, k3 started on it +2.9 ms; statements
+0.30 / +0.64 / +0.65 / +0.77 s; **commit pushed +2.4 s** (297.6 s before release; the live cycle also signs and cosigns a
checkpoint, which staging did not). Reveal: round served +1.22 s, aggregator started +1.46 s, **reveal pushed +3.4 s**.
The :02 fallback fired and exited on the lock, as designed. Every verifier check passed, every statement via the daemon.
Note the edge stamp: 21–30 µs after the boundary when a small C program waits on the PPS device, 267–277 µs when the
Python trigger process does — the same kernel event, a different wake path; recorded in the trigger either way and on
the list to explain.

## 3. Where each gain came from

- **86 s → 15 s (reveal), 80 s → 15 s (commit):** each clock host logs its evidence at source rate (`hosts/clocklog.py`,
  tmpfs rings + the timehat DB) and a statement summarises the trailing 60 s in milliseconds instead of sampling live for
  12–35 s; the three statements are gathered concurrently; the reveal sleeps to the known release instant instead of
  polling every 3 s.
- **15 s → 1.5 s (commit), 15 s → 2.0 s (reveal):** no SSH and no interpreter starts on the role hosts — `beacon-agentd`
  answers signed requests over TCP in 7–9 ms with the host scripts already imported; git work moved before the tick;
  drand verified natively with blst (0.02 s per round instead of 2.2 s on x86 / 4.7 s on the RISC-V aggregator) and in a
  thread beside the host calls; both TSAs requested at once; a persistent connection to GitHub for the push; the round
  handed from the cycle driver to the aggregator instead of fetched twice.
- **0.8 s → 3.9 ms (start):** the instant is fired by the hardware clock's own event and relayed as a self-authenticating
  datagram, not negotiated in a session. Wake latency alone went 26 s (timer) → 114 µs (clock sleep) → 5–7 µs (sleep +
  spin) → 23 µs kernel-stamped event + 170 µs to userspace (PHC PPS source, `/dev/pps1`).

## 4. Methods tried and not adopted (measured, `bench/m2m_bench.py`)

ZeroMQ REQ/REP on a persistent socket equals a persistent plain TCP connection within 0.1 ms; ZeroMQ connect-per-call is
slower than ours; CurveZMQ costs 0.15–0.4 ms warm and 4–7 ms cold for encryption the protocol does not need (statements
are public; the one secret is sealed at the application layer); PUB/SUB is 60 µs behind raw UDP one-way. The ~1.2 ms loopback figure is the cost of *that benchmark's* signed Python/JSON exchange (a 700 B Ed25519-signed
request, a 6,000 B signed response, verification on both ends), not a transport floor: the same LAN carries a raw
64-byte TCP exchange in 43–91 µs with both ends polling (`timing.md`, 2026-09-13). That investigation measured the
pieces below the socket and changed three things here: the client keeps one connection per host (a small signed exchange
1.10 → 0.38 ms), the trigger statement stays under one Ethernet frame (two IP fragments had put its p99 at 1.2 ms), and
the aggregator's listener is a blocking socket with a kernel deadline and busy-poll. The persistent-connection daemon
side is written and waits for a CLI release that pins its hash.

## 5. Floors that remain, stated as floors

- **Relays:** the League of Entropy relays publish a round **1.13–1.38 s after its release** (measured across four relays,
  order varies). No reveal can be public before about +1.5 s. This is drand's, not ours.
- **Rekor:** through 0099 the commit's external anchor was written by a CI workflow after the push, about 30 s after the
  instant (0092: 33 s, 0094: 32 s). From 0100 (17:00Z) the aggregator enters the commit into Rekor itself beside the git
  push: **integratedTime = instant + 1 s** (upload 0.66 s). CI still records the entry on the anchors branch.
- **The lead:** time to usable randomness is dominated by the lead. With the commit public at ~2 s and anchored at ~1 s,
  the lead went from 100 rounds (300 s) to **20 rounds (60 s)** at the 18:00Z cycle (pulse 0102), with the publish margin
  from 120 s to 20 s and the floor in the code from 60 to 10 rounds. 10 rounds (30 s) is the next step once a day of
  60 s cycles shows the anchor and push variance.
- **Two things we do not claim:** the aggregator's receipt and start times are its own clock's readings (bookkeeping, not
  attested); the wake and edge latencies are quoted from the statements that recorded them, never as an accuracy of the
  time base (CLAIMS.md).

## 6. How to read these numbers out of a pulse yourself

`core.cadence.trigger.statement.hw_event` (the PHC event and how long after it the time host ran), `.wake`, and
`.issued_unix_ns`; `core.cadence.received_unix_ns` and `core.cadence.self_trigger` (the aggregator's start and its
source); each `statements.<role>.statement.issued_unix_ns`; `pulse-NNNN.json.tsa.json` (`requested_unix`, token times);
the git commit time of the pulse; `pulse-NNNN.anchor.json` on the `anchors` branch (`rekor.entry.integratedTime`);
`core.cadence.started_after_release_s` and `derived.anchor_after_release_s` in the reveal. `verify.py` checks the
cadence records; the CLI (`notbefore` ≥ 0.14.0) verifies the statements they sit beside.

## 7. What went wrong on the way (so the numbers are not read as free)

ERR-016: changing a `Persistent=true` timer's schedule fired an unscheduled pair (0090/0091). ERR-017: the first live run
of the new reveal path crashed on a missing import that commit-only staging had never executed; commit 0096 was resolved by
failure pulse 0097 inside the window, and staging now runs a full pair. A DNS reverse lookup inside `chronyc sources`
stalled two clock hosts 5.3 s at the same instant (now `-n`). A thread-pool context manager joined the slowest drand relay
and held a commit 4 s (now first-answer-wins with detached threads). Each is in ERRATA.md or CADENCE.md.

## 8. Progression, pulse by pulse (2026-09-13)

One representative commit from each stage of the day, every figure relative to that hour's instant (the top of the hour;
0096 is the :02 fallback and its instant is still 15:00:00). Sources: the pulse's `core.cadence` and statement
`issued_unix_ns` fields, the aggregator's `cycle.log` ("commit pushed N s before release", "pushed N s after release"),
the anchors branch `INDEX.tsv` (`rekor_integratedTime`, 1 s resolution) and the git commit time of the chain file where
no log line exists. Sub-second numbers come from the pulse; whole seconds from logs.

| pulse (UTC) | how the hour started | aggregator process start | last host statement | commit pushed | Rekor entry | release after the instant | reveal pushed after the release | randomness usable after the instant |
|---|---|---|---|---|---|---|---|---|
| **0088** (12:00) | think's systemd timer at :00:26; target = drand latest + 100 rounds | +26 s (timer) / first statement +33.9 s | +104.1 s | +106 s | +118 s (CI) | +327 s (:05:27) | +83 s | **+410 s** |
| **0092** (13:00) | p550's clock-timed trigger over SSH to think: p550 woke +114 µs, think received it +0.68 s, cycle start +0.80 s | +4.67 s (pulse.py) | +12.6 s | +15 s | +33 s (CI) | +300 s (:05:00) | +15 s | **+315 s** |
| **0094** (14:00) | same path: p550 woke +112 µs, received +0.56 s, cycle start +0.70 s | +6.02 s | +12.7 s | +15 s | +32 s (CI) | +300 s | +15 s | **+315 s** |
| **0096** (15:00) | think's :02 fallback timer (cycle start +120 s); the reveal then crashed on a missing import (ERR-017) | +124.4 s | +132.2 s | +134 s | +149 s (CI) | +423 s (:07:03) | failure pulse 0097 pushed +165 s | none |
| **0098** (16:00) | k3, tick-started, first live pair: i210 PPS edge +267 µs, p550 woke +317 µs, trigger issued +0.52 ms; k3 started on the datagram +2.87 ms | +0.243 s | +0.767 s | +2.4 s | +14 s (CI) | +300 s | +3.4 s | **+303.4 s** |
| **0100** (17:00) | k3: edge +274 µs, woke +289 µs, issued +0.44 ms; k3 kernel receive +2.05 ms, userspace +2.11 ms, start +8.07 ms | +0.248 s | +0.652 s | +2.2 s | **+1 s (at mint)** | +300 s | +3.4 s | **+303.4 s** |
| **0102** (18:00) | k3, **lead 20 rounds**: edge +276 µs, woke +295 µs, issued +0.45 ms; k3 kernel receive +1.59 ms, userspace +1.68 ms, start +2.56 ms | +0.240 s | +0.752 s | +2.3 s | **+1 s (at mint)** | **+60 s (:01:00)** | +3.2 s (round served by the first relay +1.12 s, reveal started +1.35 s) | **+63.2 s** |
| **0108** (21:00) | k3, lead 20; **GPIO PPS removed, cadence service SCHED_FIFO**: edge **+21 µs**, woke +41 µs, issued +0.20 ms, first copy sent +1.6 ms (sign + serialize 1.4 ms, cold); k3 kernel receive +1.85 ms, start +2.84 ms | | +0.76 s | +2.4 s | +1 s | +60 s | +3.4 s | **+63.4 s** |
| **0110** (22:00) | k3, **start mode B (own clock)**: k3 woke **+18.9 µs** and started; p550 edge +37 µs, woke +39 µs after it, issued +0.27 ms, first copy +1.15 ms (warm sign); datagram at k3's kernel +1.33 ms, bound to the commit as attestation | +0.238 s | +0.637 s | +2.3 s | +1 s | +60 s | +3.2 s (reveal started +1.35 s) | **+63.2 s** |

What each column's movement was:

- **Start of the hour → aggregator start:** 26 s (a timer) → 0.8 s (SSH-carried trigger) → 2.6–8.1 ms (hardware edge, UDP,
  tick-started process) → **18.9 µs** (own clock, mode B, from 0110). Live samples: 2.87, 8.07, 2.56 ms. At 17:00 the start came 6 ms after the datagram; at 18:00
  0.88 ms after it (staging's figure), with the new gate record showing the main thread waiting at the instant
  (`main_thread_at_gate_unix_ns` = the instant, pre-tick git work 0.27 s, done 9.7 s early). The 17:00 outlier is
  unexplained and is being watched, not fixed.
- **Aggregator start → last host statement:** 70 s (think: py_ecc BLS, cold SSH to four hosts) → 8 s (warm SSH) → 0.4–0.5 s
  (beacon-agentd, concurrent requests, hot processes).
- **Last statement → commit pushed:** 2 s throughout; the git push itself is the floor now (§5).
- **Rekor:** 118 s → 32 s (CI ran sooner after the push) → 14 s → 1 s (the aggregator uploads at mint, beside the push).
- **Release after the instant:** :05:27 (drand latest + lead at commit time) → :05:00 (the instant + lead, a fixed grid) →
  :01:00 (lead 20 rounds, from 0102).
- **Reveal pushed after the release:** 83 s (py_ecc 4.7 s, cold SSH, serial hosts, one relay) → 15 s → 3.4 s (blst,
  relay race from release + 1.0 s, agentd, `--drand` hand-off). The relays themselves serve the round 1.1–1.4 s after
  release, so ~2 s of the 3.4 s is outside the lab.
- **Time to usable randomness:** 410 s → 315 s → 303 s → **63.2 s** at 0102 (the lead change). Everything below the lead
  is now ~3.2 s of which ~1.1 s is the relays; the commit was public 57.7 s before its round against a 20 s margin.

## 9. Same-instant test: k3 and p550 waking on their own clocks (lab, 2026-09-13 18:12–18:15Z)

Question (Bill): both hosts are on the same time, so why does k3 wait 2.5 ms for p550's datagram instead of both firing at
the instant? Test, outside the beacon (`bench/simul_wake.py`): at a minute boundary each host wakes on its OWN clock
(`clock_nanosleep` to T−1.5 ms, spin to T, the beacon's own method), sends its wake stamp to the other at once, and stamps
the other's datagram in the kernel (`SO_TIMESTAMPNS`) and in userspace. Clock state at the time: p550's system clock
2 ns from the i210 PHC (F9T-locked); k3's 7 ns from its PHC, which was 37 ns from the P550-BMC grandmaster.

| run (UTC) | p550 process | k3 woke | p550 woke | p550 PPS edge stamp (pps1) | k3→p550 one way | p550→k3 one way |
|---|---|---|---|---|---|---|
| 18:12:00 | normal priority | **+5.8 µs** | +6,827 µs | +269 µs | 388 µs | 240 µs |
| 18:14:00 | normal priority | **+7.0 µs** | +360 µs | +277 µs | 415 µs | 417 µs |
| 18:15:00 | `chrt -f 50` (SCHED_FIFO) | **+7.1 µs** | **+7.8 µs** | +25.8 µs | 362 µs | 325 µs |
| 18:17:00 | normal + no deep idle (`cpu_dma_latency` 0) | +6.3 µs | no data: the SSH launch to p550 timed out | | | |
| 18:18:00 | `chrt -f 50` again | **+5.3 µs** | **+8.0 µs** | +294 µs | 344 µs | 259 µs |
| 18:19:00 | normal + no deep idle (`/dev/cpu_dma_latency` 0 held) | +6.3 µs | **+8.0 µs** | **+23.0 µs** | 287 µs | 1,410 µs (k3-side outlier) |
| 18:20:00 | `chrt -f 50` pinned to CPU0 (the i210 IRQ CPU) | +6.2 µs | +278.8 µs | +275.8 µs | 283 µs | 327 µs |
| 18:22:00 | normal, `cpu-retentive` disabled on CPU0 only | +6.1 µs | +7.9 µs | +294 µs | 555 µs | 350 µs |
| 18:23:00 | normal, `cpu-retentive` disabled on CPU0 only | +6.8 µs | +8.3 µs | +283 µs | 741 µs | 359 µs |
| 18:25:00 | normal, `cpu-retentive` disabled on all four CPUs | +6.3 µs | +7.4 µs | +298 µs | 329 µs | 341 µs |
| 18:26:00 | normal, `cpu-retentive` disabled on all four CPUs | +6.5 µs | +2,719 µs | +275 µs | 467 µs | 332 µs |
| 18:28:00 | normal, PM QoS held, idle states default | +5.7 µs | **+7.9 µs** | +288 µs | 503 µs | 308 µs |
| 18:29:00 | normal, PM QoS held, idle states default | +5.6 µs | **+7.9 µs** | **+24.9 µs** | 782 µs | 395 µs |
| 18:30:00 | normal, pinned to CPU0, no QoS | +6.8 µs | +719 µs | +274 µs | 280 µs | 340 µs |
| 20:14–20:16 | normal, three baseline minutes (p550 only) | | +8.2 / +8.2 / +2,349 µs | +281 / +295 / +281 µs | | |
| 20:17–20:19 | normal, three more (an unbind attempt used the wrong device name, so nothing had changed) | | +7.8 / +8.3 / +7.4 µs | +295 / +282 / +288 µs | | |

One-way = the peer's send stamp to the receiver's kernel stamp, both software; serializing and the first `sendto` cost
80–105 µs on either host and are inside these numbers.

What it shows:

- **k3 on its own clock is 6–7 µs late, three of three.** Starting the cycle at k3's own instant instead of on the
  datagram would move the start from ~2.5 ms (8 ms once) to ~7 µs. k3's PTP-disciplined clock is the tighter thing in the
  room; the datagram is 2.5 ms behind it.
- **p550 on its own clock is not usable at normal priority** (6.8 ms, then 360 µs late) **and is 7.8 µs late at
  SCHED_FIFO 50.** p550 runs PREEMPT_RT; a normal-priority task's `clock_nanosleep` expiry goes through the timer softirq
  thread, which the FIFO-50 IRQ threads (all five igb vectors sit on CPU0 at FIFO 50) hold off around the second. The
  cadence service does not sleep on the clock, it waits on the PPS event, which is why the live trigger wakes 15–19 µs
  after the edge regardless.
- **p550's clock wake is controlled by priority or PM QoS; its PPS interrupt stamp is set by a kernel splat on CPU0.**
  The *timer wake* of a p550 process is +7.4 to +8.3 µs whenever SCHED_FIFO or PM QoS (`/dev/cpu_dma_latency` = 0) is
  in effect, and erratic otherwise (360 µs, 719 µs, 2.3 ms, 2.7 ms, 6.8 ms): a normal-priority sleeper on this
  PREEMPT_RT kernel wakes late unless the tick is kept running or it outranks the IRQ threads. The *pps1 edge stamp*
  was +23 to +26 µs in three runs and +269 to +298 µs in sixteen, and neither idle states, priority, CPU pinning nor
  QoS selected between them. The cause is elsewhere: p550's kernel logs `BUG: sleeping function called from invalid
  context` from `pps_gpio_irq_handler → pps_event → rt_spin_lock` **every second** (604 in ten minutes), a twenty-line
  backtrace generated inside the GPIO PPS hard interrupt on CPU0 with interrupts off. Read second by second, the two
  PPS devices show the order: the GPIO PPS from the LEA-6T (`pps0`) is stamped **+15 to +19 µs** after the second, the
  i210 PHC second (`pps1`) **+279 to +287 µs**, every second, both counters advancing together. The i210's MSI, also on
  CPU0, is serviced when the GPIO handler's backtrace finishes; the ~265 µs gap is the splat. The three fast stamps are
  the seconds when the i210 interrupt was serviced first. Interrupt affinity cannot be changed on this SoC (`EINVAL`
  for the i210 vectors, `EIO` for the GPIO line: all on CPU0). The i210's hardware latch of the F9T edge (ts2phc,
  ±10 ns) is untouched; only this software stamp, and everything the cadence service does after it, is late.
- **Fix applied (Bill, 2026-09-13 20:26Z): the GPIO PPS is gone from p550.** `pps-gpio` unbound now and at every boot
  (`no-gpio-pps.service`, before chrony and the cadence service), its `refclock PPS /dev/pps0 ... noselect` line commented
  out of chrony's `conf.d/gps.conf`, chrony restarted: reference IPHC, stratum 1, RMS 20 ns a few seconds after the
  restart. Result, read every second: the i210 PHC second (`pps1`) is stamped **+21 to +28 µs** (was +279 to +287), the
  splat count is zero, `/dev/pps1` is unchanged for the cadence service. What was given up: chrony's non-selected LEA-6T
  PPS fallback on p550 (the 6T still feeds the BMC's PD3 directly and its NMEA/qErr logging is untouched). HARDWARE.md
  entry 189 (2026-09-01) records the un-threading of that GPIO IRQ that made the splat; this is its cost, found and
  removed twelve days later. The trigger, the datagram and k3's start should all move ~250 µs earlier from 21:00Z.
  Separately the cadence service now runs at SCHED_FIFO 30 (it was descheduled twice around 20:00:00).
- **k3 cannot trigger on its own PHC today.** The disciplined PHC on `end0` (stmmac) exposes one periodic output pin and
  no alarm, no external timestamp and no PPS source. The idle 10GbE port's PHC (`r8127`) advertises a PPS source, but
  the vendor driver emulates it with an hrtimer (`rtl8127_hrtimer_for_pps`), enabling it raised a kernel WARNING in
  that timer on k3, no event arrived in 90 s, and the PHC read costs 25 µs. Reverted; k3 healthy. A hardware second on
  k3 means wiring the stmmac pulse output to a GPIO with `pps-gpio`, if the pin is exposed (August's pad-route notes).
- **The clocks agree to the resolution of software stamps.** In the 18:14 run the two one-way delays were 415 and
  417 µs: a clock offset d would make them differ by 2d, so |d| ≲ a few µs, consistent with the PHC readings (k3
  16 ns → −101 ns from its PHC across the runs; p550 ~1.7 µs, inside its 8 µs PHC read bracket).
- **Userspace on p550 saw k3's packet 6.2 ms after its kernel did** in the first run, the same stall that delayed the
  wake: the whole process was off-CPU, not just the sleeping thread.

Design option this opens (not built; Bill's call): k3 starts at its own instant (~7 µs) and binds p550's signed hardware
record as it arrives ~2.5 ms later, so the datagram attests the instant instead of causing the start. The pulse would then
name k3's PTP-disciplined clock as the start and p550's i210 event as the independent witness of the same second. What is
lost: today the start is *caused* by a hardware event on another host; with this change it is caused by k3's clock and
*confirmed* by that event. Three ways to use these numbers were put to Bill: **(A)** as is, k3's start caused by p550's hardware-event datagram,
+2.5 ms; **(B)** k3 starts on its own clock (+6 µs) and binds p550's hardware record when it arrives; **(C)** both fire on
their clocks. **Bill chose B (21:2xZ).** Built as `BEACON_START=own-clock` (the default) in beacon-cycle.py: the main thread
does not wait for the datagram, the listener writes it to `trigger/pending.json` on arrival and pulse.py binds it with its
userspace and kernel receive stamps; the verifier's checks are unchanged (same instant, signature under the pinned key,
target from the instant), so no CLI release is needed for the mode itself. Staged twice as full pairs on lab instants
(21:27:39Z and 21:33:45Z, `--no-finalize`, secrets retired): k3 started **+20.1 and +22.5 µs** after the instant on its own
clock; in the second run p550's datagram (edge +31 µs, issued +0.22 ms) reached k3's kernel at **+1.19 ms** and userspace at
+1.34 ms and was bound to the commit with those stamps; commit pushed +1.3 s, reveal pushed 2.0 s after release, both
pulses verified. Live from 22:00Z (pulse 0110). The first staging run also exposed a verifier crash for a commit with the
aggregator's wake record but no time-host trigger (`UnboundLocalError` in an informational line, present in every CLI
since 0.13.x, never hit by a published pulse): fixed in verify.py and released as 0.14.2. What changes in the claim: the start is caused by k3's PTP-disciplined clock and *confirmed* by a hardware
event on another host, no longer caused by it.

### 9b. Userspace budget on the trigger path (measured 2026-09-13 21:05Z, 300 warm iterations, pulse 0108's statement)

| step | p550 (sign side, Python 3.12) | k3 (verify side, Python 3.14) |
|---|---|---|
| canonical JSON of the 1,372 B statement | 197 µs (cold 314) | 106 µs |
| Ed25519 sign / verify (OpenSSL via `cryptography`) | 212 µs (cold 360) | 245 µs (cold **6,144**) |
| base64 + wrapper + `json.dumps` / `json.loads` | 94 µs | 63 µs |
| five PHC brackets | 54 µs | |
| thread hand-over (`Event.set` → `wait` returns) | | 52 µs (5 ms or 0.5 ms switch interval alike) |
| **total** | **503 µs warm** | **414 µs warm** + 52 µs hand-over |

Against the live 21:00 numbers: p550 spent 1.4 ms between `issued` and the first copy (0.95 ms at 18:00), three times the
warm figure, because the process has been asleep for an hour and everything is cold; k3 spent 0.94 ms between kernel
receipt and the start against 0.47 ms warm. The first of the cheap next steps is done: the cadence service now signs and serializes a full-size dummy statement at
T−30 ms, just before it starts polling the PPS device (`hw_wait(..., warm=)`). Same-conditions lab minutes, `--once
--no-send` at SCHED_FIFO 30: issued → first copy **1.36 ms before, 0.73 ms after** (21:07 and 21:08Z); deployed for the
22:00Z cycle (script sha256 `23210619a8d0…`, self-reported in the trigger's `tools`; not a pinned hash). Still open: and on k3 sending the
canonical statement bytes so the verifier does not re-canonicalize (~0.1 ms) and a faster Ed25519 (libsodium, if
present) for another ~0.1 ms. With the GPIO PPS gone the edge itself is at +21 µs; the remaining 2.8 ms to k3's start is
now all userspace and wire: 0.2 ms to assemble, 1.4 ms to sign cold, 0.25 ms LAN, 0.9 ms to verify and hand over.

## 10. Lead: 20 rounds against 10, by the numbers (data pulled 2026-09-13 21:30Z)

The lead is a policy: the commit must be public (git push complete) at least `PUBLISH_MARGIN_S` = 20 s before its target
round, or `beacon-cycle.py` mints a signed **failure pulse** for the hour instead (public, chain-linked, visible to every
verifier; the hour has no randomness). Mint-time Rekor anchoring runs beside the push and never blocks it. So the lead has
to cover: the instant to the push completing, with the margin behind it. Everything after the release (relay fetch, reveal)
is unaffected by the lead. Sources: k3 and think `cycle.log`, the git commit time of each chain file, the anchors branch
`INDEX.tsv`, the `.tsa.json` sidecars, and the timehat DB (`ptp4l_stream`, `epoch_stream`, `ts2phc_stream`, `gmmon_stream`).

### What has been measured

| quantity | n | median | p90 | max | source |
|---|---|---|---|---|---|
| **k3: instant → commit pushed** (0098–0108) | 6 | 2.3 s | 2.4 s | **2.4 s** | k3 log: lead − "pushed N s before release" |
| think: push duration (committed → pushed), 0012–0096 | 45 | 1 s | 2 s | **2 s** | think log: "release in X" − "pushed Y before" (1 s resolution) |
| think: git commit of the chain file after the top of the hour | 43 | 105 s | 133 s | 3,041 s (0020, 2026-09-12 manual era) | git log (the 80 s of think preparation is inside this) |
| Rekor integratedTime − instant, mint-anchored era (0100–0108) | 5 | **1 s** | 1 s | 1 s | anchors INDEX.tsv |
| Rekor integratedTime − instant, CI era (0042–0098) | 30 | 121 s | 132 s | 1,646 s (0090, the unscheduled pair, ERR-016) | anchors INDEX.tsv; CI ran after the push |
| TSA token times, k3 cycles | 12 | same second as the instant | +1 s | +1 s | `.tsa.json` (`requested_unix` = instant or +1 s) |
| drand round first served after release, k3 | 6 | 1.13 s | 1.22 s | 1.22 s | k3 log (after the release; not on the lead path) |
| k3 PHC vs grandmaster (BMC), 24 h, state s2 only | 65,942 | 0 ns | — | **167 ns** (p99 103 ns) | timehat `ptp4l_stream` |
| k3 system clock vs its PHC, 24 h | 32,130 | −8 ns | — | 225 ns (p99 155 ns) | timehat `epoch_stream` |
| p550 i210 PHC vs F9T, 24 h | 33,841 | 0 ns | — | 37 ns (p99 22 ns) | timehat `ts2phc_stream` |
| p550 system clock vs its PHC, 24 h | 32,623 | −29 ns | — | 507 ns (p99 435 ns) | timehat `epoch_stream` |
| i210's observation of the BMC grandmaster, 24 h | 8,611 | +15 ns | — | 107 ns (p99 62 ns) | timehat `gmmon_stream` |

The clocks are not a factor at any lead: the aggregator's instant is known to about 0.2 µs against a grandmaster that
is itself within 0.1 µs of the GNSS-locked i210. What the lead buys is room for the push.

Two publication failures exist in the whole log, neither a slow push: **0048** (2026-09-12 16:05Z, think): the reveal
was refused because `main` had moved under the checkout (a concurrent push) and the resume's push was rejected as
non-fast-forward (ERR-010); the 17:00 cycle found 0049 revealed at the head. **0096/0097** (2026-09-13 15:07Z): a crash in the new
reveal path, ERR-017; the failure pulse was minted inside the window. Neither would be changed by the lead. `beacon-cycle.py`
now rebases onto `origin/main` and retries a rejected push (3 attempts) and fetches `origin/main` 10 s before the tick.

### The arithmetic

| | 20 rounds (60 s) | 10 rounds (30 s) |
|---|---|---|
| target round released at | instant + 60 s | instant + 30 s |
| push must complete by | instant + 40 s | instant + 10 s |
| observed push completion, k3 | +2.2 to +2.4 s | +2.2 to +2.4 s |
| slack behind the worst observed push | **37.6 s** | **7.6 s** |
| a push slower than this fails the hour | ~39 s | **~9 s** (start +0.25 s, statements +0.75 s, then the push) |
| observed cycles that would have breached | 0 of 6 (0 of 51 counting think's 1–2 s pushes) | 0 of 6 (0 of 51) |
| randomness usable after the instant | 63.2–63.4 s | ≈ 33 s |

The two eras agree that a push takes 1–2.4 s end to end; no push in 51 commits took longer than 2.4 s, and the one
rejected push (0048) was a fork, not a slow link. At 10 rounds a nine-second push fails the hour; nothing in the record
comes within a factor of three of that.

### What a breach looks like

A push that has not completed 20 s before the round makes the aggregator mint `failure` for that seq (signed, chain-linked,
with the reason `commit-published-late` and the measured margin), push that instead, and the CI chain check fails the
commit if a pushed commit ever misses the margin. Consumers see a gap hour, never a late commit presented as on time.

### Recommendation

Go to 10 rounds after **24 clean 60 s cycles** (one day: 0102 was the first; 18:00Z 2026-09-14) provided that over those
cycles: no push completes later than +5 s (double the worst seen; that would still leave 5 s of slack at 30 s), no
push is rejected and retried, and Rekor stays at instant + 1 s. If any cycle shows a push past +5 s, hold at 20 rounds and
look at the push, not the lead. The margin stays at 20 s: with a 2.4 s push it is the number that protects against the
one thing the record has never shown, a GitHub stall, and it is what turns a stall into a visible failure rather than a
late commit.

### 10b. The same numbers from the timehat DB (2026-09-13 21:40Z)

Bill: "can we not just pull stats from timehat db on nas?" Now yes. `hosts/cyclelog.py` writes one row per cycle into
`timehat.beacon_cycle_stream` on nas1 (the database the clock streams already use), detached after `cycle complete` or a
failure pulse, from the pulse files, `trigger/anchor-NNNN.json` and `cycle.log`; it never runs before the mint and a DB
outage changes nothing. Back-filled for 0098–0108. Columns are every stamp in §8: the p550 edge and wake, the datagram's
kernel and userspace receive on k3, k3's wake and gate, pulse.py start, the four statements, commit push, Rekor, relay serve
delay, reveal start and push, and `usable_after_instant_ms`. The 60 s era today, one query:

```sql
SELECT seq, instant_utc, start_source, p550_edge_after_instant_ns, datagram_kernel_rx_after_instant_ns, k3_wake_after_instant_ns,
       commit_pushed_after_instant_ms, rekor_integrated_after_instant_s, reveal_pushed_after_release_ms, usable_after_instant_ms
FROM beacon_cycle_stream WHERE lead_rounds = 20 ORDER BY seq;
-- 0102..0108: push 2200-2400 ms, Rekor +1 s, reveal 3200-3400 ms after release, usable 63200-63400 ms
SELECT MAX(commit_pushed_after_instant_ms), AVG(commit_pushed_after_instant_ms) FROM beacon_cycle_stream WHERE lead_rounds = 20;   -- 2400, 2300
```

The 10-round test in §10 is then `SELECT COUNT(*) FROM beacon_cycle_stream WHERE lead_rounds = 20 AND commit_pushed_after_instant_ms > 5000`
over the 24 cycles: zero means go. The credentials the aggregator uses are a mode-600 copy of the clock logger's file under
`~aggregator/beacon/` (write access to the `timehat` schema only; the DB holds no key material).
