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

What each column's movement was:

- **Start of the hour → aggregator start:** 26 s (a timer) → 0.8 s (SSH-carried trigger) → 2.6–8.1 ms (hardware edge, UDP,
  tick-started process). Live samples: 2.87, 8.07, 2.56 ms. At 17:00 the start came 6 ms after the datagram; at 18:00
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
- **p550's clock wake is controlled; its PPS interrupt stamp is not.** Thirteen lab minutes, idle states, priority, CPU
  pinning and PM QoS tried in turn (table). The *timer wake* of a p550 process is +7.4 to +8.3 µs whenever SCHED_FIFO or
  PM QoS (`/dev/cpu_dma_latency` = 0) is in effect, six of six, and erratic otherwise (360 µs, 719 µs, 2.7 ms, 6.8 ms):
  a normal-priority sleeper on this PREEMPT_RT kernel wakes late unless the tick is kept running or it outranks the IRQ
  threads. The *pps1 edge stamp* (the software time at which the `irq/178` thread serviced the i210's second interrupt)
  was +23 to +26 µs in three runs and +269 to +298 µs in ten, and nothing tried selects between them: not cpu-retentive
  off (CPU0 or all), not FIFO, not a busy CPU0, not QoS (fast in two of three). The i210's hardware latch of the F9T
  edge (ts2phc, ±10 ns) is unaffected; this is the service latency of one interrupt and it costs the trigger ~250 µs on
  most hours. It stays an open item with a measured distribution rather than a fix.
- **The clocks agree to the resolution of software stamps.** In the 18:14 run the two one-way delays were 415 and
  417 µs: a clock offset d would make them differ by 2d, so |d| ≲ a few µs, consistent with the PHC readings (k3
  16 ns → −101 ns from its PHC across the runs; p550 ~1.7 µs, inside its 8 µs PHC read bracket).
- **Userspace on p550 saw k3's packet 6.2 ms after its kernel did** in the first run, the same stall that delayed the
  wake: the whole process was off-CPU, not just the sleeping thread.

Design option this opens (not built; Bill's call): k3 starts at its own instant (~7 µs) and binds p550's signed hardware
record as it arrives ~2.5 ms later, so the datagram attests the instant instead of causing the start. The pulse would then
name k3's PTP-disciplined clock as the start and p550's i210 event as the independent witness of the same second. What is
lost: today the start is *caused* by a hardware event on another host; with this change it is caused by k3's clock and
*confirmed* by that event. Three ways to use these numbers, for Bill to choose between (none built): **(A)** as is, k3's start caused by p550's
hardware-event datagram, +2.5 ms; **(B)** k3 starts on its own clock (+6 µs) and binds p550's hardware record when it
arrives ~2.5 ms later; **(C)** both fire on their clocks (p550 under PM QoS or FIFO, +8 µs), p550's datagram reaches k3
~0.4 ms after the instant, and the hardware record follows in a second datagram. Only (A) keeps "caused by a hardware
event on another host" literally true. All p550 experiments were reverted; the host is in its 17:00 state.
