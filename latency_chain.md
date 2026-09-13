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
| **usable randomness** | the instant | the reveal pulse pushed | the lead (100 rounds = 300 s, a policy) + the relays' publication delay + the reveal chain |

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
- **Rekor:** the commit's external anchor is written by a CI workflow after the push, about 30 s after the instant (verified
  for 0092 and 0094: 33 s and 32 s). Anchoring from the aggregator at mint is the next step and is what would let the
  lead shrink below five minutes.
- **The lead:** time to usable randomness is dominated by the 100-round (300 s) lead. It is a policy setting; the floor in
  the code is 60 rounds, and with the chain at 1.5 s that floor is safe. It stays at five minutes until a day of live k3
  cycles has been observed.
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
