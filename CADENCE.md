# CADENCE.md — schedule and non-reveal accountability — **ENABLED 2026-09-12 00:44:38 UTC on think**

Bill, 2026-09-12: *"It is not yet worth anyone using as a number. The next increment is an
independent timestamp on each commit, a stated cadence, and a second party who can verify a reveal
you failed to publish."*

## 1. Independent timestamp — SHIPPED
Every `commit` pulse is stamped at mint time by two RFC 3161 TSAs (freetsa.org, DigiCert) via
`beacon/tsa.py`; tokens live beside the pulse in `chain/` and in the public repo. A token taken at
commit proves the commitment predates its round with a third party's clock. Pulses 0010/0011 carry
**retroactive** tokens (labelled) — they prove existence before 2026-09-12 00:2x UTC, not pre-round.

## 2. Stated cadence — ENABLED
Running on **think** (192.168.71.34) as a systemd **user** service (`qrng-beacon.service`; until 2026-09-13 started by
`qrng-beacon.timer`, `OnCalendar=hourly`, `Persistent=true`, Linger on — since 2026-09-13 started by the **time host's
clock**, see "Cadence source" below; the timer remains at `*:02:00` as the fallback). Repo checkout `think:~/qrng-beacon`, pushing over a repo-scoped GitHub deploy
key (`think-beacon-cycle`, write access to this one repository only). First automated pair: **pulse 0012
(commit, pushed 269 s before round 32123484, two at-commit TSA tokens) → pulse 0013 (reveal, pushed 28 s
after release)**. **First UNATTENDED fire: 01:00:26 UTC 2026-09-12** (systemd `Result=success`, no human involved) → pulse 0014
(commit, pushed 273 s before round 32123921, two at-commit TSA tokens 01:00:55Z) → pulse 0015 (reveal, pushed
31 s after release). **v0.5 cut-over 2026-09-12 02:09–02:20 UTC** (timer paused, one supervised pair): pulse **0018** commit (E held on the entropy host,
four host-signed statements, two TSA tokens 02:13:48Z, pushed 224 s before round 32125363) → pulse **0019** reveal (anchored 7 s after
release, pushed 126 s after). First v0.5 pair verified as a stranger; watcher issued a pre-round COMMIT-RECEIPT at drand round 32125316.
**Review #3 cut-over 2026-09-12 02:31–02:57 UTC** (timer paused): host isolation deployed on all four hosts; pulse **0020/0021** =
first compliant, host-isolated pair; timer re-enabled 02:57:14Z. **First UNATTENDED host-isolated cycle: 03:00:26–03:06:53Z, systemd Result=success →
pulse 0022 (commit, 2 TSA 03:01:44Z, pushed 221 s before round 32126321) / 0023 (reveal); entropy host finalized.**
**05:00 UTC 2026-09-12: first cycle under the review-4 model** (recover-first, durable secret, execution enforcement from seq 26) → 0026/0027 clean.
Only think mints; `pulse.py` refuses on any host whose checkout has diverged from the published head (a checkout merely behind it fast-forwards — ERR-010).
**2026-09-13 12:26:57Z: one unscheduled pair (ERR-016)** — rewriting `qrng-beacon.timer` to the :02 fallback with `Persistent=true` made
systemd run a catch-up cycle at once → **0090/0091**, valid, `cadence.source = "think-timer"`, release 12:32:03Z, reveal pushed **15 s**
after the round (source-rate rings + concurrent statements; the previous 87 pairs took ~85 s).
**First cycle started by the time host's clock: 2026-09-13 13:00:00Z → 0092/0093.** p550 woke **113.6 µs** after the instant
(`wake.late_ns`), PHC−REALTIME 36 999 998 322 ns at wake (epoch_ok, ts2phc s2, +4 ns); think received the signed trigger **0.68 s**
after the instant and started the cycle at +0.80 s; `pulse.py commit` began at +4.7 s (git pull + recover); commit minted at
13:00:13Z and pushed **285 s before** the release; target release **13:05:00Z exactly** (`scheduled-instant+lead`); the reveal
began 1.29 s after the round, its GNSS anchor is 10 s after, pushed **15 s** after. `verify.py` passes all five cadence checks
on 0092. Next trigger armed for 14:00:00Z.

**2026-09-13 15:07Z: commit 0096 failed at the reveal (ERR-016 was the timer; this is ERR-017)** — think's 15:00 fallback cycle ran the new
reveal path, which crashed on a missing import; failure pulse **0097** was minted inside the window and the abandonment finalized.
**Aggregator moved to k3 (from pulse 0098, 2026-09-13 16:00Z).** think ran the cycle from 0012 to 0097. Bill, 2026-09-13:
*"we need to trigger on that pulse and switch to milkv from think. it has much tighter time and faster clock"* and *"we need to
do it without ssh obviously. signaling outside of auth."* k3 (Milk-V, RISC-V, `CLOCK_REALTIME` held by chrony to its PTP PHC at
~25 ns RMS, the PHC slaved to the P550-BMC grandmaster and continuously measured by the i210) now runs `beacon-cycle.py --at next`
as the `aggregator` user: a timer starts it at **:59:20**, it pulls, recovers, opens multiplexed SSH connections to the four role
hosts and a UDP listener, then sleeps to **:00:00.000 with `clock_nanosleep(TIMER_ABSTIME)`** and mints at once — nothing is
signaled to start the cycle, the clock is the trigger. The commit records the aggregator's own wake (`core.cadence.self_trigger`,
covered by the aggregator signature) and, when it arrives, the time host's signed trigger (`core.cadence.trigger`): p550 wakes on
the same instant, signs, and sends the statement three times as a **UDP datagram** — no session, no authentication handshake,
the Ed25519 signature is the authentication; measured 9 ms from the instant to the datagram on k3. drand's latest round is
fetched and BLS-verified **in parallel** with the entropy host and the statements (native blst, 0.02 s per round on k3;
pure-Python py_ecc took 4.7 s there), the reveal fetches and verifies the latest and the target rounds concurrently, and the
entropy host reveals while the clock hosts attest. think's aggregator key is retired at seq 97 in `keys/KEYS.json`; think keeps
the decisions mirror and stays a cold standby (RECOVERY.md 2f). The witness statement still comes from k3's confined `beacon`
user through the same forced command, now over loopback; aggregator and witness share a host but not a user — CLAIMS.md
states the caveat.

**The trigger is the hardware clock's own event (2026-09-13, Bill: "non-userspace. we know the time precisely.. we shouldn't
have to wait for system clock").** The i210 PHC registers its own PPS source on p550 (`/dev/pps1`): a kernel event at every
PHC second boundary, stamped by the interrupt handler. `hosts/beacon-cadence.py` now blocks in the kernel on that event
(`PPS_FETCH`) for the last second before the instant and fires when the event for the scheduled second arrives — no timer,
no clock arithmetic; the statement carries `hw_event` (the stamped edge, its sequence number, how long after the edge the
process ran: 40–150 µs measured). The clock path (`clock_nanosleep` + spin) remains only as a fallback if the event stream
is silent for 50 ms past the instant, and the statement says which one fired. On k3 the aggregator waits at the instant for
that hardware-originated datagram and starts on it when it arrives within 5 ms (`self_trigger.start_source = "hw-datagram"`,
~1 ms after the pulse across the LAN); otherwise it starts on its clock (`"clock"`). The remaining network hop goes away
with a wire: the i210's free periodic-output pin (SDP2, `n_per_out 2`) programmed to pulse at the instant, into a k3 GPIO
read through the gpio character device with edge timestamps — then k3 wakes on the physical pulse the PHC generated.

**Staging measurements before the cutover (2026-09-13, throwaway clone on k3, real hosts, commit only, secret retired afterwards).**
Run 1 (SSH multiplexed to the hosts): k3 woke 6.8 µs after the instant, p550's datagram arrived 8.7 ms after it, entropy
statement +0.92 s, gnss +1.47 s, witness +1.61 s, time +1.93 s, commit pushed **+2.9 s**. Run 2 (beacon-agentd, in-process
host scripts): woke 5.5 µs late, datagram +7.1 ms, entropy +0.49 s, gnss +0.76 s, witness +0.84 s, time +0.93 s, TSA tokens
at +1 s, commit pushed **+2.0 s** — against 14.8 s for think's 13:00 cycle the same morning. Every statement said
`execution.via = agentd` and verified against the pinned daemon hash; both cadence records named the same instant.
Runs 3–5 added the hardware trigger and k3 starting on its datagram; run 3 exposed a 5.3 s DNS stall in `chronyc sources`
(fixed with `-n`) and runs 3–4 a 4 s join on the slowest drand relay (fixed). **Run 5:** i210 second event stamped +23 µs,
p550 awake +72 µs, datagram on k3 +1.7 ms, k3 started on it at +9.5 ms (signature check before the start; the next
trim), statements in by +0.67 s, TSA tokens within the same second, **commit pushed +1.2 s after the instant**.

**Cadence source (since 2026-09-13 13:00Z, pulses 0092–0095 — think era):** the hour is started by the **time host's clock, not by think's timer**.
`hosts/beacon-cadence.py` runs on p550 (PREEMPT_RT; `CLOCK_REALTIME` disciplined by chrony from the i210 PHC, which
`ts2phc` locks to the ZED-F9T PPS) as the confined `beacon` user. At **:00:00.000 UTC** it wakes with
`clock_nanosleep(TIMER_ABSTIME)`, reads the i210 PHC and `CLOCK_REALTIME`, signs a **cadence trigger** with the
`time_attester` key and delivers it to think over SSH with a key that can run exactly one forced command there
(`beacon-trigger.py`, removed at the k3 cutover), which verified the signature against `keys/KEYS.json` and started `qrng-beacon.service`. The commit
embeds the signed trigger as `core.cadence.trigger`, and the target round is **the round released at the scheduled
instant + 100**, so the release lands at **:05:00 every hour** instead of drifting with think's start-up time.
`verify.py` checks the trigger's signature and that the target follows from the instant. If no trigger arrives, the
:02 timer runs the hour and the pulse says so (`core.cadence.source = "think-timer"`, `targeting = "drand-latest+lead"`);
one cycle per hour either way (`.cycle-hour`). The trigger records its own wake lateness (`wake.late_ns`, ~0.1–0.4 ms
measured on p550) and the PHC−REALTIME reading at the instant; think's receipt time and cycle start are recorded on
think's NTP clock as bookkeeping. What is attested is *which clock said the hour started*; the ordering claims of the
protocol are unchanged (GNSS anchor vs round release). Bill, 2026-09-13: *"think is not a precision machine. it should
start on a trigger from i210 exactly on the hour."*

**The before/after tables with every step, and the floors that remain, are in `latency_chain.md`.**

**Latency experiments, 2026-09-13 (Bill: "if anyone is going to take the timing aspect seriously we need a fast chain").**
Measured from k3 unless stated; each row is a method tried, what it cost, and what was adopted.

| step | method tried | measured | adopted |
|---|---|---|---|
| wake at the instant | `clock_nanosleep(TIMER_ABSTIME)` | 90–150 µs late (k3), 110–460 µs (p550) | sleep to T−1.5 ms then spin on the clock: **1–5 µs** |
| time host → aggregator trigger | SSH forced command | 0.5–0.7 s after the instant | **signed UDP datagram**: 9 ms after the instant (first copy), three copies 20 ms apart; ARP pre-warmed |
| aggregator → role hosts | SSH cold / multiplexed | 0.4–2.0 s cold (post-quantum KEX 1.4 s of it to protectli), 0.07–0.2 s warm | **beacon-agentd**: signed request over TCP, **7–9 ms** to the allow-list; host scripts imported once, run in-process |
| drand fetch | api / api2 / api3 / cloudflare, cold | 0.24 / 0.57 / 0.91 s / 403 (default UA) | race all relays; keep-alive GET 16–46 ms |
| drand round availability | poll every 25 ms from release | relays serve round N **1.13–1.38 s after its release**, order varies | pre-open connections, poll from release+1.0 s every 20 ms, first answer wins, handed to `pulse.py reveal --drand` |
| BLS verification | py_ecc (pure Python) | 2.2 s (think, x86), **4.7 s (k3, RISC-V)** | **blst** native via ctypes: **0.02 s**; same negative tests fail correctly |
| drand in the commit | fetch+verify before anything else | on the critical path | fetched and verified **in a thread** while the entropy host commits and the hosts attest |
| TSA (two tokens) | sequential | 0.41 s | concurrent: ~0.25 s |
| git push to GitHub | fresh SSH each push | 0.81 s negotiation | `ControlMaster` to github.com: 0.35 s |
| interpreter start | `python3 pulse.py` per phase | 0.04 s + 0.20 s imports | kept (subprocess boundary is worth the 0.25 s); candidate for in-process later |
| Rekor anchor | CI workflow after the push | 18 s after the push | unchanged for now; anchoring from the aggregator at mint is the next step and would allow a 3-minute lead |
| probe's chrony calls | `chronyc sources` (resolves source names) | **5.3 s stall on p550 and k3 at the same instant** in staging run 3 (a resolver timeout) | `chronyc -n` everywhere (probe and logger); the probe never touches DNS |
| the trigger's wake | `clock_nanosleep` + spin on the system clock | 5–7 µs late, but decided by the system clock | **blocked in the kernel on the i210 PHC's own second event** (`/dev/pps1`): edge stamped 21–30 µs after the boundary, process runs 0.1–0.8 ms after the stamp; the clock path is the fallback |
| signing the trigger | `sign_statement` re-reading the PEM key | 8–143 ms on first use | key preloaded and one warm-up signature before the instant: ~1 ms |

**ZeroMQ benchmark (2026-09-13, `bench/m2m_bench.py`, client on k3, 150 calls, a 700 B Ed25519-signed request and a
6 000 B signed response, verification on both ends — the same work on every transport; round trip, ms):**

| host | our TCP, connection per call (today) | our TCP, persistent | ZMQ REQ/REP persistent | ZMQ REQ per call | CurveZMQ persistent | CurveZMQ per call |
|---|---|---|---|---|---|---|
| p550 | 2.97 | 1.95 | 2.03 | 3.45 | 2.19 | 7.61 |
| f9t | 1.70 | 1.37 | 1.40 | 2.12 | 1.50 | 5.35 |
| protectli | 10.2 | 6.6 | 8.1 | 19.8 | 9.0 | 40.0 |
| k3 (loopback) | 1.37 | 1.17 | 1.19 | 1.38 | 1.34 | 3.81 |

One-way p550 → k3, 1.9 KB, synchronised clocks: raw UDP **244 µs** median (p90 260), ZeroMQ PUB/SUB 300 µs (p90 325, max 1.5 ms).
Reading: a persistent ZeroMQ REQ/REP socket equals a persistent plain TCP connection to within 0.1 ms; ZeroMQ's own
connect-per-call is slower than ours; CurveZMQ costs 0.15–0.4 ms per call on a warm socket and 4–7 ms cold, for
encryption the protocol does not need (statements are public; the one secret is sealed at the application layer). The
floor everywhere is Ed25519 + JSON in Python, not the socket. **Decision: keep beacon-agentd's plain TCP; keep raw UDP
for the trigger; no ZeroMQ dependency.** A pre-opened persistent connection to each daemon would save ~1 ms per call —
noted, not worth a protocol change today. protectli's numbers are its Celeron J3160, not the network.

**Reveal latency (2026-09-13):** the reveal used to be pushed ~85 s after the round because the aggregator polled drand
every 3 s and then queried the three attest hosts one after another, each sampling its clock live for 12–35 s. Now the
hosts log their clock evidence at source rate (`hosts/clocklog.py` → `/run/beacon-clocklog` rings + the timehat DB), a
statement summarises the trailing 60 s of that log in milliseconds, the aggregator gathers the three statements
concurrently, and it sleeps to the known release instant before confirming the round with drand. Same evidence, same
checks, same limits (`notbefore/timing/v1`); the window is now stated per statement (`window_s`, `ring_used`).

| parameter | value | enforced by |
|---|---|---|

| parameter | proposed | why |
|---|---|---|
| period | **1 commit/reveal pair per hour**, on the hour | `qrng-beacon.timer` |
| lead | **100 rounds = 5 min** | `beacon-cycle.py LEAD` |
| publish deadline | commit pushed + TSA-stamped **≥ 2 min before** target release | `PUBLISH_MARGIN_S`; breach → `pulse-NNNN.FAILED.json` pushed |
| reveal deadline | reveal pushed **≤ 10 min after** target release | `REVEAL_DEADLINE_S`; breach → FAILED marker pushed; watcher attests |
| host | **k3** (aggregator, from 0098); think 0012–0097 | k3: PTP-disciplined clock, 8-core RISC-V, always on; think keeps the decisions mirror |
| cadence source | **the aggregator's own PHC-disciplined clock** (`clock_nanosleep` to :00:00.000; `core.cadence.self_trigger`) **plus p550's signed trigger by UDP** (`core.cadence.trigger`) | `systemd/aggregator/qrng-beacon.timer` (:59:20) → `beacon-cycle.py --at next`; `beacon-cadence.service` on p550; `verify.py` cadence checks |
| release grid | **:05:00 UTC** every hour (round at the instant + 100) | `pulse.py commit --self-trigger/--trigger-dir`, targeting `scheduled-instant+lead` |
| fallback | k3's timer at **:02:00** runs the plain path; the pulse says `cadence.source = "k3-timer"` | `systemd/aggregator/qrng-beacon-fallback.timer` |

Operational notes: **outages and recovery are in `RECOVERY.md`** (planned-pause checklist, `pulse.py preflight`). `think:~/qrng-beacon/cycle.log` is the local record; failures are also public as
`FAILED.json` markers. To stop: `systemctl --user disable --now qrng-beacon.timer` on think. A stopped
cadence leaves no hole — holes only come from a commit without a reveal. **Since 2026-09-12 (v0.5.1) a cycle that
RUNS but cannot commit mints a signed `skip` pulse naming the refusing dependency; only a deliberately stopped timer is
silent, which is why a planned pause is announced here first (`RECOVERY.md` §3).**

## 3. Second party for non-reveal — watcher SHIPPED, operator = Grok (pending its repo/key)
The chain makes a skipped reveal *visible*; it does not make it *attested*. The design:

- A **watcher** polls the public repo and drand. For every `commit` whose
  `target_release + reveal_deadline` has passed with no matching `reveal`, it publishes a signed
  **NON-REVEAL** record (commit hash, target round, deadline, observed time) to a place we do not
  control — its own repo, with its own key.
- The watcher script will be public, so *anyone* can run it. Independence is about who actually does.
- **Proposed first watcher: Grok Bot (claude-runner).** Different vendor, different control plane,
  already runs polling routines. Not fully independent (same sponsor) — honest label: "second
  system, same sponsor". A genuinely independent third party is the step after.

`watcher.py` is public in the repo and needs no access to our systems. Once Grok publishes its watcher
repo URL and key id, they are pinned in the README as the designated watcher ("second system, same
sponsor"). Until an unrelated third party also runs it, the honest description remains: **an attested-log
prototype and a timing thesis, verifiable by anyone, with a stated cadence and a same-sponsor auditor —
not yet a number to build on.**
