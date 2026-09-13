# RECOVERY.md — what happens to the chain when things go down, and how it comes back

Written 2026-09-12 from the code paths in `pulse.py`, `beacon-cycle.py`, `hosts/entropy_host.py` and the probes, not
from intent. Every claim below names the line of behaviour it rests on. The one-command readiness check is
**`python3 pulse.py preflight`** on think (added 2026-09-12): it mints nothing and tells you whether a commit
would be accepted right now, and if not, which dependency is the reason.

## 1. What a cycle needs (the critical path)

| dependency | needed for | if it is missing |
|---|---|---|
| **think** (aggregator, timer, deploy key) | everything | nothing happens; on return the timer fires immediately (`Persistent=true`) and `recover` derives the state from the published chain |
| **Internet**: drand API, GitHub, freetsa + DigiCert | commit, reveal, failure | commit: `drand_verified()` dies → nothing minted. **Fewer than 2 TSA tokens → the commit is deleted before it is written** (`seal()`); a single TSA outage stops commits |
| **protectli** (Quantis + entropy host) | commit, reveal, **failure** | no commit; a pending commit cannot be resolved until it is back (§2c) |
| **f9t** (GNSS probe) **+ timehat DB on nas1** (`qerr_stream`, `rawx_stream`, fresh f9t rows) | commit, reveal | `collect()` dies → commit refused (nothing written) / reveal refused (signed failure) |
| **p550** (time: chrony selects IPHC, PHC − REALTIME = +37 s ± 0.5 s) | commit, reveal | same; unhealthy = `epoch_ok`/`chrony_selects_refclock` false or `ALERT` (`stamp_probe.py` epoch guard) |
| **k3** (witness: chrony selects PHC, epoch ok) | commit, reveal | same |
| fleet switch / P550-BMC GM | keep k3 and f9t disciplined | not needed instantly — chrony keeps selecting the PHC for a while — but the epoch guard trips as soon as a PHC drifts or its epoch is wiped |
| nas1 (DB) | GNSS statement only | the beacon's only dependency on nas1; a DB outage stops commits with the same "refused" signature as a bench outage |

The **timing bench** = f9t, p550, k3, the switch, the BMC. **The failure pulse does not need the bench**: `cmd_fail`
needs protectli + think + Internet, and collects gnss/time/witness only if they answer (`try/except` per host).

Since 2026-09-13 the aggregator reaches the role hosts through **`beacon-agentd`** (signed requests over TCP 5520, `hosts/agentd.py`),
not SSH; a host whose daemon is down is a host that cannot attest, exactly as an unreachable sshd was. `systemctl status beacon-agentd`
on the host; its journal names every refused request. The SSH forced-command lines remain during the transition.

## 2. What the chain looks like, by scenario

### 2a. Bench down when the hour starts → **a signed `skip` pulse (since v0.5.1); before 2026-09-12 15:xx UTC, a silent gap**
`cmd_commit` asks protectli for a commitment, then `collect()` SSHes f9t/p550/k3. An unreachable or unhealthy host
raises → `rollback()` tells protectli `abandon-prepare <seq> 000…0` + `finalize`, then `die("commit aborted before
anything was written")`. `beacon-cycle` logs `commit refused: …` and exits. Every hour, the same. Artifacts:

- **chain (v0.5.1):** `pulse-N.json` `type: skip`, `derived.reason` = the refusal text, `derived.refused_by` = the dependency
  class, aggregator-signed, RFC 3161 tokens when a TSA answered. One per refused cycle. CI verifies it (state machine
  `{reveal,failure,skip,legacy} → skip`); the watcher ignores it; `notbefore` treats it as ineligible. `cycle.log` keeps the
  full refusal text. (Before v0.5.1 the same situation left no public trace at all.)
- **protectli:** `pending/<next-seq>.abandoned` with `resolved_by_pulse_hash = 000…0` — a fresh E drawn and abandoned
  per attempt, never published (the all-zero resolver is what lets that seq be reused; ERR-008 guard).
- **hosts:** `~beacon/state.json` `commit` advanced to the next seq (allowed; it is the seq the real commit will use).

A *stopped timer* still leaves nothing (`CADENCE.md`: "a stopped cadence leaves no hole"): announce planned pauses first (§3).

### 2b. Bench dies between commit (:01) and reveal (:06) → **commit N + signed failure N+1**
`cmd_reveal` → `collect()` raises → `beacon-cycle.fail(seq, "reveal-refused", {...})` → `pulse.py fail` →
protectli signs an abandonment bound to the commit pulse hash, the bench hosts are asked and skipped if silent, the
aggregator seals a `failure` pulse, pushes it, finalizes (E overwritten). Same cycle, a few minutes late. Artifacts:

- **chain:** `pulse-N.json` (commit, two TSA tokens) then `pulse-N+1.json` `type: failure`, `derived.reason =
  "reveal-refused {...}"`, `derived.commit_pulse_hash` = N's hash, entropy statement present, gnss/time/witness
  present only if they answered. CI: state machine commit → failure is legal, green. Watcher: no NON-REVEAL (the
  commit is resolved). `notbefore verify N+1` → *not a reveal* → ineligible; the next hour's reveal is the alternate.
- the next commit is N+2 — **parity flips** (this is why the spec keys on `type`, not odd/even).

### 2c. Bench **and** protectli (or Internet) down after a commit → **unresolved commit until they return**
`fail()` cannot mint (`could not mint failure pulse`). The commit stays the chain head. After
`release + 600 s`: CI **FAILS** with *"reveal deadline passed with neither a reveal nor a signed failure pulse
(withheld reveal)"*, the watcher records **NON-REVEAL**. Every following hour: `recover` → rc 3 → *resuming
unresolved commit* → window passed → `fail(seq, "reveal-window-missed")` → retried. **It heals itself** the first
hour protectli + Internet are back: a `failure` pulse bound to the original commit lands, CI returns to green with
the NON-REVEAL now explained. The secret sits durable on protectli as `<seq>.secret`/`.revealing` meanwhile.

### 2d. think down (or crashed mid-cycle) → **pause; then exactly 2b/2c on return**
`Persistent=true` fires the timer on boot. `recover` reads the published chain and protectli's `pending`: a head
commit is resumed (reveal if still inside the window, else failure); leftovers above the head are aborted unpublished;
a `.revealing` below the head is finalized against its published resolver. The one case needing a human is printed as
**`UNRESOLVED leftover … needs operator attention`**: a prepared reveal/abandonment whose resolving pulse is not in
the published chain — read `cycle.log`, find whether the pulse was minted but not pushed (`git status` in
`~/qrng-beacon`), push it if so, else `pulse.py fail`.

### 2d'. The tick-started cycle does not run (prepare failed, k3 rebooted at :59) → **k3's :02 fallback runs the hour**; if p550's UDP trigger does not arrive → **the pulse carries the aggregator's wake record only**
Since 2026-09-13 the hour is normally started by p550's signed trigger at :00:00 (CADENCE.md §2 "Cadence source"). If it
does not arrive, `qrng-beacon.timer` (`OnCalendar=*:02:00`) starts the same service two minutes later; the commit then
targets drand-latest + lead (release ≈ :07 instead of :05) and says `cadence.source = "think-timer"`. Nothing is
skipped and nothing is hidden: the absence of a trigger is visible in the pulse. (If p550 itself is down, the commit is
refused anyway — the time statement is REQUIRED — and the hour becomes a `skip` pulse as in 2a.) Diagnose with
`journalctl -u beacon-cadence` on p550 and `~/qrng-beacon/trigger.log` on think.

### 2f. k3 (the aggregator since 0096) is down → **no cycle; fail back to think deliberately**
think is a cold standby: its checkout, deploy key and checkpoint-key copy remain, its timers are disabled, and its aggregator
key is **retired in `keys/KEYS.json` at seq 95**. To fail back: append a new validity window for think's key (or a new key) in
`KEYS.json` from the next seq, commit and push that first, then `systemctl --user enable --now qrng-beacon.timer` on think
(fallback path; it has no tick-start). That is a public act by design — a key that could silently mint from two hosts would be
a weaker log. When k3 returns, retire think's window again before re-enabling k3's timers. Never let both timers be enabled.

### 2e. Someone pushes to `main` while a cycle runs → **handled (since ERR-010)**
The cycle fast-forwards when it is merely behind, and a rejected push is rebased and retried. Before 2026-09-12 16:09
UTC this refused the reveal (ERR-010). Still avoid pushing during :00–:07 when you can — a rebase in the reveal path
is a retry, not a guarantee.

## 3. Planned outage (antenna move, bench power, switch work) — checklist

1. **Pick the window.** Never start between **:00 and :07** (a cycle is in flight). Best: **:08–:50**.
2. **Pause the timer on think:** `systemctl --user stop qrng-beacon.timer` (leave it enabled; `stop` suffices).
   Confirm no cycle is running: `pgrep -af "[b]eacon-cycle"` → nothing.
3. **Confirm a clean head:** `python3 pulse.py status` → head type `reveal` or `failure`, `entropy host pending: []`.
4. **Announce** — append to `CADENCE.md`: `PAUSED <UTC> (planned: <why>); expected resume <UTC>`; push
   (safe: the timer is stopped). This is the only way a reader can tell a planned pause from an outage (§5).
5. Do the work.
6. **Bring the bench up in this order** and wait for each to settle:
   1. switch (PTP TC), then **P550-BMC** (GM; `ptptgt 900` is RAM-only and is re-asserted by `bmc-tai-seed` at
      boot+120 s — do not rush this step);
   2. **f9t**: F9T fix + TP1 active, `qerr-f9t` streaming (Sipeed wedge self-heals; give it 3 min), `ptp4l-bmc` rms
      < 100 ns, `chronyc sources` shows `#* PTP`;
   3. **p550**: `/run/ts2phc-f9t.status` offset within ±50 ns `s2`, `chronyc sources` `#* IPHC`, PHC − REALTIME =
      +37.0 s (a link bounce wipes the i210 epoch — notebook 220 — `ts2phc-f9t`'s `ExecStartPre` re-seeds it after
      `chronyc waitsync`; if chrony has no date source yet, it waits);
   4. **k3**: `ptp4l-bmc` locked, `chronyc sources` `#* PHC`;
   5. **nas1 DB reachable from f9t** and `qerr_stream` receiving f9t rows (`SELECT MAX(ts) … WHERE src='f9t'`).
7. **`python3 pulse.py preflight`** on think until every row is `OK`. Expected when healthy:
   ```
   [OK  ] git           checkout equals origin/main
   [OK  ] chain head    seq 45 type reveal
   [OK  ] drand         round 32140103 BLS-verified under the pinned group key
   [OK  ] entropy       protectli reachable; pending []
   [OK  ] gnss          f9t: anchor epoch 3 s old (qErr -2.959 ns); needs f9t logger + timehat DB fresh
   [OK  ] time          p550: epoch_ok=True chrony_selects_IPHC=True
   [OK  ] witness       k3: epoch_ok=True chrony_selects_PHC=True
   [OK  ] tsa           2/2 tokens (freetsa, digicert); a commit needs 2
   PREFLIGHT READY
   ```
   A `FAIL` row names the dependency; a `REFUSING TO MINT:` line above it carries the host's own reason.
8. **One supervised cycle:** `cd ~/qrng-beacon && python3 beacon-cycle.py` (works at any minute; ~6 min). Read
   `cycle.log`: `committed … tsa=[…]`, `commit pushed ≥120 s before release`, `revealed …`, `finalize`, `cycle complete`.
9. **Resume:** `systemctl --user start qrng-beacon.timer`; `systemctl --user list-timers qrng-beacon.timer`.
10. **Record:** amend the `CADENCE.md` line with the actual resume time and the seq gap; ledger row.

## 4. Unplanned outage — what to do when you notice

1. **Do nothing to the chain by hand.** The cycle is designed to converge (§2). Read first:
   `tail -40 think:~/qrng-beacon/cycle.log` and `python3 pulse.py recover` (idempotent, prints what it did).
2. If the head is an **unresolved commit** older than its window and protectli is up, the next cycle mints the
   failure; to do it now: `python3 beacon-cycle.py` (it resumes and fails it).
3. Bring the bench back per §3.6, then `preflight`, then let the timer run. A commit refused for health is not an
   error to fix in the beacon; it is the bench telling you it is not ready.
4. **Never** edit `~beacon/state.json` on a host or delete `pending/` records to "unstick" anything: the seq guards
   are the equivocation defence (ERR-008). The only sanctioned reset is after a *test* seq above the live head, done
   as root, with the reason written into ERRATA.
5. Afterwards: ERRATA/notice entry with the `cycle.log` excerpt, the seq range affected, and the cause.

## 5. Known gaps (honest)

- ~~**Silent gaps.**~~ Fixed 2026-09-12 (v0.5.1): a refused commit mints a signed `skip` pulse carrying the refusing
  dependency. What remains silent is a deliberately stopped timer — announce planned pauses in `CADENCE.md` first. A skip
  is the operator's own claim about *why*; only *when* is third-party-timestamped.
- **One TSA outage stops commits** (`MIN_TSA_TOKENS = 2` of 2 configured). Adding a third TSA makes the quorum 2-of-3.
- **nas1 is in the critical path** through the GNSS statement.
- **No drill has produced a failure pulse yet** (`failure_pulses 0`). §2b/2c are read from the code and the review-4
  recovery tests, not from a live event. A deliberate drill — block one bench host for one cycle in a pre-announced
  window — would cost one hour's value and buy the first real `failure` pulse in the log. Bill's call.
- Housekeeping: protectli holds three test records `0997–0999.abandoned` from the 02:01–02:47 cut-over, in the old
  format with E in clear; never published, harmless, but they should be removed (as root, noted in the ledger).

## 6. Checkpoints (TLOG.md) — failure modes

- The aggregator signs `checkpoint` + `checkpoints/NNNNNN` inside `publish()`; a signing failure **never blocks** the
  pulse (logged as `checkpoint NOT written`) and CI turns red with *"checkpoint size N != M published pulses"* until the
  next successful publish covers everything. That red is correct: readers must be able to see when a head lagged.
- `publish-checkpoint` refuses to sign a head that is not an append-only extension of the last published checkpoint
  (fork) or a chain shorter than it (rollback). If it refuses, do not "fix" the checkpoints directory — read
  `cycle.log`, compare `checkpoints/` with `git log`, and write ERRATA; a refusal here is the tlog doing its job.
- `~/beacon/checkpoint.key` on think is the log's identity key. Losing it means a new key under the same origin (clients
  and witnesses pin the key: rotation is a documented event, not a silent swap). Back it up with the anchor key.

