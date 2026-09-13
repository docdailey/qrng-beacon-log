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

**Cadence source (since 2026-09-13):** the hour is started by the **time host's clock, not by think's timer**.
`hosts/beacon-cadence.py` runs on p550 (PREEMPT_RT; `CLOCK_REALTIME` disciplined by chrony from the i210 PHC, which
`ts2phc` locks to the ZED-F9T PPS) as the confined `beacon` user. At **:00:00.000 UTC** it wakes with
`clock_nanosleep(TIMER_ABSTIME)`, reads the i210 PHC and `CLOCK_REALTIME`, signs a **cadence trigger** with the
`time_attester` key and delivers it to think over SSH with a key that can run exactly one forced command there
(`beacon-trigger.py`), which verifies the signature against `keys/KEYS.json` and starts `qrng-beacon.service`. The commit
embeds the signed trigger as `core.cadence.trigger`, and the target round is **the round released at the scheduled
instant + 100**, so the release lands at **:05:00 every hour** instead of drifting with think's start-up time.
`verify.py` checks the trigger's signature and that the target follows from the instant. If no trigger arrives, the
:02 timer runs the hour and the pulse says so (`core.cadence.source = "think-timer"`, `targeting = "drand-latest+lead"`);
one cycle per hour either way (`.cycle-hour`). The trigger records its own wake lateness (`wake.late_ns`, ~0.1–0.4 ms
measured on p550) and the PHC−REALTIME reading at the instant; think's receipt time and cycle start are recorded on
think's NTP clock as bookkeeping. What is attested is *which clock said the hour started*; the ordering claims of the
protocol are unchanged (GNSS anchor vs round release). Bill, 2026-09-13: *"think is not a precision machine. it should
start on a trigger from i210 exactly on the hour."*

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
| host | think (aggregator) | always-on home-LAN Linux; oscpro902 travels |
| cadence source | **p550's i210-disciplined clock**: signed trigger at :00:00.000 UTC, embedded in the commit | `beacon-cadence.service` on p550; `beacon-trigger.py` on think; `verify.py` cadence checks |
| release grid | **:05:00 UTC** every hour (round at the trigger instant + 100) | `pulse.py commit --trigger` targeting `scheduled-instant+lead` |
| fallback | think's timer at **:02:00**; the pulse says `cadence.source = "think-timer"` | `qrng-beacon.timer` `OnCalendar=*:02:00` |

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
