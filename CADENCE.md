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
Running on **think** (192.168.71.34) as a systemd **user** timer (`qrng-beacon.timer`, `OnCalendar=hourly`,
`Persistent=true`, Linger on). Repo checkout `think:~/qrng-beacon`, pushing over a repo-scoped GitHub deploy
key (`think-beacon-cycle`, write access to this one repository only). First automated pair: **pulse 0012
(commit, pushed 269 s before round 32123484, two at-commit TSA tokens) → pulse 0013 (reveal, pushed 28 s
after release)**. **First UNATTENDED fire: 01:00:26 UTC 2026-09-12** (systemd `Result=success`, no human involved) → pulse 0014
(commit, pushed 273 s before round 32123921, two at-commit TSA tokens 01:00:55Z) → pulse 0015 (reveal, pushed
31 s after release). **v0.5 cut-over 2026-09-12 02:09–02:20 UTC** (timer paused, one supervised pair): pulse **0018** commit (E held on the entropy host,
four host-signed statements, two TSA tokens 02:13:48Z, pushed 224 s before round 32125363) → pulse **0019** reveal (anchored 7 s after
release, pushed 126 s after). First v0.5 pair verified as a stranger; watcher issued a pre-round COMMIT-RECEIPT at drand round 32125316.
**Review #3 cut-over 2026-09-12 02:31–02:57 UTC** (timer paused): host isolation deployed on all four hosts; pulse **0020/0021** =
first compliant, host-isolated pair; timer re-enabled 02:57:14Z; 03:00Z = first unattended isolated cycle.
Only think mints; `pulse.py` refuses on any host whose checkout is not the published head.

| parameter | value | enforced by |
|---|---|---|

| parameter | proposed | why |
|---|---|---|
| period | **1 commit/reveal pair per hour**, on the hour | `qrng-beacon.timer` |
| lead | **100 rounds = 5 min** | `beacon-cycle.py LEAD` |
| publish deadline | commit pushed + TSA-stamped **≥ 2 min before** target release | `PUBLISH_MARGIN_S`; breach → `pulse-NNNN.FAILED.json` pushed |
| reveal deadline | reveal pushed **≤ 10 min after** target release | `REVEAL_DEADLINE_S`; breach → FAILED marker pushed; watcher attests |
| host | think | always-on home-LAN Linux; oscpro902 travels |

Operational notes: `think:~/qrng-beacon/cycle.log` is the local record; failures are also public as
`FAILED.json` markers. To stop: `systemctl --user disable --now qrng-beacon.timer` on think. A stopped
cadence leaves no hole — holes only come from a commit without a reveal.

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
