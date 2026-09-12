# CADENCE.md — proposed schedule and non-reveal accountability (PROPOSED, NOT ENABLED)

Bill, 2026-09-12: *"It is not yet worth anyone using as a number. The next increment is an
independent timestamp on each commit, a stated cadence, and a second party who can verify a reveal
you failed to publish."*

## 1. Independent timestamp — SHIPPED
Every `commit` pulse is stamped at mint time by two RFC 3161 TSAs (freetsa.org, DigiCert) via
`beacon/tsa.py`; tokens live beside the pulse in `chain/` and in the public repo. A token taken at
commit proves the commitment predates its round with a third party's clock. Pulses 0010/0011 carry
**retroactive** tokens (labelled) — they prove existence before 2026-09-12 00:2x UTC, not pre-round.

## 2. Stated cadence — needs a decision
Proposed, cheapest honest version:

| parameter | proposed | why |
|---|---|---|
| period | **1 commit/reveal pair per hour**, on the hour | slow enough to watch by hand at first; fast enough to be a real log |
| lead | **100 rounds = 5 min** | leaves time to TSA-stamp and push before the round |
| publish deadline | commit pushed + TSA-stamped **≥ 2 min before** target release | measurable; a late push is a failed commit |
| reveal deadline | reveal pushed **≤ 10 min after** target release | after that the pulse is FAILED, permanently |
| host | a fleet Linux box (ryzen or think), systemd timer, `git push` inside the unit | oscpro902 travels; the loop must not |

**Not enabled** because it pushes to a public repository unattended on your account. Say the word
and which host, and it runs.

## 3. Second party for non-reveal — needs a person or an agent
The chain makes a skipped reveal *visible*; it does not make it *attested*. The design:

- A **watcher** polls the public repo and drand. For every `commit` whose
  `target_release + reveal_deadline` has passed with no matching `reveal`, it publishes a signed
  **NON-REVEAL** record (commit hash, target round, deadline, observed time) to a place we do not
  control — its own repo, with its own key.
- The watcher script will be public, so *anyone* can run it. Independence is about who actually does.
- **Proposed first watcher: Grok Bot (claude-runner).** Different vendor, different control plane,
  already runs polling routines. Not fully independent (same sponsor) — honest label: "second
  system, same sponsor". A genuinely independent third party is the step after.

Until 2 and 3 exist, the honest description of this log is: **an attested-log prototype and a timing
thesis, verifiable by anyone, used as a number by no one.**
