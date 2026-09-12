# PUBLICATION.md — how pulses leave disks we control, and what that buys

A commitment proves what it claims only if it was **published before** the round it names. Signing
is not publishing: a signature proves who, not when. So every pulse — and every commitment in
particular — must land somewhere outside our infrastructure, with a timestamp we did not write,
before its target round releases.

## What we do

**Public git repository: `https://github.com/docdailey/qrng-beacon-log`** (branch `main`).

- Every pulse is committed and pushed as soon as it is minted. For a `commit` pulse the push is
  the publication event; it MUST precede `commitment.target_release_utc`.
- The repo carries `verify.py`, `drand_anchor.py`, `keys/*.pub` and every `chain/pulse-NNNN.json`,
  so a stranger can verify without contacting us.
- First real instance: pulse **0010** (commit → drand round 32122604, release 23:59:39Z) was pushed
  at **23:58:57Z**; GitHub's own `committer.date` on that commit is **23:58:46Z**. Published 42 s
  before the round existed.

## Trust assumptions — stated, not hidden

| assumption | why it is acceptable | how to check it |
|---|---|---|
| GitHub records push/commit times honestly | third party with no stake in our randomness; its timestamps are visible to anyone via the API | `gh api repos/docdailey/qrng-beacon-log/commits/<sha>` → `commit.committer.date` |
| history is not rewritten | we *could* force-push; **any clone or mirror detects it** because the old commit hashes stop existing upstream | clone once, compare `git log` later; mirror the repo |
| the repo is what we say it is | it is under the same GitHub account that signs these notes, and the keys in `keys/` match those in every pulse | `--pin keys/` in `verify.py` |

**Weakest link, honestly:** GitHub commit timestamps are set by the *committer* (us) and merely
recorded by GitHub; the push event time is GitHub's own, but it is not exposed as durably. A
stronger, independent time-of-existence proof would be **OpenTimestamps** (free calendar servers,
anchored into the Bitcoin block chain — a timestamping protocol, not a trading position). Adding
it is one command per pulse (`ots stamp pulse.json`); it is **not installed and not decided** —
it needs Bill's call given the project's stance on anything crypto-adjacent.

## What publication does NOT do

- It does not make drand honest — that rests on the League of Entropy's threshold of independent
  operators.
- It does not stop us from **failing to reveal** a commit whose eventual value we dislike. The
  chain makes that *visible*: an unrevealed commit is a permanent hole, and `pulse.py reveal` refuses
  to skip. A consumer should treat any commit without a following reveal as a failed pulse and say so.
- It does not certify anything. See `CLAIMS.md`.
