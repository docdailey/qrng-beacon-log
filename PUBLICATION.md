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

## How pulses get there now (since 2026-09-12)

The hourly cycle on **think** pushes with a **repo-scoped deploy key** (`think-beacon-cycle`, write access
to this repository only — not an account token). Every commit pulse is **RFC 3161-stamped at mint time by
two TSAs** (freetsa.org, DigiCert) before the push, so the third-party time evidence no longer depends on
GitHub at all; GitHub's committer date is now corroboration. First at-commit-stamped pulse: 0012
(tokens 00:39:08Z, round released 00:43:39Z).

## Trust assumptions — stated, not hidden

| assumption | why it is acceptable | how to check it |
|---|---|---|
| GitHub records push/commit times honestly | third party with no stake in our randomness; its timestamps are visible to anyone via the API | `gh api repos/docdailey/qrng-beacon-log/commits/<sha>` → `commit.committer.date` |
| history is not rewritten | we *could* force-push; **any clone or mirror detects it** because the old commit hashes stop existing upstream | clone once, compare `git log` later; mirror the repo |
| the repo is what we say it is | it is under the same GitHub account that signs these notes, and the keys in `keys/` match those in every pulse | `--pin keys/` in `verify.py` |

**Weakest link, honestly (as written 2026-09-12 morning):** GitHub commit timestamps are set by the committer
(us). This was answered the same day by the RFC 3161 tokens below and by the publication anchors further below;
OpenTimestamps, flagged here as "not decided", was decided by Bill on 2026-09-12 ("go on all") once it was clear
that it is a timestamping protocol and nothing else.

## Independent timestamps — RFC 3161 (added 2026-09-12)

Each commit pulse is stamped at mint time by **two public Time-Stamping Authorities** (freetsa.org and
DigiCert) using `openssl ts` — a standards-track notary protocol, not a blockchain, so it sidesteps the
OpenTimestamps question. The token is a third party's signed statement that the pulse's SHA-256 existed
at time T; `tsa.py verify` checks the digest and the TSA's certificate chain. Two operators mean no
single party, including us, can move T. This replaces GitHub's committer date as the primary evidence
that a commitment predates its round. Tokens for pulses 0010/0011 are **retroactive** and labelled.

## What RFC 3161 does and does not prove

A token proves the stamped bytes **existed** at time T. It does **not** prove they were *published*, nor that
they were the *only* candidate: an operator could stamp several commitments before the round and publish
the favourable one afterward. GitHub's `committer.date` is supplied by the committer, not an independent
push time. Therefore: **the published commitment has third-party proof of pre-round existence; durable proof
that this was the uniquely public commitment depends on a third party observing or mirroring the repository
before the round.** That is what a watcher's pre-round COMMIT-RECEIPT provides.

## What publication does NOT do

- It does not make drand honest — that rests on the League of Entropy's threshold of independent
  operators.
- It does not stop us from **failing to reveal** a commit whose eventual value we dislike. The
  chain makes that *visible*: an unrevealed commit is a permanent hole, and `pulse.py reveal` refuses
  to skip. A consumer should treat any commit without a following reveal as a failed pulse and say so.
- It does not certify anything. See `CLAIMS.md`.

## Publication anchors — Rekor + OpenTimestamps (added 2026-09-12)

**The problem they answer.** A single-writer log can be forked by its writer in real time and shown selectively
(a *split view*). Publication on GitHub does not settle this: we control the account. What settles it is an
append-only record we do **not** control, in which every pulse we publish is entered under a pinned key, and which
anyone can enumerate.

| anchor | what is entered | who runs it | what it proves | how to check |
|---|---|---|---|---|
| **Rekor** (`rekor.sigstore.dev`) | `hashedrekord`: sha256 of the canonical anchor statement, our signature, `keys/anchor.pub` | Sigstore / OpenSSF (Linux Foundation) | the statement existed at Rekor's `integratedTime`; it is in a Merkle log whose checkpoints Rekor signs; every entry under our key is listable | `ci/verify_anchors.py` verifies SET + inclusion proof + checkpoint offline against `keys/rekor.pub`; `REFETCH=1` re-fetches live and enumerates the key |
| **OpenTimestamps** | the same digest, via four free calendar servers | independent calendar operators; final proof is a Merkle path into a **Bitcoin block header** | the digest existed before that block's time | `ots verify` against your own node, or `verify_anchors.py`, which checks the Merkle root against public header sources |

**Trust assumptions, stated.** Rekor is honest and available (it is a single organisation's log, though publicly
monitored); the block-header sources (`blockstream.info`, `mempool.space`) return true headers — anyone who doubts
that runs a node; the anchor private key lives in a GitHub Actions secret, so a compromise of our GitHub account
could forge *anchors* — but not pulses, and a forged anchor that matches no published pulse is exactly what the
split-view check flags.

**Timing.** The anchor workflow runs on each push, so a commit reaches Rekor a minute or two after it is pushed —
before its drand release. That makes Rekor a **third independent clock** on each commit (after freetsa and
DigiCert). It is downstream of minting: anchoring failure never blocks a pulse; it shows up in CI as a missing anchor.

**Retroactive.** Pulses 0001–0041 were anchored on 2026-09-12 12:47 UTC. Their Rekor times prove existence from
then; the RFC 3161 tokens are their commit-time proof. From 0042 the anchor is contemporaneous.

**What this is not.** Not a certification; not a consensus system; not a cryptocurrency position of any kind. It
is a hash in two public logs.
