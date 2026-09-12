# `anchors` branch — publication anchors for the pulse chain

One entry per published pulse, written only by the `anchor-pulses` GitHub Actions workflow (`.github/workflows/anchor.yml`
on `main`), never by the minting host. For pulse *N*:

| file | what it is |
|---|---|
| `pulse-NNNN.stmt.json` | the canonical **anchor statement** — derivable from `chain/pulse-NNNN.json` alone (`ci/anchor_lib.statement_for`) |
| `pulse-NNNN.anchor.json` | the signature over the statement by `keys/anchor.pub`, and the **Rekor** entry (UUID, log index, `integratedTime`, signed entry timestamp, inclusion proof + signed checkpoint) |
| `pulse-NNNN.stmt.json.ots` | the **OpenTimestamps** proof for the same statement digest — `pending` until a calendar commits it into a Bitcoin block, then upgraded in place |
| `INDEX.tsv` | one line per anchored pulse |

**What this buys.** The chain is a single-writer log; its operator could in principle mint two different valid
pulse-*N*s on one `prev_hash` and show each to a different audience. Every pulse is therefore entered, under a
pinned key, into a public append-only log the operator does not control. Anyone can enumerate every entry ever made
under `keys/anchor.pub` (`ci/verify_anchors.py` with `REFETCH=1` does this) — an entry that matches no published
pulse is public evidence of a hidden branch, and a published pulse with no entry is a missing anchor.

**What it does not buy.** Rekor and Bitcoin prove *existence at a time* and *inclusion in a log*; they do not
prove the pulse is honest. OpenTimestamps is a timestamping protocol: no coins are held, bought, or paid.

Verify: `git clone` the repo, `git worktree add anchors origin/anchors`, then
`pip install cryptography opentimestamps-client && REFETCH=1 python3 ci/verify_anchors.py --anchors anchors`.
