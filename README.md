# qrng-beacon-log — public, append-only record of attested randomness pulses

[![verify-chain](https://github.com/docdailey/qrng-beacon-log/actions/workflows/verify.yml/badge.svg)](https://github.com/docdailey/qrng-beacon-log/actions/workflows/verify.yml)

> A working experiment in proving not merely where public randomness came from, but when its private
> contribution became irrevocably fixed — and making a withheld reveal publicly detectable.

**Spec:** [`PROTOCOL.md`](PROTOCOL.md) (normative) · **Product contract:** [`NOTBEFORE.md`](NOTBEFORE.md) (the seed \(V\) and the labeled derive layer; draft 0.4) · **CLI:** `pip install notbefore` ([`cli/`](cli/) — `verify|value|seed|shuffle|split|sample|assign|id|range|bytes|explain|pin|checkpoint`, pinned vendored verifier; **how to use it: [`USAGE.md`](USAGE.md)**) · **Transparency log:** [`TLOG.md`](TLOG.md) (RFC 6962 tree + C2SP checkpoints, `tlog.py`; draft 2) · **Claims discipline:** [`CLAIMS.md`](CLAIMS.md) ·
**Trust assumptions:** [`PUBLICATION.md`](PUBLICATION.md) · **Cadence + failure semantics:** [`CADENCE.md`](CADENCE.md) ·
**Why:** [`THESIS.md`](THESIS.md) · **Keys:** [`keys/KEYS.json`](keys/KEYS.json) (history with validity windows) ·
**Known defects:** [`ERRATA.md`](ERRATA.md) — published pulses are never edited; defects are logged and fixed forward ·
**Independent verifications:** [`VERIFICATIONS.md`](VERIFICATIONS.md)

**Status: research prototype and adversarially honest design exercise — not infrastructure to consume.** From pulse
0020 a hostile or compromised *aggregator* cannot fabricate any host's facts (host isolation, `hosts/ISOLATION.md`); a
hostile *operator* is out of scope by design and is bounded only by drand, RFC 3161 and an independent watcher running
its own pinned verifier (`watcher/`). Known non-compliant pulses are listed in `ci/KNOWN_NONCOMPLIANT.json`.
The CI badge above re-verifies every pulse, link, commit/reveal pair, RFC 3161 token and the archive
Merkle root hourly and on every push, with a live drand re-fetch.

Each `chain/pulse-NNNN.json` is a hash-chained record. **From pulse 0018 (protocol v0.5, live since 2026-09-12 02:13 UTC) every fact is signed by
the host that produced it** — the entropy host generates, holds and reveals E; the GNSS, time and witness hosts
sign their own measurements; the aggregator signs only the assembly (`PROTOCOL.md §0`). From pulse 0010 the
chain uses **commit-then-reveal**: a `commit` pulse publishes `sha256(entropy)` bound to a *future*
drand round; the following `reveal` pulse discloses the entropy after that round exists.

**Verify anything here with no access to our systems — one command, from an empty directory:**
```bash
pip install cryptography py_ecc      # py_ecc enables full BLS verification of the drand rounds
RAW=https://raw.githubusercontent.com/docdailey/qrng-beacon-log/main
curl -sfLO $RAW/verify.py; curl -sfLO $RAW/bls_drand.py; mkdir -p keys; curl -sfL $RAW/keys/drand-quicknet.json -o keys/drand-quicknet.json
python3 verify.py $RAW/chain/pulse-0011.json --prev $RAW/chain/pulse-0010.json --pin $RAW/keys --refetch
```
Then confirm the commit was published before its round, using GitHub's timestamp rather than ours:
```bash
curl -s "https://api.github.com/repos/docdailey/qrng-beacon-log/commits?path=chain/pulse-0010.json" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)[-1]['commit']['committer']['date'])"
# 2026-09-11T23:58:46Z  <  round 32122604 release 2026-09-11T23:59:39Z
```

Why this repository exists: a commitment proves what it claims only if it was **published before**
the round it names. This repo's git history — and every clone of it — is that publication record.
Trust assumptions are spelled out in `PUBLICATION.md`. Claims discipline: `CLAIMS.md`.

## Independent timestamps (RFC 3161)

Each commit pulse carries tokens from two public Time-Stamping Authorities (freetsa.org, DigiCert),
proving with a third party's clock that the commitment existed before its round. Verify:
```bash
python3 tsa.py verify chain/pulse-0010.json      # checks digest + TSA certificate chain
```
Tokens on pulses 0010/0011 are retroactive (taken 2026-09-12 00:24 UTC, labelled in `*.tsa.json`);
from the next commit onward tokens are taken at mint time, before the target round exists.

## Publication anchors and the split-view check (Rekor + OpenTimestamps, since 2026-09-12)

This is a **single-writer** log. Its operator could, in real time, mint two different valid pulse-*N*s on one
`prev_hash` and show each to a different audience — nothing inside a single-writer log prevents that. So every
published pulse is also entered, under the pinned key `keys/anchor.pub`, into two append-only logs we do not run:
**Rekor** (the public Sigstore transparency log) and **OpenTimestamps** (Bitcoin block headers). The proofs live on
the [`anchors`](../../tree/anchors) branch. Anyone can list every Rekor entry ever made under our key; an entry that
matches no published pulse is public evidence of a hidden branch, and a pulse with no entry 25 minutes after
publication fails CI.

```bash
git worktree add anchors origin/anchors
pip install cryptography opentimestamps-client
REFETCH=1 python3 ci/verify_anchors.py --anchors anchors     # offline SET + inclusion proofs, live refetch, split-view enumeration
```
Pulses 0001–0041 were anchored retroactively (2026-09-12 12:47 UTC); from 0042 each pulse is anchored within
minutes of its push, so a commit's Rekor time precedes its drand release. See `PUBLICATION.md` and ERR-008.

## What this is, and is not

- **Log identity `notbefore.net/log`** (enabled 2026-09-12). Every pulse commit carries a C2SP checkpoint (RFC 6962 tree over all pulses) signed
  by `keys/checkpoint.pub`; `python3 tlog.py verify checkpoint --origin notbefore.net/log --pub keys/checkpoint.pub --old checkpoints/<older>`
  proves the log only ever grew. Self-signed and Rekor-anchored; no witness has cosigned yet (see `TLOG.md`).
- **No silent hours.** A cycle that runs but cannot commit publishes a signed `skip` pulse naming the refusing dependency
  (v0.5.1); only a deliberately stopped timer is silent, and that is announced in `CADENCE.md` first.
- **Not a blockchain.** Hash-linked and append-only, yes; but one writer, no consensus, no proof-of-work. The
  writer's honesty about *when* is bounded by clocks nobody here controls (drand, RFC 3161, Rekor, Bitcoin headers),
  and its honesty about *which* chain is made checkable by the anchors above. Equivocation is detectable, not prevented.

An attested-log prototype and a timing thesis. The world already has drand; what it does not have
is operators who put their own source under commit-reveal, publish before the round, measure the
clock like an instrument, and write down what they may not say. It is verifiable by anyone and
**not yet something to use as a number** — see `CADENCE.md` for what would change that.

## Archive commitment ("entropy of record")

**Archive root: `4e93d4be9ff5355d40e7e2c1d0ea599a62326aa09a651c9fa0b584764ccd95c4`** — `merkle/manifest-rehashed.json`,
over the **recomputed bytes** of all 42,935 blocks (4.50 TB, 2025-07-18 → 2025-11-15), each leaf carrying a
`sidecar_concordance` flag: **41,718** blocks match their capture-time sidecar (provenance from 2025), **1,217 (2.835 %)**
do not and carry provenance dated 2026-09-12 only (ERR-006). `merkle/leaves-rehashed.tsv` is the leaf list;
`merkle_proof.py --rehashed` produces and checks inclusion proofs, which state the block's provenance tier. The earlier
sidecar-based root `c88c4320…` (`manifest.json`) is retained, labelled, and must not be cited as the archive root.

```bash
python3 merkle/merkle_proof.py root                                   # recompute root from leaves.tsv
python3 merkle/merkle_proof.py verify merkle/proof_quantum_20251115_054715.json
```
ERR-006 is final: see `ERRATA.md` for the full account (window, sizes, tested hypotheses, statistical intactness of the bytes).

## Notes
- Pulses 0001–0009 predate commit-then-reveal and are kept for chain continuity; they contain
  non-routable LAN addresses of the originating hosts, which is deliberate transparency, not a leak.
- Nothing here is certified by any body. See `CLAIMS.md` for what we do and do not claim.

## Operating it (for operators, and for anyone auditing the operator)

- `beacon-cycle.py` — one hourly commit → TSA-stamp → push → wait → reveal → push cycle; breaches of
  `CADENCE.md` write a `chain/pulse-NNNN.FAILED.json` and push it. `systemd/` holds the timer units.
- `pulse.py` refuses to mint unless the checkout equals the published head (`origin/main`), so two
  operators cannot fork the chain by accident.
- **`RECOVERY.md`** — what the chain looks like when the timing bench, the aggregator or the entropy host goes down
  (silent gap / signed failure / unresolved commit that heals itself), the planned-outage checklist, bring-up order,
  and `python3 pulse.py preflight`, the read-only readiness check that mints nothing.
- **`cli/RELEASING.md`** — how the `notbefore` package is released, and why any change to `verify.py`, `keys/` or
  `hosts/EXPECTED.json` is only real for consumers once a new package is on PyPI (CI enforces the re-vendoring).
- **`watcher.py` — run this if you do not trust us.** It needs no access to our systems: it reads this
  repo and drand, and publishes signed `NON-REVEAL` findings under *your* key to *your* repo whenever a
  commit passes its reveal deadline without a reveal. It also records every reveal it observed, so its
  own history proves it was watching. `WATCH_REPO=docdailey/qrng-beacon-log OUT_DIR=~/beacon-watch python3 watcher.py`

## License

Software: [MIT](LICENSE). Published log data and documents: [CC BY 4.0](LICENSE-DATA). Pulse files must be
redistributed byte-for-byte to remain verifiable.
