# qrng-beacon-log — public, append-only record of attested randomness pulses

[![verify-chain](https://github.com/docdailey/qrng-beacon-log/actions/workflows/verify.yml/badge.svg)](https://github.com/docdailey/qrng-beacon-log/actions/workflows/verify.yml)

> A working experiment in proving not merely where public randomness came from, but when its private
> contribution became irrevocably fixed — and making a withheld reveal publicly detectable.

**Spec:** [`PROTOCOL.md`](PROTOCOL.md) (normative) · **Claims discipline:** [`CLAIMS.md`](CLAIMS.md) ·
**Trust assumptions:** [`PUBLICATION.md`](PUBLICATION.md) · **Cadence + failure semantics:** [`CADENCE.md`](CADENCE.md) ·
**Why:** [`THESIS.md`](THESIS.md) · **Keys:** [`keys/KEYS.json`](keys/KEYS.json) (history with validity windows) ·
**Known defects:** [`ERRATA.md`](ERRATA.md) — published pulses are never edited; defects are logged and fixed forward

**Status: research prototype and adversarially honest design exercise — not infrastructure to consume.**
The CI badge above re-verifies every pulse, link, commit/reveal pair, RFC 3161 token and the archive
Merkle root hourly and on every push, with a live drand re-fetch.

Each `chain/pulse-NNNN.json` is a hash-chained, multi-host-signed record. From pulse 0010 the
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

## What this is, and is not

An attested-log prototype and a timing thesis. The world already has drand; what it does not have
is operators who put their own source under commit-reveal, publish before the round, measure the
clock like an instrument, and write down what they may not say. It is verifiable by anyone and
**not yet something to use as a number** — see `CADENCE.md` for what would change that.

## Archive commitment ("entropy of record")

`merkle/manifest.json` commits to the 4.50 TB Quantis capture archive (42,935 blocks, 2025-07-18 →
2025-11-15) under root **`c88c4320dff421400744abb36e65ecfc6f185b1a0e9ead5ddb0e10920b7a2738`**.
`merkle/leaves.tsv` is the full leaf list; `merkle_proof.py` recomputes the root and produces or
checks inclusion proofs. A sample proof for one block is included.

```bash
python3 merkle/merkle_proof.py root                                   # recompute root from leaves.tsv
python3 merkle/merkle_proof.py verify merkle/proof_quantum_20251115_054715.json
```
The root commits to capture-time SHA-256 sidecars. A full re-hash of every block against its sidecar
is in progress; its status is published as it advances. Until it completes, the honest statement is
"sample-verified, full verification running".

## Notes
- Pulses 0001–0009 predate commit-then-reveal and are kept for chain continuity; they contain
  non-routable LAN addresses of the originating hosts, which is deliberate transparency, not a leak.
- Nothing here is certified by any body. See `CLAIMS.md` for what we do and do not claim.

## Operating it (for operators, and for anyone auditing the operator)

- `beacon-cycle.py` — one hourly commit → TSA-stamp → push → wait → reveal → push cycle; breaches of
  `CADENCE.md` write a `chain/pulse-NNNN.FAILED.json` and push it. `systemd/` holds the timer units.
- `pulse.py` refuses to mint unless the checkout equals the published head (`origin/main`), so two
  operators cannot fork the chain by accident.
- **`watcher.py` — run this if you do not trust us.** It needs no access to our systems: it reads this
  repo and drand, and publishes signed `NON-REVEAL` findings under *your* key to *your* repo whenever a
  commit passes its reveal deadline without a reveal. It also records every reveal it observed, so its
  own history proves it was watching. `WATCH_REPO=docdailey/qrng-beacon-log OUT_DIR=~/beacon-watch python3 watcher.py`

## License

Software: [MIT](LICENSE). Published log data and documents: [CC BY 4.0](LICENSE-DATA). Pulse files must be
redistributed byte-for-byte to remain verifiable.
