# qrng-beacon-log — public, append-only record of attested randomness pulses

Each `chain/pulse-NNNN.json` is a hash-chained, multi-host-signed record. From pulse 0010 the
chain uses **commit-then-reveal**: a `commit` pulse publishes `sha256(entropy)` bound to a *future*
drand round; the following `reveal` pulse discloses the entropy after that round exists.

**Verify anything here with no access to our systems:**
```bash
pip install cryptography
python3 verify.py chain/pulse-0010.json --pin keys/ --refetch
python3 verify.py chain/pulse-0011.json --pin keys/ --prev chain/pulse-0010.json --refetch
```

Why this repository exists: a commitment proves what it claims only if it was **published before**
the round it names. This repo's git history — and every clone of it — is that publication record.
Trust assumptions are spelled out in `PUBLICATION.md`. Claims discipline: `CLAIMS.md`.

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
