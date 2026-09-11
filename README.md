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
