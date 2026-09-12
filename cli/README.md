# notbefore

Consumer CLI for the public **qrng-beacon-log** — an hourly, commit-then-reveal, host-attested randomness log
anchored to drand quicknet, RFC 3161 timestamps, Rekor and OpenTimestamps. Spec: `NOTBEFORE.md` (draft 0.2) in
<https://github.com/docdailey/qrng-beacon-log>.

**What it proves:** the 32-byte attested value \(V\) of hour \(N\) was **fixed before** drand round \(R\) and
**not selected after** \(R\) existed. **What it does not prove:** that the bits are quantum, secret, certified, or
unique. This is not a certification of anything; see `CLAIMS.md` in the log repository.

```bash
pip install notbefore            # PyPI, 0.2.0; needs git and openssl on PATH; add [anchors] for OpenTimestamps proofs
notbefore verify 41              # commit 40 + reveal 41: signatures (pinned keys), drand BLS offline, RFC 3161, Rekor anchors
notbefore value 41               # V, only if verify passes
notbefore seed 41 --purpose clinic-qi-roster-2026-09-12       # S = SHA256("notbefore/derive/v1" || V || purpose)
notbefore shuffle 41 --purpose split:iris-csv:v3 rows.txt      # deterministic shuffle of the lines of rows.txt
notbefore split 41 --purpose split:iris-csv:v3 --frac 0.8 rows.txt
```

**Streams, for scripting.** Payloads go to **stdout only**; the verification transcript goes to **stderr**. So
`V=$(notbefore value 45)` is the 64-hex value and nothing else, and `notbefore shuffle … > out.txt` is clean. `-q`
silences the PASS/INFO lines; FAIL/WARN lines and a non-zero exit still report a bad pair. `--json` gives a
machine-readable result on stdout.

`seed`, `shuffle` and `split` write a **transcript** JSON (`notbefore-<seq>-<purpose>.json`) — the engineering
artifact that lets anyone reproduce the result from the public log.

**Trust model.** The verifier, the signing keys, the drand group key, the Rekor log key, the freetsa CA and the
expected host configuration are **vendored inside this package**, pinned at a named commit of the log repository
(`notbefore --version` prints it). The CLI executes only those files; the log is read as data. Updating the
verifier means updating the package — deliberately.

**Two publication surfaces.** The log is read from git (a cached clone of the repository, or `--log-dir`);
`https://notbefore.net` serves the same repository statically. Once checkpoints are enabled, `verify` also fetches
`https://notbefore.net/checkpoint` and requires it to be the same head as git's, or an append-only relative of it —
two different heads under the log's key is a split between surfaces and fails loudly (`--checkpoint-url` overrides).

Eligible pairs start at 0020/0021 (0026/0027 preferred, execution enforced). `verify 19` fails by design (ERR-007).
Pulses 0001–0041 carry retroactive anchors (2026-09-12 12:47 UTC); from 0042 anchors are contemporaneous.

MIT. Data in the log: CC BY 4.0.

**Releasing** (operators): `RELEASING.md` — every change to the verifier or keys needs a new package, and the flow there is the only way one gets made.
