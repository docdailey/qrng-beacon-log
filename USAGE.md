# Using `notbefore` — the tool, not the theorem

`notbefore` turns one hour of the public beacon into a reproducible allocation. Everything below was run against
the live log on 2026-09-12 with `notbefore` 0.4.0 (spec 0.4); the outputs are real and anyone can regenerate them.

## The workflow

1. **Pre-register**, before the hour exists: *"the split will be derived from NotBefore pulse N with purpose X"* —
   N is a future reveal seq (they are hourly), X is a string you will not reuse for anything else.
2. **Wait** for the hour to pass.
3. **Run** the command. It verifies the pair first and refuses to derive anything if verification fails.
4. **Publish the transcript** with your results. A reviewer runs the same command and gets byte-identical output;
   they need trust neither you nor this site. You could not have tried fifty splits and kept the flattering one: the
   value did not exist when you committed to using it.

If the hour you named has no valid reveal (a `failure` or `skip` pulse, or a KNOWN-NONCOMPLIANT seq), take the
**next eligible hour**, named by that rule in advance. Never an earlier one, never "best of three".

## Worked example: an 80/20 split

`cohort.txt` — twenty lines, `patient-001` … `patient-020`, one per line, UTF-8, trailing newline.

```
$ notbefore split 45 --purpose cohort-allocation-2026-09 --frac 0.8 cohort.txt
[PASS] reveal 0045 is protocol v0.5 (got 0.5)
[PASS] pulse 0045 is a reveal (type reveal)
[PASS] pulse 0044 is a commit (type commit)
[PASS] reveal names commit_seq 44 (derived.commit_seq = 44)
[PASS] commit 0044: vendored verify.py (pinned keys, chained to 0043, drand refetched)
[PASS] reveal 0045: vendored verify.py (pinned keys, chained to 0044, C = SHA256(D_commit||E), V recomputed, timing contract, drand refetched)
[PASS] drand round BLS-verified offline under the pinned quicknet group key (py_ecc)
[PASS] commit 0044: 2 RFC 3161 token(s) verify (need ≥ 2: freetsa + DigiCert)
[PASS] pulse 0044: Rekor anchor logIndex 2808375615 @ 2026-09-12T14:02:49Z — … verified offline against pinned keys, re-fetched live
[PASS] pulse 0045: Rekor anchor logIndex 2808396511 @ 2026-09-12T14:08:26Z — … verified offline against pinned keys, re-fetched live
[PASS] commit 0044: Rekor time precedes the drand release by 158 s (third independent clock on the commit)
[PASS] checkpoint signature by notbefore.net/log (vendored key id 8b627e7f)
[PASS] root at size 49 recomputes from the pulses actually read (a18b8fce51312df2…)
[PASS] pulse 0044 is included in the checkpointed tree (leaf 43, RFC 6962 inclusion proof)
[PASS] pulse 0045 is included in the checkpointed tree (leaf 44, RFC 6962 inclusion proof)
[PASS] site https://notbefore.net/checkpoint serves the same checkpoint as git (size 49)
VERIFIED — NotBefore 45 (commit 44), log 77931e25abea
notbefore: transcript written: notbefore-45-cohort-allocation-2026-09.json
notbefore: A: 16 -> cohort.txt.A   B: 4 -> cohort.txt.B
```

Files written (names default to `<input>.A` / `<input>.B`; `--out-a` / `--out-b` override):

```
cohort.txt.A  (16)  patient-013 patient-012 patient-016 patient-008 patient-009 patient-003 patient-002 patient-010
                    patient-020 patient-015 patient-011 patient-018 patient-005 patient-001 patient-017 patient-019
cohort.txt.B  (4)   patient-004 patient-014 patient-007 patient-006
```

A = the first ⌊0.8 × 20⌋ = 16 lines of the shuffle, B = the rest. The shuffle ranks each line by
`SHA256("notbefore/shuffle/v1" || S || uint64_be(i) || line)`, where `i` is the line's position in **your input
file** — so the input order is part of the allocation, and `input_sha256` in the transcript pins it.

## The transcript

`notbefore-45-cohort-allocation-2026-09.json` (purpose slugged into the name; `--transcript PATH` / `-` / `none`):

```json
{
 "A": {"count": 16, "file": "cohort.txt.A", "sha256": "96dc070b053a613ee13640dae513f50d6882178da37550d76796d0bf1d6e1ca4"},
 "B": {"count": 4,  "file": "cohort.txt.B", "sha256": "40d2c91638d56ccfc85fbeb4a1be4496f9fa9b7af4fdcf0f15ebda9dfdd85664"},
 "attested_value": "437b03cfa18eb918aa29233648e6895745fdf48733d50c326cb41a0c68f31953",
 "checks": {"ok": true, "bls_offline": true, "tsa_tokens_verified": 2, "anchors": "ok/ok", "tlog": "ok", "lines": ["[PASS] ...", "..."]},
 "cli_version": "0.4.0",
 "commit_seq": 44,
 "derive_domain": "notbefore/derive/v1",
 "derived_seed": "a35ef1ee133158e244d899890fb3ae940e165da0188a0c7fd6d21fa7f88d5ee7",
 "drand_round": 32139521,
 "frac": 0.8,
 "input_file": "cohort.txt",
 "input_sha256": "acf13f2fd96b62c8b3b47a3b55855fb3a3f84de702e1fe9edbe4b26c75532903",
 "log_git_sha": "77931e25abea6c8c72072dc12917c7d41198ee2b",
 "log_ref": "origin/main",
 "operation": "split",
 "pulse_hash_commit": "01f874250a1b3bb7a9030ecbecbc45a10b60d04ec4ac434fb3ae4a64bd53a940",
 "pulse_hash_reveal": "4d2ad9ecb3adede5ac7b5db06a785f432f06f622a36d588caf1713d88ecdf154",
 "purpose": "cohort-allocation-2026-09",
 "record_count": 20,
 "seq": 45,
 "spec": "notbefore/spec/0.4",
 "verified_utc": "2026-09-12T16:37:24Z",
 "verifier_git_sha": "caf52bd84d162bcf6c152b2a77ea6fa25c6d7017"
}
```

| field | meaning | what must match on a re-run |
|---|---|---|
| `seq`, `commit_seq`, `pulse_hash_*`, `drand_round`, `attested_value` | the pair, and V | identical (the log is append-only; a checkpoint proves it) |
| `purpose`, `derive_domain`, `derived_seed` | S = SHA256(domain ‖ V ‖ purpose) | identical for the same purpose string (NFC, no trailing newline) |
| `input_file`, `input_sha256`, `record_count` | the bytes you fed in | **must be the same bytes** — order included |
| `operation`, `frac` / `k` / `arms` / `lo`,`hi` / `n` | the derived function and its parameter | identical |
| `output_sha256`, `A`, `B` (`count`, `sha256`) | what came out | identical; file *names* may differ |
| `log_git_sha`, `log_ref`, `cli_version`, `spec`, `verifier_git_sha` | what verified it | may differ across time; `notbefore pin` freezes them |
| `checks` | the verification summary | informational |

`notbefore diff-transcript a.json b.json` tells you which of these changed and what it means (exit 0 = identical
allocation).

## Re-running, bit-stable

```
$ notbefore pin                      # writes notbefore.lock: log commit, CLI version, vendored verifier, current checkpoint
$ notbefore split 45 --purpose cohort-allocation-2026-09 --frac 0.8 cohort.txt   # ./notbefore.lock is picked up automatically
notbefore: pinned by notbefore.lock: log 77931e25abea
```

With the lock, the log is read at exactly that commit, so "main moved" cannot change a result — and it cannot hide
a split view either: the checkpoint check still runs against the head this machine saw before.

## Commit your decision first: `plan` → wait → `execute`

The workflow above relies on you having *said* the pulse and purpose in advance. `plan` makes that a first-class,
timestamped object; `execute` then accepts no choices at all.

```
$ notbefore plan --after 2026-10-01T00:00Z --purpose chart-audit-2026-q4 --sample 50 eligible.txt
contract written: notbefore-plan-chart-audit-2026-q4.json  sha256 3f9c…
registered: freetsa Sep 12 20:41:07 2026 GMT
registered: digicert Sep 12 20:41:07 2026 GMT
publish the sha256 anywhere public — then wait for the pulse and run: notbefore execute notbefore-plan-chart-audit-2026-q4.json
```

The contract is canonical JSON — selection rule (`first-eligible-reveal-released-at-or-after 2026-10-01T00:00Z`),
purpose, operation `sample`, `k = 50`, and the SHA-256 and line count of `eligible.txt` — and the two `.tsr` files
beside it are third-party proof of when it existed. Publish the hash (a commit, a registry, a dated email).

```
$ notbefore execute notbefore-plan-chart-audit-2026-q4.json       # after 2026-10-01
[PASS] contract registered: freetsa Sep 12 20:41:07 2026 GMT
[PASS] contract registered: digicert Sep 12 20:41:07 2026 GMT
[PASS] selected by rule 'first-eligible-reveal-released-at-or-after': reveal 0489 (round released 2026-10-01T00:05:27Z >= after 2026-10-01T00:00:00Z)
[PASS] every registration token (2026-09-12T20:41:07Z earliest) predates the round release by 1566860 s
… the pair's verification lines …
transcript written: notbefore-executed-3f9c….json
```

`execute` refuses if the tokens are *after* the selected round (the decision could have been made knowing V), if
the input bytes differ from the committed SHA-256, or if the contract file was edited. Failure/skip hours and
non-compliant seqs are passed over by the rule, not by you. A contract without tokens runs only with
`--allow-unregistered`, and the transcript says so.

## The other derived functions (same S, one more deterministic step)

```
$ notbefore -q sample 45 --purpose chart-audit-2026-09 --k 5 cohort.txt
patient-018 patient-015 patient-005 patient-011 patient-020            # the first 5 of the shuffle for THIS purpose

$ notbefore -q assign 45 --purpose pilot-arms-2026-09 --arms 2 cohort.txt
patient-017  0
patient-016  1
patient-002  0        # shuffled position i -> arm i mod 2; sizes differ by at most one
…

$ notbefore -q id 45 --purpose blind-ids-2026-09 --from cohort.txt
beefc2ac0b104140      # one pseudonym per input line, in input order; the output holds no names
21e2ccb67e56943e      # SHA256("notbefore/id/v1" || S || line)[:16]. Recomputable by anyone with the names and the public S:
5ab3fd2e84f009b3      # it blinds readers who lack the names, it does not encrypt them.

$ notbefore -q range 45 --purpose start-page --lo 1 --hi 240
72                    # uniform in [1,240], rejection sampling, deterministic

$ notbefore -q bytes 45 --purpose sim-seed --n 16
d0aaaf87605a043203e507f274dc0a34   # public bytes (counter-mode SHA-256 of S); seed a simulation, never a key
```

Different purposes give unrelated seeds (`chart-audit-…` vs `cohort-allocation-…` above), so one hour safely drives
many independent allocations. The same purpose always gives the same seed.

## For the methods section

```
$ notbefore -q explain 45
Randomness for this analysis was taken from NotBefore pulse 45 (commit 44) of the public qrng-beacon-log
(https://notbefore.net, log identity notbefore.net/log; log commit 77931e25abea). The commitment to the value was
published at 2026-09-12 14:00:35 UTC and timestamped by independent RFC 3161 authorities (freetsa Sep 12 14:01:45
2026 GMT; digicert Sep 12 14:01:45 2026 GMT), before drand quicknet round 32139521 was released at 2026-09-12
14:05:27 UTC; the value V = 437b03cf… was revealed at 2026-09-12 14:05:40 UTC, 13 s after the round. …
```

## Flags

| flag | effect |
|---|---|
| `-q` | only FAIL/WARN lines on stderr (payloads were always stdout-only: `V=$(notbefore value 45)`) |
| `--json` | machine-readable result on stdout |
| `--offline` | no fetch, no live drand/Rekor refetch, no site fetch; BLS, TSA, anchors and checkpoint still verify offline |
| `--no-anchors` | skip the Rekor/OpenTimestamps layer |
| `--log-dir DIR` / `--repo URL` / `--log-ref SHA` | where the log is read from (default: a cached clone of the public repo at `origin/main`) |
| `--lock FILE` | verify at the log commit recorded by `notbefore pin` (`./notbefore.lock` is used automatically) |
| `--checkpoint-url URL` | which HTTPS checkpoint to cross-check against git (default `https://notbefore.net/checkpoint`) |
| `--transcript PATH` / `-` / `none` | where the transcript goes |
| `-v` | print the vendored verifier's full output |

## What the tool does not do

It does not make the bits secret (everything is public), certify anything, or let you pick a *past* hour after seeing
its value — the whole point is that you name the hour first. Requires `git` and `openssl` on PATH; Python ≥ 3.10.
Eligible pairs start at 0020/0021 (0026/0027 preferred); `verify 19` fails by design (ERR-007).
