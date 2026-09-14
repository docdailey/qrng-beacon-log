# Releasing `notbefore` — the flow, and why it is this strict

The CLI ships its own copy of the verifier and every key (`notbefore/verifier/`, written by `vendor.py`). That is the
point of the package: an installed CLI keeps accepting exactly what it accepted on the day it was released, no matter
what later lands in the log repository. The cost is that **any change to the verifier or keys is only real for
consumers once a new package is released.** This file is that procedure.

## When a release is REQUIRED

Whenever any vendored file changes at the repo root — the CI step *"Vendored verifier matches this checkout"* fails
the build until `vendor.py` has been re-run, so this cannot be forgotten silently:

| changed at repo root | why consumers need it |
|---|---|
| `verify.py`, `bls_drand.py`, `drand_anchor.py`, `schema.py`, `tsa.py` | the verifier itself |
| `hosts/EXPECTED.json` | execution enforcement (beacon-cmd / host-config hashes) — a host rebuild without a release makes every new pulse FAIL for installed CLIs; that is intended, and is why host changes are announced in `ERRATA.md` |
| `keys/*` (`KEYS.json`, role `.pub`s, `drand-quicknet.json`, `anchor.pub`, `rekor.pub`) | key rotation — old keys stay listed with their seq windows, so old releases keep verifying old pulses |
| `hosts/*.py` | tooling-drift comparison (informational) |
| `ci/anchor_lib.py`, `ci/KNOWN_NONCOMPLIANT.json` | anchor verification; the list of pulses that are expected to fail |
| `keys/tsa/*` | the pinned RFC 3161 trust anchors (FreeTSA root + signer, DigiCert Trusted Root G4 + timestamping CA) — the verifier trusts nothing else; a TSA chain rotation is a release |

A change to `NOTBEFORE.md` that alters \(V\), \(S\), shuffle or split **requires a new domain tag** (spec §12) *and* a
new minor version; old releases keep producing the old, still-valid values.

## Version policy

Package and spec versions are **independent** (decoupled 2026-09-12 after they drifted: 0.6.0 shipped spec 0.5).
`notbefore --version` prints both; `SPEC` in the package is the binding statement. **PATCH** = re-vendoring or CLI
fixes with no change to what a valid pulse or a derived value is. **MINOR** = new behaviour or a spec change. Never reuse a version; never
delete a release (PyPI **yank** with a reason + an `ERRATA.md` entry if a release is wrong).

## The flow

```bash
# 0. main must be clean and at the published head; do NOT push between :00 and :07 (think's minting window)
cd public && git pull --ff-only origin main

# 1. bump the version in BOTH places (they must agree)
$EDITOR cli/pyproject.toml            # version = "0.2.1"
$EDITOR cli/notbefore/__init__.py     # __version__ = "0.2.1"

# 2. re-vendor: pins verifier + keys + certs at the CURRENT commit into notbefore/verifier/ and writes VENDORED.json.
#    Do this AFTER `git pull --rebase` and immediately before the push: a rebase changes your commit shas, and a
#    VENDORED.json naming a sha that never reached origin/main is a pin nobody can resolve (happened 2026-09-12; re-vendored).
(cd cli && python3 vendor.py)         # prints: vendored 23 files at <sha>

# 3. build + test locally in a clean venv (same suite CI runs; needs git + openssl; network for drand/Rekor refetch)
(cd cli && rm -rf dist && uv build && uv venv /tmp/nbv && VIRTUAL_ENV=/tmp/nbv uv pip install -r requirements-test.txt && VIRTUAL_ENV=/tmp/nbv uv pip install --no-deps "dist/notbefore-0.2.1-py3-none-any.whl" \
   && NOTBEFORE_OFFLINE=1 /tmp/nbv/bin/python -m pytest -q --strict-markers tests -m "not network" \
   && /tmp/nbv/bin/python -m pytest -q --strict-markers tests -m network)   # NOTBEFORE.md §14: offline partition + live partition must both pass (38 tests as of 0.12.1)
#    Run the suite between :08 and :50 with a freshly pulled checkout: a pulse minted mid-run makes the site cross-check fail on a stale --log-dir.

# 4. commit + push main; wait for the `notbefore-cli` workflow (build, vendored-files check, §14 suite) to go green
git add cli && git commit -m "notbefore 0.2.1: <what changed and why a release was needed>" && git push origin main

# 5. tag the TESTED commit; the tag runs the suite again and then publishes
git tag -a cli-v0.2.1 -m "notbefore 0.2.1" && git push origin cli-v0.2.1

# 6. confirm from nothing: fresh venv, fresh cache, latest pair
uv venv /tmp/nbp && VIRTUAL_ENV=/tmp/nbp uv pip install "notbefore==0.2.1" && XDG_CACHE_HOME=$(mktemp -d) /tmp/nbp/bin/notbefore verify <latest reveal seq>
/tmp/nbp/bin/notbefore --version      # must print the vendored sha from step 2

# 7. GitHub release with the artifacts, then a LEDGER row; ERRATA if the release corrects something.
#    Documentation checklist for every release: README.md, USAGE.md, WORKFLOW.md, NOTBEFORE.md §8/§16, CLAIMS.md §1, and the
#    homepage public/index.html (its claims, examples and version references change with the contract and the verifier).
gh release create cli-v0.2.1 --title "notbefore 0.2.1" --notes "<why>" cli/dist/notbefore-0.2.1*
```

## What publishes it, and what it needs

`.github/workflows/cli.yml`, job `publish`, runs only on tags `cli-v*`, only after the `test` job, in the GitHub
environment **`pypi`**, with `id-token: write`, via `pypa/gh-action-pypi-publish` — **PyPI Trusted Publishing**, no
API token anywhere. The PyPI side is a publisher registered on the `notbefore` project: owner `docdailey`,
repository `qrng-beacon-log`, workflow `cli.yml`, environment `pypi` (registered by Bill, 2026-09-12). If that
registration is ever removed the publish job fails loudly with an OIDC error; nothing else changes. The action
also uploads Sigstore attestations for the wheel and sdist (PEP 740), so the package is itself in Rekor.

## Failure modes seen or expected

- **"vendored files identical to repo root" step fails** → a vendored source changed; run step 2 and commit. If a
  TSA rotates its chain, tokens start failing `tsa.py verify` everywhere (that is the pinned behaviour, ERR-014):
  extract the new chain from a fresh token, confirm the new root out of band (vendor repository + a second trust
  store), add it under `keys/tsa/` with its fingerprint in `PINS.json`, keep the old root while old tokens exist, release.
- **Tag pushed on an untested commit** → the tag still runs the full suite first; a red suite blocks publishing.
- **Version mismatch** between `pyproject.toml` and `__init__.py` → `notbefore --version` lies; check both in step 1.
- **Push rejected non-fast-forward** → think pushed a pulse; `git pull --rebase origin main` and push again (docs and
  `cli/` never conflict with `chain/`).
- **A wrong release** → `yank` it on PyPI (never delete), publish the fix as the next PATCH, add an `ERRATA.md` entry
  naming the bad version and what it would have accepted or produced.

## Releases, for the record

`notbefore 0.2.0` — tag `cli-v0.2.0` on `db5c480`, verifier vendored at `19fed1b`, workflow run 34697049079,
published 2026-09-12 13:41 UTC; confirmed by a fresh-venv install verifying pair 0042/0043 and reproducing
`seed 43 --purpose demo:roster` = `ff2e6dff…86a7`.

`notbefore 0.7.1` — tag `cli-v0.7.1` on `ee2578f`, verifier vendored at `615cf14`, workflow run 34720242608,
published 2026-09-12 21:36 UTC; ERR-014 (pinned RFC 3161 trust roots). Confirmed by a fresh-venv install with the
host certificate store hidden (`SSL_CERT_FILE=/dev/null`) verifying pair 0058/0059 and reproducing the USAGE.md
split of pulse 45 byte-for-byte (A/B sha256 unchanged from the 0.4.0 run). 0.3.0–0.7.0 same day: see git tags.

`notbefore 0.8.0` — tag `cli-v0.8.0` on `75f8e33`, verifier vendored at `bef0e70`, workflow run 34722438210, published
2026-09-12 22:2x UTC; spec 0.6 (keygen, signed contract/2, decision-log client; log shipped `enabled: false` pending the
Worker deployment). Confirmed by a fresh-venv install: `keygen` → signed `plan --no-timestamp` → `execute
--allow-unregistered` reproduces the rule-selected pulse with `decision_log.status: disabled`, and `verify 61` passes.

`notbefore 0.8.1` — tag `cli-v0.8.1` on `6f5dd2e`, verifier vendored at `1548d6d`, workflow run 34725882908, published
2026-09-12 23:40 UTC; decision log ENABLED. Confirmed from a fresh venv against PyPI: `keygen` → `plan` signed,
timestamped and registered live (entry 3, AUTHORITATIVE, receipt verified at checkpoint size 4) → `execute` refused
on late tokens as designed → a `--no-log` dry run reproduced reveal 0023 → `verify 61` passed. **Lesson, again:** the
first 0.8.1 tag was withdrawn (run cancelled, tag deleted before publish) because a `git pull --rebase` after
vendoring had moved the commit, leaving VENDORED.json naming a sha that never reached origin — vendor AFTER the
rebase, immediately before the push, every time.

`notbefore 0.9.0` — tag `cli-v0.9.0` on `34a7a2e`, verifier vendored at `2e24989`, workflow run 34727493163, published
2026-09-13 00:19 UTC; `receipt`, `bundle`, `check-bundle`, WORKFLOW.md. Confirmed from a fresh venv against PyPI:
`keygen` → `plan --no-log --no-timestamp` → `execute --allow-unregistered` → `receipt` (all checks PASS, three honest
WARNs for the unregistered dry run) → `bundle` → `check-bundle` (BUNDLE VERIFIED, offline, fresh cache) → `verify 65`.

`notbefore 0.10.0` — tag `cli-v0.10.0` on `793b353`, verifier vendored at `618b5ce`, workflow run 34728679279, published
2026-09-13 00:48 UTC; spec 0.7: `execute` fails closed on the decision log, explicit leaf-to-namespace binding, FALLBACK.md.
Confirmed from a fresh venv against PyPI: a signed, timestamped but unregistered contract is REFUSED ("did not confirm …
authoritative preregistration"); `--allow-unregistered` runs DEGRADED and is still refused on the round gate; a live
registration (entry 6) passes the authority check and is refused only on the round gate; `verify 65` passed.

`notbefore 0.11.0` — tag `cli-v0.11.0` on `b2eec5b`, verifier vendored at `0192e7f`, workflow run 34730690854, published
2026-09-13 01:39 UTC; spec 0.8: the commit-bound value (contract/3 default, FULL-ATTESTED / COMMITMENT-FALLBACK, Rekor
anchor before the round as eligibility). Confirmed from a fresh venv against PyPI: `plan` → contract/3 → `execute
--allow-unregistered` selected commit 0042 (anchored 129 s before its round), FULL-ATTESTED, V* `879c6f72…`; `receipt`
(no FAIL), `bundle`, `check-bundle` (BUNDLE VERIFIED, V* recomputed offline from the bundled commit + drand signature);
`verify 67` passed. Test 32 (same V* with the reveal removed) ran green in CI.

`notbefore 0.12.0` — tag `cli-v0.12.0` on `41f1b14`, verifier vendored at `4fd56cc`, workflow run 34735160037 (test +
Worker conformance + publish), published 2026-09-13 03:29 UTC; spec 0.9, ERR-015 (second adversarial review, `reviews/`).
Confirmed from a fresh venv against PyPI: contract/3 `execute` selected commit 0042 with publication evidence
`rekor-live` (Rekor's signed time, 129 s before the round); `receipt`, `bundle`, `check-bundle` all report DEGRADED for
the dry run (exit 2); `verify 71` passed. Live Worker (deployed 03:20:57Z by the Git integration after migrate-001):
two keys registering one hash got entries 8 and 9, an identical retry returned the existing entry, oversized bodies
were refused with and without Content-Length, a malformed `created_utc` was rejected.

`notbefore 0.12.1` — tag `cli-v0.12.1` on `7e3c405`, verifier vendored at `4dc599a`, workflow run 34735997939, published
2026-09-13 03:48 UTC; review residuals (value-rule binding, offline-selection notice, witness quorum in bundles). Confirmed
from a fresh venv against PyPI: `verify 71` passed.

`notbefore 0.12.2` — version committed on `c93ad98` but **never tagged or published**: the tag step's head-equals-origin guard
failed after a mint landed on main, and the change (the shared verdict type, `policy.py`) shipped in 0.13.0 instead.

`notbefore 0.13.0` — tag `cli-v0.13.0` on `ae8b6ea`, verifier vendored at `7e17f49`, workflow run 34737707969 (test 3.10 + 3.12,
live, Worker conformance, publish), published 2026-09-13 04:31 UTC; spec 0.10: timing profile `notbefore/timing/v1` (review 2, T1)
plus the shared verdict type from 0.12.2. Confirmed from a fresh venv against PyPI: `verify 73` passed; the pre-release smoke ran a
`--timing-required` contract end to end (SATISFIED; receipt clocks section; check-bundle re-evaluated the profile from the bundle).

`notbefore 0.13.1` — tag `cli-v0.13.1` on `96e62c2`, verifier vendored at `f65e70e`, workflow run 34759369490 (test 3.10 + 3.12,
live, Worker conformance, publish), published 2026-09-13 13:22 UTC; package PATCH, spec 0.10 unchanged: the site cross-check
reconciles a site that is ahead of the log copy by fetching and chain-linking the missing pulses (≤ 12) instead of halting
(TLOG.md §8 — the halt had failed the live partition on 8a3c259 when the 12:27 mint landed mid-run), and the vendored verifier
carries the cadence-trigger checks (commits from 0092). Confirmed from a fresh venv against PyPI: `verify 93` passed; the PyPI
wheel's SHA-256 equals the locally built one (`ca61da44…`); with a local copy one pulse behind the site the reconcile path ran
and the pair verified.

`notbefore 0.14.0` — tag `cli-v0.14.0` on `01e17d6`, verifier vendored at `9a60e08` (content of `01e17d6`), workflow run 34762725985
(test 3.10 + 3.12, live, Worker conformance, publish), published 2026-09-13 14:33 UTC; **spec 0.11**: `execution.via = agentd`
accepted against pinned `agentd_sha256` (the machine-to-machine service that replaces the SSH forced command from the k3
cutover), k3's aggregator key (`56c30593534ad116`, valid from 96) vendored, `core.cadence.self_trigger`, native blst BLS,
relay race, concurrent TSAs. Released BEFORE the first agentd pulse because older verifiers reject those statements.
Confirmed from a fresh venv against PyPI: `verify 95` passed; PyPI wheel SHA-256 equals the local build (`962e9fec…`).

`notbefore 0.14.1` — tag `cli-v0.14.1` on `6b1bd12`, verifier vendored at `000a43a` (content of `c08c7fa`), workflow run 34771752068 (test 3.10 + 3.12, live, Worker conformance, publish), published 2026-09-13 17:35 UTC; wheel `b3be856a…` / sdist `becf0533…` equal a local rebuild of the tagged content; fresh-venv `verify 101` passed. Re-vendor after the publication margin in `schema.py` went 120 → 20 s (aggregator policy for the 60 s lead from pulse 0102, 2026-09-13 18:00Z; the CLI does not enforce the margin, so this is a PATCH: vendored files changed, contract did not).
Lesson: run `vendor.py` after the LAST commit of the set exists. Here it ran before a `--amend`, so the pin named a sha that never reached origin and a third commit re-pinned it (000a43a → 6b1bd12).

`notbefore 0.14.2` — tag `cli-v0.14.2` on `5196096`, verifier vendored at `60f26a6` (content of `a388e60`), workflow run 34784624098 (test 3.10 + 3.12, live, Worker conformance, publish), published 2026-09-13 21:49 UTC; fresh-venv verify of the latest pulse passed; wheel/sdist equal a local rebuild. Verifier fix: a commit pulse carrying the aggregator's own wake record but no time-host trigger (the `clock` /
`own-clock` start without a bound datagram) crashed `verify.py` with `UnboundLocalError: ts_` in the `[INFO]` line (found 2026-09-13 in a
staging run where the lab sender never fired; no published pulse has hit it). PATCH: vendored file changed, contract unchanged.

`notbefore 0.14.3` — tag `cli-v0.14.3` on `ac6559e`, verifier unchanged (vendored at `60f26a6`), workflow run 34791665376 (test 3.10 + 3.12, live, Worker conformance, publish), published 2026-09-14 00:15 UTC; fresh-venv verify of the latest pulse passed; wheel/sdist equal a local rebuild. CLI fix: `notbefore verify N` with N a COMMIT pulse printed three
inverted FAIL lines ("pulse 0112 is a reveal (type commit)") and "NOT VERIFIED - NotBefore 112 (commit None)", which reads as a broken
log to anyone checking the newest commit directly (2026-09-13 23:4xZ, a reviewer on 0112/0113). It now says what the number is and where
the value is: "0112 is a COMMIT pulse ... its reveal is 0113: run notbefore verify 113"; failure and skip pulses get the same treatment.
Test 19 covers it.

