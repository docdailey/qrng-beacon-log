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
(cd cli && rm -rf dist && uv build && uv venv /tmp/nbv && VIRTUAL_ENV=/tmp/nbv uv pip install "dist/notbefore-0.2.1-py3-none-any.whl[anchors,test]" \
   && /tmp/nbv/bin/python -m pytest -q tests)          # NOTBEFORE.md §14: the whole suite must pass (28 tests as of 0.7.1)

# 4. commit + push main; wait for the `notbefore-cli` workflow (build, vendored-files check, §14 suite) to go green
git add cli && git commit -m "notbefore 0.2.1: <what changed and why a release was needed>" && git push origin main

# 5. tag the TESTED commit; the tag runs the suite again and then publishes
git tag -a cli-v0.2.1 -m "notbefore 0.2.1" && git push origin cli-v0.2.1

# 6. confirm from nothing: fresh venv, fresh cache, latest pair
uv venv /tmp/nbp && VIRTUAL_ENV=/tmp/nbp uv pip install "notbefore==0.2.1" && XDG_CACHE_HOME=$(mktemp -d) /tmp/nbp/bin/notbefore verify <latest reveal seq>
/tmp/nbp/bin/notbefore --version      # must print the vendored sha from step 2

# 7. GitHub release with the artifacts, then a LEDGER row; ERRATA if the release corrects something
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

