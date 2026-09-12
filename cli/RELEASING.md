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
| `tsa-certs/freetsa-*.pem/.crt` | the pinned freetsa CA / TSA certificate (fetched by `vendor.py` if not cached) |

A change to `NOTBEFORE.md` that alters \(V\), \(S\), shuffle or split **requires a new domain tag** (spec §12) *and* a
new minor version; old releases keep producing the old, still-valid values.

## Version policy

`MAJOR.MINOR` of the package tracks the spec (`notbefore/spec/0.2` ↔ `0.2.x`). **PATCH** = re-vendoring or CLI fixes
with no change to what a valid pulse or a derived value is. **MINOR** = spec change. Never reuse a version; never
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
   && /tmp/nbv/bin/python -m pytest -q tests)          # NOTBEFORE.md §14: must be 12/12

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

- **"vendored files identical to repo root" step fails** → a vendored source changed; run step 2 and commit. If it
  fails on `tsa-certs/*` only, freetsa rotated its certificate: verify the new one out of band before committing.
- **Tag pushed on an untested commit** → the tag still runs the full suite first; a red suite blocks publishing.
- **Version mismatch** between `pyproject.toml` and `__init__.py` → `notbefore --version` lies; check both in step 1.
- **Push rejected non-fast-forward** → think pushed a pulse; `git pull --rebase origin main` and push again (docs and
  `cli/` never conflict with `chain/`).
- **A wrong release** → `yank` it on PyPI (never delete), publish the fix as the next PATCH, add an `ERRATA.md` entry
  naming the bad version and what it would have accepted or produced.

## First release, for the record

`notbefore 0.2.0` — tag `cli-v0.2.0` on `db5c480`, verifier vendored at `19fed1b`, workflow run 34697049079,
published 2026-09-12 13:41 UTC; confirmed by a fresh-venv install verifying pair 0042/0043 and reproducing
`seed 43 --purpose demo:roster` = `ff2e6dff…86a7`.
