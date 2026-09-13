<!-- External adversarial review received 2026-09-13 (America/Chicago 2026-09-12 21:20), reproduced here verbatim for the record. Response: ERRATA.md ERR-015 and `notbefore` 0.12.0 (R1–R8, R10), CI R9. Local paths in the text are the reviewer's workspace. -->

# Project review and recommendations

Reviewed September 12, 2026 (America/Chicago), against `public/` commit `d9e4ba69899954b83d7c50bf589b1d0670ecb807`, package `notbefore` 0.11.0, spec 0.8.

**Recommendation: prioritize verification correctness and stable commit selection before expanding the product.** The published chain passes its existing offline checks, but the consumer and audit paths accept evidence that does not establish the claims they report. Several issues below were reproduced with genuine published pulses and altered local copies, without changing any production data or contacting the live decision log.

## Scope and assessment

The workspace root is not a Git repository; `public/` is the main implementation and publication repository. This review covered the CLI, contract selection, receipts and bundles, decision-log Worker and schema, verifier, publication scripts, CI, and project documentation. `entropy/` contains parallel beacon code and historical artifacts; `prefab-review/` currently contains empty intake, sample, and template directories.

| Dimension | Assessment | Main reason |
| --- | --- | --- |
| Security and trust | High-priority fixes needed | Publication checks use unauthenticated metadata; bundle checks omit required authentication. |
| Correctness | High-priority fixes needed | Missing evidence can change the chosen commit; altered results can pass audit verification. |
| Performance and availability | Needs hardening | Worker requests load the whole log; input limits and numeric boundaries are incomplete. |
| Maintainability | Mixed | Good separation of source data and trusted verifier, but duplicated verification policies and incomplete CI triggers. |
| Documentation and product focus | Strong foundation, needs reconciliation | Claims and errata are unusually explicit; some instructions and version tables describe older behavior. |

Preserve these strengths:

- The CLI vendors its verifier, public keys, expected host configuration, and TSA roots; it does not execute code from the downloaded log. All vendored file hashes matched the manifest and current source in this review.
- The host signatures, domain-separated derivation, exact fractional splitting, signed checkpoints, and historical key validity windows provide useful foundations.
- `ERRATA.md`, `KNOWN_NONCOMPLIANT.json`, recovery instructions, and explicit same-sponsor witness disclosures make limitations auditable.
- Existing tests exercise real cryptographic verification and reject several classes of tampered pulse and decision-log evidence.

## Findings to fix first

P1 means a defect in a central trust or verification claim. P2 means an important correctness, availability, or engineering defect. “Reproduced” refers to local tests; it does not assert exploitation of the deployed service.

### R1 — P1: Read publication time from the authenticated Rekor entry

**Reproduced.** [commitbound.py:50](/Users/Dailey/grok_antics/public/cli/notbefore/commitbound.py:50) reads `rec["rekor"]["integratedTime"]`. The signature check authenticates the separate `rec["rekor"]["entry"]["integratedTime"]` in [anchor_lib.py:118](/Users/Dailey/grok_antics/public/ci/anchor_lib.py:118). The wrapper value is not bound to that signed value.

For commit 40, the signed Rekor time is `1789217262`, after release `1789214727`. Changing only the wrapper time to `release - 1` changed the publication verdict from false to true while `check_commit(..., anchors=True)` still passed and reported the anchor as `ok`.

**Change:** Return authenticated publication facts from the anchor verifier and use those directly for eligibility, transcripts, and receipts. Remove duplicate timestamp fields or reject disagreement with the signed entry. Apply the same correction to [receipt.py:398](/Users/Dailey/grok_antics/public/cli/notbefore/receipt.py:398).

**Acceptance:** Mutating any wrapper timestamp, index, or identity cannot change eligibility; a retroactive anchor remains ineligible without a new valid signed entry establishing otherwise.

### R2 — P1: Missing evidence must not select a different random value

**Reproduced.** [commitbound.py:73](/Users/Dailey/grok_antics/public/cli/notbefore/commitbound.py:73) treats verification failure or unavailable publication evidence as grounds to pass over a candidate and select a later commit.

With `after = 1789218330`, the complete local source selected commit 42. Suppressing only its anchor record, while retaining the exact same pulse chain and signed checkpoint, selected commit 44 instead. Both rounds were already known. An operator-controlled publication surface can therefore influence selection by withholding evidence even though it cannot change an individual commit's value.

**Change:** Distinguish proved ineligibility from unavailable or invalid evidence. An unresolved earlier candidate must cause a waiting/error result, not silently advance selection. Persist verified selection evidence and support recovery from independent mirrors or Rekor. Define what evidence conclusively excludes an earlier candidate, including how publication completeness is established.

**Acceptance:** Removing an anchor or TSA sidecar, changing a mirror, or causing a fetch failure either preserves the selected commit or stops execution. It must never silently select a later value. Add this to the adversarial cases in `FALLBACK.md`; the current reveal-withholding test does not cover evidence withholding.

### R3 — P1: Authenticate Rekor proofs in commit-bound bundles

**Reproduced.** The commit-bound branch of [receipt.py:380](/Users/Dailey/grok_antics/public/cli/notbefore/receipt.py:380) checks the record's timestamp against the transcript but never invokes `_check_anchors`. The older reveal-based branch does invoke it.

Replacing both the anchor signature and Rekor signed-entry timestamp signature with invalid bytes, then updating the unsigned bundle manifest hashes, still produced a successful `check_bundle` result. Genuine pulse signatures and BLS signatures were left intact. The manifest detects accidental corruption; an artifact author can regenerate it.

**Change:** Use one anchor-authentication implementation for online verification, receipts, and every supported bundle contract version. Require the anchor's statement digest to identify the bundled commit, validate signatures and inclusion proof under installed pins, and compare release time with the authenticated timestamp from R1.

**Acceptance:** Wrong signatures, unrelated statements, altered proof paths, and unsigned wrapper substitutions all fail with the normal checker. Test mutations with a regenerated manifest so tests exercise authentication rather than only file checksums. Rekor's [official documentation](https://docs.sigstore.dev/logging/overview/) describes its entry and inclusion-verification facilities.

### R4 — P1: Verify the decision and result, not just the seed

**Reproduced for input/output binding; selection gap confirmed by inspection.** [receipt.py:87](/Users/Dailey/grok_antics/public/cli/notbefore/receipt.py:87) copies result fields from the transcript. The bundle paths recompute the seed but do not rerun the committed operation or prove that the selected pulse satisfies the contract's first-eligible rule. The commit-bound branch returns before the older branch's output-hash loop.

In a bundle for a five-record, two-record sample, changing transcript `k` and `record_count` to 999, replacing `output_sha256` with zeros, and replacing the included roster with unrelated bytes still passed after rebuilding the manifest. The contract and signed pulse evidence were unchanged.

**Change:** Bind operation, parameters, value rule, domains, input hash, and selection rule to the signed contract. When input is included, verify it against `contract.input.sha256` and rerun [contract.py:169](/Users/Dailey/grok_antics/public/cli/notbefore/contract.py:169) to compare the actual output. Carry sufficient selection evidence to establish the first eligible commit. If private input or selection evidence is absent, report the specific unverified claim rather than claiming full result verification.

**Acceptance:** A changed input, result hash, sample size, operation, or selected commit is rejected even with a consistent manifest. A later individually valid pulse cannot substitute for the contract-selected pulse.

### R5 — P1: Preserve incomplete and degraded status through every verifier

**Reproduced.** Missing consumer timestamps are downgraded to warnings in [receipt.py:319](/Users/Dailey/grok_antics/public/cli/notbefore/receipt.py:319); an absent decision-log receipt has no corresponding failure. A locally generated execution explicitly allowed with `--allow-unregistered`, with neither consumer TSA tokens nor registration receipt, subsequently produced `gather.ok = true` and `check_bundle = true` without a checker-side opt-in.

Checkpoint enforcement has a related gap: [tlogcheck.py:62](/Users/Dailey/grok_antics/public/cli/notbefore/tlogcheck.py:62) returns `absent` without failing the overall check. Suppressing the checkpoint left pair 42/43 verified. Exceptions are also converted into warnings by [check.py:78](/Users/Dailey/grok_antics/public/cli/notbefore/check.py:78). Removing the bundle's anchors, checkpoint, and inclusion proofs still passed.

**Change:** Define a shared structured verification policy with explicit verified, incomplete, degraded, and invalid states. Required missing evidence must prevent an unqualified `VERIFIED` result. Enforce required proof coverage, not merely the validity of whichever proofs happen to be included. Keep incomplete artifacts inspectable, but preserve their status in exit codes, JSON, and rendered receipts.

**Acceptance:** A degraded execution cannot become fully verified by bundling it. Missing timestamps, registration, checkpoint, required inclusion paths, or requested witness quorum cannot be bypassed by deleting files or triggering an exception. Include explicit historical-policy exceptions where appropriate.

### R6 — P2: Handle every supported signed-contract version consistently

**Reproduced.** `CONTRACT_SPEC` now means `contract/3`, but [cli.py:327](/Users/Dailey/grok_antics/public/cli/notbefore/cli.py:327) accepts only that value for `register`. A `contract/2` file is rejected with the contradictory message “only signed contract/2 files can be registered.” Receipt verification also compares against only the current version: [receipt.py:64](/Users/Dailey/grok_antics/public/cli/notbefore/receipt.py:64) accepted a `contract/2` file without its signature and labelled it a legacy unsigned `contract/1`.

**Change:** Use `SIGNED_SPECS` for signature and registration requirements, and validate each version's allowed value and selection rules explicitly. Reject unsupported versions. Derive verification mode from the authenticated contract, not a transcript field.

**Acceptance:** A version matrix for contracts 1, 2, and 3 covers signature removal, registration retries, execution, receipt generation, and offline checking. Signed versions always require a valid bound signature.

### R7 — P2: Scope decision-log idempotency to the signer namespace

**Reproduced using the actual Worker with a local SQLite adapter.** [decisions.js:105](/Users/Dailey/grok_antics/public/worker/decisions.js:105) looks up existing entries by `contract_sha256` alone, and [schema.sql:8](/Users/Dailey/grok_antics/public/worker/schema.sql:8) makes the hash globally unique. A correctly signed statement can claim any hash when the contract is undisclosed.

Two different signing identities claiming the same hash produced HTTP 201 for the first request and HTTP 200 for the second, with the second response containing the first identity's leaf. The client should reject that receipt, but the rightful namespace still cannot register that hash. Exploitation requires learning the hash before its rightful registration; this is registration denial, not signature forgery.

**Change:** Use `(key_id, decision_id, contract_sha256)` as the idempotency key and preserve the independent first-entry rule per namespace. Return an existing receipt only when it matches the submitted statement under the documented retry semantics.

**Acceptance:** Two namespaces can independently register the same digest; an identical retry within one namespace returns its existing receipt. Test concurrent append and retry behavior against local D1 as well as SQLite.

### R8 — P2: Enforce Worker resource limits before buffering or persisting requests

**Request-size bypass reproduced; scaling concerns confirmed by inspection.** [decisions.js:187](/Users/Dailey/grok_antics/public/worker/decisions.js:187) checks only the optional `Content-Length` header before `req.text()`. A signed 180,407-byte request without that header was accepted and persisted despite the configured 163,840-byte limit. `created_utc` and `contract_spec` are checked only for string type, allowing oversized or invalid values.

Meanwhile, [decisions.js:93](/Users/Dailey/grok_antics/public/worker/decisions.js:93) loads every leaf hash even to serve an already stored latest checkpoint; proof generation rebuilds subtrees. Costs grow with the whole log, and submissions are public.

**Change:** Bound bytes while reading the body, validate field lengths and formats, and measure UTF-8 bytes for contract limits. Add deployment-level request controls appropriate to the prototype. Persist Merkle nodes/frontier and latest size so checkpoint reads and proofs do not repeatedly load and hash the whole tree.

**Acceptance:** Oversized requests are rejected with or without a length header. Add concurrent-write and growth benchmarks with explicit request-time, memory, and database-read budgets. These local tests did not assess deployed Cloudflare protections or D1 concurrency.

### R9 — P2: Cover trust-source changes and offline behavior in CI

**Confirmed by inspection.** The vendoring consistency check runs in [cli.yml:23](/Users/Dailey/grok_antics/public/.github/workflows/cli.yml:23), but the workflow triggers only for `cli/**` and its own workflow file. Changes solely to root verifier files, keys, host expectations, or `ci/anchor_lib.py` can avoid that check. The chain workflow runs on main pushes, not pull requests. The Worker conformance test is not wired into these workflows, and its vector-generation inputs are not supplied by a checked-in test runner.

**Change:** Trigger relevant checks for every vendored source and Worker/schema change, on pull requests. Separate deterministic offline tests from explicit external-service tests, using registered [pytest markers](https://docs.pytest.org/en/stable/how-to/mark.html). Some tests still request TSA tokens under `NOTBEFORE_OFFLINE=1`; the receipt tests do not consume that environment switch. Consult GitHub's [path-filter rules](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore) when defining coverage.

**Acceptance:** A root-key-only change runs vendoring validation; a Worker-only change runs its conformance and storage tests. The default suite succeeds with network access disabled. Exercise the oldest supported Python version in addition to 3.12, and pin the tested release dependency set for reproducibility.

### R10 — P2: Close offline and numeric boundary cases

- **Offline fallback — inspection:** [commitbound.py:97](/Users/Dailey/grok_antics/public/cli/notbefore/commitbound.py:97) fetches the drand round for a missing reveal even when called with `refetch=False` from `--offline`. Cache verified rounds independently of reveals and accept them as offline inputs; otherwise return a clear missing-evidence result without attempting a connection.
- **Unbounded range — reproduced:** [derive.py:78](/Users/Dailey/grok_antics/public/cli/notbefore/derive.py:78) computes an acceptance limit of zero when `hi - lo + 1 > 2**64`. `rand_range(bytes(32), 0, 2**64)` never reaches an accepting sample; the probe was terminated after one second. Reject unsupported spans before signing a contract, or implement a versioned wider sampler that preserves existing outputs.

**Acceptance:** Offline fallback performs no socket access, and range tests cover spans 1, `2**64`, and `2**64 + 1` with prompt success or an explicit validation error.

## Project-level recommendations

1. **Consolidate verification policy.** `execute`, `gather`, `check_bundle`, `check_pair`, and `check_commit` duplicate overlapping requirements. Introduce shared verified-fact objects and typed error/status results. Keep human-readable output as rendering, rather than using success strings from subprocess output as the policy boundary.
2. **Make the authoritative tree explicit.** Document `public/` as the maintained implementation. Of 15 common Python files compared with `entropy/beacon/`, only `tsa.py` differed, but the parallel copy invites future fixes to land in one place. Mark historical copies clearly or generate them. Keep operational private keys outside directories intended for copying or publication; a private-key path exists under `entropy/beacon/keys/private/`, but this review did not read its contents or establish exposure.
3. **Repair current documentation without rewriting historical evidence.** `NOTBEFORE.md` §12 still lists spec 0.5 and contract/1, and contains conflicting package-version rules. `README.md` says the decision log is still designed rather than implemented in one section. Its quick verification instructions download an incomplete set of dependencies for the current verifier. Replace the smoke-test example with a tested installed-CLI workflow. The GitHub commit API example returns a committer-controlled date, not an independent timestamp; point readers to verified TSA/Rekor evidence instead. Preserve historical pulse bytes and explain changed interpretations through errata.
4. **Use the existing market gate.** `VENTURES.md` already specifies a 14-day, three-venue experiment and an explicit stop condition. Record its start/deadline, actual venue posts, qualified requests, paying customers, support time, and revenue in one small table. Refresh stale “rehash running” and other status notes. After the P1 fixes, seek one external end-to-end audit of a real nonsensitive decision before adding more derivation commands or another product layer. This is a recommendation based on the workspace's own objectives, not new market research.
5. **Validate independence and recovery operationally.** The checked checkpoint has one same-sponsor cosignature and zero independent cosignatures. Track independent witness onboarding as an outcome. Run documented recovery drills for unavailable hosts, an interrupted publish, and competing scheduled jobs using a disposable environment; this review did not validate the hardware or live host isolation.

## Suggested delivery order

| Stage | Work | Exit criterion |
| --- | --- | --- |
| Trust fixes | R1–R5, with adversarial fixtures | Every reproduced false-pass or selection-change case fails safely; valid historical values remain reproducible. |
| Compatibility and service hardening | R6–R8, R10 | Version matrix, namespace isolation, bounded requests, and offline/boundary tests pass. |
| Release discipline | R9 and shared verification policy | Relevant PRs run offline tests, Worker checks, vendoring checks, and an installed-wheel smoke test. |
| External validation | Documentation, independent audit/witness, existing market gate | A third party reproduces a fully registered result and the project has measured demand or follows its stated stop condition. |

## Validation performed

| Check | Result |
| --- | --- |
| Published chain, `REFETCH=0 REQUIRE_BLS=1` | 67 pulses examined; 2 known noncompliant historical pulses failed as documented; 0 unexpected failures; 59 BLS checks; 60 TSA tokens; 66 chain links. |
| Archive manifests, included Merkle proofs, transparency-log self-test and current checkpoint | Passed within the chain verifier. This recomputed roots from published leaf lists, not the underlying 4.50 TB archive. |
| Selected existing CLI acceptance tests | 27 passed, 1 skipped, 4 deselected; 116.73 seconds. |
| Vendored manifest and source comparison | No hash mismatches and no source mismatches. |
| Altered-copy probes | Confirmed R1–R5, the contract/2 receipt/registration regression, and the oversized numeric range. |
| Actual Worker with local SQLite adapter | Confirmed cross-namespace hash collision and oversized-body acceptance. No live submissions. |

The four deselected acceptance tests were `test_24`, `test_26`, `test_29`, and `test_32`, which use external TSA or fallback-round paths. The original receipt test module was not run as-is because it does not honor the offline environment switch; equivalent local receipt/bundle flows and additional adversarial mutations were exercised directly. Full live-service, PyPI artifact, deployment, Bitcoin-header/OpenTimestamps, and hardware validation were outside this review.

The review used Python 3.12.14, pytest 9.1.1, cryptography 50.0.1, py-ecc 8.0.0, and OpenSSL 3.6.3 in a temporary environment. No implementation changes were made. The `public/` working tree remained clean.

Reproduction commands for the existing offline checks, after installing the CLI's test dependencies:

```sh
PYTHONPATH="$PWD/public/cli" \
XDG_CACHE_HOME=/tmp/notbefore-review-cache \
NOTBEFORE_LOG_DIR="$PWD/public" \
NOTBEFORE_OFFLINE=1 \
python -m pytest -q -p no:cacheprovider public/cli/tests/test_acceptance.py \
  -k 'not test_24 and not test_26 and not test_29 and not test_32'

# Ensure the environment's python3 is on PATH: the chain runner invokes python3.
REFETCH=0 REQUIRE_BLS=1 python public/ci/verify_chain.py
```

Local review evidence is retained in `/tmp/grok-antics-review-evidence/results.json`, `/tmp/grok-antics-review-selection.log`, `/tmp/grok-antics-review-worker.json`, and `/tmp/grok-antics-review-chain.log`. Probe sources are `/tmp/grok_antics_review_probes.py` and `/tmp/grok_antics_worker_review.mjs`. These temporary artifacts are supporting evidence; the findings and observed outcomes are recorded above so this document stands alone.
