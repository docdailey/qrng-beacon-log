# PROTOCOL.md — pulse format and verification, normative

Version **0.5** (host-attested statements; commit-then-reveal; signed failures). Pulses ≤ 0.4 remain
verifiable under the legacy path described at the end; their signatures are digest signatures, not role
attestations (ERR-005).

## 0. v0.5 in one paragraph

Each role host produces and **signs its own statement** with its own key: the **entropy host** (protectli)
generates `E`, holds it, and signs `{entropy_commitment, target_round}`; at reveal it releases `E` and signs
that; on failure it signs an abandonment. The **GNSS host** (f9t) signs the anchor epoch it measured. The
**time host** (p550) and **witness** (k3) each sign their own clock measurement. Every statement is bound to
the pulse by `{seq, phase, binding, chain_hash}` — `binding` is the entropy commitment (commit) or the commit
pulse hash (reveal/failure) — so a statement cannot be replayed into another pulse. The **aggregator** (think)
verifies each statement, assembles `core`, and signs only the assembly with a fifth key. A dishonest
aggregator therefore cannot fabricate any host's facts. All host scripts are published under `hosts/` and
version-bound into each pulse by SHA-256 (`core.tooling`).

### Trust boundary (stated precisely)
Two different adversaries, two different answers:
- **A hostile or compromised aggregator (think) or aggregator process** cannot forge any host's facts once host
  isolation is deployed (`hosts/ISOLATION.md`): each host's key and secret live under a dedicated `beacon` OS user,
  and the aggregator's SSH identity can run exactly one fixed-role forced command with locally validated
  `phase/seq/binding` and a monotonic-seq guard. **Until isolation is live on a host, that host's statements prove
  origin-by-signature only**, and `CLAIMS.md` says so.
- **A hostile operator** (the person who administers all machines) is **out of scope**: nothing in this protocol
  defends against them. What defends the consumer against the operator is the external structure — drand,
  RFC 3161 tokens, and a watcher running the operator-independent pinned verifier — which bounds *what* the operator
  can do (not before the round; not selected after commitment; not withheld without a public, attested record).
- **Equivocation (split view).** This is a single-writer log: the operator holds every signing key and can, in
  real time, produce two different valid pulse-*N*s on one `prev_hash` and show each to a different audience. The
  protocol does not prevent this; it makes it **detectable**: (a) the entropy host refuses a second commit at a seq
  that already resolved a published commit (ERR-008; raises the cost, does not bind root); (b) every published pulse
  is anchored under a pinned key in two public append-only logs (below), and every entry ever made under that key is
  enumerable; (c) independent watchers record what they observed. A fork is impossible after the fact, because a
  commit's RFC 3161 tokens must predate its drand round.

### Publication anchors (normative for the operator since 2026-09-12; verifiable by anyone)
For every `chain/pulse-NNNN.json`, the operator's CI computes the **anchor statement** — canonical JSON with keys
`anchor` (`qrng-beacon-log/anchor/1`), `repo`, `genesis` (pulse-0001 hash), `seq`, `type`, `pulse_hash`,
`prev_hash`, `file_sha256` — signs it with `keys/anchor.pub` (ECDSA P-256), and:
1. enters a `hashedrekord` (sha256 of the statement + signature + public key) into **Rekor**
   (`https://rekor.sigstore.dev`, log ID `c0d23d6a…`, key pinned in `keys/rekor.pub`);
2. submits the same digest to **OpenTimestamps** calendars, and upgrades the proof once it is in a Bitcoin block;
3. publishes statement, signature, Rekor entry (signed entry timestamp, inclusion proof, checkpoint) and the OTS
   proof on the `anchors` branch.

**Verification** (`ci/verify_anchors.py`; run by CI on every push and hourly): recompute the statement from the
pulse file and require byte-equality with the published one; the Rekor entry's hash must be sha256(statement) and
its key `keys/anchor.pub`; verify the signature; verify Rekor's signed entry timestamp and the inclusion proof
against the checkpoint, and the checkpoint's signature, all offline against `keys/rekor.pub`; with `REFETCH=1`,
fetch the entry live and require identity; for commits, report whether Rekor's `integratedTime` precedes the drand
release; verify the OTS proof's Bitcoin Merkle root against a public block header when complete. **Split-view
check:** enumerate every Rekor entry under `keys/anchor.pub`; each must be a published anchor. **A pulse with no
anchor 25 minutes after publication is non-compliant.** Pulses 0001–0041 were anchored retroactively
(2026-09-12 12:47 UTC); their Rekor times are not commit times.

### Resolution is two-phase (crash-safe)
The entropy host **prepares** a reveal or abandonment (statement signed, secret kept as `.revealing`/`.abandoning`)
and **finalizes** only when the aggregator confirms the resolving pulse is written **and published**. A crash between
prepare and finalize leaves `E` recoverable; prepare is idempotent. A reveal is refused once the deadline has passed;
the cycle records a signed failure instead.

### Execution self-report (`statement.execution`)
Every host statement says how it was produced, signed with the host's key: `user` (must be `beacon`), `host_config_sha256`
(must equal the published hash for that host) and either `via_forced_command: true` with `beacon_cmd_sha256` (the SSH
forced command, 0026 onward) or `via: "agentd"` with `agentd_sha256` and `request_nonce` (the machine-to-machine service
`hosts/agentd.py`, 2026-09-13 onward). `schema.execution_ok` accepts either against `hosts/EXPECTED.json`; a verifier older
than that rule rejects agentd statements with *"not executed via the forced command"* — upgrade (`notbefore` ≥ 0.14.0).

### Required clock statements must report a healthy clock
For `time` and `witness`, the verifier requires the statement's own `epoch_guard` to report `epoch_ok: true`, the
host's hardware refclock selected, and no alert. A signed statement that says "invalid" fails the pulse (ERR-007).
The aggregator refuses to mint such a pulse.

### Failure pulses
The entropy host's failure statement binds to the **commit pulse hash** and carries the reason; the verifier requires
that reason to equal the aggregator's published `derived.reason`.

### Skip pulses (v0.5.1, added 2026-09-12) — a refused commit is a chain event, not a silent gap
When a cycle cannot commit — a measurement host unreachable or reporting an unhealthy clock, the entropy host
unreachable, drand or the TSA quorum unavailable, the checkout not at the published head — the aggregator mints a
`type: "skip"` pulse: `statements: {}`, `derived.reason` (the refusal text), `derived.refused_by ∈ {entropy, gnss,
time, witness, drand, tsa, git, aggregator, unknown}`, `derived.attempted_unix_s`, `drand_round_seen` (informational),
`published_head_confirmed`. It is signed by the aggregator only, because the refusing dependency is normally the one
that cannot be asked; RFC 3161 tokens are attached when a TSA answers (best-effort, unlike commits). **What a skip
proves:** *when* the operator recorded a refusal and *what* it claimed. **What it does not prove:** that the claim is
true. **What it rules out:** nothing was selected or withheld for that hour — no commitment existed. Consumers never
consume a skip; `NOTBEFORE.md` §6 excludes it. A skip MAY follow a reveal, failure, legacy pulse or another skip and
MUST NOT follow an unresolved commit (that is resolved only by a reveal or a signed failure). A stopped timer still
leaves nothing — a planned pause is announced in `CADENCE.md` beforehand (`RECOVERY.md` §3).

### Known non-compliance
Pulses are immutable. When a verifier change makes an already-published pulse non-compliant, it is listed in
`ci/KNOWN_NONCOMPLIANT.json` with its erratum; CI counts it separately and fails if it ever unexpectedly passes.

### Canonical form
`canon(x)` = `json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` as UTF-8, over a value
domain containing **no floats and no integers outside ±(2⁵³−1)**. Producers rewrite every float and every
out-of-range integer as a decimal string before signing (`hosts/attest_lib.normalize`); verifiers **reject**
any core violating this. The result is RFC 8785-compatible and reproducible from any JSON library.

### Statement
```
{ "statement": { "v":"0.5", "role", "host", "seq", "phase": commit|reveal|failure, "binding", "chain_hash",
                 "issued_unix_ns": "<str>", "tools": [{name, sha256}...], ...role fields... },
  "signature": { "alg":"ed25519", "key_id", "public_key_b64", "sig_b64", "over":"canon(statement)" } }
```
`key_id` = SHA256(raw public key)[:16]; the key must be listed in `keys/KEYS.json` for that role with the pulse
seq inside its validity window.

### Core (v0.5)
```
{ "v":"0.5", "type": commit|reveal|failure, "seq", "prev_hash", "chain_hash",
  "statements": { "entropy", "gnss", "time", "witness" },      # failure: entropy required, others best-effort
  "drand_at_commit" | "drand",                                 # BLS-verified by the aggregator before use
  "derived": { ... },  "tooling": {...},  "aggregator_host": "k3" (0098+) | "think" (0018-0097),
  "cadence": { "source", "targeting", "trigger"?, "received_unix_ns"?, "aggregator_start_unix_ns", ... } }   # since 2026-09-13, see "Cadence trigger"
pulse = { "core", "pulse_hash" = SHA256(canon(core)), "signatures": { "aggregator" }, "disclosure" }
```
Required statements: commit/reveal → entropy, gnss, time, witness; failure → entropy. The entropy statement's
`seq` is the **commit's** seq in reveal and failure pulses (it refers to the commitment it resolves).

### State machine (enforced by the aggregator and by CI)
`legacy | reveal | failure  →  commit  →  reveal | failure  →  commit …` — at most one unresolved commit; a
reveal or failure must directly follow its commit; `seq` increments by exactly one.

v0.5.1: `skip` joins the resting states: `{legacy, reveal, failure, skip} -> commit | skip`; `commit -> reveal | failure` only. A verifier or CI that does not know `skip` rejects the first commit after a skipped hour with *"state machine: commit follows a reveal, failure or legacy pulse"* — upgrade the verifier (`notbefore` ≥ 0.3.0).

### Cadence trigger (added 2026-09-13; present in commits from the first triggered cycle onward)
A commit may carry `core.cadence.trigger`: a **statement signed by the time host** (p550, role `time_attester`, `kind:
"cadence-trigger"`) that its i210-disciplined clock reached the scheduled instant:
```
{ "statement": { "v":"0.5", "role":"time_attester", "host":"p550", "kind":"cadence-trigger", "chain_hash",
                 "scheduled_unix_s": <int, a drand round boundary>, "period_s", "offset_s",
                 "wake": { "clock":"CLOCK_REALTIME", "unix_ns":"<str>", "late_ns": <int>, "how" },
                 "phc":  { "device", "unix_ns":"<str>", "realtime_mid_unix_ns":"<str>", "phc_minus_realtime_ns", "bracket_ns", "tai_minus_utc_s" },
                 "clock_state": { "epoch_ok", "refclock_selected", "ts2phc_state", "ts2phc_offset_ns", ... },
                 "issued_unix_ns":"<str>", "nonce", "tools":[...], "execution": {...} },
  "signature": { "alg":"ed25519", "key_id", "public_key_b64", "sig_b64", "over":"canon(statement)" } }
```
`core.cadence.self_trigger` (from pulse 0098) is the aggregator's OWN wake record for the instant — `{host, scheduled_unix_s,
start_source: "hw-datagram" | "clock", datagram_rx_unix_ns?, time_host_event?, wake:{unix_ns, late_ns}, phc:{...}}` — covered by
the aggregator signature only (it is not a host statement). The time host's trigger statement may carry `hw_event`
`{source, assert_unix_ns, sequence, edge_after_instant_ns, woke_after_edge_ns}`: the PHC's own second-boundary interrupt the
process was blocked on; absent when the clock fallback fired (`wake.how` says which). `core.cadence.source`
is `"k3 clock + p550/i210 trigger"` (both present), `"k3 clock"` (self only), `"p550/i210 cadence trigger"` (think era, 0092–0095)
or `"<host>-timer"` (the :02 fallback, no instant); `core.cadence.targeting` is
`"scheduled-instant+lead"` (target round = the round released **at** `scheduled_unix_s` + `derived.lead_rounds`, so
`target_release_unix_s == scheduled_unix_s + lead_rounds*3`) or `"drand-latest+lead"` (the pre-2026-09-13 rule).
A trigger the aggregator could not verify is recorded as `cadence.trigger_rejected` and ignored; it is never fatal.
`received_unix_ns` (think, on receipt) and `aggregator_start_unix_ns` (think, when `pulse.py` started) are on think's
NTP clock and are latency bookkeeping, not attested quantities.

When both records are present the verifier requires them to name the same instant. The time host's trigger travels as a UDP
datagram (three copies); it is verified by signature, not by transport — there is no session to authenticate.

**Verifier checks** (`verify.py`, only when a trigger is present): the statement is a v0.5 `time_attester@p550`
`cadence-trigger` on the pinned chain; `key_id == SHA256(pk)[:16]`; the signature verifies over `canon(statement)`;
with `--pin`, the key is p550's `time_attester` key valid at this seq; `scheduled_unix_s` is a drand round boundary;
and, when `targeting == "scheduled-instant+lead"`, `target_release == scheduled_unix_s + lead_rounds*3`.
**What it proves:** which clock declared the hour, and that the target round was derived from that instant rather than
from when the aggregator happened to start. **What it does not change:** the protocol's ordering claims still rest on
the GNSS anchor versus the round release, and the trigger's own timestamps are that host's clock reading, not an
independent measurement of it. A reveal carries `core.cadence.aggregator_start_unix_ns` and `started_after_release_s`
(think's clock; bookkeeping).

### Timing contract
Commit: ≥ **2** RFC 3161 tokens taken at mint over the final bytes, else **nothing is written**; each token time
must be ≥ 120 s before `target_release`; the commit must be pushed ≥ 120 s before `target_release`. Reveal must
be pushed ≤ 600 s after release, else a **signed failure pulse** follows the commit.

---

# Legacy detail (v0.4 and earlier) This document is the specification; `verify.py` is the reference
implementation. Where they disagree, this document wins and `verify.py` has a bug.

## 1. Objects

A **pulse** is a JSON document `{ core, pulse_hash, signatures, disclosure }`.

- `core` — the signed content. `core.type ∈ {commit, reveal}` (pulses ≤ 0009 are `legacy`).
- `pulse_hash` = `SHA256(canonical(core))` as lowercase hex.
- `signatures` — a map `name → {signer, role, alg:"ed25519", key_id, public_key_b64, sig_b64}`; every
  signature is over the **32 raw bytes of `pulse_hash`**. Required names: `entropy` (role
  `entropy_signer`), `time` (`time_attester`), `time_witness` (`time_witness`).
- `disclosure` — human-readable notes; **not signed, not normative**.

**Canonical JSON** = `json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
encoded as UTF-8. Integers are JSON integers; no floats are introduced by canonicalisation.

`key_id` = first 16 hex chars of `SHA256(raw 32-byte public key)`. Pinned keys are published in `keys/`.

## 2. Chain

`core.seq` is a strictly increasing integer. `core.prev_hash` is the `pulse_hash` of pulse `seq−1`
(`"0"*64` for genesis). Files are `chain/pulse-NNNN.json`. A file `chain/pulse-NNNN.FAILED.json`
records that pulse `NNNN` breached §5 and MUST be treated as failed by consumers.

## 3. Commit pulse

```
core.commitment.entropy_commitment = SHA256( "grok_antics/commit/v1" || E )      E = 32 bytes
core.commitment.target_round       = R          (drand quicknet round, strictly > drand_at_commit.round)
core.commitment.target_release_unix_s = 1692803367 + 3·(R − 1)      (drand: round 1 is AT genesis — see ERR-004)
core.drand_at_commit               = the latest drand round at mint (proves "not earlier than")
core.time                          = §6 time block; core.time.anchor.utc_unix_s MUST be < target_release
```
The entropy `E` MUST NOT appear anywhere in a commit pulse. The publisher MUST publish the commit pulse
before `target_release`. Evidence: (a) RFC 3161 tokens `pulse-NNNN.json.<tsa>.tsr` over the exact file
bytes, taken at mint — these prove the **published** commitment **existed** before the round; (b) the public
log's history. **Neither proves uniqueness**: an operator could stamp several candidates and publish one.
Durable proof that the published commitment was the uniquely public one depends on a third party
observing or mirroring the log before the round (`watcher.py` COMMIT-RECEIPT records).

## 4. Reveal pulse

```
core.reveals.commit_seq / commit_pulse_hash   identify the commit; core.prev_hash MUST equal commit_pulse_hash
core.reveals.entropy_hex                      E
core.external_anchor                          drand round == R exactly; randomness == SHA256(signature)
core.attested_value = SHA256( "grok_antics/pulse-mix/v1" || E || randomness(32) || chain_hash(32) || R as uint64 big-endian )
```
`chain_hash` = `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` (drand quicknet). All
fields are fixed-length, so the preimage is unambiguous without separators. **Consumers use
`attested_value`; `entropy_hex` alone is not the output.**

## 5. Timing contract (CADENCE.md)

commit pushed ≥ 120 s before `target_release`; reveal pushed ≤ 600 s after. Breach → FAILED marker. A
commit with neither a reveal nor a FAILED marker after the deadline is a **withheld reveal**; an
independent watcher (`watcher.py`) publishes a signed NON-REVEAL record under its own key.

## 6. Time block

`core.time.anchor` is a GNSS epoch (`gps_week`, `gps_tow_ms`, `tow_time_base`) whose TP1 **falling,
on-time** edge was captured in i210 hardware. Uncertainty terms are published as measured, with their
windows and sample counts; a statistic with fewer than 3 samples is `null`, never a guess. Software read
latency is reported under `orchestration` and is a freshness limit, not part of the anchor.

## 7. Verification algorithm (what `verify.py` does)

1. `SHA256(canonical(core)) == pulse_hash`; every signature verifies over that **recomputed** digest;
   keys match pins if provided.
2. commit: `target_round > drand_at_commit.round`; `anchor.utc_unix_s < target_release`; drand fields
   self-consistent (`randomness == SHA256(signature)`).
3. reveal (with its commit as `--prev`): `SHA256(domain||E) == entropy_commitment`; `prev_hash ==
   commit_pulse_hash`; `external_anchor.round == target_round`; `randomness == SHA256(signature)`;
   `attested_value` recomputes; `commit.anchor < round release ≤ reveal.anchor`.
4. `--refetch`: fetch `https://api.drand.sh/<chain>/public/<round>` and compare randomness + signature.
5. RFC 3161: `openssl ts -verify -data <pulse> -in <tsr> -CAfile …` for each token (`tsa.py verify`).
6. **BLS (automatic when `py_ecc` is installed; `--no-bls` skips):** verify the drand signature under the
   **pinned** League of Entropy quicknet group key `keys/drand-quicknet.json`:
   `e(σ, g₂) == e(H(m), pk)` on BLS12-381, σ ∈ G1 (48 B), pk ∈ G2 (96 B), `m = SHA256(round as uint64 BE)`,
   `H` = RFC 9380 hash-to-G1 with DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`, plus curve and
   prime-order-subgroup checks on both points. The pin was cross-checked across three independent LoE
   relays on 2026-09-12 and is never overwritten (a key rotation is a new chain hash and a new pin).
   This removes the HTTP relay, DNS and TLS from the trust base of the reveal: a fabricated or relabelled
   round cannot pass, whatever `api.drand.sh` serves. Remaining assumptions: the pin is genuine, and
   ≥ threshold of the League's operators are honest. Reference implementation: `bls_drand.py`
   (pure Python, ~1 s per round).

## 8. What a valid reveal proves, and what it assumes

Proves: the attested value was not computable by anyone before `target_release`, and the **published**
commitment to `E` existed (third-party TSA) before `R`, so `E` was not chosen with knowledge of `R` —
**provided** that commitment was the uniquely public one, which requires pre-round observation of the log.
Assumes: the commit was published before `R` (check the TSA tokens and log history); drand's threshold
is honest; SHA-256 preimage resistance; Ed25519 keys are the operator's.
Does not claim: fitness for gambling, certification by any body, or absolute UTC accuracy (L1-only GNSS).

## Commit-bound value V* (consumer-facing; defined 2026-09-13)

Every published v0.5 **commit** defines, once its target round R exists, a value that no later action of the operator
can change:

    V* = SHA256( "notbefore/commit-bound/v1" || C || rho_R || chain_hash || R_be8 )          (25 + 32 + 32 + 32 + 8 = 129 bytes)

`C` = `core.derived.entropy_commitment` (= SHA256(D_commit ‖ E), fixed before R was knowable), `rho_R` = the drand
quicknet randomness of round R (= SHA256(BLS signature), verified under the pinned group key), `chain_hash` =
`core.chain_hash`, `R_be8` = `core.derived.target_round` as 8-byte big-endian. V* is a *derived* quantity: it is not
published in any pulse and any verifier computes it from the commit pulse and the drand round alone. The reveal of E
proves **provenance** (that C committed to specific QRNG bytes; the beacon's attested value V is recomputable) and does
not change V*. Consumers that select by commit (NOTBEFORE.md §7.13, `notbefore/contract/3`) label an hour
**FULL-ATTESTED** when the reveal verifies and **COMMITMENT-FALLBACK** when it does not; the value is the same.

A commit counts for such consumers only if it was demonstrably public before its round: both RFC 3161 tokens strictly
before the release **and** a Rekor anchor whose **signed** `integratedTime` precedes the release. The time is read from
Rekor's signed entry (SET), never from a record's unsigned copy; a verifier obtains it from Rekor itself when online
(entries located by the SHA-256 of the anchor statement derived from the pulse bytes, verified under the pinned anchor
and Rekor keys) or from a signature-verified record offline. Absence of a record in the operator's anchors branch is
not evidence: a verifier that cannot establish a candidate's eligibility MUST halt rather than advance to a later
commit; only Rekor's own "no entry" after the 1500 s anchor grace period, or a signed time at/after the release,
proves ineligibility. That makes eligibility a pre-round, irrevocable fact: nothing decided with knowledge of rho_R
can make an eligible commit ineligible or vice versa (ERR-015). The operator retains only pre-round, blind choices (skip, delay publication — visible in the log and in CI),
which cannot bias a decision; it can still withhold provenance and stall the cadence. Rationale and residuals:
`FALLBACK.md`.

## Timing profile (consumer-facing verification policy; defined 2026-09-13)

A pulse's timing statements (`time`, `witness`, `gnss`) are **authenticated** by their host signatures and pulse binding.
Since `notbefore` 0.13.0 a consumer may also declare, in its contract and before the round, a **timing profile** the
selected commit's evidence must satisfy — a versioned, testable acceptance policy evaluated identically online, in
receipts and in offline bundles, and reported **separately** from cryptographic integrity and from the application result.

`notbefore/timing/v1` requires, on the selected commit (and on its reveal when one verifies):

| role | required observations | limits |
|---|---|---|
| time (p550) | `epoch_guard.epoch_ok`, `chrony_selects_iphc`; `discipline`: servo `ts2phc`, states `["s2"]`; `mesh_crosscheck` present | discipline: ≥ 3 samples, RMS ≤ 100 ns, \|min\|,\|max\| ≤ 250 ns; mesh: ≥ 3 samples, RMS ≤ 250 ns, \|min\|,\|max\| ≤ 1000 ns, monitor states `["s0"]` (a free-running monitor is expected in s0), 0 < path_delay ≤ 10 000 ns, BMC Announce mentions clockClass 6 (an observation, not authentication) |
| witness (k3) | `epoch_guard.epoch_ok`, `chrony_selects_refclock`; `discipline` states `["s2"]` | ≥ 10 samples, RMS ≤ 250 ns, \|min\|,\|max\| ≤ 1000 ns |
| gnss (f9t) | `anchor.utc_available_flag`; leapS + 19 == TAI−UTC | sawtooth-log coverage ≥ 95 % over the window, sawtooth sd ≤ 10 ns, \|qErr\| ≤ 50 ns for the epoch, ≥ 8 raw measurements in the fix |
| cross-statement | every statement's TAI−UTC equal (37) | every `CLOCK_REALTIME` stamp within 600 s of the GNSS anchor epoch (freshness, never accuracy); the pulse's own anchor within 600 s of the GNSS epoch |

Verdicts: **SATISFIED**, **NOT-SATISFIED** (an observation outside its limit), **NOT-EVALUABLE** (required evidence
missing or malformed — non-finite numbers, wrong types, no statements; pulses before 0018 are NOT-EVALUABLE by
construction). Missing optional evidence never grants a timing claim. **The profile never changes which commit a
contract consumes:** with `timing.required = false` the verdict is reported in the transcript; with `required = true`
a verdict other than SATISFIED refuses execution *on the selected commit* — no other value is tried (no timing-triggered
reroll; this extends the R2/R5 rule). Calibration: every healthy v0.5 commit and reveal in the record (0020–0071)
satisfies v1; 0018/0019 (KNOWN-NONCOMPLIANT, witness guard misfired) do not. Minting still gates only on epoch health
and reference selection; a profile failure at mint is published, not hidden. Implementation: `cli/notbefore/timing.py`.
