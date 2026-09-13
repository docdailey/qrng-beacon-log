# NotBefore — specification

**Status:** draft 0.9, 2026-09-13 — 0.8 with the commit-bound rule's evidence and verdict semantics fixed after an adversarial review (ERR-015: publication evidence from Rekor's signed entries, halt when it cannot be established; VERIFIED / DEGRADED / INVALID verdicts); 0.8 added the **commit-bound value** (§4.6, §7.13: contracts consume V* fixed by the commit and the drand round, so a withheld reveal cannot change or void a decision); 0.7 made execution fail closed on the decision log (§7.12: an unconfirmed registration is a refusal, not a warning); 0.6 added signed contracts and the write-once decision log (§7.12: a consumer identity, `contract/2`, and a second transparency log in which the first statement per decision wins); 0.5 added decision contracts (§7.11: the consumer's commitment, timestamped before the pulse); 0.4 added the derived functions `sample`/`assign`/`id`/`range`/`bytes` (§7.6–7.10) and the tool commands `explain`/`pin`/`diff-transcript` (§8); 0.3 added the `skip` pulse type (protocol v0.5.1); 0.1 was reviewed against the live code and chain by claude-main; every change is listed in §16  
**Implements over:** `qrng-beacon-log` protocol v0.5 (live log)  
**Normative language:** MUST / MUST NOT / SHOULD / MAY

NotBefore is a **public, hourly, commit-then-reveal seed** with a **labeled derivation** API.  
It proves a 32-byte value was **fixed before** a named drand quicknet round and **not selected after** that round existed. It does not prove the bits are quantum, secret, certified, or unique in the universe.

The running publication log is the GitHub repository `docdailey/qrng-beacon-log`. This spec names the *product contract* a consumer can rely on. Wire formats already on disk keep their existing domain tags until a tagged protocol cut.

---

## 0. One paragraph

Once an hour the entropy host draws 32 bytes \(E\), publishes \(C = \mathrm{SHA256}(D_{\mathrm{commit}} \| E)\) bound to a **future** quicknet round \(R\), and notarizes that commit with two RFC 3161 TSAs before \(R\) exists. After \(R\) is published by the League of Entropy, the host reveals \(E\) and the attested value is

\[
V = \mathrm{SHA256}(D_{\mathrm{mix}} \| E \| \rho \| H_{\mathrm{chain}} \| R_{\mathrm{be8}})
\]

where \(\rho\) is the 32-byte quicknet randomness for \(R\). A consumer who needs a seed for a *purpose* computes

\[
S = \mathrm{SHA256}(D_{\mathrm{derive}} \| V \| \mathrm{purpose})
\]

and records \((\mathrm{seq}, \mathrm{purpose}, S)\). That is the whole product.

---

## 1. Goals and non-goals

### 1.1 Goals

- Publish one checkable 32-byte **attested value** \(V\) per successful hour.
- Make “fixed before \(R\), not chosen after seeing \(R\)” independently verifiable with no access to the lab.
- Give an engineer a deterministic **labeled seed** \(S\) from \(V\) so a roster shuffle or data split can be reproduced from the public log.
- Fail closed: no \(V\), no \(S\).

### 1.2 Non-goals (MUST NOT be claimed)

- Secret key generation or custody of customer key material.
- Licensed gaming / lottery / GLI.
- NIST / FIPS / SP 800-90B / AIS-31 / Common Criteria / ISO 17025 of *this service*.
- Absolute UTC accuracy; nanosecond *stamp* accuracy.
- That \(V\) is “quantum” as a verified property (the source *device* may be named; `verify` does not check physics).
- That RFC 3161 proves uniqueness (it proves **existence** of those bytes at \(T\)).
- Defense against a hostile operator who administers every host (out of scope; bounded only by drand + TSA + public anchors + a watcher the operator does not control).
- Immutability, or *prevention* of operator equivocation. A split view (two valid pulse-\(N\)s) is **detectable** — anchors (§4.5) and watchers — not prevented. Say "detectable".
- Any cryptocurrency position. OpenTimestamps is a timestamp proof (a Merkle path into a Bitcoin block header); nothing is held, bought, or paid.

---

## 2. Names and objects

| Name | Symbol | Meaning |
|---|---|---|
| NotBefore pulse \(N\) | — | The public commit+reveal pair whose reveal seq is \(N\) (first compliant reveal is 21; see §6). The pair is identified by `core.derived.commit_seq` on the reveal, **never by parity** |
| Commit pulse | — | `core.type == "commit"`, publishes \(C\) and target \(R\) |
| Reveal pulse | — | `core.type == "reveal"`, publishes \(E\) and \(V\) |
| Anchor | — | The Rekor + OpenTimestamps entry for a pulse, on the `anchors` branch (§4.5) |
| Attested value | \(V\) | Mix output; the only value that may be called “NotBefore attested” |
| Purpose | \(P\) | Non-secret UTF-8 label for a use of \(V\) |
| Derived seed | \(S\) | \(\mathrm{SHA256}(D_{\mathrm{derive}} \| V \| P)\); this is what programs consume |
| Tape | — | Optional later publication of unselected batch leaves; **not** attested (§11) |

Speak of **NotBefore 41** meaning reveal pulse 0041 and its predecessor commit.

In the live log so far commits happen to be even and reveals odd. That is incidental: a signed `failure` pulse (commit → failure → commit) flips it. Implementations MUST key on `type` and `derived.commit_seq`, never on parity.

---

## 3. Cryptographic constants

Live log (protocol v0.5, do not change until a version cut):

```
H_chain     = 52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
              (drand quicknet chain hash)
genesis     = 1692803367
period      = 3
release(R)  = genesis + (R - 1) * period     # round 1 is AT genesis (ERR-004)
D_commit    = "grok_antics/commit/v1"        # UTF-8 bytes
D_mix       = "grok_antics/pulse-mix/v1"     # UTF-8 bytes
```

This spec **adds**:

```
D_derive    = "notbefore/derive/v1"          # UTF-8 bytes
```

A future protocol cut SHOULD retag commit/mix to `notbefore/commit/v1` and `notbefore/mix/v1`. Until that cut, verifiers MUST accept the live tags above. New derive implementations MUST use `notbefore/derive/v1` only.

Quicknet scheme: `bls-unchained-g1-rfc9380`.  
\(\rho = \mathrm{SHA256}(\sigma)\) where \(\sigma\) is the BLS threshold signature on \(m = \mathrm{SHA256}(R\) as uint64 BE\()\).  
Full check: \(e(\sigma, g_2) = e(H(m), \mathrm{pk})\) under the pinned group key in `keys/drand-quicknet.json`.

Ed25519 keys and validity windows: `keys/KEYS.json`.

Where the objects live in a v0.5 pulse (verified on 0040/0041):

```
C   commit: core.statements.entropy.statement.entropy_commitment   (also core.derived.entropy_commitment)
R   commit: core.derived.target_round        reveal: core.drand.round
E   reveal: core.statements.entropy.statement.entropy_hex
ρ   reveal: core.drand.randomness            σ: core.drand.signature
V   reveal: core.derived.attested_value      (mix documented in core.derived.mix)
```

Publication anchors (since 2026-09-12, §4.5):

```
anchor statement domain   qrng-beacon-log/anchor/1        (ci/anchor_lib.statement_for)
anchor key                keys/anchor.pub   ECDSA P-256, id 0ba35c3f423663b7
Rekor                     https://rekor.sigstore.dev   log ID c0d23d6a…  key pinned in keys/rekor.pub
```

---

## 4. Hourly protocol (normative, live)

### 4.1 Commit (seq \(N-1\), type `commit`)

Entropy host draws \(E \in \{0,1\}^{256}\), holds it, and signs a statement containing

\[
C = \mathrm{SHA256}(D_{\mathrm{commit}} \| E),\quad R_{\mathrm{target}}
\]

with \(R_{\mathrm{target}}\) strictly after the latest quicknet round at commit time. Default lead: **100 rounds ≈ 5 min**.

GNSS, time, and witness hosts each sign their own measurement, bound to \(\{seq, phase, C, H_{\mathrm{chain}}\}\).

Aggregator assembles `core`, computes `pulse_hash = SHA256(canonical(core))`, signs the assembly only.

Publication MUST include:

- `chain/pulse-00xx.json`
- two RFC 3161 tokens (freetsa + DigiCert), label `at-commit`
- git push to `main` **≥ 120 s** before `release(R_target)` (computed, not the field that may still carry ERR-004 +3 s on old pulses)

A commit whose tokens or push miss the margin is **FAILED**, not late-OK.

### 4.2 Reveal (seq \(N\), type `reveal`)

After `release(R_target)` exists: disclose \(E\), same \(R\), compute

\[
V = \mathrm{SHA256}(D_{\mathrm{mix}} \| E \| \rho \| H_{\mathrm{chain}} \| R_{\mathrm{be8}})
\]

- \(E\): 32 bytes  
- \(\rho\): 32 bytes quicknet randomness  
- \(H_{\mathrm{chain}}\): 32 bytes  
- \(R_{\mathrm{be8}}\): `R` as uint64 big-endian (8 bytes)  
- \(D_{\mathrm{mix}}\) = ASCII `grok_antics/pulse-mix/v1` = **24 bytes**; preimage length 24 + 32 + 32 + 32 + 8 = **128 bytes** (recomputed against pulse 0041's `attested_value`: equal). Implementations MUST use the exact live domain string.

Reveal MUST be pushed **≤ 600 s** after `release(R_target)`. GNSS reveal anchor MUST be \(\ge\) that release. Predecessor MUST be the matching commit. `SHA256(D_commit \| E)` MUST equal the commit’s \(C\).

### 4.3 Failure

If the reveal cannot be published in time, the chain MUST grow a signed `failure` bound to the commit pulse hash. Consumers MUST treat that hour as having **no** \(V\). There is no substitute leaf and no “use last hour.”

### 4.2a Commit-bound value V* (spec 0.8)
For any v0.5 commit with commitment \(C\), chain hash and target round \(R\), once round \(R\) exists:

\[ V^* = \mathrm{SHA256}(\texttt{"notbefore/commit-bound/v1"} \,\|\, C \,\|\, \rho_R \,\|\, \mathrm{chain\_hash} \,\|\, R_{be8}) \]

(129-byte preimage; \(\rho_R = \mathrm{SHA256}(\sigma_R)\) BLS-verified under the pinned quicknet key). \(V^*\) is fixed by data
the operator committed to before \(\rho_R\) was knowable and by data nobody here controls; no reveal, failure, skip or
silence afterwards changes it. In the random-oracle model it is as unpredictable as \(E \oplus\) drand (\(C\) is a hash of
\(E\)). The reveal keeps its role as **provenance**: it shows \(C\) committed to genuine QRNG bytes and lets the beacon's
own \(V\) (§4.2) be recomputed. Labels: **FULL-ATTESTED** (reveal verifies) / **COMMITMENT-FALLBACK** (it does not).
\(V^*\) is never published in a pulse; every verifier derives it (`notbefore.commitbound.value`). Normative text:
`PROTOCOL.md` §"Commit-bound value".

### 4.3a Skip (protocol v0.5.1)

If a cycle cannot commit at all (a host unreachable or unhealthy, drand/TSA/git unavailable), the aggregator publishes a `type: "skip"` pulse with `derived.reason` and `derived.refused_by`, aggregator-signed, RFC 3161 when available. It is **not** consumable and produces no \(V\). It MAY follow a reveal, failure, legacy pulse or skip; it MUST NOT follow an unresolved commit. Verifiers older than this rule reject the first commit after a skip ("state machine: commit follows a reveal, failure or legacy pulse"); `notbefore` ≥ 0.3.0 accepts it.

### 4.4 Host isolation (v0.5)

From seq **18** statements are per-host. From seq **26** each statement MUST carry an `execution` block matching `hosts/EXPECTED.json` (user `beacon`, forced command, published `beacon-cmd` and host-config hashes).  
Seq **18–19** are KNOWN-NONCOMPLIANT (ERR-007). They MUST NOT be consumed.

Pulses **1–17** are legacy digest signatures (ERR-005). They MAY be verified as a hash chain. They MUST NOT be called host-attested. They SHOULD NOT be used as NotBefore seeds.

---

### 4.5 Publication anchors (normative for the operator; since 2026-09-12)

For every published pulse the operator's CI signs the canonical **anchor statement** (derivable from the pulse file alone) with `keys/anchor.pub` and enters it into **Rekor** (hashedrekord) and **OpenTimestamps**; proofs live on the `anchors` branch. A pulse with no Rekor anchor 25 minutes after publication is non-compliant. Every Rekor entry ever made under the anchor key MUST correspond to a published pulse; `ci/verify_anchors.py` enumerates them (the split-view check). Pulses 0001–0041 were anchored **retroactively** (2026-09-12 12:47 UTC); from 0042 the anchor is contemporaneous and a commit's Rekor `integratedTime` precedes `release(R)` (first live case: 0042, 129 s before). See `PROTOCOL.md` and ERR-008.

---

## 5. Verification (consumer)

A consumer MUST be able to verify from an empty directory:

```text
pip install cryptography py_ecc
git clone https://github.com/docdailey/qrng-beacon-log.git
cd qrng-beacon-log
python3 verify.py chain/pulse-NNNN.json --prev chain/pulse-MMM.json --pin keys --refetch
python3 tsa.py verify chain/pulse-MMM.json
git worktree add anchors origin/anchors && pip install opentimestamps-client
REFETCH=1 python3 ci/verify_anchors.py --anchors anchors      # SHOULD (consumer); MUST (operator CI)
```

`verify.py` MUST check, and a NotBefore consumer MUST require all of:

1. `pulse_hash == SHA256(canonical(core))`
2. Every required Ed25519 signature over the object the role actually attests (v0.5) or over the digest (legacy — do not consume)
3. Keys in `KEYS.json` validity window for that seq
4. Hash chain `prev_hash`
5. \(C = \mathrm{SHA256}(D_{\mathrm{commit}} \| E)\)
6. \(R\) on the reveal equals the commit target
7. \(\rho = \mathrm{SHA256}(\sigma)\); \(\sigma\) BLS-verifies under the pinned quicknet key
8. Live refetch of \(R\) matches the pulse (when network is available)
9. \(V\) recomputes
10. `release(R)` computed as §3; commit published ≥ 120 s before; reveal after release and ≤ 600 s after
11. Two TSA tokens verify on the commit; token time ≤ `release(R) - 120`
12. SHOULD: both pulses of the pair have anchors that verify (`verify_anchors.py`), and no Rekor entry under `keys/anchor.pub` is unexplained

Exit non-zero ⇒ MUST NOT emit \(V\) or \(S\).

---

## 6. Eligibility for consumption

A reveal pulse \(N\) is a **NotBefore-eligible** seed if and only if:

| Rule | Requirement |
|---|---|
| Protocol | `core.v == "0.5"` |
| Seq | \(N \ge 21\) (18–19 are KNOWN-NONCOMPLIANT, ERR-007) |
| Pair | Predecessor is commit \(N-1\), verified together |
| Execution | If \(N-1 \ge 26\), execution blocks enforce |
| CI list | seq not in `ci/KNOWN_NONCOMPLIANT.json` |
| Type | reveal succeeded (not `failure`, not `skip`) |
| Verifier | current `verify.py` + `tsa.py` exit 0 |
| Anchor | SHOULD: `verify_anchors.py` passes for the pair; for \(N \ge 42\) the commit's Rekor `integratedTime` precedes `release(R)`; for \(N \le 41\) anchors are retroactive (existence from 2026-09-12 12:47 UTC only) |

**First eligible pair:** 0020/0021.  
**Preferred floor:** 0026/0027 (execution enforced).  
**Current cadence:** hourly on the hour, host `think`, timer `qrng-beacon.timer`.

If the named hour is ineligible or missing, the consumer MUST take a **later** eligible hour named in advance as the alternate (the next eligible reveal in the log — typically the next cycle; a `failure` pulse shifts numbering, so name it by rule, not by \(N+2\)), never an earlier one, never a “best of three.”

---

## 7. Derive API (the useful layer)

### 7.1 Purpose

`purpose` is UTF-8 NFC, 1–256 bytes, non-secret.  
MUST match `^[A-Za-z0-9._:/=@+-]+$` if used on a CLI (no spaces; use `-` or `_`).  
SHOULD be stable and specific: `clinic-qi-roster-2026-09-12`, `split:iris-csv:v3`.

### 7.2 Derived seed

```
S = SHA256(  D_derive  ||  V  ||  purpose  )
```

- \(D_{\mathrm{derive}}\) = ASCII `notbefore/derive/v1` (19 bytes)
- \(V\) = 32 raw bytes of attested_value (decode hex)
- `purpose` = raw UTF-8 bytes, no length prefix, no delimiter other than the domain (domain is fixed-length ASCII so this is unambiguous)

Output: 32 bytes, hex lowercase for display.

Different purposes MUST produce independent \(S\) (as far as SHA-256 preimages). The same \((N, purpose)\) MUST always produce the same \(S\).

### 7.3 Shuffle

Input: ordered list of records \(x_0,\ldots,x_{k-1}\), pulse \(N\), purpose \(P\).

```
key = S(N, P)
rank(x) = SHA256( "notbefore/shuffle/v1" || key || uint64_be(i) || utf8(x_i) )
```

Stable sort by `rank` ascending, hex tie-break on `x`.  
The list order *before* shuffle is part of the transcript and MUST be archived with \(N\) and \(P\).

### 7.4 Split

Input: ordered list, pulse \(N\), purpose \(P\), fraction \(f \in (0,1)\).

Shuffle as §7.3. First \(\lfloor f \cdot k \rfloor\) items = set A, rest = set B.  
Do not re-draw.

### 7.6 Sample — exactly \(K\)
`sample N --purpose P --k K file`: shuffle as §7.3, take the first \(K\) (\(0 \le K \le k\)). "Pick 12 charts"; `split`
with an odd fraction is the wrong tool for an exact count.

### 7.7 Assign — balanced arms
`assign N --purpose P --arms m file`: shuffle as §7.3; shuffled position \(i\) (0-based) → arm \(i \bmod m\) (0-based).
Arm sizes differ by at most one. Output: `record<TAB>arm`, in shuffled order.

### 7.8 Id — pseudonyms
`id N --purpose P --from file [--len 16]`: each line → `hex(SHA256("notbefore/id/v1" || S || line))[:len]`, in input
order, one per line, **without** the line. A pseudonym is not a secret: anyone who holds the name list and the (public)
\(S\) recomputes it. It blinds readers who lack the names; it does not encrypt them. Do not put raw names in the output.

### 7.9 Range — uniform integer
`range N --purpose P --lo a --hi b`: uniform in \([a,b]\) by rejection sampling: for counter \(c = 0,1,\dots\),
\(r_c\) = first 8 bytes of `SHA256("notbefore/range/v1" || S || c_be8)` as uint64 BE; with `span = b−a+1` and
`limit = ⌊2⁶⁴/span⌋·span`, the first \(r_c <\) `limit` gives \(a + (r_c \bmod\) `span`\()\). Unbiased; deterministic.

### 7.10 Bytes — a public byte stream
`bytes N --purpose P --n n`: first \(n\) bytes of counter-mode SHA-256, `SHA256("notbefore/bytes/v1" || S || c_be8)`
for \(c = 0,1,\dots\). Suitable to seed a local CSPRNG for a reproducible simulation. **Public if \(P\) is public** —
never use it as key material.

### 7.11 Decision contracts — the consumer's commitment (spec 0.5)
The log commits its entropy before the public randomizer; this closes the other side: the **consumer commits the
decision before the NotBefore value exists**. `notbefore plan` writes a canonical JSON contract
(`notbefore/contract/1`): a selection rule, the purpose, the operation and every parameter, and the input file's
SHA-256 and record count. Its bytes are **timestamped** by two public RFC 3161 TSAs (freetsa, DigiCert) — the same
kind of third-party evidence the log's commits carry. **This is timestamping, not registration:** it proves the
bytes existed at T; it does not force the user to disclose them later. Publishing the SHA-256 where it cannot be
withdrawn is the user's job until a decision log exists (`DECISION-LOG.md`).

**Canonical form** is RFC 8785 JCS. A contract contains only strings, integers, objects and arrays — never a float;
`frac` is a decimal string applied exactly (`floor(Fraction(frac) · n)`) — so any JCS implementation reproduces the
same bytes and the same hash.

**Selection rule** `first-eligible-reveal-released-at-or-after(after_utc)`: walk reveals in seq order; the first one
whose drand round released at or after `after` **and** whose pair verifies under the pinned verifier is the pulse.
Failure and skip hours and KNOWN-NONCOMPLIANT seqs are passed over by the rule, never by a person.

**Execution** `notbefore execute contract.json` accepts no choices. It MUST: verify the contract is canonical
(byte-identical to its hash); verify **both** expected TSA tokens and refuse if either is missing, if any token fails
to verify, or if an unexpected TSA identity is present; select the pulse by the rule with **no candidate limit**;
**refuse unless the LATEST token time is strictly before that pulse's round release** (one early token and one late
token is a refusal — the decision could have been finalized with knowledge of \(V\)); refuse if the input bytes
differ from the committed SHA-256; then run the operation with the contract's parameters and write a transcript
carrying the contract hash, the timestamp times and the selection. A contract with missing tokens runs only with
`--allow-unregistered`, labelled as such in the transcript; that flag never overrides a failing or late token.
`plan` exits non-zero if it could not obtain both tokens; `notbefore timestamp <contract>` requests only the missing
one, idempotently.

**What it proves.** That this exact decision — rule, purpose, operation, parameters, input — existed at the TSA
times, before the value it depends on was knowable; combined with the log's own commitment, neither party chose
after seeing the thing that mattered. **What it does not prove:** that the *only* contract registered was this one.
A user can still timestamp several and publish one; §7.12 closes that with the write-once decision log. (Before 0.6
the defence was the same as for any preregistration — publish the hash where it cannot be quietly withdrawn.)

### 7.13 Commit-bound contracts — the operator cannot steer (spec 0.8)
Since 0.8 a signed contract is `notbefore/contract/3`: contract/2 plus `value: {rule: "commit-bound", domain:
"notbefore/commit-bound/v1"}` and the selection rule `first-eligible-commit-released-at-or-after(after_utc)`.
**Commit eligibility:** protocol v0.5, seq ≥ 20, not KNOWN-NONCOMPLIANT, the vendored verifier passes on the commit
(host statements, chain link), both RFC 3161 tokens verify with the LATEST strictly before the round release, **and**
a Rekor anchor for the commit with `integratedTime` strictly before the release (third-party evidence the commit was
public before the randomness existed). A commit *proved* to lack one of these is passed over *by rule*, and the transcript
says so. **Proof, not absence (0.9 / ERR-015):** the anchor's time is Rekor's SIGNED `integratedTime`, taken from
Rekor itself when online (entries found by the statement hash derived from the pulse bytes, verified under the pinned
anchor and Rekor keys) or from a signature-verified record offline; a record's unsigned fields are never read. A
candidate whose eligibility cannot be established — no Rekor answer and no verified record, an unauthenticated copy of
the pulse, missing token sidecars — HALTS execution; the verifier never advances past it. "Rekor has no entry" is
decisive only once the anchor grace period (1500 s) after the round has passed. **Execution** computes \(V^*\) (§4.2a) from the selected commit and \(\rho_R\) — taken from the verifying
reveal (FULL-ATTESTED) or fetched from drand and BLS-verified under the pinned key (COMMITMENT-FALLBACK); while the
reveal window (600 s) is still open and no reveal exists it MUST wait (exit 3) so the label is final — and derives
\(S = \mathrm{SHA256}(D_{derive} \| V^* \| P)\) exactly as before. The transcript carries `value_rule`, `provenance`,
`commit_bound_value`, `commit_seq`, `reveal_seq` (or null), the drand round with its signature (so a bundle can
re-verify offline), and `publication_evidence` (the Rekor record's time relative to the release). `contract/1` and
`contract/2` keep the reveal-based rule for their own transcripts.

**What this closes.** After the round exists the operator knows \(V^*\) but has no second value to choose: revealing,
failing or staying silent leaves it unchanged, and eligibility was fixed before the round by clocks the operator does
not run. **What remains:** the operator can still stall (skip, delay publication or anchoring — all before knowing
\(\rho_R\), hence blind, and all visible), and can withhold *provenance* for an hour. Operational note: since
2026-09-12 12:47 UTC every commit has been Rekor-anchored 129–208 s before its round.

### 7.12 Signed contracts and the decision log — first statement wins (spec 0.6)
**Identity.** `notbefore keygen` creates one Ed25519 key per consumer (`~/.config/notbefore/identity.key`, 0600, never
uploaded); `key_id = SHA256(raw public key)[:16]` (the log's own key convention, PROTOCOL.md §5). There is no
recovery and no escrow: a lost key is an abandoned namespace.

**Contract/2** = contract/1 plus `signer {alg: ed25519, key_id, public_key_b64}` and `decision_id` (default: the
purpose string; ^[A-Za-z0-9._:/=@+-]{1,256}$). For serious use `decision_id` SHOULD be bound to an external artifact
so that renaming is visible to whoever holds it — cryptography does not recognise semantic aliases. Convention:
`<registry id>/<protocol version>/<decision>`, e.g. `NCT01234567/protocol-3/randomization-1` or `audit-order-8812/v2/sample-1`.

**Decision statement.** `plan` signs `{"spec": "notbefore/decision/1", decision_id, key_id, public_key_b64,
contract_sha256, contract_spec, created_utc}` (canonical JSON) with the identity key and writes statement + signature
to `<contract>.sig.json`. The statement names the contract by **hash**: registering discloses nothing about the
decision unless `--disclose` publishes the body too.

**The decision log** (`DECISION-LOG.md`) is a second C2SP transparency log, origin `notbefore.net/decisions`
(`keys/DECISIONS.json`, key `keys/decisions.pub`), RFC 6962 over canonical leaves
`{"spec": "notbefore/decision-leaf/1", index, received_utc, seq_in_namespace, statement, signature_b64, tsa_sha256,
contract_disclosed}`. **Write-once rule:** `(key_id, decision_id)` is a namespace; the first valid statement appended
for it has `seq_in_namespace 1` and is the authoritative preregistration; later ones are amendments and are never the
entry `execute` accepts for the original randomization. Submission is idempotent per `contract_sha256`; nothing is
updated or deleted. The log is mirrored byte-for-byte into `decisions/` in the repository, its checkpoints are
witness-cosigned there and anchored into Rekor like the pulse log's.

**Client trust.** The CLI trusts only the vendored origin and key: a receipt or lookup counts only after the
checkpoint note verifies under `keys/decisions.pub`, the leaf is canonical and its statement verifies, and the
inclusion proof reaches the note's root. A receipt that fails is an error.

**Execution** additionally MUST: verify the `.sig.json` statement against the contract's bytes, signer and
`decision_id` (refuse otherwise); look the namespace up (live, or the `decisions/` mirror when `--offline`); **refuse
if the first entry for the namespace is a different contract** (superseded) or if the authoritative entry was received
at or after the round release; record `decision_log {status, index, seq_in_namespace, size, root_b64, received_unix}` in
the transcript. **Since 0.7 execution FAILS CLOSED:** `unregistered`, `unreachable`, `disabled` and `mirror-absent`
are refusals — the log, not the consumer, says which contract was the preregistration, and a property that matters
must not depend on a reviewer noticing a warning. `--allow-unregistered` is the single, explicit escape hatch for a
DEGRADED run (missing tokens, unconfirmed registration, legacy `contract/1`), labelled as such in every line of the
transcript; it never overrides a late token, a superseded contract or a registration at/after the round. The
verifier binds every decision-log leaf it trusts to the queried `(key_id, public_key, decision_id)` and
`seq_in_namespace = 1` explicitly — an inclusion proof shows a leaf is in the tree, not that it belongs to the
namespace asked about — and, offline, scans the mirrored tree for an earlier leaf in the namespace rather than
trusting `INDEX.json`. Legacy `contract/1` files execute only with `--allow-unregistered`, labelled `contract_spec` and
`contract_signature_verified: false`. `plan` exits non-zero if the submission fails; `notbefore register <contract>`
retries it idempotently.

**What it proves, now.** Both that this exact decision existed before the value was knowable (RFC 3161 tokens, and
the log's receipt time fixed by anchored checkpoints) and that it was **the** preregistration for its
`(key_id, decision_id)`. **What it still does not prove:** that two decision ids, or two keys, are not the same
experiment under different names — that is what the `decision_id` convention and publishing your `key_id` are for.

### 7.5 Transcript (MUST keep)

```json
{
  "spec": "notbefore/derive/v1",
  "seq": 41,
  "commit_seq": 40,
  "pulse_hash_reveal": "...",
  "attested_value": "...",
  "purpose": "clinic-qi-roster-2026-09-12",
  "derived_seed": "...",
  "verifier_git_sha": "...",
  "log_git_sha": "..."
}
```

This file is the engineering artifact. Screenshots of hex are not.

The shipped CLI writes this skeleton plus: `pulse_hash_commit`, `drand_round`, `derive_domain`, `operation` and its parameter (`frac` | `k` | `arms` | `lo`,`hi` | `n` | `hexlen`), `input_file`, `input_sha256`, `record_count`, `output_sha256` (or `A`/`B` with `count`+`sha256` for `split`), `log_ref`, `cli_version`, `spec`, `verified_utc`, and a `checks` summary. Field-by-field meaning and what must be stable on a re-run: `USAGE.md`.

---

## 8. CLI (normative behavior)

**Status: implemented** — package `notbefore` in `cli/` of the log repository (the current release is whatever PyPI serves; `notbefore --version` prints package, spec and vendored-verifier commit — this document deliberately names no package version) (**`pip install notbefore`** — released to PyPI 2026-09-12 13:41 UTC via Trusted Publishing, with Sigstore attestations). The verifier, keys, drand group key, Rekor key, both RFC 3161 trust chains (FreeTSA and DigiCert roots — no system store, no download) and expected host configuration are **vendored** in the package and pinned to a named log commit (`notbefore --version`); the log is read as data. §14 is its acceptance suite and runs in CI (`.github/workflows/cli.yml`). Requires `git` and `openssl` on PATH.

```text
notbefore verify   <seq>                                   # exit 0/1; transcript on stderr
notbefore value    <seq>                                   # V hex on stdout, only if verify passes
notbefore seed     <seq> --purpose <P>                     # S hex
notbefore shuffle  <seq> --purpose <P> <file>              # shuffled lines on stdout
notbefore split    <seq> --purpose <P> --frac 0.8 <file>   # <file>.A / <file>.B  (--out-a/--out-b)
notbefore sample   <seq> --purpose <P> --k 12 <file>       # first 12 of the shuffle
notbefore assign   <seq> --purpose <P> --arms 2 <file>     # record<TAB>arm, arms 0..m-1
notbefore id       <seq> --purpose <P> --from <file>       # pseudonym per line (--len 16)
notbefore range    <seq> --purpose <P> --lo 1 --hi 6       # one uniform integer
notbefore bytes    <seq> --purpose <P> --n 32              # hex bytes (public)
notbefore keygen                                           # once: the consumer identity (Ed25519) that signs decision statements (§7.12)
notbefore plan --after <UTC> --purpose <P> --sample 12 <file>   # signed decision contract: two RFC 3161 tokens + write-once decision-log entry (also --split/--assign/--id/--range/--bytes/--seed; --decision-id, --disclose, --no-log)
notbefore register <contract.json>                         # (re)submit a signed contract's statement to the decision log, idempotently
notbefore execute <contract.json>                          # no choices: rule-selected COMMIT (contract/3: value V*, FULL-ATTESTED / COMMITMENT-FALLBACK; exit 3 = reveal window still open), latest token before the round, FIRST entry for its decision_id, committed input only
notbefore receipt <contract.json>                          # one-page human-readable receipt; every line re-derived and re-verified (WORKFLOW.md)
notbefore bundle <contract.json> --out b.zip               # self-contained verification bundle: contract+sidecars, transcript, pulse pair+tokens+checkpoint+proofs+anchors, decision-log leaf/proof, keys, README, MANIFEST
notbefore check-bundle b.zip                               # OFFLINE re-verification of a bundle with this installation's pinned keys and roots
notbefore explain  <seq>                                   # methods-section paragraph: commit/TSA/round/release/V/eligibility
notbefore checkpoint                                       # the log's signed head, verified; site cross-check; cached-head consistency
notbefore pin                                              # write notbefore.lock (log sha, CLI, verifier); --lock makes re-runs bit-stable
notbefore diff-transcript a.json b.json                    # what changed: input, pulse, purpose, versions
```
Every derive command writes a transcript (§7.5) unless `--transcript none`; `--transcript -` prints it. Global flags:
`-q` (only FAIL/WARN on stderr), `--json`, `--offline`, `--no-anchors`, `--repo URL`, `--log-dir DIR`, `--log-ref SHA`,
`--lock notbefore.lock`, `--checkpoint-url`. Consumer walkthrough with real files: `USAGE.md`.

- `verify` prints PASS/FAIL lines to **stderr**, exit 0/1; since 0.4.0 it also proves the pair's inclusion in the log's signed checkpoint (`notbefore.net/log`), cross-checks the checkpoint served by `https://notbefore.net/checkpoint`, and refuses if the head is not an append-only extension of the head this machine saw before. Every payload (`value`, `seed`, shuffled lines) is **stdout only**, so `V=$(notbefore value N)` is the bare hex. `-q` suppresses PASS/INFO lines; failures still print and exit 1.
- `value` prints \(V\) hex only if verify would pass; else exit 1, no stdout hex.
- `seed` prints \(S\) hex under the same rule.
- Implementation MAY wrap the published `verify.py` rather than reimplement BLS.

Default log: a cached clone of `https://github.com/docdailey/qrng-beacon-log` at `origin/main`. `--repo`, `--log-dir`, `--log-ref` (or a `notbefore.lock`) override. Keys are never taken from the log: the verifier, all keys and the checkpoint identity are vendored in the package.

---

## 9. Time and publication (what may be said)

May say:

- Commit bytes existed at TSA time \(T\) (two operators).
- \(T < \mathrm{release}(R)\) by ≥ 120 s on a consumed pulse.
- GNSS envelope from i210 PHC on p550, disciplined to ZED-F9T PPS; quote RMS **with window**.
- A pulse's time is anchored on the hardware-captured GNSS epoch (F9T TP1 → i210 EXTTS, `ts2phc` ~8 ns RMS); software timestamps in statements are freshness only, never an accuracy claim.

MUST NOT say: nanosecond-accurate timestamps; NIST-traceable UTC; calibrated absolute time.

Authoritative public clocks for the *NotBefore bound* are: **computed `release(R)`**, **TSA token time** (two operators), **Rekor `integratedTime`** on the commit's anchor (contemporaneous from 0042; retroactive before), and **git first-commit time on the commit file** (weakest: set by the committer). GNSS is the lab envelope and the fail-closed gate, not the consumer’s notary.

---

## 10. Operator and adversary model

| Adversary | Bound |
|---|---|
| Compromised aggregator `think` | Cannot forge host statements under isolation (seq ≥ 26 + EXPECTED.json) |
| Entropy host | Can bias \(E\) *before* commit; cannot change \(E\) after commit; cannot pick after \(R\) |
| Hostile operator of all hosts | Out of protocol scope |
| Split-view / two valid pulse-\(N\) | **Detectable, not prevented.** Only the key holders can make one, and only in real time (TSA tokens must predate \(R\)). The entropy host refuses a second commit at a seq that resolved a published commit (ERR-008); every pulse is anchored under `keys/anchor.pub` in Rekor + Bitcoin and every entry under that key is enumerable; watchers publish first-seen hashes. Consumers MUST pin a clone/commit SHA and SHOULD run `verify_anchors.py` |
| Anchor-key compromise (GitHub Actions secret) | Can forge *anchors*, not pulses; a forged anchor matching no published pulse is exactly what the split-view check flags |
| Withheld reveal | Visible hole; MUST be a signed `failure` or a watcher NON-REVEAL; consumer skips the hour |

---

## 11. Batch leaves (NOT normative in v0.1)

Reserved extension **NotBefore/batch**. Not required to ship the CLI.

Sketch only:

- After public pulse \(N-1\), form 3600 leaves  
  \(C_t = \mathrm{SHA256}(\texttt{notbefore/leaf/v1} \| H_{N-1} \| t \| E_t)\), \(t=0..3599\).
- Pulse \(N\) commit publishes the Merkle root (still one TSA, one git object).
- \(i = \mathrm{int}(\rho) \bmod 3600\) — from the quicknet **randomness** \(\rho\), which is unknowable before release. (The 0.1 draft had \(i = R \bmod 3600\); \(R\) is the target round chosen at commit time, so the operator would know \(i\) before committing and could bias \(E_i\). That would have defeated the construction.) Reveal **only** \(E_i\).
- Unselected leaves are either erased or published *after* \(R\) as **tape**, never as attested \(V\).
- Purpose-binding of a non-\(i\) leaf MUST appear in the commit before \(R\) or it is forbidden.

Do not implement this until isolation can hold a vector of \(E\) and refuse the wrong \(i\).

---

## 12. Versioning

| Item | Version |
|---|---|
| This spec | `notbefore/spec/0.9` (the CLI prints the exact constant in `notbefore --version` and every transcript) |
| Decision contract | `notbefore/contract/1` |
| Package version | **independent of the spec version** (was "MAJOR.MINOR tracks the spec" until 0.5; `notbefore --version` prints both, and `SPEC` in the package is the binding statement) |
| Id / range / bytes domains | `notbefore/id/v1`, `notbefore/range/v1`, `notbefore/bytes/v1` |
| Derive domain | `notbefore/derive/v1` |
| Shuffle domain | `notbefore/shuffle/v1` |
| Live log protocol | `0.5` (`schema.py`) |
| Eligible floor (preferred) | reveal seq ≥ 27, pair 26/27 |

Breaking changes to \(V\) or \(S\) require a new domain tag. Old \(V\) stay verifiable under old tags.

Package version ↔ spec: `notbefore` `MAJOR.MINOR` tracks this spec's version; PATCH = re-vendored verifier/keys or CLI fixes with no change to any valid value. Any change to the vendored verifier, keys or `hosts/EXPECTED.json` reaches consumers only through a new release — procedure in `cli/RELEASING.md`.

---

## 13. Worked check (implementors)

Given a verified reveal with

```
V_hex = attested_value          # 64 hex chars
P     = "demo:roster"
```

```
S = SHA256( b"notbefore/derive/v1" + bytes.fromhex(V_hex) + b"demo:roster" )
```

Two independent implementations MUST match \(S\).  
If they do not, the spec is wrong or the purpose bytes differ (NFC, newline). Purpose MUST NOT include a trailing newline.

---

## 14. Acceptance tests for a NotBefore client

1. `verify 23` on a clean clone passes (0022/0023, v0.5 isolated).  
2. `verify 19` fails (ERR-007).  
3. `value 19` exits 1.  
4. `seed 23 --purpose demo:roster` is stable across two runs.  
5. Changing one character of purpose changes \(S\).  
6. Offline BLS: with `py_ecc`, no WARN, pairing check on the reveal’s \(R\).  
7. TSA: two PASS on the predecessor commit.  
8. Mutate \(E\) in a temp copy → verify fails.  
9. Mutate \(V\) → verify fails.  
10. Transcript written and contains `log_git_sha`.

---

## 15. What to build first

1. `notbefore` CLI over the existing repo (no new pulse format).  
2. Use it on one real roster; file the transcript.  
3. Only then consider §11.

The log already runs. NotBefore is the name of the contract and the derive layer. It is not a second beacon.

---

## 16. Changelog

**0.5.1 (2026-09-12, later).** §7.11 hardened after code review (ERR-013): both TSAs required, no failing token tolerated, gate on the LATEST token, no candidate cutoff in the rule, JCS/no-float canonical form, "timestamping" not "registration". Package and spec versions decoupled (§12). `DECISION-LOG.md` sketches the write-once decision log that would turn timestamping into registration.

**0.9 (2026-09-13).** After the second adversarial review (ERR-015): §7.13 publication evidence comes from Rekor's signed entries, never a record wrapper, and a verifier halts rather than advancing when it cannot establish a candidate's eligibility; receipts, bundles and `check-bundle` return VERIFIED / DEGRADED / INVALID (exit 0 / 2 / 1), bind the transcript to the signed contract and re-run the operation when the input is bundled; a missing checkpoint fails for checkpointed pulses; range spans > 2^64 are refused. `notbefore` 0.12.0.

**0.8 (2026-09-13).** The commit-bound value (§4.2a) and commit-bound contracts (§7.13, `contract/3`, the default for signed contracts): the consumer's value is \\(V^*\\) fixed by the commit and the drand round; a withheld reveal changes nothing (FULL-ATTESTED / COMMITMENT-FALLBACK); commit eligibility requires a Rekor anchor before the round, making it a pre-round, irrevocable fact. Adopted by Bill after the 2026-09-13 adversarial review (`FALLBACK.md`, with the publication-evidence refinement). `notbefore` 0.11.0.

**0.7 (2026-09-13).** Execution fails closed on the decision log for `contract/2` (§7.12); `--allow-unregistered` is the only escape hatch and labels the run DEGRADED; decision-log leaves are bound explicitly to the queried namespace, live and offline. Both from an external adversarial review. The same review's remaining finding — selective abort by the operator — is a protocol decision recorded in `FALLBACK.md`, not yet adopted. \(V\), \(S\) and all derived functions unchanged. `notbefore` 0.10.0.

**0.6 (2026-09-12).** Signed contracts and the write-once decision log (§7.12): `notbefore keygen`, `contract/2` with `signer` + `decision_id`, `.sig.json` decision statements, the second log `notbefore.net/decisions` (first statement per namespace is authoritative; `execute` refuses a superseded contract or a registration at/after the round; `--require-log`; `decisions/` mirror for offline checks). Prompted by the review that timestamping proves *when* but not *which*. \(V\), \(S\) and all derived functions unchanged. `notbefore` 0.8.0.

**0.5 (2026-09-12).** Decision contracts (§7.11): `plan` (canonical contract, two RFC 3161 tokens, published hash) and `execute` (choice-free; rule-selected pulse; registration must predate the round; committed input only). Prompted by a review pointing out that the operator's commitment was first-class while the consumer's preregistration was prose. \(V\), \(S\) and all derived functions unchanged. Doc correction after ERR-014 (same day): §8 now states that both RFC 3161 trust chains are vendored and pinned — the verifier trusts no host certificate store and downloads nothing; `notbefore` ≥ 0.7.1 behaves that way.

**0.4 (2026-09-12).** Derived functions on the same \(S\): `sample` (§7.6), `assign` (§7.7), `id` (§7.8), `range` (§7.9), `bytes` (§7.10) with their domains; tool commands `explain`, `pin`/`--lock`, `diff-transcript`, `checkpoint` (§8). \(V\), \(S\), shuffle and split unchanged. Status line and §8 no longer name a stale package version or a `--pin` flag that the CLI never had.

**0.3 (2026-09-12).** Protocol v0.5.1 adds the `skip` pulse (§4.3a): a refused commit becomes a signed, timestamped chain event instead of a silent gap. Eligibility (§6) excludes it explicitly. a `notbefore` release from 0.3.0 on vendors the verifier that accepts a commit after a skip; earlier releases reject the first commit after any skipped hour. \(V\), \(S\), shuffle and split are unchanged (same domains).

**0.2 (2026-09-12, claude-main review of the 0.1 draft against `pulse.py`, `schema.py`, `beacon-cycle.py`, `verify.py`, `tsa.py` and pulses 0040/0041).** Everything in 0.1 that could be checked against the code was correct — domains, `release(R)`, lead 100 rounds, margin 120 s, deadline 600 s, "missed margin ⇒ signed failure", the TSA CLI, the mix order, \(\rho = \mathrm{SHA256}(\sigma)\), the eligibility floors — except:

1. **Mix preimage length**: \(D_{\mathrm{mix}}\) is 24 bytes, so the preimage is 128 bytes, not "120 if 16" (§4.2; recomputed on 0041).
2. **Parity is not an invariant**: commits even / reveals odd is incidental and a `failure` pulse flips it. Identify pairs by `type` + `derived.commit_seq` (§2, §6 alternate rule).
3. **Batch-leaf selection** \(i = R \bmod 3600\) would let the operator know \(i\) at commit time; changed to \(\mathrm{int}(\rho) \bmod 3600\) (§11, still non-normative).
4. **Publication anchors** (Rekor + OpenTimestamps, ERR-008) were not in 0.1: added §4.5, verification step 12, an eligibility row, a fourth public clock (§9), and the split-view row of §10 rewritten from "pin a clone" to "detectable, not prevented".
5. Non-goals gained "immutability / prevention of equivocation" and "any cryptocurrency position" (§1.2), matching `CLAIMS.md`.
6. Object paths in a v0.5 pulse were added to §3 so an implementor need not guess.
7. §8 now describes the shipped CLI (`cli/`, package `notbefore`, vendored pinned verifier); at 0.2's first draft it said the CLI did not exist yet.
