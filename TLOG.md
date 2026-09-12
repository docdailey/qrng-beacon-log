# qrng-beacon-log → C2SP transparency-log conformance

**Spec draft 2 · 2026-09-12 · target: `docdailey/qrng-beacon-log`** — draft 1 as received, reviewed against the repository by claude-main; changes listed in §15. Implementation status in §16.

Goal: make the beacon log witnessable by the **existing** C2SP witness network, so split-view
detection stops depending on recruiting bespoke verifiers.

---

## 0. Why this, and what it buys

The log's security claim is *not before, not after*: a value was fixed before a drand round
existed and not selected after it. That claim collapses if the operator can serve two different
logs to two different parties. The current defence is the split-view check inside `verify-chain`
— which is operator-run, so it defends against accident, not against the operator.

Independent witnesses fix that. A witness stores **one checkpoint** and verifies an **O(log n)
consistency proof** on each update; it never downloads the log. That cheapness is what makes
strangers willing to run them, and it is exactly what the current data structure cannot support.

**Deliberate scope limit:** this spec adds a Merkle tree and checkpoints. It does **not** change
the pulse format, the hash chain, the anchors, or `notbefore`'s existing semantics.

---

## 1. Current state (verified against the repo, 2026-09-12)

```
chain/pulse-NNNN.json    hash chain, prev_hash -> chain_hash, 45 pulses
                         Ed25519 statements, `over: canon(statement)`
merkle/                  STATIC archive commitment: 42,935 leaves over quantum_cache.
                         Two manifests: the superseded sidecar root c88c4320… (kept, labelled, ERR-006)
                         and the authoritative archive root 4e93d4be… over recomputed bytes.
                         merkle_proof.py: root | prove | verify [--rehashed]
```

Canonicalisation already in use (`verify.py:49`, identical to `hosts/attest_lib.canon`):

```python
def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
```

### 1.1 What the existing merkle/ tree is not

`merkle/` is a frozen one-shot commitment to a 4.5 TB capture archive. It is **not** reusable
here, for three reasons:

1. It has no `consistency` command — only `root`, `prove`, `verify`. *(verified)*
2. Its leaf preimage is `SHA256(0x00 || filename || 0x00 || sha256_hex)`, domain-separated but
   **not** RFC 6962. *(verified: `merkle_proof.py:30`)*
3. Its internal node rule is *"odd node promoted"*, which is **not** RFC 6962's split rule and
   produces different roots for every non-power-of-two size. *(verified: `merkle_proof.py:36`)*

Keep it. It serves its own purpose. Do not extend it.

### 1.2 Why the hash chain is insufficient

`prev_hash`/`chain_hash` proves append-only **only to a party holding every entry**. A witness
would have to replay the whole log on each update — precisely the cost `tlog-witness` exists to
avoid. No existing witness operator can add a hash chain as configuration.

---

## 2. Normative: the leaf

```
leaf_data(n) = canonical(J(n))
```

where `J(n)` is the **complete parsed JSON object** of `chain/pulse-NNNN.json` for `seq = n`,
and `canonical` is the function in §1. Leaf index is `n − 1` (pulse `seq` is 1-based; tree
indices are 0-based). `seq` is dense by construction (every pulse type — commit, reveal, failure, **skip** — takes
the next integer), so the mapping has no holes; `tlog.py` refuses to build a tree over a chain with a seq gap.

**Rationale:** committing to `canonical(J)` rather than the file bytes makes the leaf invariant
under reformatting, and reuses the canonicalisation the signatures already rely on. Committing
to the whole record — statements and signatures included — means the tree covers everything
published, not just the core.

### 2.1 Immutability requirement (NORMATIVE, and a change in practice)

Once pulse `n` is included in a signed checkpoint, `chain/pulse-NNNN.json` **MUST NOT** change
by even one byte of canonical form. Anything learned later — TSA tokens, Rekor indices, OTS
upgrades — **MUST** live in sidecars outside the tree (`pulse-NNNN.json.tsa.json`, as today).

This is the single biggest operational constraint the tree imposes. Late-arriving anchor data
already goes to sidecars, so current practice complies; it now becomes a hard rule, and
`verify-chain` MUST enforce it by recomputing every leaf and comparing to the last checkpoint.

---

## 3. Normative: the tree (RFC 6962 §2.1)

Exactly RFC 6962. No variations.

```
MTH([])        = SHA-256("")                                  # empty tree
MTH([d0])      = SHA-256(0x00 || d0)                           # leaf
MTH(D[0:n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))   # internal
                 where k is the LARGEST POWER OF TWO STRICTLY LESS THAN n
```

⚠️ `k = largest power of two < n` is **not** the same as pairing adjacent nodes and promoting a
lone odd node. The archive tree in `merkle/` uses the latter. Using it here yields roots that
disagree with every other implementation at every non-power-of-two size — which is all sizes
that matter. This is the most likely single source of an interop failure.

At 45 leaves — and at 10⁶ — rebuilding the whole tree per append is microseconds. **Do not**
implement tiles, incremental storage, or a database. Recompute from `chain/` each time.

---

## 4. Normative: the checkpoint

Per `c2sp.org/tlog-checkpoint`, the body is three-plus lines, each newline-terminated:

```
<origin>
<tree size, ASCII decimal, no leading zeroes>
<base64 of the RFC 6962 root hash at that size>
```

Example:

```
qrng.example.org/beacon
45
qhL7yq2V0mZ1cC1hVQ0rXnFhq0zvHn2Kx3eGx0W7Ays=
```

### 4.1 Origin line

MUST be non-empty, stable **forever**, and unique to this log. Convention is a schema-less URL.
It is also the signature key name (§5).

**Decided 2026-09-12: the domain is `notbefore.net` (Bill holds it; site in progress).** Origin line: **`notbefore.net/log`**
— recorded in `keys/CHECKPOINT.json` with the checkpoint public key (`keys/checkpoint.pub`, Ed25519, origin-bound
key ID `8b627e7f`; private key `~/beacon/checkpoint.key` on think, distinct from the aggregator key). The identity
file carries `enabled: false` until the exact string is confirmed; the first signed checkpoint fixes it forever.
Do **not** use a `github.com/...` path: the origin outlives any particular hosting choice.

### 4.2 Extension lines

Permitted but **discouraged** — monitors cannot audit them. Do not put timestamps, drand rounds
or pulse metadata here; that belongs in the pulse records, which the tree already covers.

---

## 5. Normative: the signed note (`c2sp.org/signed-note`)

```
<note text, ending in \n>
<blank line>
— <key name> <base64( keyID[4] || signature )>\n
```

- Note text MUST be valid UTF-8, no ASCII control characters except `\n`, and MUST end with `\n`.
- Signature line begins with **em dash U+2014**, then space. Not a hyphen.
- Base64 payload is `4 + n` bytes: big-endian uint32 key ID, then the signature over the
  **note text** (everything before the blank line, inclusive of its trailing newline).
- Key name is the origin line.

### 5.1 Ed25519 key ID

```
keyID = SHA-256( key_name || 0x0A || 0x01 || pubkey_32 )[:4]
```

`0x01` is the Ed25519 algorithm identifier. Signature is RFC 8032 Ed25519 over the note text.

⚠️ This is **not** the repo's existing `key_id` (currently an 8-byte hex such as
`1fc857c9f439ab9a`). The checkpoint key ID is a distinct, spec-mandated derivation. Keep both;
do not try to unify them.

### 5.2 Key separation (NORMATIVE)

The checkpoint signing key **MUST** be distinct from the entropy-signer and GNSS-attester keys — and from the
aggregator key (same host, different assertion; `tlog.py keygen`).
A checkpoint asserts *"this is the log"*; a statement asserts *"this host observed this"*. One
key doing both lets a compromise of either escalate into the other.

Verifiers MUST ignore signature lines whose key ID they do not recognise — this is what permits
witness cosignatures to be appended to the same note.

---

## 6. Proofs

### 6.1 Inclusion (RFC 6962 §2.1.1)

`PATH(m, D[0:n])` — audit path for leaf `m` in a tree of size `n`. Implemented in `tlog.py inclusion <seq>`
(RFC 6962 rule; `merkle_proof.py` is left alone).

### 6.2 Consistency (RFC 6962 §2.1.2) — the genuinely new piece

`PROOF(m, D[0:n])` proves tree size `m` is a prefix of tree size `n`. This is what a witness
verifies on every update, and there is currently no implementation in the repo.

```
PROOF(m, D[0:n]) = SUBPROOF(m, D[0:n], true)

SUBPROOF(m, D[0:m], true)  = {}
SUBPROOF(m, D[0:m], false) = { MTH(D[0:m]) }
SUBPROOF(m, D[0:n], b)     with k = largest power of two < n:
    if m <= k:  SUBPROOF(m, D[0:k], b)        ++ { MTH(D[k:n]) }
    if m >  k:  SUBPROOF(m-k, D[k:n], false)  ++ { MTH(D[0:k]) }
```

Implemented in `tlog.py consistency <m> <n>`, verified by RFC 9162 §2.1.4.2, and tested against the
certificate-transparency vectors in `tlog.py selftest` (§9).

---

## 7. Witness integration (`c2sp.org/tlog-witness@v1.0.0`)

On each new pulse:

1. Append the leaf, recompute the root, build the checkpoint (§4), sign it (§5).
2. POST to each configured witness: the new checkpoint plus a **consistency proof** from the
   witness's last known size to the new size.
3. Witness verifies consistency against its stored head, returns a **timestamped cosignature**
   (`c2sp.org/tlog-cosignature@v1.0.1`).
4. Append cosignature lines to the checkpoint and publish it.

A v1 cosignature means: *as of time T, the largest consistent head the cosigner has seen for
this origin has this root hash.* Two cosignatures disagreeing at one size is a provable split
view — which is the whole objective.

Publish the current checkpoint at a stable path — `checkpoint` at the repo root, plus `checkpoints/NNNN` for
history — written by the aggregator in the **same commit as the pulse** (`beacon-cycle.publish`), so a pulse and
the checkpoint that covers it are never separable. Witness submission runs from CI afterwards and records cosigned
checkpoints on the `anchors` branch; a checkpoint with too few cosignatures is still published (§11).

See `c2sp.org/tlog-policy` for how a client decides how many cosignatures suffice.

---

## 8. Client side (`notbefore`)

Additive; existing commands keep working.

- `notbefore checkpoint [--witness-quorum N]` — fetch, verify log signature and ≥N cosignatures (0.4.0, once
  checkpoints exist).
- `notbefore verify` — additionally verify the pulse's **inclusion proof** against a cosigned
  checkpoint, and verify **consistency** with any checkpoint cached from a previous run.

That last clause is the point: a client that remembers the head it saw last time detects a split
view by itself, without contacting anyone. Persist the newest verified checkpoint under the
user's cache dir and refuse — loudly — on an inconsistency.

---

## 9. Conformance

`tlog.py selftest` runs these; CI runs it on every push. Verified 2026-09-12: empty root, the eight
certificate-transparency roots (sizes 1–8), the published consistency proofs (1→8), (6→8), (2→5), every
inclusion path and consistency pair for sizes ≤ 8, and a signed-note round trip. Check specifically:

- empty tree root = `SHA-256("")` = `e3b0c442…`
- sizes 1..8 roots, and every consistency pair `(m, n)` for `m < n ≤ 8`
- a signed note round-trip: correct em dash, correct key ID derivation, signature over note
  text including its trailing newline

Commit these as unit tests. Interop bugs in this area are silent — a wrong node rule produces a
perfectly well-formed checkpoint that simply nobody else agrees with.

---

## 10. Backfill

47 pulses at the time of writing. Build the tree over all of them, publish one checkpoint at that size, and
treat it as the log's genesis for witnessing purposes. No need to reconstruct historical checkpoints —
witnesses only ever care about consistency from the first head they personally saw.

Freeze all 45 records first (§2.1) and add the CI check that recomputes every leaf.

---

## 11. Operational notes

- **Failure and skip pulses.** They are leaves — every `chain/pulse-NNNN.json` is, by seq. The tree commits to
  everything published, including failures and refused hours, or the omission becomes a place to hide something.
  *(decided 2026-09-12)*
- **Cadence.** Hourly commit+reveal means ~17,500 leaves/year. Trivial.
- **Witness downtime.** A checkpoint with too few cosignatures should be published anyway and
  back-filled; do not stall the beacon on a witness.
- **Key rotation.** Handled by the ignore-unknown-signature rule, but the **origin must never
  change**.

---

## 12. Decisions needed before implementation

1. ~~**Origin line**~~ — `notbefore.net/log` (domain decided 2026-09-12; string awaiting one-word confirmation).
2. ~~**Checkpoint signing key**~~ — generated on think, `~/beacon/checkpoint.key`, public key in `keys/checkpoint.pub` (2026-09-12). **Back it up with the anchor key.**
3. ~~Failure pulses as leaves~~ — yes, and skip pulses (decided).
4. **Witnesses to approach** — transparency-dev and sigstore operators first; they add logs by
   configuration.

---

## 13. Effort

The tree, checkpoint and signed-note encoding are a day. The consistency proof plus its test
vectors are most of another. The witness HTTP client is small. The genuinely new operational
discipline is §2.1 immutability, and that is a CI check.

## 14. The differentiator, when you approach witness operators

```
gnss.statement.role       gnss_attester
gnss.statement.host       f9t
issued_unix_ns            1789221940328825963
```

A separate GNSS attester role that signs its own measurement on the receiver host: the on-time edge captured in
hardware, the receiver's per-epoch sawtooth logged, a stated error budget, and a time host whose statement carries
its own clock-health guard. Witness operators see plenty of logs; they rarely see one whose time claims are made
by the instruments and bounded in writing. Lead with that — and **not** with nanosecond figures or the word
"traceable": `CLAIMS.md` forbids quoting nanoseconds as timestamp accuracy (the userspace read is 27–47 µs; only
the anchoring epoch is hardware-captured) and forbids any traceability claim. Draft 1's "PTP-locked within ~15 ns
of TAI … metrologically traceable" would have been a CLAIMS violation on first contact.

---

## References

- RFC 6962 §2.1 — Merkle tree, inclusion and consistency proofs
- `c2sp.org/tlog-checkpoint` — checkpoint body format
- `c2sp.org/signed-note` — note envelope, key ID derivation
- `c2sp.org/tlog-witness@v1.0.0` — witness protocol
- `c2sp.org/tlog-cosignature@v1.0.1` — cosignature semantics
- `c2sp.org/tlog-policy` — client trust policy
- RFC 8032 — Ed25519

---

## 15. Changes from draft 1 (review against the repository, 2026-09-12)

1. §1: the archive root to name is `4e93d4be…` (recomputed bytes); `c88c4320…` is the superseded sidecar root (ERR-006). The three structural claims about `merkle/` were checked in the code and are correct.
2. §2: seq density stated (skip pulses, v0.5.1, are leaves too); `tlog.py` refuses a chain with a gap.
3. §4.1: origin decision left to Bill with a concrete candidate (`notbefore.org/log`); nothing is signed until then.
4. §5.2: the checkpoint key is also distinct from the aggregator key.
5. §7: checkpoint written in the same commit as the pulse; witness submission from CI; cosigned copies on `anchors`.
6. §11/§12: failure **and skip** pulses are leaves — decided.
7. §14: pitch rewritten to comply with `CLAIMS.md` (no nanosecond accuracy claims, no "traceable").
8. §9/§13: implementation and self-test exist (`tlog.py`); effort estimate replaced by status (§16).

## 16. Implementation status (2026-09-12)

| piece | status |
|---|---|
| RFC 6962 tree, inclusion path, consistency proof, RFC 9162 verifiers | `tlog.py`, self-tested against CT vectors |
| checkpoint body, signed note, Ed25519 key-ID derivation, note verification | `tlog.py checkpoint / sign / verify` |
| CI: self-test on every push; recompute the live root; verify `checkpoint` when present | `ci/verify_chain.py` |
| aggregator writes `checkpoint` + `checkpoints/NNNNNN` in the pulse's commit (`tlog.py publish-checkpoint`, append-only self-check, rollback refusal) | implemented, dry-run tested; **enabled the moment the origin string is confirmed** |
| Rekor-anchoring of each checkpoint (`anchors/checkpoint-NNNNNN.*`, expected by the split-view check) | implemented |
| CI: checkpoint required once enabled, size == pulses, consistent with the previous one | implemented |
| `notbefore checkpoint`; `verify` proves the pair's inclusion and checks consistency with the head this machine last saw | implemented; ships as 0.4.0 with the first checkpoint |
| witness submission (`tlog-witness`) | after the above; needs operators to configure the log (outreach is HELD) |
| `notbefore.net` serving the repository root statically (Workers Static Assets, `wrangler.jsonc`; `/checkpoint` and `/checkpoints/*` text/plain, CORS-open) | **live 2026-09-12** (Bill); `/checkpoint` answers 404 until the first checkpoint is committed |
| client cross-check: `https://notbefore.net/checkpoint` must be the git head or an append-only relative of it | implemented (`notbefore` ≥ 0.3.1, `--checkpoint-url`) |
| verification over HTTPS alone (no git clone): needs served inclusion/consistency material — `c2sp.org/tlog-tiles` or CI-published proofs | next; today the site is a publication and cross-check surface, git is the verification source |
