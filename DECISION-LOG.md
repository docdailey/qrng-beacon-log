# DECISION-LOG.md — the write-once decision log (built 2026-09-12; spec 0.6 §7.12)

RFC 3161 tokens prove a decision contract's bytes existed at T. They do not make the contract **authoritative**: a
consumer could timestamp several contracts and publish the favourable one. The decision log closes that: a public,
append-only, **write-once** transparency log of signed decision statements, built from the parts this repository
already had (RFC 6962 tree, C2SP checkpoints, witnesses, Rekor anchors) plus one new piece, the submission endpoint.

## Objects

**Consumer identity.** `notbefore keygen` writes one Ed25519 key (`~/.config/notbefore/identity.key`, mode 0600, never
uploaded). `key_id = SHA256(raw public key)[:16]` — the convention the log's own host keys use.

**Contract** (`notbefore/contract/2`) = contract/1 + `signer {alg, key_id, public_key_b64}` + `decision_id`.
`decision_id` defaults to the purpose string; for serious use bind it to an external artifact so that renaming is
visible to the people who hold that artifact — cryptography cannot recognise semantic aliases. Convention:
`<registry id>/<protocol version>/<decision>`, e.g. `NCT01234567/protocol-3/randomization-1` or `audit-order-8812/v2/sample-1`.

**Decision statement** — what the key signs and what the log stores (canonical JSON, RFC 8785):
```json
{"spec": "notbefore/decision/1", "decision_id": "…", "key_id": "…16 hex…", "public_key_b64": "…",
 "contract_sha256": "…64 hex…", "contract_spec": "notbefore/contract/2", "created_utc": "…Z"}
```
`signature_b64` = Ed25519 over the canonical statement. `plan` writes both beside the contract as `<contract>.sig.json`.
The statement carries the **hash** of the contract, so registering discloses nothing about the decision itself;
`--disclose` publishes the contract body too. The consumer's RFC 3161 tokens may be submitted alongside; the leaf
records their hashes.

**Leaf** (RFC 6962 leaf = canonical JSON; `leaf_hash = SHA256(0x00 ‖ leaf)`):
```json
{"spec": "notbefore/decision-leaf/1", "index": N, "received_utc": "…Z", "seq_in_namespace": k,
 "statement": {…}, "signature_b64": "…", "tsa_sha256": {"freetsa": "…", "digicert": "…"}, "contract_disclosed": false}
```

## The write-once rule

`(key_id, decision_id)` is a namespace. The **first valid statement** appended for it gets `seq_in_namespace 1` and
is the authoritative preregistration. Later statements for the same tuple are appended as amendments
(`seq_in_namespace 2, 3, …`) — visible, but never the entry `execute` accepts for the original randomization. A
statement whose `contract_sha256` is already present **in the same namespace** is returned unchanged (idempotent
retry); a different key or decision id may register the same hash independently — a hash is not a claim on anyone
else's namespace (review R7, 2026-09-13). Nothing is updated or deleted; the only operation is append.

## The log

| piece | where | what |
|---|---|---|
| origin | `notbefore.net/decisions` (permanent; identity in `keys/DECISIONS.json`, key `keys/decisions.pub`, note key id `e516adc9`) | a second C2SP log, distinct from the pulse log `notbefore.net/log` |
| writer | Cloudflare Worker `worker/decisions.js`, storage D1 (`worker/schema.sql`), signing key in the Worker secret `DECISIONS_SIGNING_KEY` (offline backup on the minting host) | validates the statement (shape, key_id, Ed25519), enforces write-once, appends, signs a checkpoint, returns an inclusion proof |
| mirror | `decisions/` in this repository (`decisions_mirror.py`, timer on the minting host at :20 and :50) | every leaf byte-for-byte, every checkpoint, `INDEX.json` of namespaces; verified before it is written; witness cosignatures gathered here |
| witnesses | the same `keys/WITNESSES.json` list; the decisions verifier key added to each witness | cosign `decisions/checkpoint` (c2sp tlog-witness); same-sponsor witnesses are labelled as such |
| anchors | `ci/anchor_pulses.py` (records `decisions-checkpoint-NNNNNNNN`) | every mirrored checkpoint into Rekor under `keys/anchor.pub` |

### Endpoints (JSON unless noted; CORS-open; nothing is cached)
```
GET  /decisions                          status: origin, size, checkpoint, verifier key, rule
GET  /decisions/checkpoint               latest signed note (text/plain)       GET /decisions/checkpoint/<size>
GET  /decisions/entry/<index>            the leaf (canonical JSON)             …/contract  …/tsa/<freetsa|digicert>
GET  /decisions/proof/<index>?size=      inclusion path at that size (default: current)
GET  /decisions/consistency?old=&new=    consistency proof between two sizes
GET  /decisions/lookup?key_id=&decision_id=   all entries for the namespace + the authoritative leaf, proof and checkpoint
GET  /decisions/leaves?from=&to=         pages of leaves (mirroring)
POST /decisions/submit                   {statement, signature_b64, tsa_tokens?, contract?} → 201 receipt (200 if it existed)
```
Requests need a `User-Agent` header (Cloudflare answers the bare Python default with 403; the CLI and the mirror send
their own). A receipt is `{index, seq_in_namespace, authoritative, received_utc, leaf, size, checkpoint, proof}`. The CLI trusts
none of it until the note verifies under the **vendored** key for the **vendored** origin and the proof reaches the
note's root; a receipt that fails is an error, not a warning.

## What the verifier establishes

1. `T_decision_commit < T_randomness_knowable` — from the RFC 3161 tokens (both, latest strictly before the round) and
   now also from the log's `received_utc` of the authoritative entry, itself later fixed in time by the mirrored
   checkpoint's Rekor anchor; and
2. **this was the authoritative preregistration for that decision** — from write-once inclusion: `execute` looks the
   namespace up, requires the first entry to be *this* contract, verifies the inclusion proof and the checkpoint
   signature, and refuses a superseded contract outright. Unregistered, unreachable or disabled is a **refusal**
   (0.10.0; `--allow-unregistered` is the only, loudly labelled, escape hatch). Offline, the mirror in the log checkout
   answers the same question. Every leaf the client trusts is bound explicitly to the queried `(key_id, public_key,
   decision_id)` and `seq_in_namespace = 1`; the offline check also scans the mirrored tree for an earlier leaf in the
   namespace instead of trusting `INDEX.json`.

## What it still cannot do

- **Semantic aliases.** Nothing stops calling one experiment `trial-A` and `trial-B` under one key, or using two keys.
  The defence is the `decision_id` convention above plus publishing your `key_id` where your peers can see it.
- **Coercion of the Worker.** The operator could refuse a submission (a denial, visible to the submitter, not a forgery)
  or, in principle, reorder entries arriving in the same second. It cannot alter or remove an entry without a split
  view: every client that has seen a checkpoint keeps it, the mirror keeps every leaf, witnesses cosign, and Rekor
  holds the checkpoints. Equivocation is *detectable*, not prevented — the same posture as the pulse log (CLAIMS.md).
- **Time better than seconds.** `received_utc` is the Worker's clock; the RFC 3161 tokens remain the primary evidence
  of when the contract existed. The two are consistent by construction (a contract is timestamped before it is
  registered) and a gap between them is itself informative.

## Status and order of work
1. ✅ `notbefore keygen`, signed `contract/2`, `.sig.json` statements (0.8.0).
2. ✅ The log: Worker + D1 + checkpoints (`worker/`), mirror (`decisions_mirror.py`), anchors, witness key.
3. ✅ `execute` consults the log (live, or the mirror offline); the transcript carries `decision_log`.
4. ✅ Live since 2026-09-12 23:29 UTC at `https://notbefore.net/decisions` (Worker `qrng-beacon-log`, D1
   `notbefore-decisions`); `keys/DECISIONS.json` `enabled: true` from `notbefore` 0.8.1. Entries 0–2 are the release's
   own live test (throwaway keys, decision ids `trial:abc@v1` and `test:live:…`) and entry 3 is the 0.8.1
   release confirmation (`release:0.8.1`), entries 4–6 the 0.10.0 confirmation and live test, entries 7–9 the 0.12.0 Worker
   smoke test (two keys registering one hash under `smoke:r7:…`: namespace-scoped idempotency, review R7) and are labelled as such here rather
   than removed — nothing is ever removed. The first mirror commit was `DECISIONS mirror: size 0`; the mirror runs at
   :20 and :50 and its checkpoints are anchored like the pulse log's.
