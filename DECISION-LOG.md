# DECISION-LOG.md — from timestamping to registration (design note, not built)

RFC 3161 tokens prove a decision contract's bytes existed at T. They do not make the contract **authoritative**: a
user can timestamp several contracts and publish the favourable one. Closing that needs an append-only, public,
write-once destination — a second transparency log, built from parts this repository already has.

## Object
```
{ "consumer_pubkey": <ed25519 vkey>, "decision_id": <string, see below>, "contract_sha256": <hex>,
  "contract_signature": <ed25519 over the contract bytes>, "tsa_evidence": [<the .tsr files, base64>] }
```
`(consumer_pubkey, decision_id)` is a **write-once namespace**: the first valid entry wins; later entries for the
same tuple are appended as amendments and can never be the one `execute` uses for the original randomization.

## Log
Same machinery as the pulse log: RFC 6962 tree over entries (`tlog.py`), C2SP checkpoints signed under a second
origin (e.g. `notbefore.net/decisions`), checkpoints Rekor/OTS-anchored and cosigned by the same witnesses, the
whole thing served statically from the repository the way `chain/` and `checkpoint` are today. Submission is the
only new piece: an endpoint (a Worker on notbefore.net is the natural home) that validates the object, enforces
write-once, appends, and returns an inclusion proof.

## What the verifier can then establish
1. `T_decision_commit < T_randomness_knowable` — from the TSA tokens and the tree's checkpoint time; and
2. **this was the authoritative preregistration for that decision** — from write-once inclusion.

## What it still cannot do
Cryptography cannot recognise semantic aliases: nothing stops calling one experiment `trial-A` and `trial-B`. For
high-stakes use, `decision_id` must be derived from an external artifact — a protocol registration number and version,
an audit order digest, an IRB protocol digest — so that renaming is visible to the people who hold that artifact.

## Order of work
1. `notbefore keygen` (consumer identity) and `contract_signature` in `plan` — no server needed.
2. The log: tree + checkpoints + anchors (reuse), write-once submission endpoint (new), `decisions/` served statically.
3. `execute` consults the log: the contract must be the first entry for its `(pubkey, decision_id)`; the transcript
   carries the inclusion proof.
4. Witnesses cosign the decision log's checkpoints alongside the pulse log's.
