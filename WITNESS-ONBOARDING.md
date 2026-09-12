# Getting an independent witness — the onboarding packet

The log speaks `c2sp.org/tlog-witness@v1.0.0` (client in `tlog.py`; exercised hourly against our own same-sponsor
witness `notbefore.net/witness/ryzen`). An **independent** witness is a configuration change on both sides:
they add our log to their list; we add their URL and key to `keys/WITNESSES.json` under `independent_witnesses`.
Until an operator we do not control has cosigned a checkpoint, `CLAIMS.md` forbids the word "witnessed".

## Where independent witnesses come from: the Witness Network

<https://witness-network.org> — a community-maintained log list that its member witnesses provision
automatically. Participation is **one email** to `participate (at) lists.witness-network.org`
(guidelines: <https://witness-network.org/participate>). Lists: `testing` (dev), `staging` (long-lived
prototyping/dogfooding), `production` (not available yet). Witnesses currently serving staging + testing include
`geomys.org/witness/navigli`, `witness.stagemole.eu`, `transparency.dev/witnesses`; testing also
`witness1.smartit.nu`, `remora.n621.de`, `witness.markovianprotocol.com` (see the witness tables on the site).

Our entry in their `log-list-format.md` terms:

```
vkey notbefore.net/log+8b627e7f+AfPQekreiy4JUcf8TEcJs4Mj00EHL7JvHUSSLXeyZVLs
qpd 60
contact https://notbefore.net/  (docdailey on GitHub)
```

(`origin` is omitted: it equals the vkey key name, as they recommend for new logs.)

## The request, ready to send (Bill decides when — outreach is held until he says go)

> **Subject:** Participation request — notbefore.net/log (staging)
>
> Origin line: `notbefore.net/log`
> Public key (vkey, Ed25519 0x01): `notbefore.net/log+8b627e7f+AfPQekreiy4JUcf8TEcJs4Mj00EHL7JvHUSSLXeyZVLs`
> add-checkpoint rate: two per hour (one per published pulse: commit at :01, reveal at :06), plus rare back-fills; request `qpd 60`.
> List: **staging** — a real, running log with real users; we are happy to dogfood.
> Contact: https://notbefore.net/ · GitHub docdailey/qrng-beacon-log · [Bill's email]
> What the log is: an hourly commit-then-reveal randomness beacon (hardware QRNG, drand quicknet round as the public
> anchor, two RFC 3161 timestamps per commit, per-pulse Rekor + OpenTimestamps anchors, host-attested statements).
> The Merkle tree is RFC 6962 over every published pulse record (`checkpoint` / `checkpoints/NNNNNN` at the repo root
> and at https://notbefore.net/checkpoint; consistency proofs computed by `tlog.py`). Checkpoints are signed in the
> same commit as the pulse; the log has never been rewritten (append-only is CI-enforced and Rekor-anchored).
> Current size ~50 pulses, ~17,500/year. Expected lifetime: indefinite; the origin is permanent by policy.
> Spec/docs: https://notbefore.net/TLOG.md · verifier: `pip install notbefore` (`notbefore checkpoint`).

## After approval

1. Add each network witness that serves the staging list to `keys/WITNESSES.json` → `independent_witnesses`
   (`name`, `verifier_key` from their about page, `url` = their add-checkpoint base URL, `independent: true`).
   The log starts asking them on the next pulse; only cosignatures that verify are appended.
2. CI reports `independent: N` on every checkpoint; `notbefore verify --witness-quorum 1` starts passing.
3. Update `CLAIMS.md`: "witnessed" becomes sayable, with the operators named.
4. Vendor + release `notbefore` so the independent witness keys ship in the package.

## What this does and does not prove

A witness cosignature proves the witness saw this head and that it was consistent with every earlier head it had
cosigned — i.e. **no split view and no rollback across the witness's observations**. It does not prove a pulse is
honest, and a same-sponsor witness proves only that the machinery works.
