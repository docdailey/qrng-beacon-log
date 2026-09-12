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

## The request — SENT by Bill 2026-09-12 (~17:40 UTC) to participate@lists.witness-network.org

To: participate@lists.witness-network.org · Subject: *Participation request — notbefore.net/log (staging list)*

Contents: origin line; vkey (Ed25519 0x01, key name = origin); the log-list entry (`vkey … / qpd 60 / contact
docdailey@gmail.com`); add-checkpoint rate (two per hour — commit at :01, reveal at :06 — plus rare back-fills; ~48/day,
qpd 60 for headroom); list = **staging**, real log, happy to dogfood; contact (email, https://notbefore.net/, the
repository); what the log is (hourly commit-then-reveal beacon, RFC 3161 + Rekor + OTS anchors, RFC 6962 tree,
checkpoints at `/checkpoint` and `/checkpoints/NNNNNN`, ~52 entries, ~17,500/year, permanent origin and key policy);
implementation notes (tlog-witness v1 client exercised hourly against our own witness; RFC 6962 / signed-note /
cosignature vectors in `tlog.py selftest`; invitation to report non-conformance); commitment to configure the staging
witnesses' endpoints on approval.

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
