# Exact timing is trust

Bill's thesis, 2026-09-11. This file records what the claim means operationally and what the lab
notebook has already proved about it.

## The claim (restated 2026-09-13, after external review D4)

The system is a **composition**, and each part proves one specific thing:

| part | what it fixes | what it proves — and only this |
|---|---|---|
| commitment (C = H(E) published before round R; the consumer's signed contract registered before R) | a *choice* | that the choice existed, byte for byte, before the randomness did |
| drand round R (BLS-verified under the pinned group key) | the *randomness* | that nobody, us included, could compute a value depending on ρ_R before R was released — **under drand's own assumptions** (threshold of honest operators; no early access to a round) |
| host signatures (entropy, GNSS, time, witness) over their own measurements | *observations* | who observed what, bound to which pulse; not that the observation is true of the physical world |
| the timing mesh (F9T-disciplined i210 measuring the LEA-6T-disciplined BMC; k3 downstream) | *corroboration* of clock operation | that two GNSS-disciplined paths agreed within the published figures over the published window; not absolute UTC accuracy, and today authenticated rather than policy-enforced |
| external anchors (RFC 3161 tokens, Rekor, OpenTimestamps, C2SP checkpoints, witnesses) | *history* | that a record existed, and was public, no later than a clock nobody here runs said so; and that rewriting it afterwards would be detectable |

"Exact timing is trust" is the thesis about the third and fourth rows: a signed random value proves only that
someone held a key; pinning it to a measured instant makes it *attestable* — it existed at T, in an order anyone
can check. Entropy answers *what*; time answers *when*. Without a trustworthy *when*, the *what* cannot be audited
at all. So the timestamp is **load-bearing** and earns the same scrutiny as the entropy: measured, bounded, published
with its own error terms, and independently checkable.

What exact timing does **not** do, stated once here and never blurred below: it does not prove *who*, it does not by
itself prove that a single publisher did not mint several candidates and publish one (that is what commitment,
publication evidence and the decision log are for), and a nanosecond-class GNSS epoch near an event does not turn
into a nanosecond bound on *publication* or on an adversary's grinding window — publication is evidenced by RFC 3161
tokens and Rekor entries at their own, coarser, uncertainty. **Externally anchored existence, observed arrival,
receiver epoch and original creation are four different facts**; each claim below names which one it is about.

## What the lab notebook proved about it

| notebook | what it proved | what it means for the thesis |
|---|---|---|
| **220** — a link bounce wipes the i210 integer second while `ts2phc` still reports `offset 12 ns s2` | A clock can be **confidently, silently wrong by 37 seconds** with every health metric green | **The sharpest form of the thesis.** This is a *trust* failure, not a precision failure. Precision metrics could not see it; only an independent invariant could. Hence `epoch_guard`, and `make_pulse.py` **fails closed** |
| **189** — un-threading the pps-gpio IRQ cut I210-vs-CLOCK_REALTIME 18 µs → 5 µs; the residual floor is *"eliminated by the SDP0 EXTTS fanout (i210 hardware-stamps the pulse, no IRQ → ~ns)"* | The trustworthy stamp is the **hardware capture**, not a software clock read | Anchor on the EXTTS-captured GNSS epoch. Software read cost is a *freshness* limit, reported separately and never folded into the anchor |
| **212** — sawtooth is autocorrelated (lag-1 +0.839); correcting it took a receiver 6.13 → 1.68 ns sd (r²=0.970) | A known, **correctable** error that no servo can average away | Worth correcting *at the capture*. Leaving a knowable bias in a trust layer is a choice, and it should be a documented one |
| **214/215** — 69 ns antenna delay **measured**; BMC EXTI latency trimmed via `ptptgt 900`; F9T is **L1-only**, 0 signals on L2 | Which terms are calibrated and which are not | Trust requires naming the uncalibrated terms. **Absolute** UTC carries an uncorrected ionospheric term until L1/L2 (TW3972). Precision now; absolute later — say which is which |

## The honest boundary

Exact timing proves **when**. It does not prove **who**, and it does not prove a single publisher
did not generate many candidate values and publish the one it preferred — every candidate would
carry a perfectly correct timestamp.

The two halves compose, though, and this is the useful part:

> **Precision is the multiplier on an anchor — for the events our clocks actually capture.** Mix in an external
> value (a drand round) and the claim becomes "we could not have known the output before T". The hardware-captured
> GNSS epoch then bounds, to the clock's stated uncertainty, *when the host assembled and signed the pulse* relative
> to T. It does **not** bound when the pulse became public: publication is evidenced by the RFC 3161 tokens and the
> Rekor entry, each at its own accuracy (a TSA states an accuracy interval around `genTime`; Rekor's `integratedTime`
> is one second granular), and local nanoseconds do not narrow those. A grinding window is bounded by the coarsest
> evidence in the chain, not the finest.

So: **time is the ordering-and-freshness half of trust; distributed verification is the
non-selection half.** We have built the first to an unusually high standard.

## The external anchor (added 2026-09-11) — half of the second thing

Every pulse from **0009** onward mixes in a **drand** round from the League of Entropy:

```
attested_value = SHA256( "grok_antics/pulse-mix/v1"
                       || quantis_entropy[32] || drand_randomness[32]
                       || chain_hash[32]      || round_be8[8] )
```

Network **quicknet**, chain `52db9ba7…e971`, period 3 s, scheme `bls-unchained-g1-rfc9380`.
Unchained, so each round stands alone and `randomness == SHA256(signature)` is checkable with no
crypto library at all. `make_pulse.py` **fails closed**: no drand, no pulse.

**What it buys — and this is a real, checkable claim we could not make before:**

> The attested value **could not have been computed before drand round R was released**, because it
> is a hash over that round's randomness. Anyone can re-fetch round R from four independent
> operators and confirm it. That is a lower bound on the value's age that does not depend on
> trusting us at all.

**Where Bill's thesis does its work.** The bound above is "not before T_R". How *tight* it is depends
entirely on how precisely we can show the pulse was assembled just after T_R — which is a timing
claim. pulse-0009's GNSS anchor lands **1.0 s** after the round release, and that gap is published.
Precision is the multiplier on the anchor: with a vague clock the same anchor would only say
"sometime that minute".

**What it still does NOT buy, stated plainly:** mixing bounds **precomputation**, not **selection**.
A single publisher can still generate many candidate pulses *after* round R is released and publish
a preferred one — each would carry a perfect timestamp and a valid anchor. Closing that requires the
entropy to be committed **before** the round exists (commit-then-reveal).

Partial measure already in place: each pulse declares `commitment.next_target_round` (current + 100
rounds ≈ 5 min ahead), and `verify.py --prev` enforces that the successor used a round **≥** that
target. That round did not exist when the predecessor was signed, so grinding of the *successor* is
bounded. Full commit-then-reveal for a pulse's own entropy is the remaining step.


## Commit-then-reveal (shipped 2026-09-11, pulses 0010/0011) — the second half

From pulse 0010 onward, selection after the round is excluded **conditional on the commitment having been the uniquely public one before the round** (reviewer, 2026-09-12 — see below):

```
COMMIT  (pulse N)    publish  C = SHA256("grok_antics/commit/v1" || E)  bound to FUTURE drand round R
                     E is held back (chain/pending, mode 600). Anchored by GNSS; three signatures.
                     ---- pushed to the public log BEFORE R releases ----
REVEAL  (pulse N+1)  after drand releases R: disclose E; mix with R exactly as before
                     attested_value = SHA256(mix_domain || E || drand_R || chain || R)
```

**What a stranger can now check, with nothing but the public repo, Rekor and api.drand.sh:** that `C` existed
and was public before `R` (two RFC 3161 tokens at mint and the Rekor anchor's signed time — never a git or GitHub
commit date, which the committer controls), that the revealed `E` hashes to `C`,
that the mixed round is exactly the committed `R`, and that `R`'s randomness is what the League of
Entropy served. Therefore the attested value was **unknowable to anyone — the publisher included —
before R released, and the publisher could not have chosen E after seeing R.**

First real instance: pulse 0010 anchored 23:56:45Z, pushed 23:58:57Z, round 32122604 released
23:59:39Z, reveal 0011 anchored 46 s later. `E` was fixed **174 s** before its round existed (by the host's own
GNSS clock; 0010 predates the RFC 3161 tokens that give third-party evidence from 0018 on, and its Rekor anchor is
retroactive).

**This is where "exact timing is trust" stops being a slogan — with its scope named.** Both edges of the window —
commit-before-round and reveal-after-round — carry hardware-anchored GNSS epochs with measured uncertainty, so the
*host's* ordering of its own work relative to the round is a measurement anyone can re-derive. The *public*
ordering (that the commit was out before the round) rests on the RFC 3161 tokens and the Rekor anchor, which are
what the verifier enforces; the GNSS epochs corroborate, they do not replace them.

### What is still assumed — say it every time

1. **The commit was public before R.** The signature cannot prove that; the RFC 3161 tokens (existence) and the
   Rekor anchor's signed time (publication under our key, on a clock we do not run) do, and contract/3 consumers
   require both before the round. Git history is corroboration, not evidence.
2. **drand is honest** — the League of Entropy's threshold of independent operators.
3. **We reveal every commit.** A commit without a following reveal is a visible hole in the chain,
   and `pulse.py reveal` refuses to skip. Consumers must treat an unrevealed commit as a failed pulse.
4. **SHA-256 is preimage resistant.**

None of these is "trust us about the random value". That was the point.

**Precise statement (2026-09-12):** the published commitment has third-party proof of pre-round *existence*
(two RFC 3161 tokens at mint); durable proof that it was the *uniquely public* commitment still depends on
observing or mirroring the repository before the round. An operator could stamp several candidates and
publish one. A watcher that signs receipts for commitments it sees before their round closes this; that is
the watcher's second job.


## Why there is no proof-of-work (added 2026-09-12)

Bill: "this reminds me of blockchain without work" — and then, "so anyone could branch this pulse chain."

Structurally it is that: hash-linked, append-only, one writer, no mining. What proof-of-work buys a blockchain is
an **expensive clock**: rewriting history costs redoing the work, so the longest chain becomes "what happened, in
order." Bitcoin burns energy to manufacture unforgeable time among strangers who trust nobody.

We do not manufacture time; we **borrow it from things nobody here controls**. drand: a commit cannot be back-dated
past a round, because the round's BLS signature is the proof the round exists and its value was unknowable before
release. RFC 3161: two third parties signed "this commit hash existed before T". GNSS: the on-time edge is captured
in hardware. Rekor: a public transparency log holds the hash of every pulse under our anchor key, with its own
clock. OpenTimestamps: the same digest is committed into Bitcoin block headers — the one place we do lean on
proof-of-work, and we lean on someone else's.

So the trust model is a **transparency log** (Certificate Transparency, Rekor, the NIST beacon), not a blockchain.
Blockchains solve a problem we do not have — many mutually distrusting *writers* agreeing on order. Our only question
is whether *one* writer can lie about *when*. That is the thesis in one line.

**The honest answer to "can anyone branch it".** A stranger cannot: five pinned-key signatures per pulse. The
operator can, in real time only, and until 2026-09-12 nothing prevented or even documented it (ERR-008). What a
blockchain has that a single-writer log lacks is **replication**; what we have instead is *detection*: the host
refuses a second commit at a resolved seq (raises the cost, does not bind root), every pulse is anchored under a
pinned key in Rekor and Bitcoin, anyone can enumerate every entry we ever made, and independent watchers compare
what they saw. Equivocation is not prevented. It is made public.

## Where this stands (Bill, 2026-09-12)

The value is the **operator discipline**, not the bytes: a source under commit-reveal, published before
the round, a clock measured as an instrument, and a written list of forbidden sentences. drand already
provides randomness; almost nobody provides *that*. It is worth keeping and not yet worth using as a
number. What changes that is not more pulses — it is an independent timestamp on each commit (now
RFC 3161, two TSAs), a stated cadence, and a second party who will attest a reveal we failed to publish.
See `CADENCE.md`.

## Where this stands (2026-09-13)

Since the paragraph above: cadence and RFC 3161 tokens on every commit (v0.5), signed failures and skips, checkpoints
and a same-sponsor witness, the decision log (the consumer's commitment, write-once), and the commit-bound value
(the operator can fail a consumer but cannot steer one). The two things still missing are an operator we do not
control cosigning the checkpoints, and a verifier that *enforces* the timing evidence it authenticates (`T1` in
`reviews/`). Until the second exists, the mesh is corroboration we publish, not a property we check.
