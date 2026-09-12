# Exact timing is trust

Bill's thesis, 2026-09-11. This file records what the claim means operationally and what the lab
notebook has already proved about it.

## The claim

A signed random value proves only that someone held a key. Pin it to an instant and it becomes
**attestable**: it existed at T, not before, in an order anyone can check. Entropy answers *what*;
time answers *when*. Without a trustworthy *when*, the *what* cannot be audited at all — you are
back to "trust me".

So the timestamp is **load-bearing**, and it earns the same scrutiny as the entropy: measured,
bounded, published with its own error terms, and independently checkable.

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

> **Precision is the multiplier on an anchor.** Mix in an external value (a drand round, a NIST
> pulse) and the claim becomes "we could not have known the output before T". Exact, *attestable*
> time then bounds how long anyone had to grind alternatives between T and publication —
> milliseconds instead of "sometime that minute". Without an anchor, precise time bounds nothing.
> Without precise time, an anchor is loose.

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

The selection gap is closed for every pulse from 0010 onward:

```
COMMIT  (pulse N)    publish  C = SHA256("grok_antics/commit/v1" || E)  bound to FUTURE drand round R
                     E is held back (chain/pending, mode 600). Anchored by GNSS; three signatures.
                     ---- pushed to the public log BEFORE R releases ----
REVEAL  (pulse N+1)  after drand releases R: disclose E; mix with R exactly as before
                     attested_value = SHA256(mix_domain || E || drand_R || chain || R)
```

**What a stranger can now check, with nothing but the public repo and api.drand.sh:** that `C` was
published before `R` existed (git history + GitHub's timestamp), that the revealed `E` hashes to `C`,
that the mixed round is exactly the committed `R`, and that `R`'s randomness is what the League of
Entropy served. Therefore the attested value was **unknowable to anyone — the publisher included —
before R released, and the publisher could not have chosen E after seeing R.**

First real instance: pulse 0010 anchored 23:56:45Z, pushed 23:58:57Z (GitHub committer.date
23:58:46Z), round 32122604 released 23:59:39Z, reveal 0011 anchored 46 s later. `E` was fixed
**174 s** before its round existed.

**This is where "exact timing is trust" stops being a slogan.** Both edges of the window —
commit-before-round and reveal-after-round — are hardware-anchored GNSS epochs, published with their
measured uncertainty. A vague clock would make the ordering claim an assertion; ours makes it a
measurement anyone can re-derive.

### What is still assumed — say it every time

1. **The commit was published before R.** The signature cannot prove that; the public log's history
   does. Trust assumptions for that log are in `PUBLICATION.md`.
2. **drand is honest** — the League of Entropy's threshold of independent operators.
3. **We reveal every commit.** A commit without a following reveal is a visible hole in the chain,
   and `pulse.py reveal` refuses to skip. Consumers must treat an unrevealed commit as a failed pulse.
4. **SHA-256 is preimage resistant.**

None of these is "trust us about the random value". That was the point.


## Where this stands (Bill, 2026-09-12)

The value is the **operator discipline**, not the bytes: a source under commit-reveal, published before
the round, a clock measured as an instrument, and a written list of forbidden sentences. drand already
provides randomness; almost nobody provides *that*. It is worth keeping and not yet worth using as a
number. What changes that is not more pulses — it is an independent timestamp on each commit (now
RFC 3161, two TSAs), a stated cadence, and a second party who will attest a reveal we failed to publish.
See `CADENCE.md`.
