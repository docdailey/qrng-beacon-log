# FALLBACK.md — selective abort by the operator, and the commit-bound value (ADOPTED 2026-09-13; spec 0.8 §4.2a, §7.13)

**The attack** (external adversarial review, 2026-09-13). The operator commits E, waits for drand round R, computes
V = H(D_mix ‖ E ‖ ρ_R ‖ chain ‖ R), and only then decides whether to reveal. A withheld reveal becomes a signed
`failure` (or an unresolved commit); the consumer's rule passes the hour over and consumes the *next* pulse. The
commitment is intact, the evidence is public (ERR-style failure pulses, the watcher's NON-REVEAL records, a visible
gap), but the operator has chosen, after seeing the value, whether that value is consumable. Today this sits inside
the stated non-goal (`NOTBEFORE.md` §1.2: a hostile operator is out of scope; `CLAIMS.md`: equivocation and
withholding are *detectable*, not prevented). It is nonetheless the one remaining outcome-bias lever.

**The reviewer's construction.** On a failed reveal, define an unabortable fallback from information that is
irrevocably public before ρ_R:

    V_fallback = H(D_fallback ‖ C ‖ ρ_R ‖ chain_hash ‖ R)          C = H(D_commit ‖ E), published at commit time

so a withheld reveal degrades provenance (QRNG bytes not demonstrated) but still yields deterministic randomness.

**Why that is not yet enough.** After ρ_R exists the operator knows *both* V (from E) and V_fallback (from C). Choosing
to reveal or to abort is a choice between two known values: one bit of bias survives. The construction closes the
"reroll" but not the "coin".

**The refinement: make the consumable value commit-bound in every case.**

    V* = H("notbefore/commit-bound/v1" ‖ C ‖ ρ_R ‖ chain_hash ‖ R_be8)

- V* is fixed the moment ρ_R exists, by data the operator committed to before ρ_R was knowable (C, chain_hash, R)
  and data nobody here controls (ρ_R). Nothing the operator does afterwards — reveal, fail, skip the reveal, go
  offline — changes it. There is no second value to choose.
- In the random-oracle model V* is as unpredictable as E ⊕ drand: C is a hash of E, so E's entropy is in C.
- The reveal of E keeps its job, which is *provenance*: it proves C was a commitment to specific QRNG bytes and lets
  the verifier recompute the beacon's own attested value V. It stops being the thing the decision depends on.
- Refusing to *commit* (a `skip`) cannot bias anything: at commit time ρ_R is 100 rounds in the future.
- Withdrawing a commit after publication is equivocation, already detectable (git, TSA, Rekor, checkpoint,
  witnesses); a consumer's rule that keys on *published commits* leaves no room for a quiet retraction.

**Consumer semantics (contract/3).** The selection rule becomes "the first eligible **commit** whose target round
released at or after `after`" (a commit is eligible if published and TSA-timestamped ≥ 120 s before its round, chained,
host-signed). The value is V*. The label is:

    FULL-ATTESTED         the reveal verifies: E revealed, C = H(D_commit ‖ E) checked, V recomputed, QRNG provenance shown
    COMMITMENT-FALLBACK   no verifying reveal by the deadline (failure/unresolved): V* stands, provenance not demonstrated

Consumers may execute as soon as ρ_R exists and the commit verifies; they SHOULD wait for the reveal deadline
(600 s) so the label is final. Derivation is unchanged (S = H(D_derive ‖ V* ‖ purpose)) with a new spec version so a
transcript says which value rule it used.

**What changes where.** Protocol v0.6: `derived.commit_bound_value` published on the reveal *and* on the failure
pulse, but defined so any verifier computes it from the commit + drand alone. `verify.py`: compute and check it.
`notbefore` contract/3 + `execute`: select commits, compute V*, label. Docs: PROTOCOL, NOTBEFORE (§4, §6, §7, §16),
CLAIMS (a hostile operator can no longer bias a consumer decision; it can still withhold provenance and stall the
cadence — say exactly that). Legacy: contract/1–2 keep the reveal-based V for their own transcripts.

**Adopted** (Bill, 2026-09-13: "do it"), with one refinement found while building it. The consumer's value V* is
unabortable, but *eligibility* must also be a pre-round fact, or the operator regains a lever by withholding a
commit's **publication** (mint privately, learn ρ_R, publish only if favourable — leaving no trace). So a commit
counts only if it was demonstrably public before its round: both RFC 3161 tokens strictly before the release **and** a
Rekor anchor with `integratedTime` before the release. Then no decision taken with knowledge of ρ_R can change which
commit a contract consumes: an unanchored commit cannot be made eligible afterwards, an anchored one cannot be
withdrawn. What the operator keeps is blind and visible — skip, delay, withhold provenance — i.e. denial, not bias.
Practicality: since live anchoring began (2026-09-12 12:47 UTC) every commit has been anchored 129–208 s before its
round (median 204 s). An hour whose anchor is late is simply not eligible for contract/3 consumers; a think-side
anchoring step (rather than waiting for GitHub Actions) would widen that margin and is the natural next hardening.

Implementation: `PROTOCOL.md` §"Commit-bound value"; `NOTBEFORE.md` §4.2a, §7.13; `cli/notbefore/commitbound.py`
(`value`, `select_commit`, `publication_evidence`, `verify_round`); `check.check_commit`; contract/3 is the default for
signed contracts from `notbefore` 0.11.0; `receipt`/`bundle`/`check-bundle` re-derive V* offline from the bundled
commit and the transcript's drand signature. Test 32 executes one contract against the log and against a copy of the
log with the reveal removed and gets the same V*, seed and output. *The operator can fail you, but cannot steer you.*
