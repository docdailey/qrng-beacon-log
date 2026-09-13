# CLAIMS.md — binding on all copy, both agents

**How to read this file (restructured 2026-09-13 after external review D2).** §1 is the *current* rule set: one row per claim
with the evidence it rests on, when it became true, what the verifier does about it and what must be said beside it. §2 is
the consolidated list of phrasings that are never allowed. §3 records conflicts that accumulated while this file grew by
appendix and states the ruling. §4 is the history: every dated section as it was written, retained verbatim because
corrections to a claim are themselves evidence — **quote §1, never §4**. When §1 and §4 disagree, §1 wins and §3 says why.

## 1. Current claims

| Claim (what we MAY say) | Evidence it rests on | Since | Verifier behaviour | Say alongside / assumptions |
|---|---|---|---|---|
| **Entropy source:** "ID Quantique Quantis USB", vendor certifications quoted as the vendor's with a URL | vendor documentation | always | none | never "certified/validated" of *our* service; no NIST/FIPS/CC/AIS-31 claims for us |
| **Archive:** "root `4e93d4be…95c4` over the recomputed bytes of all 42,935 blocks (4.50 TB); 41,718 match their 2025 capture-time sidecar, 1,217 (2.835 %) do not and carry 2026-09-12 provenance only" | `merkle/manifest-rehashed.json`, CI recomputes both roots | 2026-09-12 (ERR-006 final) | CI fails on root mismatch | never `c88c4320…` as the root; never "verified archive" without both counts; archive bytes are never "unpredictable" without the commitment construction |
| **Corpus labels:** `quantum_cache/raw` is Quantis output; `dev_random_raw` is a Linux `/dev/random` control corpus | capture provenance | 2026-09-11 | none | the control corpus is never quantum, never sold, never blended; device rate is the sustained 500 KB/s |
| **Time base:** "an Intel i210 hardware PHC on p550 disciplined to a u-blox ZED-F9T PPS by `ts2phc`; the F9T TP1 edge is captured in hardware (EXTTS)" | `time_attester` statement: servo state, RMS, window; `epoch_guard` | pulses ≥ 0003 (f9t stamped 0001–0002, superseded) | v0.5: epoch health + chrony reference selection are REQUIRED; a pulse fails closed without them | always quote the sampling window with any RMS; software `CLOCK_REALTIME` fields are freshness only (ERR-012) |
| **Precision vs accuracy:** "~8–10 ns RMS discipline over the stated window" | the statement's measured figures | per pulse | authenticated; checked against `notbefore/timing/v1` when a contract declares it (0.13.0) | **never** a nanosecond figure as accuracy vs UTC; absolute budget is uncalibrated except the **measured** 69 ns antenna delay; L1-only today (ionospheric term uncorrected); dual-band is roadmap |
| **Two GNSS paths, one mesh:** "the i210 (F9T-disciplined) continuously measures the BMC grandmaster (LEA-6T-disciplined); k3 is disciplined by that BMC and signs its own clock observations" | `mesh_crosscheck` in the time statement; `time_witness` statement | statements signed from 0018; mesh field per `stamp_probe.py` | authenticated (signature, pulse binding); enforced against `notbefore/timing/v1` when a contract declares it (0.13.0), reported otherwise | describe as **measure and trim** (the i210 monitor is `free_running`; the BMC carries the `ptptgt` trim); k3 is a **same-sponsor downstream participant**, not an independent reference; both paths start at GPS |
| **Receiver telemetry:** "F9T qErr sd ≈ 2.26 ns (n≈358k), logged, not applied; LEA-6T core sd 6.02 ns with 3 excursions > 1 µs in 468,631 samples" | timehat DB `qerr_stream` | 2026-09-11 | none | qErr is quantisation jitter, never accuracy; quote both LEA-6T numbers or neither; sawtooth is autocorrelated (lag-1 +0.839) — **no quadrature argument**; sign: corrected = raw + qErr |
| **Public randomness anchor:** "the attested value is a hash over drand quicknet round R, so it could not have been computed before R's release; the drand signature is BLS-verified under the pinned group key" | `drand` block; `bls_drand.py` | 0003+ (anchor), full BLS 2026-09-12 | verify.py fails closed without the round; BLS required in CI | the pin and the ≥t-honest-operators assumption remain; never "drand is verified" without them |
| **Commit-then-reveal:** "E's hash was published before round R, E revealed after: unknowable before, not choosable after" | commit/reveal pair, RFC 3161 tokens at mint, publication in git, Rekor | pairs from 0010/0011; v0.5 from 0018; first compliant 0020/0021 | verify.py: C = H(D‖E), timing contract, tokens ≥ 2 (v0.5) | a commit with no reveal is a failed pulse; "provably fair"/"unbiased" never; not for gambling |
| **Host attestation & isolation:** "each host signs its own statement; a compromised aggregator cannot fabricate a host's facts (confined OS user, fixed-role forced command)" | v0.5 statements; `hosts/ISOLATION.md`; `execution` self-reports enforced | statements 0018; isolation 0020; enforced self-reports 0026 | verify.py strict path | the *operator* (all machines) is out of scope of this property; 0018/0019 are KNOWN-NONCOMPLIANT (ERR-007) |
| **Failures and skips are chain events** | signed `failure` / `skip` pulses | v0.5 / v0.5.1 | state machine enforced | a skip records the operator's stated cause, it does not prove it |
| **Cadence source:** "the hour is started by the time host's i210-disciplined clock, not by the aggregator's timer: p550 signs a cadence trigger at :00:00.000 UTC, the commit embeds it, and the target round is the round released at that instant + 100, so releases are at :05:00" | `core.cadence.trigger` (a `time_attester` statement: `scheduled_unix_s`, `wake.late_ns`, PHC−REALTIME at wake); first triggered cycle **0092/0093** (2026-09-13 13:00:00Z: p550 woke 114 µs after the instant, think received the trigger 0.68 s after, commit at :00:13, release 13:05:00Z) | 0092 | `verify.py` checks the trigger's signature under p550's pinned key, that the instant is a round boundary and that `target_release == instant + lead×3`; a pulse without a trigger says `cadence.source = "think-timer"` (the :02 fallback) | the trigger attests **which clock declared the hour**, not the aggregator's own timing — think's receipt and start times are its NTP clock, bookkeeping only; wake lateness is quoted from the trigger, never as an accuracy figure; 0090/0091 are an unscheduled pair from a timer change (ERR-016) |
| **Single-writer transparency log:** "hash-linked, append-only, tamper-evident; not a blockchain; equivocation is *detectable*, not prevented" | five pinned-key signatures per pulse; Rekor entries under `keys/anchor.pub`; OTS; watchers | anchors 2026-09-12 (0001–0041 retroactive) | `verify_anchors.py` enumerates every Rekor entry under the key | never "immutable"; name the independent records; 0001–0041 Rekor times are not commit times; no cryptocurrency is held or used |
| **Checkpoints:** "an RFC 6962 tree head as a C2SP checkpoint signed under `notbefore.net/log`, published with each pulse; consistency checkable against any earlier head" | `checkpoint`, `checkpoints/NNNNNN`, site cross-check | 2026-09-12 16:21Z (size 49) | CLI verifies signature, recomputes root, proves inclusion, keeps a cached head; a missing checkpoint FAILS for pulses ≥ 49 | proves membership and non-rewrite relative to a held head, not honesty |
| **Cosignatures:** "checkpoints are cosigned by `notbefore.net/witness/ryzen`, a witness we operate (same sponsor, second system)" | cosignature lines | 2026-09-12 | `--witness-quorum N` counts only independent witnesses | never "witnessed" or "independently witnessed" until an operator we do not control has cosigned; then name them |
| **RFC 3161 trust:** "tokens verify only against roots pinned in `keys/tsa/`" | `PINS.json` | 0.7.1 (ERR-014) | fail closed without the pin | never "publicly trusted"; a TSA chain rotation is a release |
| **Decision log:** "the first statement per (key_id, decision_id) is the authoritative preregistration; live at notbefore.net/decisions since 2026-09-12 23:29Z" | Worker + D1, mirror `decisions/`, cosigned + Rekor-anchored checkpoints | 0.8.1 | `execute` fails closed without a confirmed registration (0.10.0); superseded → refuse | idempotent per namespace; aliases across ids or keys are a naming problem the log makes visible; entries 0–9 are release/smoke tests; "registered" ≠ "timestamped" |
| **Commit-bound value:** "for a contract/3 decision the operator can fail you but cannot steer you: V* is fixed by the commit and the drand round; a withheld reveal changes nothing; eligibility (tokens + Rekor anchor before the round) is a pre-round fact taken from Rekor's signed entries; a verifier that cannot establish it halts" | `commitbound.py`; Rekor-direct evidence; test 32/33 | spec 0.9 / `notbefore` ≥ 0.12.0 (**not** 0.11.0, ERR-015) | halts on unavailable evidence; never advances on absence | the operator can still stall and withhold provenance (COMMITMENT-FALLBACK); unpredictability rests on drand's; not for contract/1–2 or the beacon's own V |
| **Verdicts:** "VERIFIED / DEGRADED / INVALID (exit 0/2/1); a DEGRADED receipt or bundle is a dry run" | `policy.py` | 0.12.0 | one result type behind every verifier | never present a DEGRADED transcript as preregistered |
| **The name:** NotBefore is the product contract ("fixed before round R, not selected after") | `NOTBEFORE.md` | 2026-09-12 | — | never "NotBefore-certified"; never "PulseTrain"; the CLI verifies, it does not certify |

## 2. Never

certified · accredited · validated (of our service) · NIST / FIPS 140 / SP 800-90B / Common Criteria / AIS-31 validation ·
ISO 17025 / "calibration" / "NIST-traceable" (except "traceable to a GPS-disciplined stratum-1 reference, with uncertainty") ·
anything implying fitness for gambling or lottery · generating or holding a customer's keys · "unpredictable" of archive
bytes without the commitment construction · nanosecond accuracy vs UTC · "accurate to 2 ns" · "2 ns system" · a hardcoded
leap-second offset · "independent reference" for k3 · "independent witness" for a same-sponsor witness · "witnessed" until an
outside operator cosigns · "immutable" · "prevents equivocation" · "provably fair" / "unbiased" · "prevents p-hacking" ·
"the operator cannot stall" · "registered" when only timestamped · a package version in the normative spec · `c88c4320…` as
the archive root · the quadrature argument · Git or GitHub commit dates as publication evidence.

## 3. Conflicts in the history, and the ruling

| Conflict | Ruling (current) |
|---|---|
| Antenna delay "unmeasured" vs "69 ns measured" | **Measured** (notebook 213/215); it is a calibrated term. The rest of the absolute budget is uncalibrated. |
| Sawtooth "removed in quadrature" vs its retraction | **Retracted.** The sawtooth is autocorrelated; it is logged, not applied; corrected = raw + qErr. |
| k3 "independent witness" vs "monitored peer / downstream participant" | **Downstream, same-sponsor participant** disciplined by the BMC that the i210 measures; both paths start at GPS. Its value is corroboration inside one measured mesh, not independence. |
| i210 monitor "read-only" vs the BMC `ptptgt` trim | **Measure and trim.** The i210 never steers; the loop closes through the BMC trim, which is a separate control path and must be drawn as one. |
| "hourly on think's timer" (CADENCE.md, NOTBEFORE.md before 2026-09-13) vs "started by p550's clock" | **p550's clock since 0092** (2026-09-13 13:00Z). think's timer is the :02 fallback and a fallback pulse says so in `core.cadence.source`. |
| "Until commit-then-reveal ships" / "until a decision log exists" | **Shipped.** Commit-then-reveal from 0010/0011 (v0.5 from 0018); the decision log live since 2026-09-12 23:29Z; commit-bound contracts from 0.12.0. |
| Archive root `c88c4320…` vs `4e93d4be…` | **`4e93d4be…95c4`** with the concordant/discordant counts (ERR-006 final). |
| "Every pulse carries …" | Scope every property to its activation: statements 0018, isolation 0020, enforced self-reports 0026, checkpoints 49, anchors live from 0042 (0001–0041 retroactive). |

## 4. History — dated sections as written (retained; do not quote)

## We MAY say
- "Quantum entropy source: **ID Quantique Quantis USB**" — with a link to the vendor's own spec.
- Vendor certifications, quoted **as the vendor's, with a source URL**, never as ours.
- "Timestamp traceable to a **GPS-disciplined stratum-1 reference**", with the uncertainty stated.
- "Hash-chained, signed, and **independently verifiable** — here is the verifier."
- Measured facts we produced: throughput, test-suite results, capture windows.

## We MAY NOT say — ever
- **certified · accredited · validated** applied to *our* service.
- **NIST / FIPS 140 / SP 800-90B validation / Common Criteria / AIS-31** of our service.
  (The NIST *test suites* are public; running them is not validation. Say "we ran SP 800-22",
  never "we are SP 800-22 certified".)
- **ISO 17025**, "calibration", or "NIST-traceable" for anything but time — and for time, only
  "traceable to a GPS-disciplined stratum-1 reference", with uncertainty.
- Anything implying fitness for **gambling or lottery**. No licensed gaming operators as
  customers — that is GLI-19 / GLI-11 plus jurisdictional licensing, a different universe.
- Any offer to **generate keys** for a customer. We never hold anyone's key material.
- "Unpredictable" applied to **archive** bytes without the commitment construction. We have held
  them; absent a published Merkle root they are cherry-pickable and must be described that way.

## Required disclosures
- Archive blocks ship labeled with capture date range, at-rest location, and single-use status.
- Every byte served is recorded in a served-bytes ledger and **never served twice**.

## Added 2026-09-11 after Gate 1 — corpus labelling (binding)

- `/Volumes/Expansion/quantum_cache/raw/**` is **Quantis output**. May be described as quantum.
- `/Volumes/Expansion/dev_random_raw/**` is **Linux `/dev/random`**, a CSPRNG control corpus.
  It may **never** be described as quantum, sold as quantum, or blended into a quantum SKU.
  Its only legitimate uses are as the control arm of a comparison and as clearly-labelled control data.
- Archive integrity may be stated as: *"each file carries a capture-time SHA-256 sidecar; sampled
  verification matches."* It may **not** be stated as proof of unpredictability at any past instant —
  the hashes are self-generated and were never externally anchored.
- Never quote 43,421 (sidecar count) as the file count. 43,010 files are on disk; 411 sidecars are orphans.
- Quote the device's **sustained 500 KB/s**, never the 20 MB/s ring-buffer burst.


## Added 2026-09-11 — time claims (binding)

**Authoritative timer = the Intel i210 PHC (`/dev/ptp0`) on p550.** f9t is the GNSS receiver host in
the discipline chain and may be named as such. f9t is **not** the beacon's clock; pulses 0001–0002
were stamped from it and are superseded.

### We MAY say
- "Timestamped from an Intel i210 hardware PHC disciplined to a u-blox ZED-F9T GNSS PPS by `ts2phc`."
- The **measured** discipline figures, with their sampling window stated — e.g. "8.3 ns RMS over a
  45 s window, servo locked (`s2`)". Always quote the window; a number without one is marketing.
- "TAI−UTC read from the kernel at stamp time" (it is, via `adjtimex`).
- "chrony reports stratum 1, RefID IPHC, root dispersion ~2.2 µs."

### We MAY NOT say
- **Any nanosecond figure as the accuracy of a timestamp.** A pulse's time is anchored on the GNSS epoch of an
  edge captured in hardware (F9T TP1 → i210 EXTTS, `ts2phc`, ~8 ns RMS discipline) with an **uncalibrated**
  absolute budget; the `CLOCK_REALTIME` fields in statements are freshness and ordering only and are never an
  accuracy claim. No software clock read is part of the anchor, so read latency is not a precision term and must
  not be presented as one (ERR-012). Quoting "nanosecond-accurate timestamps" would still be false.
- **"Accurate to UTC" / "NIST-traceable time" / "calibrated".** Absolute accuracy is uncalibrated —
  antenna cable delay, PPS coax length, i210 SDP0 input latency, and the receiver's own UTC error
  are all unmeasured by us. We claim *precision* and a *traceable discipline chain*.
- A hardcoded leap-second offset. TAI−UTC must be read at stamp time.
- Any time claim while the ts2phc servo is not in state `s2`, or when the sampling window shows
  peaks outside the quoted RMS. The pulse carries the raw numbers; let them speak.


## Added 2026-09-11 — two time bases (binding)

- **p550 / i210 remains the authoritative time base.** k3 / Milk-V is an **independent witness**, not
  the authority. Its chain starts at a different receiver (LEA-6T via the P550-BMC), so calling it
  "the clock" would silently change which reference a pulse is on.
- k3 is an **independent witness**, not a better clock: 41 ns discipline vs p550's 8 ns. Never describe k3 as
  the better clock.
- The published `primary_minus_witness_ns` is **not** an offset between the two time bases. Both
  stamps are fetched over SSH and the delta is dominated by acquisition skew. Never quote it as a
  clock comparison; the pulse states this and carries the skew bound beside it.
- **Do not call k3 an "independent reference".** Its grandmaster (the P550-BMC PHC) is continuously
  measured by the very i210 that carries the primary time base, at ~25 ns RMS. k3 is a **monitored
  peer inside one mesh** — which is a *stronger* trust claim than independence-without-verification,
  and must be described that way rather than overstated as independence.
- The two chains are additionally **not independent against a GNSS-common failure** (both start at
  GPS). Say so whenever "independent" appears in any form.
- **"~2 ns" belongs to the ZED-F9T and means qErr standard deviation** (2.255 ns, 21 days, 357,982
  samples, zero excursions >50 ns). It is jitter/granularity, **never** accuracy versus UTC(k).
  "Accurate to 2 ns" is a false claim.
- When quoting the LEA-6T, quote **both** numbers or neither: core sd 6.02 ns **and** 3 excursions
  past 1 µs in 468,631 samples over 21 days. Quoting only the core hides the tail; quoting only the
  raw 2.3 µs sd misrepresents three outliers as typical.


## Added 2026-09-11 — GNSS telemetry claims (binding)

- The **timehat DB** (nas1 `192.168.69.133:3309`, schema `timehat`) is the evidence base:
  `qerr_stream` and `rawx_stream`, receiver `src='f9t'`. Quote row counts and windows, never
  adjectives.
- **"~2.26 ns" is the ZED-F9T sawtooth sd** (n=358,232; last 15 min 99.7–100 % coverage). It is
  quantisation jitter. It is **not** the system's accuracy and **not** the stamp uncertainty.
- ❌ **Never call this a "2 ns system".** The delivered i210 discipline is 8.3 ns RMS; removing the
  sawtooth in quadrature leaves ~8.0 ns, so the receiver is not the dominant error term. Quote the
  8.3 ns when describing the clock; describe a pulse's time by its hardware-captured anchor and its stated,
  uncalibrated absolute budget — never by a software clock read.
- **The sawtooth is logged, not applied.** Never imply the i210 is sawtooth-corrected. If that
  changes, re-measure before changing a word of copy.
- RAWX `leapS` is **GPS−UTC (18)**. TAI−UTC = leapS + 19 = 37. Publishing leapS as "TAI−UTC" would
  be wrong by 19 seconds.
- Satellite count and constellation mix are an **integrity indicator, not proof**. "Harder to spoof"
  is fair; "spoof-proof" is not.
- Never publish raw RAWX frames in a pulse — a digest only. The f9t frame store is 394 MiB and grows.


## Added 2026-09-11 after reading the lab notebook (binding)

- ✅ **The 69 ns antenna cable delay is MEASURED** (notebook 213/215), not assumed. Our earlier
  "unverified by us" wording was wrong; it belongs in calibrated terms.
- ❌ **Do not repeat the quadrature argument.** The sawtooth is strongly autocorrelated (lag-1
  +0.839) and cannot be averaged away by any servo. Correcting it measurably took a receiver from
  6.13 to 1.68 ns sd. Sign: corrected = raw + qErr.
- ⚠️ **Never publish a timestamp without the epoch guard.** A link bounce wipes the i210 integer
  second while every servo metric still reads healthy (notebook 220). `make_pulse.py` fails closed
  on `epoch_ok=False` or chrony no longer selecting IPHC. A pulse minted without that check is not
  trustworthy regardless of how good its other numbers look.
- ⚠️ **Absolute accuracy is capped by L1-only operation.** The F9T sees 0 signals on L2 today, so
  absolute UTC/TAI carries an uncorrected ionospheric term. Dual-band L1/L2 (TW3972) is a
  **roadmap** item. Never present dual-band or "real UTC/TAI" as a current property.
- The i210 monitor never steers, but the loop closes through the BMC `ptptgt` trim. Describe it as
  "measure and trim", not as either "read-only" alone or "steering slave".


## Added 2026-09-11 — external anchor (binding)

- ✅ **We MAY now say**: "the attested value could not have been computed before <UTC time>, because
  it is a hash over drand quicknet round <N>, which did not exist until then — re-fetch it yourself
  from api.drand.sh." This is checkable by anyone and does not require trusting us.
- ❌ **We MAY NOT say** the value was "unpredictable", "unbiased" or "provably fair". Mixing drand
  bounds **precomputation**, not **selection**: a single publisher can still mint several candidates
  after the round releases and publish a preferred one. Until commit-then-reveal ships, say
  "could not have been computed before T", never "could not have been chosen".
- Quote the **assembly window** (`gnss_anchor_minus_drand_release_s`) whenever the anchor is cited;
  the bound's tightness is a timing claim, and the number is published for exactly that reason.
- ✅ Since 2026-09-12 `verify.py` performs **full BLS verification** of each drand round under the pinned
  League of Entropy quicknet group key when `py_ecc` is installed (CI always does). We MAY say "the
  drand signature is verified under the pinned group key; the relay is not trusted". We may NOT say
  "drand is verified" without the pin caveat, and never imply we verified the *threshold ceremony*
  itself — the pin and the ≥t-honest-operators assumption remain.
- `make_pulse.py` fails closed if drand is unreachable or if `randomness != sha256(signature)`.
  A pulse without an external anchor is a pre-v0.3 artifact and must not be sold as anchored.


## Added 2026-09-11 — commit-then-reveal, public log, archive commitment (binding)

- ✅ For **reveal pulses (0011+)** we MAY say: "the attested value was unknowable to anyone, including
  us, before <round release UTC>, and the entropy could not have been chosen after — its hash was
  published in pulse N at <push time> and is visible in the public log's history." Always cite the
  public log; the claim rests on publication, not signature.
- ❌ Still MAY NOT say "provably fair", "unbiased", or anything implying fitness for gambling. The
  scheme is honest; the market it must not enter is a legal matter, not a cryptographic one.
- ⚠️ A **commit with no following reveal is a failed pulse** and must be described as such. Never
  quietly skip one.
- **Archive commitment**: quote **root `c88c4320…2738`, 42,935 blocks, 4.50 TB, 2025-07-18 →
  2025-11-15**. Never quote 43,010 (bins on disk) or 43,421 (sidecars) as the committed count: 57
  sidecars were unparseable, 429 point at missing files, and 75 bins have no valid sidecar — none of
  those are committed. Until the full re-hash finishes, say "sample-verified; full verification in
  progress (<checked>/42,935)". Never say "verified" without the number.
- Public log trust assumptions (GitHub timestamps, force-push detectability) are stated in
  `PUBLICATION.md` and must accompany any claim that depends on publication time.


## Added 2026-09-12 after external review (binding)

- ❌ Do not say "the selection gap is closed". ✅ Say: *the published commitment has third-party proof of
  pre-round existence (RFC 3161, two TSAs, at mint); durable proof that it was the uniquely public
  commitment depends on observing or mirroring the repository before the round.*
- ❌ Until v0.5, do not describe the three signatures as independent role attestations. ✅ "Three named
  hosts signed the record's digest" (ERR-005).
- drand release times are `genesis + (round − 1)·period`. Any figure derived from the old formula is 3 s late
  (ERR-004); quote recomputed margins, not the published `timeline` fields, for pulses 0009–0015.


## Added 2026-09-12 — v0.5 attestation (binding)

- ✅ From pulse **0018**: "each host signed its own statement: the entropy host generated, held and revealed E;
  the GNSS host signed the anchor it measured; the time host and witness signed their own clock measurements;
  the aggregator signed only the assembly." Before 0018: digest signatures only (ERR-005).
- ✅ "Failures are signed chain events" (v0.5). ❌ Never describe an unsigned `FAILED.json` as a chain event.
- ✅ "Every v0.5 commit carries at least two RFC 3161 tokens taken at mint, each ≥ 120 s before its round."
- Decision log (spec 0.6, `DECISION-LOG.md`): ✅ "the first decision statement for a (key_id, decision_id) is the
  authoritative preregistration; a superseded contract is refused by `execute`". ✅ Since 0.10.0: "`execute` fails closed —
  no confirmed registration, no output; `--allow-unregistered` produces a run labelled DEGRADED". ❌ Never present a
  DEGRADED transcript as a preregistered result.
- Commit-bound value (spec 0.9 §4.2a/§7.13, `FALLBACK.md`, `notbefore` ≥ 0.12.0 — NOT 0.11.0, see ERR-015): ✅ "for a
  contract/3 decision the operator can fail you but cannot steer you: the value \(V^*\) is fixed by the commit and the
  drand round, a withheld reveal changes nothing, eligibility (tokens + Rekor anchor before the round) is a pre-round
  fact established from Rekor's signed entries — never from the operator's anchor branch — and a verifier that cannot
  establish it halts rather than advancing". ✅ Say "verdicts are VERIFIED / DEGRADED / INVALID; a DEGRADED receipt or
  bundle is a dry run". ✅ Say
  "COMMITMENT-FALLBACK hours carry no QRNG provenance". ❌ Never say the operator "cannot stall" or "cannot withhold
  provenance" — it can, blindly and visibly. ❌ Never apply the steering claim to contract/1–2 or to the beacon's own
  reveal-based \(V\). ✅ "registration is write-once and
  append-only; equivocation by the log is detectable (mirror, witnesses, Rekor), not prevented". ❌ Never "prevents
  p-hacking" or "proves this was the only analysis": two decision ids or two keys can name one experiment — say
  "aliases are a naming problem the log makes visible, not one it solves". ❌ Never say a contract is "registered" when
  only RFC 3161 tokens exist: that is *timestamped*. ✅ Since 2026-09-12 23:29 UTC (`notbefore` ≥ 0.8.1): "the decision log is live at
  notbefore.net/decisions"; say "entries 0–2 are release tests" if asked about its first entries.
- ✅ Since 2026-09-12 (ERR-014): "RFC 3161 tokens are verified only against trust anchors pinned in `keys/tsa/`
  (FreeTSA root + signer, DigiCert Trusted Root G4 + timestamping CA, fingerprints in `PINS.json`) — never the
  host's certificate store, never a download." ❌ Never say a token is "trusted by the system" or "publicly
  trusted"; the verifier trusts exactly the roots the release pins, and a TSA chain rotation is a release.
- The aggregator is still a single party that *assembles*; it cannot forge host facts but it can choose not
  to publish. That is what the watcher's COMMIT-RECEIPT and NON-REVEAL records exist to expose.


## Added 2026-09-12 — archive after ERR-006 (binding)

- ❌ Do not describe the archive as "verified", "hash-manifested" or "committed" without the ERR-006 qualifier.
- ✅ Say (FINAL): "the archive root is `4e93d4be…95c4` over the recomputed bytes of all 42,935 blocks (4.50 TB);
  41,718 blocks match their capture-time sidecar (provenance from 2025), 1,217 (2.835 %) do not and carry provenance
  dated 2026-09-12 only; discordant blocks are excluded from any capture-time claim."
- ❌ Never cite `c88c4320…` as the archive root (it commits to sidecar hashes that are wrong for 1,217 blocks); never
  present a subset rate as an archive rate; never say "verified archive" without the concordant/discordant counts.
- Never quote `c88c4320…` as the archive's integrity root. Quote `manifest-verified.json` once it exists, with its
  leaf count, and quote the mismatch count beside it.


## Added 2026-09-12 after review #3 (binding)

- Pulses **0018/0019** fail the current verifier (ERR-007). Describe them as "first v0.5 pair; witness guard misfired;
  content valid on live evidence; formally non-compliant". **The first fully compliant v0.5 pair is 0020/0021**
  (host-isolated, witness health enforced, stranger-verified, watcher-receipted before its round).
- ✅ **From pulse 0020 (host isolation live 2026-09-12):** "a hostile or compromised aggregator cannot fabricate any
  host's facts: keys and secrets live under a confined OS user on each host, and the aggregator can only invoke one
  fixed-role forced command with locally validated phase/seq/binding." ❌ Never extend that to the **operator**: the
  person who administers all machines is out of scope by design; what bounds the operator is drand, RFC 3161 and an
  independent watcher — say so in the same breath. Pulses 0001–0019 do not carry the isolation property.
- ❌ Do not call the watcher independent while it trusts code or keys from the watched repository. ✅ v3 watcher runs only
  its operator's pinned verifier and keys (`watcher/make_pins.py`).
- The archive figure is **1,217 of 42,935 blocks = 2.835 %** (final, full re-hash 2026-09-12). The earlier "5.6 %" was
  the rate within the first third scanned and must not be quoted as an archive rate.

## Added 2026-09-12 — single-writer log, forks, anchors (binding)

- ✅ Say: "a hash-linked, append-only, **single-writer transparency log** — not a blockchain. There is no consensus
  and no proof-of-work because there is one writer; the question is whether that writer can lie about *when*, and
  that is bounded by clocks nobody here controls (drand, RFC 3161, Rekor, Bitcoin block headers)."
- ✅ Say: "a stranger cannot extend the chain (five pinned-key signatures per pulse). The operator can fork it only
  in real time (RFC 3161 tokens must predate the drand round), and any fork is **detectable** by anyone who
  enumerates the Rekor entries under `keys/anchor.pub` or compares two observers' copies."
- ❌ Never say equivocation is *prevented*. It is *detectable*. When asked, name the independent records as of the
  date: GitHub history, Rekor, the OpenTimestamps calendars/Bitcoin, and the watchers (2026-09-12: one, ours).
- ❌ Never say "immutable". Say "append-only and tamper-evident: a rewrite needs new signatures and new TSA tokens,
  and leaves orphaned Rekor entries under our own key."
- ✅ OpenTimestamps: "a timestamp proof anchored in Bitcoin block headers, via free calendar servers."
  ❌ Never imply any cryptocurrency is held, bought, paid, traded or endorsed. The proof is a Merkle path to a
  public block header; that is all it is.
- ✅ Rekor: "the public Sigstore transparency log (OpenSSF / Linux Foundation)". It is a third-party log, not a
  certification of anything.
- ✅ Pulses 0001–0041: "anchored retroactively, 2026-09-12 12:47 UTC". ❌ Never present their Rekor times as
  commit times.

## Added 2026-09-12 — the name (binding)

- ✅ **NotBefore** is the name of the *product contract*: the consumer-facing seed (`attested_value` \(V\)) and the
  labeled derive layer (`NOTBEFORE.md`). It is one log, not a second beacon. The claim in the name is exactly the
  claim we can prove: "fixed before round \(R\), not selected after".
- ❌ Never "NotBefore-certified", "NotBefore-grade", or any phrasing that makes the name sound like a standard or an
  accreditation. ❌ Never "PulseTrain" (rejected 2026-09-12: crowded name space, an existing hardware product).
- ✅ The CLI shipped 2026-09-12 (`cli/`, package `notbefore`; first PyPI release 0.2.0 that day, current release per PyPI — never quote a package version in the normative spec). ✅ Say "the CLI verifies with a pinned, vendored verifier"; ❌ never say the package "certifies" a pulse.

## Added 2026-09-12 — skip pulses (binding)

- ✅ Say: "a cycle that runs but cannot commit publishes a signed, timestamped `skip` pulse naming the dependency
  that refused; no hour passes without a chain event unless the operator deliberately stops the timer, which is
  announced in advance."
- ❌ Never say a skip *proves* the stated cause. It proves the operator recorded that cause at that time (aggregator
  signature; RFC 3161 when available). ❌ Never say a skip is a failure of the beacon's security claim: no commitment
  existed, so nothing was selected or withheld.

## Added 2026-09-12 — transparency-log checkpoints (binding)

- ✅ Say: "the log publishes an RFC 6962 tree head as a C2SP checkpoint signed under the origin `notbefore.net/log`, in the
  same commit as each pulse; anyone can recompute the root and check consistency with any earlier checkpoint."
- ❌ Never say "witnessed" or "cosigned" until an operator we do not control has actually cosigned a checkpoint. Until
  then the honest phrase is "self-signed checkpoints, Rekor-anchored; consistency checkable by any client that
  remembers its last head."
- ❌ Never present the checkpoint as proof that a pulse is *honest*; it proves the pulse is in *this* log and that the
  log did not rewrite or fork its past relative to a head someone holds.

## Added 2026-09-12 — cosignatures (binding)

- ✅ Say: "checkpoints are cosigned by `notbefore.net/witness/ryzen`, a witness we operate ourselves (same sponsor,
  second system); it proves the witness protocol path works, not independence."
- ❌ "Witnessed", "independently witnessed", "cosigned by the Witness Network" — not until an operator we do not
  control has cosigned; then name them. `notbefore verify --witness-quorum N` counts only independent witnesses.

