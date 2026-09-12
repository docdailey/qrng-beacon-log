# CLAIMS.md — binding on all copy, both agents

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

