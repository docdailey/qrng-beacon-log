# ERRATA.md — known defects in published pulses, and their fixes

Pulses are signed and hash-chained, so a published pulse is **never edited**. A defect is corrected in
the tooling, takes effect from a stated seq onward, and is recorded here permanently. Consumers of the
affected pulses should read the affected field as described below. Newest first.

---

## ERR-020 — the 15:00Z hour was skipped: the LAN path between the fleet timing switch and the router drops a third or more of NEW connections, stickily per flow (2026-09-14; open on the hardware side)

**What happened.** At 15:00:31Z the commit was refused: `[tsa] digicert: URLError timed out` after the 25 s request
timeout, leaving one TSA token where the beacon demands two (`MIN_TSA_TOKENS`), so the cycle minted the signed **skip
pulse 0140** and abandoned the prepared secret on the entropy host - nothing was written. The pulse's `refused_by` field
reads `entropy` because the classifier matched the words "entropy host" in the tail of the reason ("E abandoned and erased
on the entropy host") before it matched `[tsa]`; the reason text itself is correct. The published field stands; the
classifier now tests the TSA wording first.

**What was found.** The DigiCert timeout was not DigiCert's. Measured from the aggregator k3 between 15:12Z and 15:44Z,
with raw UDP DNS queries and fresh TCP connects toward the router (192.168.68.1) and the internet: a subset of flows gets
no reply at all, and the subset is fixed by the flow's 5-tuple - four retransmissions on the same socket never recover,
a new socket (a new source port) usually does. Fresh flows lost: 4 of 40 at 15:16Z, 24 of 60 at 15:18Z, 20 of 60 at
15:28Z; fresh TCP connects failing after 3.5 s: 8 of 25 from k3, 11 of 25 from p550, 19 of 25 from f9t (15:36-15:44Z).
think, wired to the main router, lost 0 of 40 flows and 0 of 40 connects at the same minutes. Pings, kept connections
(SSH sessions, ptp4l, chrony, the trigger listener) and LAN flows between hosts (f9t and k3 to the NAS database, 25 of
25 each) were unaffected. The common factor is "a host behind the fleet timing switch talking to or through the router".
It is not k3 (identical from p550 and f9t), not DNS (raw UDP and TCP alike), not IPv6 (both families), not the NIC
(pinning every flow to k3's other transmit queue changed nothing), and not a server (DigiCert, freetsa, drand, GitHub,
Rekor and Cloudflare all answer in under 0.3 s when the flow gets through). The physical cause is on the router side of
that path and needs hands: a router or satellite restart, or moving the switch's uplink to a port on the main unit.

**What it affected.** One hour without a commit (15:00Z), recorded honestly as skip pulse 0140. No value was withheld
or revealed improperly. The 06:00-14:00Z hours minted normally, so either the loss began after 14:00Z or its rate was
low enough that no fetch fell on a dead flow. A side finding on k3: its resolver preferred an IPv6 DNS server and IPv6
addresses, so under the same per-flow loss every lookup took 5-15 s; k3 now prefers IPv4 (`/etc/gai.conf` precedence)
and IPv4 resolvers, and its git SSH connect timeout is 6 s. Those shorten the worst case; they are not the cause.

**What was done (commit 94b536e, live for the 16:00Z cycle).** Every outbound connection the cycle makes now retries on
a fresh socket with a short timeout, so a dead flow costs seconds instead of the hour: the entropy-host RPC connect
(4 x 4 s), each TSA request (3 x 8 s, the two TSAs still in parallel), the cycle's pull, push and rebase (25/40 s, three
attempts), the drand latest-round fetch (3 x 6 s) and pulse.py's git fetch (3 x 20 s); local git verbs get 45 s so
nothing can hang. No protocol, format or verifier change. Still open: the path itself (above), and a third pinned TSA so
that a single unreachable authority cannot skip an hour (2-of-3).

**Outcome at 16:00Z.** With the retries live the hour minted normally: commit 0141 with both TSA tokens in under a
second, pushed 57.6 s before release; reveal 0142 pushed 4.8 s after release. No retry was needed on those steps. The
mint-time Rekor upload did land on a dead flow: it did not finish inside its 10 s budget and was left to CI's anchoring
pass as designed, so from 0.15.1 that request too retries on a fresh socket (3 x 8 s instead of one 40 s wait).

**Placed (16:35Z, fleet-wide survey).** Thirteen hosts ran the same probe at the same minute. The four that lose flows
(k3, p550, f9t, timehat) are exactly the hosts wired to Deco satellite **192.168.71.249** (30:68:93:a8:50:86): 0.3-0.5 ms
to it, ~3 ms to the main unit over its wireless backhaul, 6-8 of 30 fresh router-bound flows lost each. Hosts wired to
the other satellite 192.168.71.250 (beast, gx10-1; also ~3 ms to the main over wireless) and hosts wired to the main
unit (think, ryzen, macstu, protectli, cm5-0) lost 0 of 30. LAN connections *through* the sick satellite to any host on
the other two are clean (15 of 15 to beast, gx10-1, rtx4500, nas1, protectli); only flows the main unit must route or
terminate die. The satellite's backhaul also shows one-second latency spikes (a ping from beast to it: 5 ms min,
1 082 ms max). Remedy is on that unit: restart it, give it a wired backhaul, or move the fleet switch's uplink to the
main unit or the other satellite.

**Lesson.** Loss that is sticky per flow is invisible to every monitor that keeps its socket - ping, PTP, chrony, an SSH
session - and only shows in things that open a new connection per request, which is exactly what the beacon's TSA,
Rekor and git steps do. The probe that finds it is "N fresh sockets, count the ones that never answer"; the mitigation
that works without touching hardware is "retry on a new socket", not a longer timeout.

## ERR-019 — commit 0138 could not be revealed or failed for 2 h 35 min: a stalled receiver stream put the GNSS anchor before the release, and the failure path then broke on its own reason string (2026-09-14 12:01–14:36Z)

**What happened.** At 12:01:01Z the round for commit 0138 was served 1.11 s after its release and the reveal began. f9t's
GNSS anchor came back as 1789387259 (one second before the release 1789387260), because the receiver's serial stream had
stalled - the same row loss that has dropped its sawtooth-log coverage below 95 % since the F9T incident (ERR-018). The
reveal asked f9t again three times 0.7 s apart, got the same stale second each time, and was refused ("reveal anchored
before the round released"). The cycle then tried to mint the failure pulse, and that path had two defects of its own:
the reason string (built with `json.dumps`, so quoted) was passed through `shlex.split` on its way to the entropy host's
daemon, which strips quotes and, on the 200-character truncation cutting inside a quoted section, raised ValueError - the
12:01Z crash. The 13:00Z and 14:00Z cycles resumed the unresolved commit as designed, reached the failure path, and were
refused with "entropy host signed a different failure reason": the host had signed the de-quoted string. Neither hour
minted its own commit. Resolved by hand at 14:36Z: failure pulse **0139** minted with a single-token reason, published,
finalized on the entropy host, verified; the chain resumed at 15:00Z.

**What it affected.** Two hours without a pulse (13:00Z, 14:00Z) and one commit resolved 2 h 35 min late, by a failure
pulse rather than a reveal. No value was revealed or withheld improperly: 0138's secret stayed on the entropy host in the
`abandoning` state until finalized as abandoned. CI's chain check failed from 12:50Z to 14:36Z on the unresolved commit,
which is what it is for. 0138 is NOT-SATISFIED under the timing profile (f9t coverage 88.7 %) and is listed in
`ci/TIMING_PROFILE_EXCEPTIONS.json`. The pre-built trigger datagram deployed at 11:34Z worked as intended and is unrelated
(0138's trigger reached k3's kernel 0.55 ms after the instant).

**What was done.** (1) The failure reason is sent to the daemon as one argument, never shell-split; if the host's signed
wording differs, the pulse carries the host's wording instead of refusing. (2) The reveal keeps asking f9t for a fresh
anchor every second for up to 60 s, never past the reveal window, instead of three quick tries. (3) The cycle driver's
failure extras are plain `key=value`, no quotes or braces. Open: the receiver's serial stream itself (Sipeed bridge or
receiver; ERR-018), and the stamp-probe window that makes f9t's coverage a per-pulse verdict.

**Lesson.** A failure path is only a failure path if it has been exercised end to end with realistic inputs; this one
had been fixed once (ERR-017) for the reason string and still carried a shell-splitting step nobody had run a quoted
string through.

**Addendum (15:50Z).** The receiver row loss named above has held f9t's sawtooth-log coverage between 67 % and 91 %
for every pulse from **0126 (06:00Z) onward** (the database holds 2 245-3 568 f9t rows per hour since 00:00Z against a
steady 3 600 from the timehat 6T logger; the loss is scattered single seconds, not whole-minute gaps). Those pulses are
NOT-SATISFIED under the timing profile for that reason alone and are listed as an open range in
`ci/TIMING_PROFILE_EXCEPTIONS.json`; the range closes at the first pulse whose coverage is back above 95 %.

## ERR-018 — operator error during a clock incident: the time host's PHC was set 73.8 s off by hand for four minutes, and the aggregator's clock followed NTP 60 s away from its PHC (2026-09-14 00:32–00:50Z; no pulse minted or affected)

**What happened.** While Bill re-seated the ZED-F9T (a loose TP1 wire), its pulse into p550's i210 was absent or disturbed
from 00:29Z. `ts2phc`, which never steps, railed the i210 at its ±6.25 % frequency limit chasing the bad edges and had the
PHC 130 ms off UTC+37 s by 00:40Z; p550's chrony marked IPHC a falseticker. The operator (Claude, on Bill's instruction to
check the recovery) stopped ts2phc and then applied a manual `phc_ctl adj` **with the wrong sign** (`phc_ctl cmp` prints
REALTIME − PHC, not PHC − REALTIME), putting the PHC **+73.8 s** off at 00:43:49Z; the attempt to undo it with a negative
`phc_ctl adj` was silently rejected, and a first restart of the i210's ptp4l servo railed too. The PHC was set correctly
with `clock_settime` at 00:48:14Z and disciplined by the P550-BMC grandmaster (`bmc-phc-monitor`, normally read-only,
`free_running 0`), locking at −7 ns; chrony re-selected IPHC. Independently, from 00:34Z k3's chrony, seeing no majority
among its PTP PHC, p550's NTP and timehat, **followed p550's NTP instead of its own hardware clock** and stepped and slewed
the aggregator's system clock to **60 s ahead** by 00:48Z (six 1–2 s steps, then slewing at maximum rate, tracking p550
as the operator moved p550's PHC); it snapped back −60.02 s at 00:49:27Z and re-selected the PHC at 00:50:27Z. The F9T
pulse was back and steady at 00:52Z, gone again 01:01–01:16Z while the wire was fixed, and the PHC was handed back to
ts2phc at 01:25Z after 20 s of edges within 40 ns (the BMC ptp4l returned to read-only).

**What it affected.** No pulse. The last cycle before the incident finished at 00:01:03Z with Rekor's integratedTime one
second after its instant, and the next (01:00Z, 0116/0117) ran on correct clocks with p550 on the BMC discipline; both
verify. Had a commit been attempted in the window, the witness's own epoch guard (|PHC − system − TAI| > 0.5 s) would have
refused it, producing a public skip pulse. The excursions are recorded, second by second, in the timehat clock streams
(`ts2phc_stream`, `epoch_stream` for k3: PHC − system fell from 37.000 s to −23 s and back; `ptp4l_stream`, `gmmon_stream`).
The 01:00Z cycle paid 12 s twice because p550's stamp probe falls back to a 12 s live sampling window when ts2phc is not
running (push +14.4 s, reveal +16.1 s after release; margins intact).

**What was done.** (1) k3's chrony PHC refclock is `prefer trust` (01:34Z): NTP can no longer outvote the PTP PHC.
(2) A recovery procedure for a disturbed F9T pulse is written into HARDWARE.md (stop ts2phc first; BMC fallback discipline;
set the PHC with `clock_settime`, never `phc_ctl adj` by eye; verify the pulse free-running before handing back).
(3) The incident timeline is in CADENCE.md §2. Open: cap the stamp probe's live window and prefer the ptp4l ring when
ts2phc is stopped (a vendored host tool, so a CLI release); consider `noselect` on k3's NTP servers.

**Addendum, 02:30Z.** The F9T pulse did not stay steady after the 01:25Z hand-back: ts2phc recorded excursions of tens to hundreds
of milliseconds in roughly one minute of every three from 01:39Z (01:39–41, 01:43–44, 01:49–53, 01:58–02:01, 02:04, 02:06–08,
02:11–13, 02:16, 02:22–23, 02:25–26), the receiver's own serial stream lost rows in the same minutes and at 02:23Z reported a
time pulse with `qErr` −368.7 ms flagged invalid, and p550's chrony flapped IPHC between falseticker and selected four times
(02:16, 02:22, 02:25, 02:26Z) without stepping. The fault is at the receiver or its connections, not only the TP1 wire. Two
pulses carry the consequence in their signed time statements and are honest about it: **0116/0117 (01:00Z)** are
NOT-EVALUABLE under the timing profile (ts2phc stopped: no discipline numbers; the BMC monitor was servoing, so `s2` where the
profile expects the read-only `s0`), and **0118/0119 (02:00Z)** are NOT-SATISFIED (F9T→i210 discipline 225 µs RMS with a
+1.01 ms sample on the commit, 4.96 ms RMS with a −34.7 ms sample on the reveal; mesh likewise). Their cryptographic
verification is unaffected; a contract that *requires* the profile would refuse them, which is the intended behaviour.
At 02:27Z p550 was returned to the BMC discipline (ptp4l `free_running 0`, −1 ns; IPHC −4 ns; second event +24 µs) with
ts2phc stopped, and stays there until the F9T pulse is clean for a sustained period. Cycles minted on the BMC discipline
will be NOT-SATISFIED under v1's `servo == ts2phc` requirement and pay the stamp probe's 12 s fallback; both are known.

**Addendum, 03:30Z.** The pulse stayed intermittent through 03:20Z (clean windows at 03:00 and 03:10, 51 edges with a 33.7 ms
outlier at 03:20); p550 remains on the BMC discipline. **0120/0121 (03:00Z)** verify and are NOT-EVALUABLE under the profile
(mesh monitor servoing; f9t sawtooth-log coverage 86 % from the receiver's serial row loss); they and every pulse until the
hand-back are listed in `ci/TIMING_PROFILE_EXCEPTIONS.json` (an open range from 0122). Each such cycle also pays the stamp
probe's 12 s fallback (push +14.4 s, reveal +16.6 s at 03:00Z; margins intact).

**Closure, 04:15Z.** The F9T pulse read clean in three consecutive ten-minute windows (03:51, 04:01, 04:11Z: 60–61 edges per
minute, worst offsets 43–67 ns) and the gated watcher handed the i210 PHC back to ts2phc at 04:11:16Z: locked at +3 ns, the BMC
ptp4l returned to read-only, chrony IPHC −4 ns. **0122/0123 (04:00Z)**, minted eleven minutes earlier on the BMC discipline,
verify and are NOT-EVALUABLE under the profile like 0116–0121; the exception range is closed at 0123 and from 0124 every
pulse must satisfy the profile again. Total: eight pulses (0116–0123) fail the timing profile because of this incident, none
fails cryptographic verification, and the record says which and why.

**Lesson stated plainly.** A hand correction to a stratum-1 clock must be measured twice and applied with a tool whose
sign convention has been read, not guessed; and a chronyd that can step without limit (`makestep 1 -1`) must not be allowed
to choose an NTP peer over the hardware clock it exists to follow.

## ERR-017 — commit 0096 failed at the reveal: the new reveal path crashed on a missing import, and the first failure pulse could not mint (2026-09-13)

**What was wrong.** The fast-chain commit (`01e17d6`, 14:20Z) restructured `pulse.py reveal` so the cycle driver could
hand over the drand round it had already fetched (`--drand FILE`). In that branch the thread-pool class used a few lines
later was never imported (the import sat in the other branch). Every staging run before the cutover had been commit-only,
so the reveal path was never executed; an external latency review found the defect by static probing at about 15:00Z,
and think's 15:00 cycle hit it live at 15:07:04Z — think's checkout had been pulled to the new code by its decisions-mirror
job at 14:50, and its :02 fallback ran the new driver. `pulse.py reveal` raised, the driver tried to mint a failure pulse,
and that failed too: the failure reason it passed to the entropy host contained characters the host's command sanitizer
strips (quotes, newlines, a traceback), so the host signed a *different* reason string and the aggregator refused to mint
("entropy host signed a different failure reason"). The cycle exited with commit 0096 published and unresolved, and the
entropy host holding 0096 in the `abandoning` state (E retired unrevealed, awaiting finalization).

**Fix.** At 15:09:38Z, inside the reveal window, the operator minted **failure pulse 0097** for commit 0096 from think with a
reason that survives the sanitizer, published it with checkpoint 000097, and finalized the abandonment (E erased). The
chain records the commit, its failure and the stated cause; nothing was rewritten. Code: the executor is imported at module
level and inside the function (`pulse.py`); the failure path now sanitizes the reason exactly as the hosts do before
sending and comparing it, so a failure pulse can always mint; the staging procedure now runs a full pair (commit **and**
reveal, 60-round lead, no finalize, secret retired afterwards) before any cutover. The other findings of the same review
were verified and fixed in the same commit (exact-round hand-off, DNS-free probes, locked ring writes, bounded warm-up,
honest start labels, the lead gate). No consumer decision is known to have selected 0096: a failed commit is ineligible
by rule and the commit-bound value of a later commit is unaffected.

## ERR-016 — an unscheduled cycle at 12:26:57Z when the fallback timer's schedule was changed (2026-09-13)

**What was wrong.** While moving the hour's start from think's timer to the time host's clock (CADENCE.md §2 "Cadence
source"), `qrng-beacon.timer` was rewritten from `OnCalendar=hourly` to `OnCalendar=*:02:00` (the fallback) and reloaded
at 12:26:57Z. The timer has `Persistent=true`; systemd compared the new schedule's most recent elapse (12:02) with the
last recorded trigger (12:00:26) and ran the service immediately as a missed run. That started a full cycle off the
hourly grid: **pulse 0090** (commit 12:27:10Z, target release 12:32:03Z, `core.cadence.source = "think-timer"`,
`targeting = "drand-latest+lead"`) and **pulse 0091** (reveal, pushed 15 s after the round). Both verify; nothing about
their construction differs from a scheduled pair. The stated cadence is one pair per hour on the hour, and this pair is
outside it. Operator error, not a chain fault.

**Fix.** The pair stays in the chain (append-only). CADENCE.md records it. Operational rule: when changing a
`Persistent=true` timer's schedule, stop the timer first or touch its stamp file
(`~/.local/share/systemd/timers/stamp-<unit>.timer`) before `daemon-reload`, so the new schedule cannot be read as a
missed elapse. The one-cycle-per-hour guard in `beacon-cycle.py` (`.cycle-hour`) does not cover this case because it
was the first cycle of that hour. (At 13:02 the fallback timer fired while the triggered 13:00 cycle was still running;
systemd treated the start as a no-op because the unit was active, so no second cycle began — the guard was not needed.)

## ERR-015 — 0.11.0 read publication time from an unsigned field and advanced past withheld evidence (2026-09-13)

**What was wrong.** The commit-bound rule shipped in `notbefore` 0.11.0 decided "was this commit public before its
round?" from the anchor record's convenience copy of Rekor's `integratedTime`, which is not covered by Rekor's signed
entry timestamp; the record wrapper could be edited to make a retroactive anchor look timely. Second, a commit whose
anchor record was *missing* from the log source was passed over by rule — but the anchors branch is operator-controlled
and editable after the round, so absence there is not proof of anything; an operator (or a tampered mirror) could steer
a contract to the next commit by deleting a record. Third, the commit-bound bundle checker read the record's time
without running the anchor verifier at all, so forged records passed offline. All three were found within hours by an
external adversarial review (`recommendations.md` R1–R3). The steering claim in `CLAIMS.md` was therefore not yet
earned for the four hours 0.11.0 was current; no consumer decision is known to have relied on it.

**Fix (0.12.0, spec 0.9).** Anchor verification binds the wrapper's `integratedTime` and `logIndex` to the SIGNED
entry and exports the signed values (`CheckResult.anchor_facts`); nothing downstream reads the wrapper. Publication
evidence comes from Rekor itself when online — entries found by the statement hash derived from the pulse bytes,
verified under the pinned anchor and Rekor keys — and from a signature-verified record when offline; a commit with no
evidence HALTS execution ("refusing to advance past a candidate whose eligibility cannot be established") instead of
advancing; "Rekor has no entry" is decisive only after the anchor grace period. The bundle checker runs the same anchor
verifier as the online path. Tests: 32 (deleting the local record changes nothing online; offline halts), 33 (a
wrapper rewritten to one second before the round is not believed; the signed time wins). Also from the same review:
verification verdicts are now VERIFIED / DEGRADED / INVALID with exit codes 0 / 2 / 1 so a dry run cannot become
"verified" by being bundled (R5); bundles re-run the committed operation when the input is included and bind the
transcript's parameters to the signed contract (R4); a missing checkpoint fails for checkpointed pulses; `register`
accepts every signed contract version (R6); range spans above 2^64 are refused instead of looping forever (R10); the
decision log's idempotency is per signer namespace, not per global hash (R7), and request bodies are measured after
reading (R8).

## ERR-014 — the TSA verifier trusted less than the documentation claimed: FreeTSA fetched-on-absence, DigiCert via the system store (2026-09-12)

**What was wrong.** `NOTBEFORE.md`, the package README and `cli/RELEASING.md` said the FreeTSA CA was "vendored and
pinned". The vendored files were indeed shipped, but `tsa.py`'s code path would download them if absent, and
DigiCert tokens were verified against whatever `/etc/ssl` bundle the machine had. A verifier that pins its own
verification code and keys but defers its timestamp trust to the host's certificate store is not what the docs
described. Found by external code review.

**Fix.** `keys/tsa/` now holds the four trust anchors as tracked files — FreeTSA root (`A6:37:9E:7C…`) and signer,
DigiCert Trusted Root G4 (`55:2F:7B:DC…`, fetched from DigiCert's repository and cross-checked against the macOS
system root store) and the DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1 intermediate (`CA:0B:15:54…`,
taken from a live token) — with `PINS.json` recording fingerprints, sources and expiry. `tsa.py verify` uses only
these (`-CAfile <pinned root>`, pinned intermediate as `-untrusted`; `openssl ts` builds its store from the given
files only and never loads the default paths — confirmed on OpenSSL 3.0.13 and 3.6.3 by offering the wrong root while
the right one sat in the system store), never downloads, and fails closed when a pin is missing. Tested: every existing token still verifies (newest pulse, first v0.5 pair, the
retroactive tokens on 0010, a decision contract); hiding the DigiCert root or offering the wrong root makes that
TSA's token FAIL. Consequence, stated: when a TSA rotates its chain, tokens fail loudly until a release pins the new
chain — that is the behaviour a pinned verifier should have. Shipped as `notbefore` 0.7.1; the repo-root verifier
(CI) uses the same files.

## ERR-013 — `execute` gated decision contracts on the EARLIEST TSA token and ignored token failures; `plan` exited 0 with fewer than two tokens (2026-09-12)

**Affected:** `notbefore` 0.6.0 (on PyPI ~20:32–20:5x UTC), the first release with decision contracts. Found by
external code review within the hour.

**What was wrong.** NOTBEFORE.md §7.11 required two TSAs and refusal "if any token time is not before the selected
round". The code compared `min(token times)` with the release, so one early valid token plus one late (or
corrupt) token passed; `verify_registration()` treated one token as enough and its failure flag was ignored;
`plan` warned but succeeded with a single token; `select_pulse()` stopped after five non-verifying candidates,
diverging from the normative "first eligible" rule; `frac` was a float inside a "canonical" JSON, which another
JCS implementation need not serialize identically; and the prose called RFC 3161 timestamping "registration".

**Fix (0.7.0).** A pure gate `timestamp_verdict()` — both expected TSA identities present and verifying, no failing
token, no unexpected identity, **latest** token strictly before the round — used for `plan` (exit 1 if incomplete;
idempotent `notbefore timestamp` fetches only the missing token) and `execute` (`--allow-unregistered` covers a
*missing* token for a labelled dry run and never a failing or late one). No candidate cutoff. `frac` is a decimal
string applied exactly. The words are now "timestamped" and "this is timestamping, not registration". Tests 25–27
cover the gate exhaustively, the real-file negatives (deleted token, corrupted token, edited contract byte, edited
roster, late timestamps), and traversal past six failed candidates. Contracts written by 0.6.0 remain valid; only the
verifier was too lenient, and no 0.6.0 contract was executed against a real pulse.

## ERR-012 — copy and probe framed userspace clock-read latency as the timestamp precision bound; the beacon never uses such a read (2026-09-12)

**What was wrong.** `CLAIMS.md`, `HARDWARE.md`, `NOTBEFORE.md` §9 and `TLOG.md` §14 said a pulse stamp was "good to
27–47 µs" because a userspace PHC read costs that much, and `hosts/stamp_probe.py` spent 41 back-to-back reads
choosing the "cheapest" one and reporting read-cost statistics. But no software clock read is part of a pulse's
time: the anchor is the GNSS epoch of an edge captured in i210 silicon (SDP0 EXTTS) and disciplined by `ts2phc`;
the `CLOCK_REALTIME` field in a time statement is freshness and ordering only. Presenting read latency as the
precision term understated what the anchor is and confused readers about what is measured (Bill, 2026-09-12: "we
don't even use the userspace read").

**Fix.** The read-cost sections and figures are removed; the precision model is stated as *receiver epoch error ⊕
ts2phc discipline ⊕ uncalibrated fixed delays*, with software timestamps labelled freshness. `stamp_probe.py` now
takes one `CLOCK_REALTIME` reading as freshness, keeps the PHC-vs-REALTIME cross-check (it shows chrony tracking the
PHC), and no longer reports read costs. Tool hashes in statements change accordingly (informational drift warning).
The 2026-09-11 k3-vs-p550 read-latency comparison remains in the notebook and in git history; it was a real
measurement, just not a property of a pulse.

## ERR-011 — checkpoint anchor statements hashed the whole note, so the first cosignature broke the anchor check (2026-09-12)

**What happened.** The Rekor anchor statement for a checkpoint included `note_sha256` over the entire
`checkpoints/NNNNNN` file. Signed notes accumulate signature lines: when `notbefore.net/witness/ryzen` cosigned
checkpoint 000051 at 17:21 UTC (commit `7839b04`), the file changed and CI reported *"published statement differs
from the file — a checkpoint changed after anchoring"* — a false alarm; the head had not changed, only a witness
line had been appended. The verify run on `7839b04` failed on that.

**Fix.** `note_sha256` is now over the note **reduced to the log's own signature line** (cosignatures stripped).
For a note anchored before any cosignature the reduced note is byte-identical to what was anchored, so the existing
Rekor entries for 000049–000051 match without re-anchoring; a cosignature appended later no longer disturbs the
anchor. Verified against the live anchors branch: all three checkpoints PASS, no unexplained entries.

**Lesson.** Anchor the *head* (origin, size, root, the log's signature), never the mutable envelope around it.

## ERR-010 — a doc push during the minting window made the 16:00 UTC cycle refuse its own reveal; rescued by hand inside the deadline (2026-09-12)

**What happened.** Commit 0048 was minted and pushed at 16:01:47 UTC. At 16:04:49 claude-main pushed two
documentation/CLI commits to `main` — inside the :00–:07 window the operator notes themselves say never to push in —
and at 16:07:27 Bill pushed a site fix. `pulse.py reveal` at 16:05:31 refused: *"checkout is not the published
head; pull first, never mint on a fork"*; the signed-failure path refused for the same reason, so for two minutes the
chain head was an unresolved commit with no reveal and no failure. Rescue: think fast-forwarded to `origin/main` and
`beacon-cycle.py` resumed the commit (16:07); the reveal minted but its push was rejected by the second concurrent
push; `git pull --rebase && git push` landed **REVEAL 0049 at 16:08:46 UTC, 199 s after the round released** — inside
the 600 s contract — and the entropy host finalized (E erased). Pulses 0048/0049 are valid; no value was lost.

**What was wrong.** The aggregator treated *any* difference between its checkout and `origin/main` as a fork. Being
merely **behind** a head that contains only other people's docs is not a fork, and with a second person now pushing
to `main` (the notbefore.net site lives in this repository) a "never push :00–:07" convention is not a safety
property.

**Fix.** `require_synced()` fast-forwards when the checkout is a strict ancestor of `origin/main` with a clean
chain, and still refuses when it has commits origin lacks (diverged). `beacon-cycle.publish()` retries a rejected push
after `git pull --rebase` (up to 3×; our commits touch only `chain/` and the checkpoint files, so the rebase is
conflict-free; a failed rebase is aborted and raised). The window rule remains a courtesy, no longer load-bearing.

**Also fixed by this incident's review:** `recover` would have stalled on a *local* unpushed reveal at the next
cycle (`git pull --ff-only` fails on divergence); the rebase-retry covers that case too.

## ERR-009 — the split-view check raised a false "possible hidden branch" on an anchor still in flight; a transient Rekor network error failed a run (2026-09-12)

**Affected:** `ci/verify_anchors.py` between `dfaf75e` (12:50 UTC) and the fix; CI runs **34698076944** (14:01 UTC,
COMMIT pulse 0044) and **34696292826** (13:23 UTC, hourly). No pulse, key or anchor was wrong; **no split view
occurred.** Found by Bill's other Claude session reading the failed run, 2026-09-12 ~14:10 UTC.

**What was wrong (1).** The check enumerated every Rekor entry under `keys/anchor.pub` and called any entry that was
not yet a *record on the `anchors` branch* "unexplained". But the anchor job uploads to Rekor **before** it pushes the
branch, and the verify job checks the branch out at job start; so a verify run inside that window saw pulse 0044's
own anchor (logIndex 2808375615, 14:02:49 UTC) as a hidden branch while simultaneously listing 0044 as
`missing_in_grace` — "44 pulses, 43 anchored, 44 entries under the key" was the same object counted from both sides.
Intermittent: it fired only when the verify step ran between the upload and the branch push.

**What was wrong (2).** In the 13:23 run, one live Rekor refetch (pulse 0021) failed with `Connection reset by peer`
and was treated as a broken anchor. The offline proof — signed entry timestamp + inclusion proof + checkpoint, all
verified against the pinned Rekor key — had passed; a transient network error is not evidence against it.

**Why it matters.** For a log whose claim is verifiability, a verifier that cries "hidden branch" at its own
in-flight anchor is worse than one that misses a real one: it teaches readers to ignore the alarm.

**Fix.** (1) An entry under the anchor key is now matched **by its recorded hash** against the statement hash
recomputed from *every* published pulse, not by the presence of a record on the branch. A match to a pulse whose
record is still absent is reported `[WAIT] … in flight` (counted in `rekor_entries_in_flight`) and becomes a
failure only if the record stays missing past the 25-minute grace; a hash that matches **no** published pulse is
the alarm, as before. (2) Live refetches retry three times with backoff and then degrade to `[WARN]` with the
offline proof standing (`rekor_refetch_failed` counts them). (3) Tally relabel: `commit_rekor_late` was 16 in every
run — those are exactly the sixteen commit pulses ≤ 0041 whose anchors are retroactive by construction (ERR-008);
they are now `commit_rekor_retroactive`, and `commit_rekor_late` counts only commits ≥ 0042 whose anchor missed the
release (0 so far; every contemporaneous commit has anchored ~2 min before its round). Tested against the live
branch with pulse 0045's record hidden (in flight → PASS with one WAIT) and pulse 0030's hidden (overdue → FAIL).

**Second shape, same day (16:07 UTC run on `b23b5e6`):** the verify job's *checkout* was older than a pulse that was
pushed and anchored seconds later (0049), so 0049's Rekor entry matched no pulse in that checkout. Fix: before calling
an entry unexplained, the check fetches `origin/main` and tests the next pulses' statement hashes; and an entry younger
than the grace period that still matches nothing is a `[WAIT]`, becoming the alarm only if it remains unexplained.

**Not changed:** the CLI (`notbefore`) does not enumerate Rekor entries and was not affected; its per-pulse refetch
already degraded to a warning.

## ERR-008 — the entropy host accepted a second commit at an already-resolved seq; operator equivocation was neither prevented nor documented (2026-09-12)

**Affected:** `hosts/entropy_host.py` before hash `d2eaa923b7ac817f…`; `PROTOCOL.md`, `CLAIMS.md`, `THESIS.md`
through commit `75c0366`, none of which stated the split-view limitation. `hosts/beacon-cmd` is unchanged: its
`seq < last` guard is a *backdating* guard by design (an unpublished commit legitimately reuses its seq).

**What was wrong.** After a commit at seq N had been published and resolved (revealed or abandoned),
`entropy_host.py commit N` would mint a fresh commitment at the same seq. With the aggregator assembling pulses,
the operator could produce two different valid pulse-Ns on one `prev_hash` — a fork — and show each to a different
audience. Nothing published said so; a reader could not have known the log was equivocation-*detectable* only by
comparing independent observations, of which there was exactly one (ours).

**Not a stranger's capability, and not retroactive.** Every pulse carries five signatures under pinned keys, so a
fork by anyone but the key holders fails verification; and a commit's RFC 3161 tokens must predate its drand round,
so both branches of a fork would have to be made live inside the same publication window.

**Fix.** (1) `entropy_host.py` refuses `commit N` when seq N has a record in state `revealing`/`abandoning`/`revealed`,
or `abandoned` with a real resolver hash (an abandonment bound to the all-zero hash means the commit never entered
the published chain, and the seq may be reused). Deployed on protectli 2026-09-12 12:45 UTC and exercised through
the forced command. Defence in depth only — root on the host can delete the record. (2) **Publication anchors:**
every published pulse is entered, under the pinned key `keys/anchor.pub`, into Rekor (the public Sigstore
transparency log) and OpenTimestamps (Bitcoin block headers); `ci/verify_anchors.py` verifies each anchor offline
against the pinned Rekor key and **enumerates every Rekor entry ever made under the anchor key** — an anchored
hidden branch is publicly visible, and a published pulse with no anchor fails CI after 25 minutes. (3) PROTOCOL,
CLAIMS and THESIS now state the single-writer split-view limitation and what bounds it.

**Retroactive anchors.** Pulses 0001–0041 were anchored 2026-09-12 12:47 UTC, after the fact (Rekor log indices
2807717612–2807718704). Their Rekor times prove existence *from then*, not from minting; the TSA tokens remain the
commit-time proof. From 0042 on, the workflow anchors each pulse within minutes of its push, so a commit's Rekor
`integratedTime` precedes its drand release — a third clock on the commit.

**Found by:** Bill's question "so anyone could branch this pulse chain?" (2026-09-12), answered by reading the guard
code instead of the design intent.

## ERR-007 — required witness statements in pulses 0018/0019 report "invalid" while the pulses verify

**Affected:** pulses **0018, 0019** (the first v0.5 pair), `core.statements.witness.statement.measurement.epoch_guard`.
**What was wrong:** the witness (k3) statement carries `epoch_ok: false`, `chrony_selects_iphc: false` and an ALERT
text saying timestamps from this clock are invalid — yet the strict verifier passed the pulses, because it checked the
witness's **signature** and never its **content**. Two defects: (1) the epoch guard was written for p550 and misfires on
k3: k3's chrony disciplines from its PHC with `offset -37` rather than the `tai` option, so its kernel TAI offset is
**0** and the guard computed a 37 s "epoch error"; and k3's refclock id is `PHC`, not `IPHC`; (2) the verifier treated
required clock statements as attested-if-signed.
**Was k3's clock actually bad?** No, on live evidence taken 2026-09-12 02:3x UTC: PHC − CLOCK_REALTIME = 36.999985 s
(PHC holds TAI, system UTC — exactly right), chrony stratum 1 selecting `PHC` at RMS 15 ns, ptp4l offset to the BMC
grandmaster −6 ns. The guard's verdict was wrong; the pulses' *timestamps* were fine. That does not excuse a pulse that
says "invalid" and passes.
**Fix (2026-09-12):** the probe is host-aware (expected refclock id passed per host; when the kernel TAI offset is
unset it uses the IERS constant and says so); the **aggregator refuses to mint** if a required clock statement reports
an unhealthy clock; **the verifier now fails a pulse whose required time or witness statement reports
`epoch_ok != true`, an unselected hardware refclock, or any ALERT** — pulses 0018/0019 therefore now **fail** the current
verifier, as they should, and are recorded here as valid-in-content but formally non-compliant. **The first fully
compliant pair is 0020/0021** (2026-09-12 02:50–02:55 UTC). Latent issue also
logged: k3's `offset -37` is the hardcoded leap-second form; it should be the `tai` option (gap #10).
**Found by:** external reviewer, 2026-09-12 (review #3, finding 4).

## ERR-006 — archive manifest hashes do not match the bytes on disk for 2.835 % of blocks (FINAL, 2026-09-12)

**Affected:** the sidecar-based commitment root **`c88c4320…2738`** (`merkle/manifest.json`) and any capture-time
provenance claim for the 1,217 blocks listed in `merkle/mismatch.json`.

**Final result of the full re-hash (every one of 42,935 blocks, 4.50 TB, read on macstu 2026-09-12):**
**1,217 blocks (2.835 % of the archive) do not match the SHA-256 in their capture-time sidecar; 41,718 do.** No block
was missing or unreadable. (The preliminary entry's "5.6 %" was the rate within the first third scanned, where the
failures are concentrated; the archive-wide figure is 2.835 %.)

**Where they are.** Mismatches begin on **2025-08-15** and run through **2025-09-02** (worst days 08-25 at 38.1 % and
08-26 at 37.7 %), with three isolated later blocks (09-05, 09-06, 09-28). **62 of 83 capture days have zero
mismatches**, including the entire first four weeks (07-18 → 08-14). Sizes: 815 exactly 100 MiB; 401 between 16 and
48 KiB over 100 MiB; one truncated at 85,573,632 bytes.

**What was tested and rejected:** the sidecar hash is not the hash of the first 100 MiB, of the first `size_bytes`
bytes, or of any of 25 offset/length windows of the file — it bears no verifiable relation to the written bytes. mtimes
are consistent with a single original write, which argues against (does not prove) later modification. The one
mismatching sidecar examined in detail belongs to a collector session started 2025-08-15T09:00:41Z, coinciding with
the onset; a session-level attribution across all 1,217 blocks was **not** established (the August collector logs do
not exist). **The bytes themselves are statistically intact**: a mismatching block from 08-25 is indistinguishable from
a good block (Shannon 7.999983 vs 7.999983, all SP 800-22 pass, MCV 7.962 vs 7.962). This is a **broken provenance
record, not corrupted data** — with the caveat that passing randomness tests cannot prove the bytes came from the
Quantis; only the sidecar could, and for these blocks it does not.

**The correction — a new archive root over the recomputed bytes of every block:**

| | sidecar manifest (superseded, kept for the record) | **archive manifest (cite this)** |
|---|---|---|
| file | `merkle/manifest.json`, `leaves.tsv` | **`merkle/manifest-rehashed.json`, `leaves-rehashed.tsv`** |
| leaf hash | capture-time sidecar SHA-256 | **SHA-256 of the bytes as re-read 2026-09-12** |
| root | `c88c4320dff421400744abb36e65ecfc6f185b1a0e9ead5ddb0e10920b7a2738` | **`4e93d4be9ff5355d40e7e2c1d0ea599a62326aa09a651c9fa0b584764ccd95c4`** |
| leaves | 42,935 | 42,935 (**41,718 concordant, 1,217 discordant**) |
| per-leaf `sidecar_concordance` | — | `true` = provenance chain intact from 2025; `false` = provenance dated 2026-09-12 only |

`merkle_proof.py --rehashed` produces and verifies inclusion proofs that carry the concordance flag; a proof for a
discordant block says so in its `provenance` field, and a proof that claims concordance falsely does not verify.
Discordant blocks are usable as random data with provenance dated 2026-09-12 and are **excluded from any claim that
rests on capture-time provenance**. This is an archive root, not a subset root: every readable block is in it.

**Found by:** our own full re-hash, started 2026-09-11 after the sidecar-based manifest was built; headline math
corrected after external review (review #3, finding 5); final numbers 2026-09-12 12:05 UTC.

## ERR-005 — role signatures were digest signatures, not role attestations (architecture)

**Affected:** every pulse to date (**0001–0015** and any minted before the v0.5 cut-over).
**What was wrong:** the orchestrator computed `pulse_hash` and asked each host to sign that digest.
The entropy host never checked that the commitment was over bytes it produced; the time host never
checked that the timestamp in `core` was its own measurement; the witness signed without seeing the
observation. A dishonest orchestrator could fabricate `core` and still collect all three signatures.
**How to read the affected signatures:** "three named machines signed this digest" — evidence that the
record was not altered after signing and that three hosts participated; **not** independent attestation
by each host of the fact its role names.
**Fix (v0.5, in progress):** each host produces and signs its own statement (entropy host generates and
holds `E` and signs `{commitment, target_round}`; time host signs its own measurement object; witness signs
its own observation); the aggregator assembles the already-signed statements and signs the assembly with a
fourth key. Host-side scripts are published and version-bound into each pulse by hash. **Architecture effective from pulse 0018** (first v0.5 commit; 0016/0017 are the last v0.4 pair). **Host isolation
(the part that makes the aggregator unable to fabricate host facts) effective from pulse 0020.**
**Found by:** external reviewer, 2026-09-12.

## ERR-004 — every drand release time was computed 3 s late

**Affected:** pulses **0009–0015**: `commitment.target_release_unix_s` / `target_release_utc` (commits),
`external_anchor.round_release_unix_s` and `drand_at_commit.round_release_unix_s` (all), `timeline.*`
(reveals), `commitment.next_target_round_release_unix_s` (0009).
**What was wrong:** `drand_anchor.round_time()`, `watcher.py` and `PROTOCOL.md` used
`genesis + round × period`. drand defines **round 1 as occurring at genesis**, so the correct expression is
`genesis + (round − 1) × period`. Verified empirically 2026-09-12: under the old formula the live round's
"release time" sat up to 2 s in the future while the round was already being served.
**Consequences:** every published release time is **+3 s**; every "commit before round" margin was
overstated by 3 s and every "reveal after round" margin understated by 3 s; the verifier compared against
the published (late) value, so it could in principle have accepted a commitment made up to 3 s after the
round existed; the watcher waited 3 s too long. **All published claims survive** — the smallest true
commit-before-round margin is 171 s.
**Recomputed interpretation of every affected pulse:**

| seq | type | round | published release | true release | recomputed margin |
|---|---|---|---|---|---|
| 9 | legacy | 32122254 | 1789170129 | 1789170126 | single-phase |
| 10 | commit | 32122604 | 1789171179 | 1789171176 | commit precedes round by 171 s (published 174) |
| 11 | reveal | 32122604 | 1789171179 | 1789171176 | reveal follows round by 49 s (published 46) |
| 12 | commit | 32123484 | 1789173819 | 1789173816 | commit precedes round by 296 s (published 299) |
| 13 | reveal | 32123484 | 1789173819 | 1789173816 | reveal follows round by 4 s (published 1) |
| 14 | commit | 32123921 | 1789175130 | 1789175127 | commit precedes round by 297 s (published 300) |
| 15 | reveal | 32123921 | 1789175130 | 1789175127 | reveal follows round by 3 s (published 0) |

**Fix (commit on 2026-09-12, before pulse 0016):** formula corrected in `drand_anchor.py`, `watcher.py`,
`PROTOCOL.md`; **`verify.py` now computes release times itself from the round number and never trusts the
pulse's field** — for the affected pulses it prints a `[WARN] ERR-004` naming the +3 s and runs every
ordering check against the true time.
**Found by:** external reviewer, 2026-09-12, citing the drand specification ("round 1 starts at genesis time").

## ERR-003 — verifying pulses 0001–0002 with `--pin` failed after the time key rotated

**Affected:** verification of pulses **0001, 0002** with `verify.py --pin keys/` (the pulses themselves are correct).
**Symptom:** `[FAIL] time key matches pinned time_attester.pub`. The `time_attester` role moved from f9t
(key `4687aa55eff780e4`, pulses 1–2) to p550 (`6dae96e8faa9678a`, pulse 3 →), and pinning was a single
file per role, so the retired key had no standing.
**Fix (commit `590f46f`, 2026-09-12):** `keys/KEYS.json` — a key history with `valid_from_seq` /
`valid_to_seq`. `verify.py --pin` now checks the signing key is listed for its role **at that seq**.
Retired keys remain listed so old pulses stay verifiable and are never valid for new ones.
**Found by:** CI (`ci/verify_chain.py`) on its first full-chain run.

## ERR-002 — anchor text said "rising-to-on-time edge"; the on-time edge is FALLING

**Affected:** `core.time.anchor.what` in pulses **0007–0015**. Wording only; no number is affected.
**Facts:** the ZED-F9T is configured `TP-POL_TP1=0` (falling edge on the second) because the i210/igb
driver latches **only** falling edges and ignores edge-select flags; ts2phc runs `extts_polarity both`
and discards the edge that is 100 ms off the second. So the hardware-captured, on-time edge is the
**falling** edge.
**Fix (commit `590f46f`):** `gnss_probe.py` text corrected; effective from pulse **0016**.
**Found by:** external reviewer, 2026-09-12 ("some edge/anchor wording deserves reconciliation").

## ERR-001 — a signed, single ts2phc offset was published under an RMS label

**Affected:** pulses **0004–0015**. Field `core.time.precision.anchor_uncertainty.i210_servo_residual_ns_rms`
(pulses 0007–0015) or `core.time.precision.primary_discipline_rms_ns` (0004–0006).

| seq | published "RMS" | seq | published "RMS" | seq | published "RMS" |
|---|---|---|---|---|---|
| 0004 | 10 | 0008 | −6 | 0012 | −11 |
| 0005 | −12 | 0009 | −21 | 0013 | −8 |
| 0006 | −12 | 0010 | 1 | 0014 | 8 |
| 0007 | 1 | 0011 | 10 | 0015 | −8 |

**How to read the affected field:** it is **`last_offset_ns`** — the *signed, instantaneous* ts2phc offset
at the moment of the probe — **not** an RMS. An RMS cannot be negative; the sign is the giveaway. The true
servo residual over a window on this hardware is ~8 ns RMS (measured 8.27 ns over 45 s on 2026-09-11 and
8.25 ns over 12 s on 2026-09-12), and the instantaneous values above are consistent with that.
**Root cause:** the p550 probe's ts2phc branch read `/run/ts2phc-f9t.status` **once**, yielding only
`last_offset_ns`; the pulse builder used `offset_ns_rms or last_offset_ns` as a fallback and kept the RMS
label. The same defect produced 1-sample "RMS" values in the BMC cross-check block of some pulses.
**Fix (commit `590f46f`, 2026-09-12):** the probe now samples the servo over a 12 s window and reports
`last_offset_ns`, `offset_ns_rms`, `samples`, `offset_ns_min/max` as **distinct** fields; `offset_ns_rms`
is `null` when fewer than 3 samples fell in the window; the pulse never substitutes one for the other.
Effective from pulse **0016** (first cycle after the fix, 2026-09-12 02:00 UTC).
**Found by:** external reviewer, 2026-09-12 ("pulse 0015 reports an impossible negative RMS value").
**Why it matters here:** this project's claims discipline rests on publishing measured quantities with
their windows. A mislabelled statistic is exactly the failure `CLAIMS.md` exists to prevent. Recorded
here so the record of being wrong is as public as the record of being right.
