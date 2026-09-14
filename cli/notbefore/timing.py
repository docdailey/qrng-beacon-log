"""timing.py — the timing profile: a versioned, testable policy over the signed timing statements a pulse carries
(review T1; PROTOCOL.md §"Timing profile"; NOTBEFORE.md §7.14).

Until now the verifier AUTHENTICATED the timing statements (host signatures, pulse binding) and REQUIRED only epoch
health and chrony reference selection. This module adds an explicit, versioned acceptance policy over the published
figures, evaluated identically online, in receipts and in offline bundles, and reported SEPARATELY from
cryptographic integrity and from the application result:

    SATISFIED       every required observation is present, well-formed, fresh and within the profile's limits
    NOT-SATISFIED   a required observation is outside its limit (servo not locked, epoch lost, excursion too large ...)
    NOT-EVALUABLE   required evidence is missing or malformed (no statements, no mesh block, non-finite numbers, wrong units)

A contract may declare `timing: {profile: "notbefore/timing/v1" | "notbefore/timing/v2", required: bool}`. **v2** (spec 0.12) is v1
plus cadence provenance: the commit's `cadence.self_trigger` (the aggregator declared the instant on its own disciplined
clock) and `cadence.trigger` (p550's i210 hardware second event corroborates the same instant) must both be present, name
the same drand-boundary instant, and meet bounded event/issue/receive latencies; every host statement must be issued
within 30 s of the instant; the reveal must begin within 60 s of the release. An absent or rejected trigger is a FAIL
(the hour lacks a second clock's corroboration); a commit before 0098 has no self-trigger record and is NOT-EVALUABLE. The policy NEVER changes which commit
a contract consumes: a failed or unevaluable profile reports (required=false) or REFUSES on the selected commit
(required=true) — it does not advance to another known random value (this extends R2/R5: no timing-triggered reroll).

Profile v1 (the numbers are chosen from the published record: every healthy v0.5 pulse since 0018 passes; a link bounce,
a free-running disciplining servo, a stale statement or a missing mesh does not):

  time host (p550, i210 disciplined by the F9T PPS):
      epoch_guard.epoch_ok == true and chrony_selects_iphc == true                       (the notebook-220 invariant)
      discipline: servo == ts2phc, states == ["s2"], samples >= 3, offset_ns_rms <= 100, |min|,|max| <= 250 ns
      mesh_crosscheck (i210 observing the BMC GM): samples >= 3, offset_ns_rms <= 250, |min|,|max| <= 1000 ns,
          servo_states == ["s0"] (a free-running MONITOR is expected in s0; that is not a fault), 0 < path_delay_ns <= 10000,
          bmc_announced_health mentions clockClass 6 (an OBSERVATION of the GM's Announce, not authentication of the source)
  witness (k3, disciplined by the BMC GM over PTP):
      epoch_guard.epoch_ok == true and chrony_selects_refclock == true
      discipline: states == ["s2"], samples >= 10, offset_ns_rms <= 250, |min|,|max| <= 1000 ns
  gnss (f9t, the receiver):
      anchor.utc_available_flag == true; leap_seconds_gps_minus_utc + 19 == tai_minus_utc_s
      anchor_quality: coverage_pct >= 95 over the 15-min sawtooth window, sawtooth_sd_ns <= 10, |sawtooth_qerr_ns_this_epoch| <= 50,
          gnss_fix.num_measurements >= 8
  cross-statement: all tai_minus_utc_s equal; every statement's CLOCK_REALTIME stamp within 600 s of the GNSS anchor epoch
      (freshness of the statement, never an accuracy term); the GNSS anchor epoch within 600 s of the pulse's own anchor.

Numbers are parsed strictly: strings that are not finite decimals, missing keys and wrong types make the profile
NOT-EVALUABLE — missing optional evidence never grants a timing claim."""
import math, json
from decimal import Decimal, InvalidOperation

PROFILE_ID = "notbefore/timing/v1"                       # v1: clock-health statements (spec 0.10)
PROFILE_V1, PROFILE_V2 = "notbefore/timing/v1", "notbefore/timing/v2"
PROFILES = (PROFILE_V1, PROFILE_V2)
FIRST_V2_SEQ = 98                                         # the aggregator's own wake record (cadence.self_trigger) exists from 0098 (k3)
# v2 = v1 + cadence provenance (spec 0.12, 2026-09-14): the hour was declared by the aggregator's own disciplined clock AND
# corroborated by the time host's i210 hardware second event, both naming the same drand-boundary instant, with bounded
# event -> issue -> receive latency and timely signed host statements. Limits from the record (0098-0118): edge stamp
# +21..+280 us, p550 process 15 us..1.2 ms after the edge, issued <= 1.7 ms, received at k3 <= 2.9 ms (8.1 ms once), host
# statements <= 0.8 s (12.7 s once, the 01:00Z 2026-09-14 probe fallback), reveal started <= 1.5 s after release.
CADENCE = {"k3_wake_late_max_ns": 100_000_000, "edge_min_ns": -1_000_000, "edge_max_ns": 5_000_000, "woke_after_edge_max_ns": 5_000_000,
           "issued_max_ns": 20_000_000, "received_max_ns": 500_000_000, "stmt_after_instant_max_s": 30, "reveal_start_max_s": 60, "reveal_stmt_after_release_max_s": 60}
GENESIS, PERIOD = 1692803367, 3

def default_profile(commit_seq):
    """The strongest profile defined for a pulse's era: v2 from 0098 (self-trigger record + hardware trigger), v1 before."""
    try: return PROFILE_V2 if int(commit_seq) >= FIRST_V2_SEQ else PROFILE_V1
    except Exception: return PROFILE_V1
LIMITS = {"time": {"disc_rms_max": 100, "disc_abs_max": 250, "disc_samples_min": 3, "mesh_rms_max": 250, "mesh_abs_max": 1000, "mesh_samples_min": 3, "path_delay_max": 10000},
          "witness": {"disc_rms_max": 250, "disc_abs_max": 1000, "disc_samples_min": 10},
          "gnss": {"coverage_min": 95, "sawtooth_sd_max": 10, "qerr_abs_max": 50, "nmeas_min": 8},
          "freshness_s": 600}
FIRST_PROFILED_SEQ = 18          # v0.5 statements begin at 0018; earlier pulses are NOT-EVALUABLE by construction

class Timing:
    def __init__(self, profile=PROFILE_V1): self.profile = profile; self.lines = []; self.missing = []; self.failed = []; self.facts = {}
    def req(self, ok, what):                       # a required observation: present and within limits?
        (self.lines.append(("[PASS] " if ok else "[FAIL] ") + what)); (None if ok else self.failed.append(what))
    def absent(self, what): self.missing.append(what); self.lines.append("[MISSING] " + what)
    @property
    def verdict(self): return "NOT-EVALUABLE" if self.missing else ("NOT-SATISFIED" if self.failed else "SATISFIED")
    def summary(self): return {"profile": self.profile, "verdict": self.verdict, "failed": self.failed, "missing": self.missing, "facts": self.facts}

def _num(x):
    """Strict finite number from int/str-decimal; None otherwise (bool is not a number)."""
    if isinstance(x, bool) or x is None: return None
    if isinstance(x, (int, float)): return float(x) if math.isfinite(float(x)) else None
    if isinstance(x, str):
        try: d = Decimal(x.strip()); return float(d) if d.is_finite() else None
        except (InvalidOperation, ValueError): return None
    return None

def _get(d, *path):
    for p in path:
        if not isinstance(d, dict) or p not in d: return None
        d = d[p]
    return d

def evaluate(core, profile=PROFILE_V1):
    """Evaluate a profile over one pulse core (commit or reveal). Returns a Timing. v2 = v1 + cadence provenance."""
    if profile not in PROFILES: raise ValueError(f"unknown timing profile {profile!r}")
    T = Timing(profile); L = LIMITS
    sts = core.get("statements") if isinstance(core, dict) else None
    if not isinstance(sts, dict) or not all(r in sts for r in ("time", "witness", "gnss")):
        T.absent("v0.5 host statements (time, witness, gnss)"); return T
    S = {r: (sts[r].get("statement", sts[r]) if isinstance(sts[r], dict) else {}) for r in ("time", "witness", "gnss")}
    M = {r: (S[r].get("measurement") if isinstance(S[r].get("measurement"), dict) else None) for r in S}
    for r in M:
        if M[r] is None: T.absent(f"{r} measurement block")
    if T.missing: return T
    t, w, g = M["time"], M["witness"], M["gnss"]
    # ---- time host
    if _get(t, "epoch_guard", "epoch_ok") is None: T.absent("time.epoch_guard.epoch_ok")
    else: T.req(_get(t, "epoch_guard", "epoch_ok") is True and _get(t, "epoch_guard", "chrony_selects_iphc") is True, "time host: PHC epoch intact and chrony selects the i210 PHC (notebook-220 invariant)")
    d = t.get("discipline") if isinstance(t.get("discipline"), dict) else None
    if not d: T.absent("time.discipline")
    else:
        n, rms, lo, hi = _num(d.get("samples")), _num(d.get("offset_ns_rms")), _num(d.get("offset_ns_min")), _num(d.get("offset_ns_max"))
        if None in (n, rms, lo, hi): T.absent("time.discipline numbers (samples/rms/min/max well-formed)")
        else:
            T.req(d.get("servo") == "ts2phc" and d.get("states") == ["s2"], f"time host: disciplining servo ts2phc locked (states {d.get('states')})")
            T.req(n >= L["time"]["disc_samples_min"] and rms <= L["time"]["disc_rms_max"] and abs(lo) <= L["time"]["disc_abs_max"] and abs(hi) <= L["time"]["disc_abs_max"],
                  f"time host: F9T->i210 discipline {rms:g} ns RMS over {int(n)} samples, min {lo:g} / max {hi:g} ns (limits {L['time']['disc_rms_max']} RMS, +/-{L['time']['disc_abs_max']})")
            T.facts["time_discipline"] = {"rms_ns": rms, "samples": int(n), "min_ns": lo, "max_ns": hi, "window_s": _num(d.get("window_s"))}
    m = t.get("mesh_crosscheck") if isinstance(t.get("mesh_crosscheck"), dict) else None
    if not m: T.absent("time.mesh_crosscheck (i210 observation of the BMC grandmaster)")
    else:
        n, rms, lo, hi, pd = _num(m.get("samples")), _num(m.get("offset_ns_rms")), _num(m.get("offset_ns_min")), _num(m.get("offset_ns_max")), _num(m.get("path_delay_ns"))
        if None in (n, rms, lo, hi, pd): T.absent("time.mesh_crosscheck numbers (samples/rms/min/max/path_delay well-formed)")
        else:
            T.req(n >= L["time"]["mesh_samples_min"] and rms <= L["time"]["mesh_rms_max"] and abs(lo) <= L["time"]["mesh_abs_max"] and abs(hi) <= L["time"]["mesh_abs_max"],
                  f"mesh: i210 observes the BMC GM at {rms:g} ns RMS over {int(n)} samples, min {lo:g} / max {hi:g} ns (limits {L['time']['mesh_rms_max']} RMS, +/-{L['time']['mesh_abs_max']})")
            T.req(m.get("servo_states") == ["s0"], f"mesh: the monitor is free-running (s0 expected; got {m.get('servo_states')})")
            T.req(0 < pd <= L["time"]["path_delay_max"], f"mesh: PTP path delay {pd:g} ns within sanity bounds (a delay estimate, not a symmetry proof)")
            T.req("clockClass 6" in str(m.get("bmc_announced_health", "")), f"mesh: BMC Announce reports clockClass 6 / GPS-locked ({m.get('bmc_announced_health')}) — an observation, not authentication of the source")
            T.facts["mesh"] = {"rms_ns": rms, "samples": int(n), "min_ns": lo, "max_ns": hi, "window_s": _num(m.get("window_s")), "path_delay_ns": pd}
    # ---- witness
    if _get(w, "epoch_guard", "epoch_ok") is None: T.absent("witness.epoch_guard.epoch_ok")
    else: T.req(_get(w, "epoch_guard", "epoch_ok") is True and _get(w, "epoch_guard", "chrony_selects_refclock") is True, "witness: PHC epoch intact and chrony selects its PHC")
    d = w.get("discipline") if isinstance(w.get("discipline"), dict) else None
    if not d: T.absent("witness.discipline")
    else:
        n, rms, lo, hi = _num(d.get("samples")), _num(d.get("offset_ns_rms")), _num(d.get("offset_ns_min")), _num(d.get("offset_ns_max"))
        if None in (n, rms, lo, hi): T.absent("witness.discipline numbers well-formed")
        else:
            T.req(d.get("states") == ["s2"], f"witness: ptp4l locked to the BMC GM (states {d.get('states')})")
            T.req(n >= L["witness"]["disc_samples_min"] and rms <= L["witness"]["disc_rms_max"] and abs(lo) <= L["witness"]["disc_abs_max"] and abs(hi) <= L["witness"]["disc_abs_max"],
                  f"witness: BMC->k3 discipline {rms:g} ns RMS over {int(n)} samples, min {lo:g} / max {hi:g} ns (limits {L['witness']['disc_rms_max']} RMS, +/-{L['witness']['disc_abs_max']})")
            T.facts["witness_discipline"] = {"rms_ns": rms, "samples": int(n), "min_ns": lo, "max_ns": hi}
    # ---- gnss
    a = g.get("anchor") if isinstance(g.get("anchor"), dict) else None; q = g.get("anchor_quality") if isinstance(g.get("anchor_quality"), dict) else None
    if not a or not q: T.absent("gnss.anchor / gnss.anchor_quality")
    else:
        leap, tai = _num(a.get("leap_seconds_gps_minus_utc")), _num(a.get("tai_minus_utc_s"))
        T.req(a.get("utc_available_flag") is True, "gnss: receiver reports UTC available for the anchoring epoch")
        if None in (leap, tai): T.absent("gnss leap/TAI numbers")
        else: T.req(leap + 19 == tai, f"gnss: TAI-UTC {tai:g} == leapS {leap:g} + 19 (derived from the constellation)")
        cov, sd, qe, nm = _num(q.get("coverage_pct")), _num(q.get("sawtooth_sd_ns")), _num(a.get("sawtooth_qerr_ns_this_epoch")), _num(_get(q, "gnss_fix", "num_measurements"))
        if None in (cov, sd, qe, nm): T.absent("gnss quality numbers (coverage/sawtooth sd/qErr/measurements well-formed)")
        else:
            T.req(cov >= L["gnss"]["coverage_min"], f"gnss: sawtooth log coverage {cov:g} % over the {q.get('sawtooth_window')} window (>= {L['gnss']['coverage_min']} %)")
            T.req(sd <= L["gnss"]["sawtooth_sd_max"] and abs(qe) <= L["gnss"]["qerr_abs_max"], f"gnss: qErr {qe:g} ns this epoch, sd {sd:g} ns over the window (logged, not applied)")
            T.req(nm >= L["gnss"]["nmeas_min"], f"gnss: {int(nm)} raw measurements in the fix (>= {L['gnss']['nmeas_min']}; an integrity indicator, not proof)")
            T.facts["gnss"] = {"qerr_ns": qe, "sawtooth_sd_ns": sd, "coverage_pct": cov, "measurements": int(nm), "utc_unix_s": _num(a.get("utc_unix_s"))}
    # ---- cross-statement consistency and freshness
    tais = {r: _num(M[r].get("tai_minus_utc_s") if r != "gnss" else _get(M[r], "anchor", "tai_minus_utc_s")) for r in M}
    if None in tais.values(): T.absent("tai_minus_utc_s on every statement")
    else: T.req(len(set(tais.values())) == 1 and list(tais.values())[0] == 37, f"all statements agree on TAI-UTC ({sorted(set(tais.values()))})")
    anchor_utc = _num(_get(g, "anchor", "utc_unix_s")); own = _num(_get(core, "derived", "anchor_utc_unix_s"))
    stamps = {r: _num(_get(M[r], "stamp", "utc_ns")) for r in ("time", "witness")}
    if anchor_utc is None or None in stamps.values(): T.absent("statement stamps / GNSS anchor epoch for the freshness check")
    else:
        for r, ns in stamps.items():
            dt = ns / 1e9 - anchor_utc; T.req(abs(dt) <= L["freshness_s"], f"{r} statement stamped {dt:+.1f} s from the GNSS anchor epoch (freshness only; limit +/-{L['freshness_s']} s)")
        if own is not None: T.req(abs(own - anchor_utc) <= L["freshness_s"], f"pulse anchor {own - anchor_utc:+.1f} s from the GNSS statement's epoch")
    if profile == PROFILE_V2: _cadence_v2(core, T)
    return T

def _cadence_v2(core, T):
    """Profile v2, the cadence provenance of the hour (commit) and the promptness of the reveal (reveal)."""
    C = CADENCE; typ = core.get("type"); cad = core.get("cadence") if isinstance(core.get("cadence"), dict) else {}
    sts = core.get("statements") if isinstance(core.get("statements"), dict) else {}
    def issued(role):
        st = sts.get(role, {}); st = st.get("statement", st) if isinstance(st, dict) else {}
        return _num(st.get("issued_unix_ns"))
    if typ == "commit":
        sw = cad.get("self_trigger") if isinstance(cad.get("self_trigger"), dict) else None
        if not sw: T.absent("cadence.self_trigger (the aggregator's own wake record; exists from pulse 0098 - earlier commits are NOT-EVALUABLE under v2)"); return
        t0 = _num(sw.get("scheduled_unix_s")); rel = _num(_get(core, "derived", "target_release_unix_s")); lead = _num(_get(core, "derived", "lead_rounds"))
        if None in (t0, rel, lead): T.absent("cadence.self_trigger.scheduled_unix_s / derived release and lead"); return
        T.req(t0 == int(t0) and (int(t0) - GENESIS) % PERIOD == 0 and rel == t0 + lead * PERIOD,
              f"cadence: the declared instant is a drand round boundary and the target round is that instant + {int(lead)} rounds")
        Tn = int(t0) * 10**9
        late = _num(_get(sw, "wake", "late_ns"))
        if late is None: T.absent("cadence.self_trigger.wake.late_ns")
        else: T.req(0 <= late <= C["k3_wake_late_max_ns"], f"cadence: the aggregator started {late / 1e6:.3f} ms after the instant on its own disciplined clock ({sw.get('start_source')}; limit {C['k3_wake_late_max_ns'] / 1e6:g} ms)")
        tr = (cad.get("trigger") or {}).get("statement") if isinstance(cad.get("trigger"), dict) else None
        if not isinstance(tr, dict):
            T.req(False, "cadence: the time host's signed hardware-event statement is bound to this commit" + (f" (rejected: {cad.get('trigger_rejected')})" if cad.get("trigger_rejected") else " (absent: no corroboration of the instant by a second clock)")); return
        T.req(tr.get("kind") == "cadence-trigger" and tr.get("host") == "p550" and tr.get("role") == "time_attester", "cadence: the corroborating statement is p550's time_attester cadence-trigger")
        T.req(_num(tr.get("scheduled_unix_s")) == t0, f"cadence: the time host names the same instant as the aggregator ({int(t0)})")
        hw = tr.get("hw_event") if isinstance(tr.get("hw_event"), dict) else None
        how = _get(tr, "wake", "how")
        T.req(how == "pps-event" and bool(hw) and hw.get("source") == "i210-pps", f"cadence: the time host fired on the i210 PHC's hardware second event, not a clock fallback (wake.how={how!r}, hw_event.source={(hw or {}).get('source')!r})")
        if hw:
            edge, woke, ass = _num(hw.get("edge_after_instant_ns")), _num(hw.get("woke_after_edge_ns")), _num(hw.get("assert_unix_ns"))
            if None in (edge, woke, ass): T.absent("cadence.trigger.hw_event numbers (edge/woke/assert well-formed)")
            else:
                T.req(C["edge_min_ns"] <= edge <= C["edge_max_ns"] and ass == Tn + edge, f"cadence: hardware edge stamped {edge / 1e3:+.1f} us from the instant (limits {C['edge_min_ns'] / 1e3:g}..{C['edge_max_ns'] / 1e3:g} us) and consistent with the assert stamp")
                T.req(0 <= woke <= C["woke_after_edge_max_ns"], f"cadence: the time host's process ran {woke / 1e3:.1f} us after the edge (limit {C['woke_after_edge_max_ns'] / 1e6:g} ms)")
                T.facts["cadence_edge_after_instant_ns"] = edge; T.facts["cadence_woke_after_edge_ns"] = woke
        iss = _num(tr.get("issued_unix_ns")); rx = _num(cad.get("received_unix_ns")); krx = _num(cad.get("datagram_kernel_rx_unix_ns"))
        if iss is None or rx is None: T.absent("cadence.trigger.issued_unix_ns / cadence.received_unix_ns")
        else:
            T.req(0 <= iss - Tn <= C["issued_max_ns"], f"cadence: the time host issued its statement {(iss - Tn) / 1e6:.3f} ms after the instant (limit {C['issued_max_ns'] / 1e6:g} ms)")
            T.req(iss <= rx <= Tn + C["received_max_ns"], f"cadence: the aggregator received it {(rx - Tn) / 1e6:.3f} ms after the instant (limit {C['received_max_ns'] / 1e6:g} ms)")
            T.facts["cadence_issued_after_instant_ns"] = iss - Tn; T.facts["cadence_received_after_instant_ns"] = rx - Tn
            if krx is not None: T.facts["cadence_kernel_rx_after_instant_ns"] = krx - Tn
        T.facts["cadence_start_source"] = sw.get("start_source"); T.facts["cadence_aggregator_late_ns"] = late
        for role in ("entropy", "gnss", "time", "witness"):
            v = issued(role)
            if v is None: T.absent(f"{role}.issued_unix_ns")
            else: T.req(0 <= (v - Tn) / 1e9 <= C["stmt_after_instant_max_s"], f"cadence: {role} statement issued {(v - Tn) / 1e9:.3f} s after the instant (limit {C['stmt_after_instant_max_s']} s)")
    elif typ == "reveal":
        rel = _num(_get(core, "derived", "round_release_unix_s")); st_ = _num(cad.get("started_after_release_s"))
        if rel is None or st_ is None: T.absent("reveal cadence: derived.round_release_unix_s / cadence.started_after_release_s (from 0098)"); return
        T.req(0 <= st_ <= C["reveal_start_max_s"], f"cadence: the reveal began {st_:.3f} s after the round's release (limit {C['reveal_start_max_s']} s)")
        Rn = int(rel) * 10**9
        for role in ("entropy", "gnss", "time", "witness"):
            v = issued(role)
            if v is None: T.absent(f"{role}.issued_unix_ns")
            else: T.req(0 <= (v - Rn) / 1e9 <= C["reveal_stmt_after_release_max_s"], f"cadence: {role} reveal statement issued {(v - Rn) / 1e9:.3f} s after the release (limit {C['reveal_stmt_after_release_max_s']} s)")
        T.facts["reveal_started_after_release_s"] = st_

def evaluate_pulses(*cores, profile=PROFILE_V1):
    """Evaluate each core; the overall verdict is the worst (NOT-EVALUABLE > NOT-SATISFIED > SATISFIED)."""
    res = [evaluate(c, profile) for c in cores if c is not None]
    order = {"NOT-EVALUABLE": 2, "NOT-SATISFIED": 1, "SATISFIED": 0}
    worst = max(res, key=lambda r: order[r.verdict]) if res else None
    return res, (worst.verdict if worst else "NOT-EVALUABLE")
