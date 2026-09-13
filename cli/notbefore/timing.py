"""timing.py — the timing profile: a versioned, testable policy over the signed timing statements a pulse carries
(review T1; PROTOCOL.md §"Timing profile"; NOTBEFORE.md §7.14).

Until now the verifier AUTHENTICATED the timing statements (host signatures, pulse binding) and REQUIRED only epoch
health and chrony reference selection. This module adds an explicit, versioned acceptance policy over the published
figures, evaluated identically online, in receipts and in offline bundles, and reported SEPARATELY from
cryptographic integrity and from the application result:

    SATISFIED       every required observation is present, well-formed, fresh and within the profile's limits
    NOT-SATISFIED   a required observation is outside its limit (servo not locked, epoch lost, excursion too large ...)
    NOT-EVALUABLE   required evidence is missing or malformed (no statements, no mesh block, non-finite numbers, wrong units)

A contract may declare `timing: {profile: "notbefore/timing/v1", required: bool}`. The policy NEVER changes which commit
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

PROFILE_ID = "notbefore/timing/v1"
LIMITS = {"time": {"disc_rms_max": 100, "disc_abs_max": 250, "disc_samples_min": 3, "mesh_rms_max": 250, "mesh_abs_max": 1000, "mesh_samples_min": 3, "path_delay_max": 10000},
          "witness": {"disc_rms_max": 250, "disc_abs_max": 1000, "disc_samples_min": 10},
          "gnss": {"coverage_min": 95, "sawtooth_sd_max": 10, "qerr_abs_max": 50, "nmeas_min": 8},
          "freshness_s": 600}
FIRST_PROFILED_SEQ = 18          # v0.5 statements begin at 0018; earlier pulses are NOT-EVALUABLE by construction

class Timing:
    def __init__(self): self.lines = []; self.missing = []; self.failed = []; self.facts = {}
    def req(self, ok, what):                       # a required observation: present and within limits?
        (self.lines.append(("[PASS] " if ok else "[FAIL] ") + what)); (None if ok else self.failed.append(what))
    def absent(self, what): self.missing.append(what); self.lines.append("[MISSING] " + what)
    @property
    def verdict(self): return "NOT-EVALUABLE" if self.missing else ("NOT-SATISFIED" if self.failed else "SATISFIED")
    def summary(self): return {"profile": PROFILE_ID, "verdict": self.verdict, "failed": self.failed, "missing": self.missing, "facts": self.facts}

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

def evaluate(core):
    """Evaluate profile v1 over one pulse core (commit or reveal). Returns a Timing."""
    T = Timing(); L = LIMITS
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
    return T

def evaluate_pulses(*cores):
    """Evaluate each core; the overall verdict is the worst (NOT-EVALUABLE > NOT-SATISFIED > SATISFIED)."""
    res = [evaluate(c) for c in cores if c is not None]
    order = {"NOT-EVALUABLE": 2, "NOT-SATISFIED": 1, "SATISFIED": 0}
    worst = max(res, key=lambda r: order[r.verdict]) if res else None
    return res, (worst.verdict if worst else "NOT-EVALUABLE")
