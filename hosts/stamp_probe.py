#!/usr/bin/env python3
"""stamp_probe.py <phc_dev> — report this host's clock state for a time/witness statement.

The pulse's time is anchored elsewhere, in hardware (GNSS epoch of the i210-captured edge); nothing here is a
timestamp accuracy claim. The CLOCK_REALTIME reading is FRESHNESS/ordering; the PHC cross-check shows chrony tracking
the PHC; the epoch guard, discipline and mesh sections are the clock-health evidence the verifier enforces. (ERR-012)
"""
import ctypes, ctypes.util, os, sys, time, json, re, statistics, subprocess
CLOCK_REALTIME = 0
class TS(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
class TX(ctypes.Structure):
    _fields_ = [("modes",ctypes.c_uint),("offset",ctypes.c_long),("freq",ctypes.c_long),
        ("maxerror",ctypes.c_long),("esterror",ctypes.c_long),("status",ctypes.c_int),
        ("constant",ctypes.c_long),("precision",ctypes.c_long),("tolerance",ctypes.c_long),
        ("tv_sec",ctypes.c_long),("tv_usec",ctypes.c_long),("tick",ctypes.c_long),
        ("ppsfreq",ctypes.c_long),("jitter",ctypes.c_long),("shift",ctypes.c_int),
        ("stabil",ctypes.c_long),("jitcnt",ctypes.c_long),("calcnt",ctypes.c_long),
        ("errcnt",ctypes.c_long),("stbcnt",ctypes.c_long),("tai",ctypes.c_int),("pad",ctypes.c_int*11)]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(TS)]
_t = TS()
def gettime(c):
    if libc.clock_gettime(c, ctypes.byref(_t)) != 0: raise OSError(ctypes.get_errno())
    return _t.tv_sec*10**9 + _t.tv_nsec
def st(v):
    v = sorted(v); return {"n":len(v),"min_ns":v[0],"p50_ns":v[len(v)//2],
                           "p99_ns":v[int(len(v)*0.99)] if len(v)>4 else v[-1],"max_ns":v[-1],
                           "stdev_ns":round(statistics.pstdev(v),1)}
def chrony():
    o={}
    try:
        for ln in subprocess.run(["chronyc","-n","tracking"],capture_output=True,text=True,timeout=8).stdout.splitlines():
            if ":" in ln: k,v=ln.split(":",1); o[k.strip()]=v.strip()
    except Exception as e: o["error"]=str(e)
    return o

phc_dev = sys.argv[1]
expect_refid = sys.argv[2] if len(sys.argv) > 2 else "IPHC"       # p550: IPHC; k3: PHC
tx=TX(); ret=libc.adjtimex(ctypes.byref(tx)); tai_kernel=int(tx.tai)
# ERR-007: a host whose chrony uses "offset -37" instead of "tai" never programs the kernel TAI offset,
# so adjtimex reports 0. The epoch guard must not mistake that for a wiped epoch.
IERS_TAI_UTC = 37
tai = tai_kernel if tai_kernel > 0 else IERS_TAI_UTC
tai_source_note = ("kernel adjtimex" if tai_kernel > 0 else
                   "kernel TAI offset unset on this host; using the IERS constant %d (guard fallback)" % IERS_TAI_UTC)

# Freshness reading: one CLOCK_REALTIME read. Not a precision term (ERR-012).
stamp_ns=gettime(CLOCK_REALTIME)

# Cross-check: does CLOCK_REALTIME actually track the PHC? (2026-09-29, ERR-024) One kernel call brackets each PHC read with
# system-clock reads, and the tightest bracket is kept: a hardware cross-timestamp (PTP_SYS_OFFSET_PRECISE) if the NIC has
# one, else PTP_SYS_OFFSET_EXTENDED, else PTP_SYS_OFFSET; a userspace sandwich only if the ioctls are missing. The old
# userspace sandwich (separate syscalls, 7-21 us windows) put the PHC read off-centre: -1000 ns on p550, +350 ns on k3.
import fcntl, struct
PTP_MAX_SAMPLES = 25
CT = struct.Struct("qII")                                 # struct ptp_clock_time {s64 sec; u32 nsec; u32 reserved}
def _ioc(d, nr, size): return (d << 30) | (size << 16) | (ord("=") << 8) | nr
SZ_BASIC, SZ_EXT, SZ_PREC = 16 + (2 * PTP_MAX_SAMPLES + 1) * 16, 16 + PTP_MAX_SAMPLES * 3 * 16, 3 * 16 + 16
PTP_SYS_OFFSET = _ioc(1, 5, SZ_BASIC)
PTP_SYS_OFFSET_PRECISE = _ioc(3, 8, SZ_PREC)
PTP_SYS_OFFSET_EXTENDED = _ioc(3, 9, SZ_EXT)
def _ns(buf, off): s, n, _ = CT.unpack_from(buf, off); return s * 10**9 + n
def _tightest(samples):
    """samples: [(pre, phc, post)]. Keep the tightest window; samples within 1 % of it tie (a coarse system tick, e.g.
    p550's 1 us, makes 1999 vs 2000 ns meaningless) and are averaged, since their midpoints are dithered by the tick.
    Returns (offset_ns, window_ns, n_used)."""
    w = min(post - pre for pre, _, post in samples)
    offs = [phc - (pre + post) / 2 for pre, phc, post in samples if post - pre <= w * 1.01]
    return round(sum(offs) / len(offs)), w, len(offs)

def phc_minus_realtime(fd, n=25):
    """PHC - CLOCK_REALTIME in ns: (offset_ns, window_ns, n_tightest, method, samples). PRECISE (hardware cross-timestamp, window 0),
    else the tightest kernel bracket from EXTENDED or basic PTP_SYS_OFFSET, else a userspace sandwich."""
    try:
        b = bytearray(SZ_PREC); fcntl.ioctl(fd, PTP_SYS_OFFSET_PRECISE, b)
        return _ns(b, 0) - _ns(b, 16), 0, 1, "PTP_SYS_OFFSET_PRECISE", 1
    except OSError: pass
    try:
        b = bytearray(SZ_EXT); struct.pack_into("I", b, 0, n); fcntl.ioctl(fd, PTP_SYS_OFFSET_EXTENDED, b)
        k = struct.unpack_from("I", b, 0)[0]                            # ts[i] = {sys_before, phc, sys_after}
        return (*_tightest([tuple(_ns(b, 16 + (i * 3 + j) * 16) for j in range(3)) for i in range(k)]), "PTP_SYS_OFFSET_EXTENDED", k)
    except OSError: pass
    try:
        b = bytearray(SZ_BASIC); struct.pack_into("I", b, 0, n); fcntl.ioctl(fd, PTP_SYS_OFFSET, b)
        k = struct.unpack_from("I", b, 0)[0]; ts = [_ns(b, 16 + i * 16) for i in range(2 * k + 1)]   # sys, phc, sys, ..., sys
        return (*_tightest([(ts[2 * i], ts[2 * i + 1], ts[2 * i + 2]) for i in range(k)]), "PTP_SYS_OFFSET", k)
    except OSError: pass
    clk = ((~fd) << 3) | 3; smp = []
    for _ in range(n):
        smp.append((time.clock_gettime_ns(time.CLOCK_REALTIME), time.clock_gettime_ns(clk), time.clock_gettime_ns(time.CLOCK_REALTIME)))
    return (*_tightest(smp), "userspace-sandwich", n)

phc_x={}
try:
    fd=os.open(phc_dev, os.O_RDONLY)
    off, win, tied, method, n = phc_minus_realtime(fd)
    phc_x={"device":phc_dev,
           "clock_name":open(f"/sys/class/ptp/{os.path.basename(phc_dev)}/clock_name").read().strip(),
           "phc_minus_realtime_ns":off, "window_ns":win, "method":method, "samples":n, "tightest_samples":tied,
           "meaning":"PHC - CLOCK_REALTIME at the midpoint of the tightest kernel bracket (samples within 1 % of it averaged); "
                     "window_ns bounds the read, not a stamp accuracy; how closely CLOCK_REALTIME follows the PHC"}
    os.close(fd)
except Exception as e:
    phc_x={"device":phc_dev,"error":str(e)}

# ---- ring buffers (beacon-clocklog, 2026-09-13): the host logs its clock evidence at SOURCE rate to /run/beacon-clocklog;
# a statement summarises the trailing WINDOW of that log in milliseconds instead of sampling live for tens of seconds.
# If a ring is missing or stale the probe falls back to live sampling and says so (ring_used=false).
RING_DIR="/run/beacon-clocklog"; RING_WINDOW_S=int(os.environ.get("BEACON_RING_WINDOW_S","60")); RING_STALE_S=15
def ring_rows(name, window_s=RING_WINDOW_S):
    """Rows of the last window_s seconds of a ring, newest last; [] if absent or stale."""
    try:
        now=time.time(); rows=[]
        for l in open(os.path.join(RING_DIR,name+".jsonl")):
            if not l.strip(): continue
            try: rows.append(json.loads(l))
            except Exception: pass                    # a line still being written (or damaged) is skipped, not fatal for the ring
        rows=[r for r in rows if now-r.get("t",0)<=window_s]
        if not rows or now-rows[-1]["t"]>RING_STALE_S: return []
        return rows
    except Exception: return []
def ring_span(rows): return round(rows[-1]["t"]-rows[0]["t"],1) if len(rows)>1 else 0.0

# Discipline: whichever servo this host actually runs.
disc={}
rows=ring_rows("ts2phc")
if rows:
    vals=[r["offset_ns"] for r in rows]; last=rows[-1]
    disc={"servo":"ts2phc","reference":"u-blox ZED-F9T TP1 PPS (falling, on-time edge) -> i210 SDP0",
          "last_offset_ns":last["offset_ns"],"state":last["state"],"freq_ppb":last["freq_ppb"],
          "window_s":ring_span(rows),"samples":len(vals),
          "offset_ns_rms":round((sum(x*x for x in vals)/len(vals))**0.5,2) if len(vals)>=3 else None,
          "offset_ns_min":min(vals),"offset_ns_max":max(vals),
          "states":sorted({r["state"] for r in rows}),
          "source":"ring /run/beacon-clocklog/ts2phc.jsonl (beacon-clocklog, one row per ts2phc update)","ring_used":True,
          "note":"offset_ns_rms is null when fewer than 3 samples fell in the window; last_offset_ns is signed and instantaneous"}
try:
  if disc: raise StopIteration
  # Only a ts2phc host has this status file; a ptp4l-only host (k3) skips straight to the ptp4l ring/journal below.
  if not os.path.exists("/run/ts2phc-f9t.status"): raise StopIteration
  # Fallback: sample the ts2phc status live over a window so RMS is a real statistic with a stated n,
  # never a single signed offset mislabelled as RMS.
  if True:
    seen_ts={}; pat_ts=re.compile(r"offset\s+(-?\d+)\s+(s\d)\s+freq\s+([-+]?\d+)")
    t_end_ts=time.time()+12
    while time.time()<t_end_ts:
        try:
            txt=open("/run/ts2phc-f9t.status").read()
            m=pat_ts.search(txt); u=re.search(r"updated\s*:\s*(.+)",txt)
            if m and u: seen_ts[u.group(1).strip()]=(int(m.group(1)),m.group(2),int(m.group(3)))
        except Exception: pass
        time.sleep(0.5)
    if seen_ts:
        vals=[v[0] for v in seen_ts.values()]; last=list(seen_ts.values())[-1]
        disc={"servo":"ts2phc","reference":"u-blox ZED-F9T TP1 PPS (falling, on-time edge) -> i210 SDP0",
              "last_offset_ns":last[0],"state":last[1],"freq_ppb":last[2],
              "window_s":12,"samples":len(vals),
              "offset_ns_rms":round((sum(x*x for x in vals)/len(vals))**0.5,2) if len(vals)>=3 else None,
              "offset_ns_min":min(vals),"offset_ns_max":max(vals),
              "states":sorted({v[1] for v in seen_ts.values()}),"ring_used":False,
              "note":"offset_ns_rms is null when fewer than 3 samples fell in the window; last_offset_ns is signed and instantaneous"}
except StopIteration: pass
except Exception: pass
# ptp4l (since 2026-09-28, ERR-023): ptp4l reports once a second (summary_interval 0: rms and max |offset| of that second's
# syncs); clocklog keeps one row per summary with the port state it last announced. The GM syncs at 8 Hz, so a 60 s window
# summarises ~480 syncs. Signed min/max and the servo state are not in ptp4l's summary and are not claimed.
def ptp4l_disc(rows, source, ring_used):
    return {"servo":"ptp4l","reference":"P550-BMC GPS GM (domain 44, UDPv4)",
            "summaries":len(rows),"summary_interval_s":1,"window_s":ring_span(rows) if ring_used else None,
            "offset_ns_rms":round((sum(r["rms_ns"]**2 for r in rows)/len(rows))**0.5,1),
            "offset_ns_max_abs":max(r["max_abs_ns"] for r in rows),
            "path_delay_ns_last":rows[-1].get("path_delay_ns"),"port_states":sorted({r["port_state"] for r in rows if r.get("port_state")}),
            "source":source,"ring_used":ring_used,
            "note":"ptp4l's own once-a-second summaries; offset_ns_rms combines the window's per-second RMS values, offset_ns_max_abs is the largest per-second max |offset|"}
if not disc:
    rows=[r for r in ring_rows("ptp4l") if "rms_ns" in r]
    if rows: disc=ptp4l_disc(rows,"ring /run/beacon-clocklog/ptp4l.jsonl (beacon-clocklog, one row per ptp4l 1 s summary)",True)
if not disc:
    try:
        j=subprocess.run(["journalctl","-u","ptp4l-bmc","-u","ptp4l-slave","--since","-2min","-o","cat"],
                         capture_output=True,text=True,timeout=10).stdout
        seen={}; port=None
        for l in j.splitlines():
            ps=re.search(r"port \d+(?: \([^)]*\))?: \S+ to (\S+)", l)
            if ps: port=ps.group(1); continue
            m=re.search(r"\[([\d.]+)\]:? rms\s+(\d+)\s+max\s+(\d+)\s+freq\s+([-+]?\d+)\s+\+/-\s+\d+(?:\s+delay\s+(-?\d+))?", l)
            if m: seen[m.group(1)]={"rms_ns":int(m.group(2)),"max_abs_ns":int(m.group(3)),"path_delay_ns":int(m.group(5)) if m.group(5) else None,"port_state":port}
        rows=list(seen.values())[-60:]
        if rows: disc=ptp4l_disc(rows,"journal (ptp4l 1 s summaries, last 60)",False)
    except Exception as e: disc={"error":str(e)}

# Mesh cross-check: on p550 the i210 continuously MEASURES the BMC PHC (free_running,
# read-only) so the BMC grandmaster is never an unwatched clock.
mesh={}
rows=ring_rows("mesh")
if rows:
    v=[r["offset_ns"] for r in rows]
    mesh={"what":"i210 PHC continuously measures the P550-BMC PHC (ptp4l free_running=1, "
                 "slaveOnly=1 -> read-only instrument; it never steers the i210)",
          "monitor":"bmc-phc-monitor.service","samples":len(v),"window_s":ring_span(rows),
          "offset_ns_min":min(v),"offset_ns_max":max(v),
          "offset_ns_rms":round((sum(x*x for x in v)/len(v))**0.5,1),
          "offset_ns_stdev":round(statistics.pstdev(v),1) if len(v)>1 else None,
          "path_delay_ns":rows[-1]["path_delay_ns"],
          "servo_states":sorted({r["state"] for r in rows}),
          "bmc_announced_health":rows[-1].get("health"),
          "source":"ring /run/beacon-clocklog/mesh.jsonl (beacon-clocklog, one row per monitor update)","ring_used":True}
try:
  if mesh: raise StopIteration
  if not os.path.exists("/run/bmc-phc.status"): raise StopIteration      # only p550 runs the BMC monitor
  if True:
    seen={}
    pat2=re.compile(r"master offset\s+(-?\d+)\s+(s\d)\s+freq\s+([-+]?\d+)\s+path delay\s+(-?\d+)")
    t_end=time.time()+20
    while time.time()<t_end:
        try:
            t=open("/run/bmc-phc.status").read()
            m=pat2.search(t); u=re.search(r"updated\s*:\s*(.+)",t); h=re.search(r"health\s*:\s*(.+)",t)
            if m and u: seen[u.group(1).strip()]=(int(m.group(1)),m.group(2),int(m.group(4)),h.group(1).strip() if h else None)
        except Exception: pass
        time.sleep(0.4)
    v=[x[0] for x in seen.values()]
    if v:
        mesh={"what":"i210 PHC continuously measures the P550-BMC PHC (ptp4l free_running=1, "
                     "slaveOnly=1 -> read-only instrument; it never steers the i210)",
              "monitor":"bmc-phc-monitor.service","samples":len(v),"window_s":20,
              "offset_ns_min":min(v),"offset_ns_max":max(v),
              "offset_ns_rms":round((sum(x*x for x in v)/len(v))**0.5,1),
              "offset_ns_stdev":round(statistics.pstdev(v),1) if len(v)>1 else None,
              "path_delay_ns":list(seen.values())[-1][2],
              "servo_states":sorted({x[1] for x in seen.values()}),
              "bmc_announced_health":list(seen.values())[-1][3],"ring_used":False}
except StopIteration: pass
except Exception as e:
    mesh={"error":str(e)}

# ---- EPOCH GUARD (lab notebook entry 220) ----
# A link bounce RESETS the i210 SYSTIM registers and destroys the PHC's integer second.
# ts2phc -s generic disciplines only the SUB-SECOND phase, so it keeps reporting a perfect
# "offset 12 ns s2" lock while the seconds label is gone. Every servo metric stays green.
# The ONLY symptom is PHC-REALTIME drifting off TAI-UTC. Check it explicitly and fail closed.
guard={"check":"PHC - CLOCK_REALTIME must equal TAI-UTC (+%d s) within 0.5 s" % tai,
       "tai_minus_utc_used":tai,"tai_source":tai_source_note,"expected_refid":expect_refid,
       "why":"lab notebook entry 220: a link bounce wipes the i210 epoch while ts2phc still "
             "reports a healthy lock. Servo metrics cannot detect this; only this difference can.",
       "self_heal":"iphc-epoch-check.service via udev 99-iphc-epoch.rules on enp1s0 change"}
try:
    if phc_x.get("phc_minus_realtime_ns") is not None:
        delta = phc_x["phc_minus_realtime_ns"] / 1e9 - tai
        guard["phc_minus_realtime_minus_tai_s"] = round(delta, 6)
        guard["epoch_ok"] = abs(delta) < 0.5
        if not guard["epoch_ok"]:
            guard["ALERT"] = ("i210 PHC EPOCH WIPED - the integer second is wrong. "
                              "Timestamps from this clock are invalid. "
                              "Remedy: systemctl restart ts2phc-f9t")
    else:
        guard["epoch_ok"] = None
except Exception as e:
    guard["epoch_ok"] = None; guard["error"] = str(e)
try:
    guard["iphc_epoch_check_status"] = open("/run/iphc-epoch-check.status").read().strip()[:300]
except Exception:
    guard["iphc_epoch_check_status"] = None
# chrony must still be SELECTING this host's hardware refclock ('#*'), not a LAN/NTP fallback
try:
    src = subprocess.run(["chronyc","-n","sources"],capture_output=True,text=True,timeout=8).stdout
    line = [l for l in src.splitlines() if l.split()[1:2] == [expect_refid]] if src else []
    guard["chrony_refclock_line"] = line[0].strip() if line else None
    guard["chrony_selects_refclock"] = bool(line and line[0].strip().startswith("#*"))
    guard["chrony_selects_iphc"] = guard["chrony_selects_refclock"]      # legacy field name, same meaning
except Exception as e:
    guard["chrony_selects_refclock"] = None; guard["chrony_selects_iphc"] = None

tr=chrony()
print(json.dumps({
 "host":os.uname().nodename,"kernel":os.uname().release,"arch":os.uname().machine,
 "stamp":{"clock":"CLOCK_REALTIME","utc_ns":stamp_ns,
          "meaning":"freshness/ordering of this statement only; the pulse's time is the hardware-captured GNSS epoch"},
 "tai_minus_utc_s":tai,"tai_source":f"adjtimex ret={ret} status=0x{tx.status:x}; {tai_source_note}",
 "phc_crosscheck":phc_x,"discipline":disc,"mesh_crosscheck":mesh,"epoch_guard":guard,
 "chrony":{"reference_id":tr.get("Reference ID"),"stratum":tr.get("Stratum"),
           "rms_offset":tr.get("RMS offset"),"root_delay":tr.get("Root delay"),
           "root_dispersion":tr.get("Root dispersion"),"leap_status":tr.get("Leap status")},
 "kernel_error_bounds":{"maxerror_us":tx.maxerror,"esterror_us":tx.esterror},
}))
