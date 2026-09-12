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
        for ln in subprocess.run(["chronyc","tracking"],capture_output=True,text=True,timeout=8).stdout.splitlines():
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

# Cross-check: does CLOCK_REALTIME actually track the PHC?
phc_x={}
try:
    fd=os.open(phc_dev, os.O_RDONLY); clkid=((~fd)<<3)|3
    d=[]
    for _ in range(21):
        a=gettime(CLOCK_REALTIME); p=gettime(clkid); b=gettime(CLOCK_REALTIME)
        d.append(p-(a+b)//2)
    ds=sorted(d)
    phc_x={"device":phc_dev,
           "clock_name":open(f"/sys/class/ptp/{os.path.basename(phc_dev)}/clock_name").read().strip(),
           "phc_minus_realtime_median_ns":ds[len(ds)//2],
           "phc_minus_realtime_spread_ns":ds[-1]-ds[0],
           "meaning":"how closely CLOCK_REALTIME follows the PHC (chrony tracking); not a stamp accuracy"}
    os.close(fd)
except Exception as e:
    phc_x={"device":phc_dev,"error":str(e)}

# Discipline: whichever servo this host actually runs.
disc={}
try:
    # Sample the ts2phc status over a window so RMS is a real statistic with a stated n,
    # never a single signed offset mislabelled as RMS.
    seen_ts={}; pat_ts=re.compile(r"offset\s+(-?\d+)\s+(s\d)\s+freq\s+(-?\d+)")
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
              "states":sorted({v[1] for v in seen_ts.values()}),
              "note":"offset_ns_rms is null when fewer than 3 samples fell in the window; last_offset_ns is signed and instantaneous"}
except Exception: pass
if not disc:
    try:
        j=subprocess.run(["journalctl","-u","ptp4l-bmc","--since","-5min","-o","cat"],
                         capture_output=True,text=True,timeout=10).stdout
        offs=[int(x) for x in re.findall(r"master offset\s+(-?\d+)", j)][-60:]
        pd=[int(x) for x in re.findall(r"path delay\s+(-?\d+)", j)][-10:]
        states=sorted(set(re.findall(r"offset\s+-?\d+\s+(s\d)", j)))[-2:]
        if offs: disc={"servo":"ptp4l","reference":"P550-BMC GPS GM (domain 44, UDPv4)",
            "samples":len(offs),"offset_ns_min":min(offs),"offset_ns_max":max(offs),
            "offset_ns_rms":round((sum(x*x for x in offs)/len(offs))**0.5,1),
            "offset_ns_stdev":round(statistics.pstdev(offs),1),
            "path_delay_ns_last":pd[-1] if pd else None,"states":states}
    except Exception as e: disc={"error":str(e)}

# Mesh cross-check: on p550 the i210 continuously MEASURES the BMC PHC (free_running,
# read-only) so the BMC grandmaster is never an unwatched clock.
mesh={}
try:
    seen={}
    pat2=re.compile(r"master offset\s+(-?\d+)\s+(s\d)\s+freq\s+(-?\d+)\s+path delay\s+(-?\d+)")
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
              "bmc_announced_health":list(seen.values())[-1][3]}
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
    if phc_x.get("phc_minus_realtime_median_ns") is not None:
        delta = phc_x["phc_minus_realtime_median_ns"] / 1e9 - tai
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
    src = subprocess.run(["chronyc","sources"],capture_output=True,text=True,timeout=8).stdout
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
