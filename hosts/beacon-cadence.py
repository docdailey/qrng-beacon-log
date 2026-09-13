#!/usr/bin/env python3
"""beacon-cadence.py — the beacon's clock-driven trigger. Runs ON the time host (p550: PREEMPT_RT, CLOCK_REALTIME
disciplined by chrony from the i210 PHC, itself locked to the ZED-F9T PPS) as the confined `beacon` user.

At every scheduled instant (hourly, :00:00 UTC) it wakes with clock_nanosleep(TIMER_ABSTIME), reads the i210 PHC and
CLOCK_REALTIME, signs a CADENCE TRIGGER with the time_attester key and hands it to the aggregator (think) over SSH with a
key that can run exactly one forced command there (beacon-trigger.py). The aggregator starts the cycle on receipt and
embeds the signed trigger in the commit pulse (core.cadence), so the instant that defined the hour is attested by the
clock that measured it, not by the aggregator. think's own timer is only a fallback (:02) and the pulse says so.

Bill, 2026-09-13: "think is not a precision machine. it should start on a trigger from i210 exactly on the hour."

  beacon-cadence.py                 run forever (systemd: beacon-cadence.service)
  beacon-cadence.py --once [--at T] [--no-send]   one trigger, at unix second T (default: next scheduled instant);
                                    --no-send prints the signed trigger instead of delivering it (testing)
"""
import os, sys, json, time, ctypes, ctypes.util, subprocess, secrets
sys.path.insert(0, os.path.expanduser("~/beacon"))
import attest_lib as A

PERIOD_S = int(os.environ.get("CADENCE_PERIOD_S", "3600")); OFFSET_S = int(os.environ.get("CADENCE_OFFSET_S", "0"))
PHC_DEV = os.environ.get("PHC_DEV", "/dev/ptp0"); HOSTNAME = "p550"
AGG = os.environ.get("CADENCE_AGGREGATOR", "willy@192.168.71.34")
KEY = os.path.expanduser("~/.ssh/cadence_ed25519"); KH = os.path.expanduser("~/.ssh/known_hosts")
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
RING_DIR = "/run/beacon-clocklog"; STATE_DIR = "/run/beacon-cadence"
CLOCK_REALTIME, TIMER_ABSTIME, EINTR = 0, 1, 4

class TS(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.clock_nanosleep.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(TS), ctypes.POINTER(TS)]

def log(m): print(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + m, file=sys.stderr, flush=True)   # stdout carries only --no-send output

def sleep_until(t_ns):
    """Absolute sleep on CLOCK_REALTIME: a chrony slew or step moves the wake WITH the clock (a relative sleep would not)."""
    while True:
        ts = TS(t_ns // 10**9, t_ns % 10**9)
        r = libc.clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, ctypes.byref(ts), None)
        if r == 0: return
        if r != EINTR: raise OSError(r, os.strerror(r))

def phc_read(fd):
    """Tightest of five REALTIME/PHC/REALTIME brackets."""
    clk = ((~fd) << 3) | 3; best = None
    for _ in range(5):
        a = time.clock_gettime_ns(CLOCK_REALTIME); p = time.clock_gettime_ns(clk); b = time.clock_gettime_ns(CLOCK_REALTIME)
        if best is None or b - a < best[2] - best[0]: best = (a, p, b)
    a, p, b = best
    return {"device": PHC_DEV, "unix_ns": str(p), "realtime_mid_unix_ns": str((a + b) // 2),
            "phc_minus_realtime_ns": p - (a + b) // 2, "bracket_ns": b - a}

def ring_last(name):
    """Newest row of a beacon-clocklog ring (clock-health evidence already being logged at source rate), or None."""
    try:
        rows = [l for l in open(os.path.join(RING_DIR, name + ".jsonl")).read().splitlines() if l.strip()]
        r = json.loads(rows[-1]); r["age_s"] = round(time.time() - r["t"], 2); return r
    except Exception: return None

def trigger(t0):
    fd = os.open(PHC_DEV, os.O_RDONLY)
    try:
        sleep_until(t0 * 10**9)
        wake = time.clock_gettime_ns(CLOCK_REALTIME); phc = phc_read(fd)
    finally: os.close(fd)
    ep, ts2 = ring_last("epoch") or {}, ring_last("ts2phc") or {}
    st = {"v": "0.5", "role": "time_attester", "host": HOSTNAME, "kind": "cadence-trigger", "chain_hash": CHAIN_HASH,
          "scheduled_unix_s": t0, "period_s": PERIOD_S, "offset_s": OFFSET_S,
          "wake": {"clock": "CLOCK_REALTIME", "unix_ns": str(wake), "late_ns": wake - t0 * 10**9,
                   "how": "clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME) on PREEMPT_RT; CLOCK_REALTIME is chrony-disciplined from the i210 PHC (refid IPHC)"},
          "phc": {**phc, "tai_minus_utc_s": ep.get("tai_minus_utc_s"),
                  "meaning": "i210 PHC (TAI) read at wake; phc_minus_realtime_ns minus tai_minus_utc_s*1e9 is how far the system clock sat from the PHC at the trigger"},
          "clock_state": {"epoch_ok": ep.get("epoch_ok"), "refclock_selected": ep.get("refclock_selected"), "epoch_row_age_s": ep.get("age_s"),
                          "ts2phc_state": ts2.get("state"), "ts2phc_offset_ns": ts2.get("offset_ns"), "ts2phc_row_age_s": ts2.get("age_s"),
                          "source": "beacon-clocklog rings (/run/beacon-clocklog)"},
          "issued_unix_ns": A.now_ns_str(), "nonce": secrets.token_hex(16),
          "tools": A.tool_binding(os.path.abspath(__file__), os.path.join(os.path.expanduser("~/beacon"), "attest_lib.py")),
          "execution": A.execution_context(),
          "meaning": "the time host's clock reached the scheduled instant; the aggregator starts the cycle on receipt and embeds this statement in the commit (PROTOCOL.md 'Cadence trigger')"}
    return A.sign_statement("time_attester", st), wake

def send(signed):
    cmd = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={KH}", "-o", "IdentitiesOnly=yes", AGG, "trigger"]
    r = subprocess.run(cmd, input=json.dumps(signed), capture_output=True, text=True, timeout=40)
    return r.returncode, (r.stdout or r.stderr).strip()[:400]

def next_instant(now): return ((int(now) - OFFSET_S) // PERIOD_S + 1) * PERIOD_S + OFFSET_S

def main():
    a = sys.argv[1:]; once = "--once" in a; dry = "--no-send" in a
    fixed = int(a[a.index("--at") + 1]) if "--at" in a else None
    os.makedirs(STATE_DIR, exist_ok=True)
    while True:
        target = fixed if fixed is not None else next_instant(time.time())
        log(f"next trigger at {target} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(target))}Z), in {target - time.time():.1f} s")
        while target - time.time() > 2.5: time.sleep(min(60.0, target - time.time() - 2.0))      # coarse wait, then absolute
        signed, wake = trigger(target); st = signed["statement"]
        log(f"trigger {target}: woke {st['wake']['late_ns'] / 1000:.1f} us late; PHC-REALTIME {st['phc']['phc_minus_realtime_ns']} ns; "
            f"epoch_ok {st['clock_state']['epoch_ok']} ts2phc {st['clock_state']['ts2phc_state']} {st['clock_state']['ts2phc_offset_ns']} ns")
        tmp = os.path.join(STATE_DIR, ".last.json.tmp")
        json.dump({"sent_unix_ns": str(time.time_ns()), "trigger": signed}, open(tmp, "w")); os.replace(tmp, os.path.join(STATE_DIR, "last.json"))
        if dry: print(json.dumps(signed))
        else:
            rc, out = send(signed)
            if rc != 0: time.sleep(2); rc, out = send(signed)
            log(f"aggregator {'accepted' if rc == 0 else f'REFUSED rc={rc}'}: {out}")
        if once: return
        fixed = None; time.sleep(5)

if __name__ == "__main__": main()
