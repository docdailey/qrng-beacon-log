#!/usr/bin/env python3
"""simul_wake.py - lab test, NOT part of the beacon.

Two disciplined hosts wake on the same second boundary, each on its OWN clock, each sends its wake stamp to the other
at once, and each stamps what it receives (kernel SO_TIMESTAMPNS and userspace). One JSON line comes out per host.

    simul_wake.py --at UNIX_S --peer IP [--port 5511] [--label NAME] [--phc /dev/ptpN] [--pps /dev/ppsN]

With both clocks right, the two one-way delays agree; if the clocks differ by d, one direction reads 2d longer than
the other, so  d = (delay(a->b) - delay(b->a)) / 2  assuming a symmetric path. The wake lateness on each host is its own
scheduler + spin error; the PHC bracket shows how far the system clock sat from the hardware clock at the wake; the PPS
fetch (p550 only) shows where the GNSS second actually was.
"""
import os, sys, json, time, socket, threading, ctypes, ctypes.util, fcntl, struct, errno

def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

T = int(arg("--at")); PEER = arg("--peer"); PORT = int(arg("--port", "5511")); LABEL = arg("--label", socket.gethostname())
PHC = arg("--phc"); PPS = arg("--pps"); PPS_FETCH = 0xc00870a4

class _TS(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def sleep_until(t_ns, spin_ns=1_500_000):
    """clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME) to t - spin, then spin on the clock (the beacon's own method)."""
    while True:
        ts = _TS((t_ns - spin_ns) // 10**9, (t_ns - spin_ns) % 10**9)
        r = _libc.clock_nanosleep(0, 1, ctypes.byref(ts), None)
        if r == 0: break
        if r != errno.EINTR: raise OSError(r, os.strerror(r))
    while time.clock_gettime_ns(time.CLOCK_REALTIME) < t_ns: pass

def phc_bracket(fd, n=5):
    clk = ((~fd) << 3) | 3; best = None
    for _ in range(n):
        a = time.clock_gettime_ns(time.CLOCK_REALTIME); p = time.clock_gettime_ns(clk); b = time.clock_gettime_ns(time.CLOCK_REALTIME)
        if best is None or b - a < best[2] - best[0]: best = (a, p, b)
    a, p, b = best
    return {"phc_minus_realtime_ns": p - (a + b) // 2, "bracket_ns": b - a, "note": "PHC is TAI on both hosts: 37 s of the difference is the leap offset"}

def pps_fetch(fd):
    buf = bytearray(64); struct.pack_into("qiI", buf, 48, 0, 0, 0)                 # zero timeout = return the last event now
    fcntl.ioctl(fd, PPS_FETCH, buf, True)
    aseq = struct.unpack_from("I", buf, 0)[0]; asec, ansec = struct.unpack_from("qi", buf, 8); return aseq, asec, ansec

# ---- socket: kernel receive stamps, busy poll, 1 s blocking deadline
SO_BUSY_POLL, SO_TIMESTAMPNS, SCM_TIMESTAMPNS = 46, 35, 35
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", PORT))
for opt, val in ((SO_BUSY_POLL, 200), (SO_TIMESTAMPNS, 1)):
    try: s.setsockopt(socket.SOL_SOCKET, opt, val)
    except OSError: pass
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, (1).to_bytes(8, "little") + (0).to_bytes(8, "little"))

got = []
def receiver(until):
    while time.time() < until:
        try: data, anc, _, addr = s.recvmsg(2048, 512)
        except (socket.timeout, BlockingIOError, InterruptedError): continue
        except OSError as e:
            if e.errno in (11, 4): continue
            raise
        rx = time.clock_gettime_ns(time.CLOCK_REALTIME); krx = None
        for lvl, typ, cdata in anc:
            if lvl == socket.SOL_SOCKET and typ == SCM_TIMESTAMPNS and len(cdata) >= 16:
                sec, nsec = int.from_bytes(cdata[:8], "little", signed=True), int.from_bytes(cdata[8:16], "little", signed=True); krx = sec * 10**9 + nsec
        if len(data) < 20: continue                                                # ARP warm-up
        try: p = json.loads(data)
        except Exception: continue
        got.append({"from": addr[0], "kernel_rx_ns": krx, "user_rx_ns": rx, "payload": p})

# ---- prepare well before the instant: ARP, PHC and PPS handles, the receiver thread, a warm JSON path
s.sendto(b"warm", (PEER, PORT))
phc_fd = os.open(PHC, os.O_RDONLY) if PHC else None
pps_fd = os.open(PPS, os.O_RDONLY) if PPS else None
json.dumps({"warm": 1}); json.loads("{}")
threading.Thread(target=receiver, args=(T + 1.0,), daemon=True).start()
if phc_fd is not None: phc_bracket(phc_fd)
if pps_fd is not None:
    try: pps_fetch(pps_fd)
    except OSError: pass
time.sleep(0.2)
sys.setswitchinterval(0.0005)

# ---- the instant
sleep_until(T * 10**9)
wake = time.clock_gettime_ns(time.CLOCK_REALTIME)
msg = json.dumps({"from": LABEL, "T": T, "wake_ns": wake}).encode()
send = time.clock_gettime_ns(time.CLOCK_REALTIME)
for _ in range(3): s.sendto(msg, (PEER, PORT))
sent = time.clock_gettime_ns(time.CLOCK_REALTIME)
phc = phc_bracket(phc_fd) if phc_fd is not None else None
pps = None
if pps_fd is not None:
    t_end = time.time() + 0.2
    while time.time() < t_end:
        try:
            aseq, asec, ansec = pps_fetch(pps_fd)
            if asec >= T: pps = {"assert_seq": aseq, "edge_after_T_ns": (asec - T) * 10**9 + ansec, "seen_after_T_ns": time.clock_gettime_ns(time.CLOCK_REALTIME) - T * 10**9}; break
        except OSError: pass
        time.sleep(0.0002)

# ---- collect the peer's stamp
t_end = T + 1.0
while time.time() < t_end and not any(g["payload"].get("T") == T for g in got): time.sleep(0.001)
peer = None
for g in got:
    if g["payload"].get("T") == T:
        pw = int(g["payload"]["wake_ns"])
        peer = {"from": g["from"], "label": g["payload"].get("from"), "peer_wake_late_ns": pw - T * 10**9,
                "kernel_rx_after_T_ns": None if g["kernel_rx_ns"] is None else g["kernel_rx_ns"] - T * 10**9,
                "user_rx_after_T_ns": g["user_rx_ns"] - T * 10**9,
                "one_way_from_peer_wake_kernel_ns": None if g["kernel_rx_ns"] is None else g["kernel_rx_ns"] - pw,
                "copies_seen": sum(1 for x in got if x["payload"].get("T") == T)}
        break

out = {"label": LABEL, "T": T, "wake_late_ns": wake - T * 10**9, "send_after_wake_ns": send - wake, "three_sends_took_ns": sent - send,
       "phc": phc, "pps": pps, "peer": peer, "python": sys.version.split()[0]}
print(json.dumps(out), flush=True)
