#!/usr/bin/env python3
"""beacon-cadence.py — the beacon's clock-driven trigger. Runs ON the time host (p550: PREEMPT_RT, CLOCK_REALTIME
disciplined by chrony from the i210 PHC, itself locked to the ZED-F9T PPS) as the confined `beacon` user.

At every scheduled instant (hourly, :00:00 UTC) it wakes with clock_nanosleep(TIMER_ABSTIME), reads the i210 PHC and
CLOCK_REALTIME, signs a CADENCE TRIGGER with the time_attester key and sends it to the aggregator as a UDP DATAGRAM.
There is no session and no authentication handshake: the datagram IS a signed statement, and the aggregator verifies
the signature against keys/KEYS.json. The aggregator (k3) does not wait for it - it wakes on its own PHC-disciplined
clock at the same instant and mints; the datagram arrives within milliseconds and is embedded in the commit
(core.cadence.trigger) as the i210 host's attestation of the instant. Bill, 2026-09-13: "it should start on a trigger
from i210 exactly on the hour" / "we need to do it without ssh obviously. signaling outside of auth."

  beacon-cadence.py                 run forever (systemd: beacon-cadence.service)
  beacon-cadence.py --once [--at T] [--no-send]   one trigger, at unix second T (default: next scheduled instant);
                                    --no-send prints the signed trigger instead of sending it (testing)
  env CADENCE_UDP=host:port          where the datagram goes (default 192.168.68.24:5510, the aggregator k3)
"""
import os, sys, json, time, ctypes, ctypes.util, subprocess, secrets, socket, fcntl, struct, base64
sys.path.insert(0, os.path.expanduser("~/beacon"))
import attest_lib as A

PERIOD_S = int(os.environ.get("CADENCE_PERIOD_S", "3600")); OFFSET_S = int(os.environ.get("CADENCE_OFFSET_S", "0"))
PHC_DEV = os.environ.get("PHC_DEV", "/dev/ptp0"); HOSTNAME = "p550"
UDP = os.environ.get("CADENCE_UDP", "192.168.68.24:5510")       # aggregator host:port for the signed datagram
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
RING_DIR = "/run/beacon-clocklog"; STATE_DIR = "/run/beacon-cadence"
# The i210 PHC registers its own PPS source (/dev/pps1 on p550): a kernel event at every PHC second boundary, stamped in
# CLOCK_REALTIME by the interrupt handler (~22 us after the boundary on this PREEMPT_RT box). A process blocked in
# PPS_FETCH runs 40-150 us after that stamp (measured 2026-09-13). The hardware clock decides the instant; nothing here
# sleeps on the system clock. Constants from <sys/timepps.h> on p550 (the size field the kernel actually encodes is 8).
PPS_DEV = os.environ.get("CADENCE_PPS_DEV", "/dev/pps1"); PPS_FETCH, PPS_SETPARAMS, PPS_GETPARAMS = 0xc00870a4, 0x400870a2, 0x800870a1
HW_GRACE_S = 0.05                                          # if the PHC event for the instant has not come by then, fall back to the clock
CLOCK_REALTIME, TIMER_ABSTIME, EINTR = 0, 1, 4
DRY = False

class TS(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.clock_nanosleep.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(TS), ctypes.POINTER(TS)]

def log(m): print(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime(time.time())) + m, file=sys.stderr, flush=True)   # stdout carries only --no-send output

def sleep_until(t_ns, spin_ns=1_500_000):
    """Absolute sleep on CLOCK_REALTIME to t_ns - spin_ns (a chrony slew or step moves the wake WITH the clock; a relative
    sleep would not), then spin on the clock for the last 1.5 ms: scheduler lateness of 100-500 us becomes a few us."""
    while True:
        ts = TS((t_ns - spin_ns) // 10**9, (t_ns - spin_ns) % 10**9)
        r = libc.clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, ctypes.byref(ts), None)
        if r == 0: break
        if r != EINTR: raise OSError(r, os.strerror(r))
    while time.clock_gettime_ns(CLOCK_REALTIME) < t_ns: pass

POLL_MS = 30
def hw_wait(t0, pfd, warm=None):
    """Wait for the PHC's second event for second t0. Blocked in the kernel until POLL_MS before the instant, then
    polling the device (zero timeout) so the core is awake when the interrupt lands: a process blocked for a second paid
    an idle wake of 0.05-2.2 ms (staging runs 3-8); the threaded interrupt handler that stamps the event may pay the same.
    Returns {"assert_unix_ns", "sequence", "woke_unix_ns"} or None when no event came by t0 + HW_GRACE_S (fall back)."""
    buf = bytearray(64)
    def fetch(timeout_s):
        sec = int(timeout_s); struct.pack_into("qiI", buf, 48, sec, int((timeout_s - sec) * 1e9), 0)
        fcntl.ioctl(pfd, PPS_FETCH, buf, True)
        aseq = struct.unpack_from("I", buf, 0)[0]; asec, ansec = struct.unpack_from("qi", buf, 8); return aseq, asec, ansec
    import errno
    try:
        while time.time() < t0 - POLL_MS / 1000:                              # blocked: consume the earlier seconds' events
            try: aseq, asec, ansec = fetch(max(0.001, t0 - POLL_MS / 1000 - time.time()))
            except OSError as e:
                if e.errno == errno.ETIMEDOUT: continue                       # nothing in this slice - expected between two seconds' events
                raise
            if asec >= t0: return {"assert_unix_ns": asec * 10**9 + ansec, "sequence": aseq, "woke_unix_ns": time.clock_gettime_ns(CLOCK_REALTIME)}
        if warm is not None:
            try: warm()                                                       # T-30 ms: sign + serialize a full-size dummy so the real one runs warm (21:00Z: 1.4 ms cold vs 0.5 ms warm)
            except Exception: pass
        while time.time() < t0 + HW_GRACE_S:                                  # polling (zero timeout = no wait): the last POLL_MS and the grace window
            aseq, asec, ansec = fetch(0.0)
            if asec >= t0: return {"assert_unix_ns": asec * 10**9 + ansec, "sequence": aseq, "woke_unix_ns": time.clock_gettime_ns(CLOCK_REALTIME)}
    except OSError: return None
    return None

def phc_read(fd, n=5):
    """Tightest of n REALTIME/PHC/REALTIME brackets (5 before the instant; 1 on the fast path after the edge, 12 us)."""
    clk = ((~fd) << 3) | 3; best = None
    for _ in range(n):
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
    """Everything that does not depend on the instant is prepared BEFORE the sleep (tool hashes, execution context, ring
    reads, the open socket); after the wake only the clock reads, the signature and the send stand between the instant
    and the datagram on the wire. (First measurement, 2026-09-13: 12 ms to sign, then 157 ms of imports and file writes
    before the first copy left. Now the send comes first.)"""
    fd = os.open(PHC_DEV, os.O_RDONLY)
    # The signed statement stays under one Ethernet frame (<= 1,400 B): a 2,330 B statement was two IP fragments and its
    # p99 delivery went from 0.4 to 1.2 ms (timing.md, 2026-09-13). Field meanings live in PROTOCOL.md, not in the packet.
    static = {"v": "0.5", "role": "time_attester", "host": HOSTNAME, "kind": "cadence-trigger", "chain_hash": CHAIN_HASH,
              "scheduled_unix_s": t0, "period_s": PERIOD_S, "offset_s": OFFSET_S,
              "tools": A.tool_binding(os.path.abspath(__file__), os.path.join(os.path.expanduser("~/beacon"), "attest_lib.py"))}
    priv = A.load_private("time_attester"); raw, pub_b64, kid = A.pub_of(priv)   # key in memory before the instant
    def sign(statement):
        """attest_lib.sign_statement without re-reading the PEM (its first call cost 8-143 ms on p550; this is ~1 ms)."""
        st = A.normalize(statement); sig = priv.sign(A.canon(st))
        return {"statement": st, "signature": {"alg": "ed25519", "key_id": kid, "public_key_b64": pub_b64, "sig_b64": base64.b64encode(sig).decode(), "over": "canon(statement)"}}
    sign({"warm": 1})                                                         # first-use costs paid before the instant
    # Fast signer: libsodium via ctypes (112 us vs 197 us for OpenSSL through `cryptography` on p550, identical signatures);
    # falls back to priv.sign if the library is absent. The seed is the same 32 bytes the PEM holds.
    _sodium = None
    try:
        _lib = ctypes.util.find_library("sodium")
        if _lib:
            _so = ctypes.CDLL(_lib); _so.sodium_init(); _sk = ctypes.create_string_buffer(64); _pk = ctypes.create_string_buffer(32)
            _so.crypto_sign_seed_keypair(_pk, _sk, priv.private_bytes_raw())
            if _pk.raw == raw:
                _sigbuf = ctypes.create_string_buffer(64); _siglen = ctypes.c_ulonglong()
                def _sodium(msg):
                    _so.crypto_sign_detached(_sigbuf, ctypes.byref(_siglen), msg, len(msg), _sk); return _sigbuf.raw
                if _sodium(b"warm") != priv.sign(b"warm"): _sodium = None
    except Exception: _sodium = None
    fast_sign = _sodium or priv.sign
    # Pre-built datagram (Bill, 2026-09-14: "get a datagram ready and send on the dot"): everything that does not depend on the
    # event is canonicalized BEFORE the instant; after the edge only the event numbers are substituted into the canonical
    # template (25 us, byte-identical to a fresh canon), signed (112 us) and wrapped by concatenation (11 us).
    SENT = {"issued": "__ISSUED__", "assert": "__ASSERT__", "wake": "__WAKE__", "phc": "__PHC__", "mid": "__MID__",
            "edge": -777777001, "woke": -777777002, "late": -777777003, "pmr": -777777004, "br": -777777005, "seq": -777777006}
    prebuilt = {}
    def build_template(ep, ts2, nonce):
        tst = A.normalize(dict(static, wake={"clock": "CLOCK_REALTIME", "unix_ns": SENT["wake"], "late_ns": SENT["late"], "how": "pps-event"},
                               hw_event={"source": "i210-pps", "device": PPS_DEV, "assert_unix_ns": SENT["assert"], "sequence": SENT["seq"],
                                         "edge_after_instant_ns": SENT["edge"], "woke_after_edge_ns": SENT["woke"]},
                               phc={"device": PHC_DEV, "unix_ns": SENT["phc"], "realtime_mid_unix_ns": SENT["mid"], "phc_minus_realtime_ns": SENT["pmr"], "bracket_ns": SENT["br"],
                                    "tai_minus_utc_s": ep.get("tai_minus_utc_s")},
                               clock_state={"epoch_ok": ep.get("epoch_ok"), "refclock_selected": ep.get("refclock_selected"), "epoch_row_age_s": ep.get("age_s"),
                                            "ts2phc_state": ts2.get("state"), "ts2phc_offset_ns": ts2.get("offset_ns"), "ts2phc_row_age_s": ts2.get("age_s")},
                               issued_unix_ns=SENT["issued"], nonce=nonce))
        # split once on the sentinels (each occurs exactly once) so the fill is a single join, not eleven passes over 1.1 KB
        import re
        toks = sorted((str(v) for v in SENT.values()), key=len, reverse=True)
        parts = re.split("(" + "|".join(re.escape(t) for t in toks) + ")", A.canon(tst).decode())
        prebuilt["parts"] = parts; prebuilt["slots"] = {tok: i for i, tok in enumerate(parts) if tok in toks}
        assert len(prebuilt["slots"]) == len(SENT), "every sentinel must appear once in the template"
        prebuilt["prefix"] = b'{"statement":'; prebuilt["suffix"] = (',"signature":{"alg":"ed25519","key_id":"' + kid + '","public_key_b64":"' + pub_b64 + '","sig_b64":"').encode()
        prebuilt["tail"] = b'","over":"canon(statement)"}}'
    def fast_datagram(hw, wake, phc, issued_ns):
        """The canonical statement with the event numbers filled in, signed and wrapped. Returns (datagram bytes, statement dict)."""
        t0_fill = time.clock_gettime_ns(CLOCK_REALTIME); parts = list(prebuilt["parts"]); slots = prebuilt["slots"]
        vals = {"issued": issued_ns, "assert": str(hw["assert_unix_ns"]), "wake": str(wake), "phc": phc["unix_ns"], "mid": phc["realtime_mid_unix_ns"],
                "edge": str(hw["assert_unix_ns"] - t0 * 10**9), "woke": str(hw["woke_unix_ns"] - hw["assert_unix_ns"]), "late": str(wake - t0 * 10**9),
                "pmr": str(int(phc["phc_minus_realtime_ns"])), "br": str(int(phc["bracket_ns"])), "seq": str(int(hw["sequence"]))}
        for key, val in vals.items(): parts[slots[str(SENT[key])]] = val
        t1 = time.clock_gettime_ns(CLOCK_REALTIME); mb = "".join(parts).encode(); sig = fast_sign(mb); t2 = time.clock_gettime_ns(CLOCK_REALTIME)
        out = prebuilt["prefix"] + mb + prebuilt["suffix"] + base64.b64encode(sig) + prebuilt["tail"]
        prebuilt["timing"] = {"fill_us": (t1 - t0_fill) / 1e3, "sign_us": (t2 - t1) / 1e3, "wrap_us": (time.clock_gettime_ns(CLOCK_REALTIME) - t2) / 1e3, "signer": "libsodium" if _sodium else "openssl"}
        return out, mb
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); host, port = UDP.rsplit(":", 1); dest = (host, int(port))
    try:
        ep, ts2 = ring_last("epoch") or {}, ring_last("ts2phc") or {}       # read a moment before the instant (rows <= 1 s old)
        if not DRY: sock.sendto(b"cadence-arp-warm", dest)                   # resolves the aggregator's MAC now, not at the instant (E1: 8 ms)
        pfd = None
        try: pfd = os.open(PPS_DEV, os.O_RDWR)
        except OSError as e: log(f"{PPS_DEV} not available ({e}); clock fallback")
        hw = None
        if pfd is not None:
            sleep_until((t0 - 1) * 10**9 - 200_000_000)                    # be blocked in the kernel for the last second's events
            dummy = dict(static, wake={"clock": "CLOCK_REALTIME", "unix_ns": str(t0 * 10**9), "late_ns": 0, "how": "warm-up"},
                         hw_event={"source": "i210-pps", "device": PPS_DEV, "assert_unix_ns": str(t0 * 10**9), "sequence": 0, "edge_after_instant_ns": 0, "woke_after_edge_ns": 0},
                         phc={"device": "/dev/ptp0", "unix_ns": str(t0 * 10**9), "realtime_mid_unix_ns": str(t0 * 10**9), "phc_minus_realtime_ns": 0, "bracket_ns": 0, "tai_minus_utc_s": 37},
                         clock_state={"epoch_ok": True, "refclock_selected": "IPHC", "epoch_row_age_s": 0.0, "ts2phc_state": "s2", "ts2phc_offset_ns": 0, "ts2phc_row_age_s": 0.0},
                         issued_unix_ns=A.now_ns_str(), nonce=secrets.token_hex(16))
            nonce = secrets.token_hex(16)
            def warm():
                json.dumps(sign(dummy), separators=(",", ":")).encode()
                try:
                    build_template(ep, ts2, nonce); prebuilt["ok"] = True
                    # run the fast path once on dummy numbers so its first real execution is warm (79 -> ~25 us fill, 162 -> ~112 us sign)
                    fast_datagram({"assert_unix_ns": t0 * 10**9, "woke_unix_ns": t0 * 10**9, "sequence": 0}, t0 * 10**9, phc_read(fd, n=1), A.now_ns_str()); prebuilt.pop("timing", None)
                except Exception as e: prebuilt["ok"] = False; log(f"template not built ({type(e).__name__}: {str(e)[:60]}); slow path")
            hw = hw_wait(t0, pfd, warm=warm); os.close(pfd)
        if hw is None:
            if time.time() < t0: sleep_until(t0 * 10**9)
            wake = time.clock_gettime_ns(CLOCK_REALTIME); how = "clock-fallback"          # clock_nanosleep to T-1.5 ms then a spin (PROTOCOL.md)
        else:
            wake = hw["woke_unix_ns"]; how = "pps-event"                                   # blocked in the kernel on the PHC's second event
        data = None
        if hw is not None and prebuilt.get("ok"):
            try:
                phc = phc_read(fd, n=1)                                                       # one bracket (12 us), not five
                data, mb = fast_datagram(hw, wake, phc, A.now_ns_str()); st = None; signed = None      # parse AFTER the sends
            except Exception as e: data = None; log(f"fast path failed ({type(e).__name__}: {str(e)[:60]}); slow path")
        if data is None: phc = phc_read(fd)
        if data is None: st = dict(static, wake={"clock": "CLOCK_REALTIME", "unix_ns": str(wake), "late_ns": wake - t0 * 10**9, "how": how},
                  hw_event=None if hw is None else {"source": "i210-pps", "device": PPS_DEV, "assert_unix_ns": str(hw["assert_unix_ns"]), "sequence": hw["sequence"],
                                                     "edge_after_instant_ns": hw["assert_unix_ns"] - t0 * 10**9, "woke_after_edge_ns": hw["woke_unix_ns"] - hw["assert_unix_ns"]},
                  phc={**phc, "tai_minus_utc_s": ep.get("tai_minus_utc_s")},
                  clock_state={"epoch_ok": ep.get("epoch_ok"), "refclock_selected": ep.get("refclock_selected"), "epoch_row_age_s": ep.get("age_s"),
                               "ts2phc_state": ts2.get("state"), "ts2phc_offset_ns": ts2.get("offset_ns"), "ts2phc_row_age_s": ts2.get("age_s")},
                  issued_unix_ns=A.now_ns_str(), nonce=secrets.token_hex(16))
        if data is None: signed = sign(st); data = json.dumps(signed, separators=(",", ":")).encode()
        sent = []
        for _ in range(3):
            if not DRY: sock.sendto(data, dest)
            sent.append(time.clock_gettime_ns(CLOCK_REALTIME))
            if _ < 2: time.sleep(0.02)
        if signed is None: signed = json.loads(data); st = signed["statement"]
        if prebuilt.get("timing"): log("fast path: fill %(fill_us).0f us, sign %(sign_us).0f us (%(signer)s), wrap %(wrap_us).0f us" % prebuilt["timing"])
    finally:
        os.close(fd); sock.close()
    return signed, wake, sent, len(data)

def next_instant(now): return ((int(now) - OFFSET_S) // PERIOD_S + 1) * PERIOD_S + OFFSET_S

def main():
    a = sys.argv[1:]; once = "--once" in a; dry = "--no-send" in a
    global DRY; DRY = dry
    fixed = int(a[a.index("--at") + 1]) if "--at" in a else None
    os.makedirs(STATE_DIR, exist_ok=True)
    while True:
        target = fixed if fixed is not None else next_instant(time.time())
        log(f"next trigger at {target} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(target))}Z), in {target - time.time():.1f} s")
        while target - time.time() > 2.5: time.sleep(min(60.0, target - time.time() - 2.0))      # coarse wait, then absolute
        signed, wake, sent, nbytes = trigger(target); st = signed["statement"]
        hw = st.get("hw_event"); log(f"trigger {target}: {'hardware event: edge +%d ns, woke %d ns after it' % (hw['edge_after_instant_ns'], hw['woke_after_edge_ns']) if hw else 'clock fallback'}; "
            f"woke {st['wake']['late_ns'] / 1000:.1f} us after the instant; issued (pre-sign stamp) at +{(int(st['issued_unix_ns']) - target * 10**9) / 1e6:.3f} ms; "
            f"{'would send' if dry else 'sent'} {nbytes} B{' (FRAGMENTS!)' if nbytes > 1400 else ''} x3 by UDP to {UDP}, first copy at +{(sent[0] - target * 10**9) / 1e6:.3f} ms; "
            f"PHC-REALTIME {st['phc']['phc_minus_realtime_ns']} ns; epoch_ok {st['clock_state']['epoch_ok']} ts2phc {st['clock_state']['ts2phc_state']} {st['clock_state']['ts2phc_offset_ns']} ns")
        tmp = os.path.join(STATE_DIR, ".last.json.tmp")
        json.dump({"sent_unix_ns": str(sent[0]), "trigger": signed}, open(tmp, "w")); os.replace(tmp, os.path.join(STATE_DIR, "last.json"))
        if dry: print(json.dumps(signed))
        if once: return
        fixed = None; time.sleep(5)

if __name__ == "__main__": main()
