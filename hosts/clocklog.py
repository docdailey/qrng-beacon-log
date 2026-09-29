#!/usr/bin/env python3
"""clocklog.py — log a host's clock evidence at SOURCE rate, so a statement can be made in milliseconds from data that
already exists (Bill, 2026-09-13: "if something isn't logged we need for stats, let's do it").

  p550 (ROLE=time):    ts2phc discipline (offset/state/freq per PPS)   -> ring ts2phc.jsonl  + DB timehat.ts2phc_stream
                       i210's observation of the BMC GM (bmc-phc.status) -> ring mesh.jsonl  + DB timehat.gmmon_stream (existing table)
                       epoch guard (PHC - CLOCK_REALTIME - TAI, chrony refclock selection) -> ring epoch.jsonl + DB timehat.epoch_stream
  k3   (ROLE=witness): ptp4l discipline (below)
                       epoch guard as above
  every host running ptp4l (p550 ptp4l-slave, k3/f9t ptp4l-bmc): ptp4l's own once-a-second summary (summary_interval 0:
                       rms and max |offset| of that second's syncs, mean freq, path delay) plus the port state it last announced
                       -> ring ptp4l.jsonl and DB timehat.ptp4l_summary, one row per second (2026-09-28, ERR-023: nothing at the
                       8 Hz sync rate is kept; ptp4l_stream is no longer written).

Rings live in /run/beacon-clocklog/<name>.jsonl (tmpfs, world-readable, trimmed to RING_S seconds); the probe reads the
trailing window from them and falls back to live sampling only if a ring is missing or stale. The DB is the long-term
record (review T3 groundwork); a DB outage never stops the ring. Every row is deduplicated on the source's own update
marker, so a row is one real servo update, never a re-read of the same line."""
import os, re, sys, json, time, subprocess, threading, queue
from datetime import datetime, timezone
ROLE = os.environ.get("ROLE") or ("time" if os.uname().nodename.startswith("p550") else "witness")
RING_DIR = "/run/beacon-clocklog"; RING_S = 1800; DB_ENV = os.environ.get("TIMEHAT_DB_ENV", "/home/willy/timehat-db.env")
PHC = os.environ.get("PHC_DEV", "/dev/ptp0" if ROLE == "time" else "/dev/ptp1"); REFID = "IPHC" if ROLE == "time" else "PHC"
os.makedirs(RING_DIR, exist_ok=True)

def now_ms(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
import fcntl
def _locked(name):
    """One lock file per ring: appends and the trim rewrite exclude each other (an append during the rewrite was lost)."""
    f = open(os.path.join(RING_DIR, "." + name + ".lock"), "a"); fcntl.flock(f, fcntl.LOCK_EX); return f
def ring_append(name, row):
    p = os.path.join(RING_DIR, name + ".jsonl"); lk = _locked(name)
    try:
        with open(p, "a") as f: f.write(json.dumps(row, separators=(",", ":")) + "\n")
        try: os.chmod(p, 0o644)
        except Exception: pass
    finally: lk.close()
def ring_trim(name):
    p = os.path.join(RING_DIR, name + ".jsonl"); lk = _locked(name)
    try:
        lines = open(p).read().splitlines(); cutoff = time.time() - RING_S; keep = []
        for l in lines:
            try:
                if json.loads(l).get("t", 0) >= cutoff: keep.append(l)
            except Exception: pass                                            # a damaged line is dropped, never propagated
        if len(keep) != len(lines): open(p + ".tmp", "w").write("\n".join(keep) + ("\n" if keep else "")); os.replace(p + ".tmp", p); os.chmod(p, 0o644)
    except FileNotFoundError: pass
    except Exception as e: print("trim", name, e, flush=True)
    finally: lk.close()

class DB:
    """Best-effort MySQL sink. Rows are QUEUED and ONE writer thread owns the connection: pymysql connections are not
    thread-safe, and on 2026-09-13 two loops sharing one connection deadlocked k3's logger 80 s after start (one thread hung
    in recv, the other on the reader lock) and both rings went stale. Read/write timeouts bound any DB stall; the queue is
    bounded and drops the oldest rows while the DB is away, so the rings (the probe's source) are never delayed by it."""
    def __init__(self):
        self.c = None; self.env = {}; self.q = queue.Queue(maxsize=20000); self.dropped = 0
        try: self.env = dict(l.strip().split("=", 1) for l in open(DB_ENV) if "=" in l and not l.startswith("#"))
        except Exception as e: print("db env:", e, flush=True)
    def conn(self):
        import pymysql
        if self.c is None:
            self.c = pymysql.connect(host=self.env["TIMEHAT_DB_HOST"], port=int(self.env["TIMEHAT_DB_PORT"]), user=self.env["TIMEHAT_DB_USER"], password=self.env["TIMEHAT_DB_PASS"], database=self.env["TIMEHAT_DB_NAME"], autocommit=True, connect_timeout=6, read_timeout=10, write_timeout=10)
            cur = self.c.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS ts2phc_stream (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL, host VARCHAR(16) NOT NULL, offset_ns INT NOT NULL, state VARCHAR(4) NOT NULL, freq_ppb INT, KEY k_ts (ts), KEY k_host_ts (host, ts))")
            cur.execute("CREATE TABLE IF NOT EXISTS ptp4l_stream (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL, host VARCHAR(16) NOT NULL, offset_ns INT NOT NULL, state VARCHAR(4) NOT NULL, freq_ppb INT, path_delay_ns INT, KEY k_ts (ts), KEY k_host_ts (host, ts))")
            cur.execute("CREATE TABLE IF NOT EXISTS ptp4l_summary (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL, host VARCHAR(16) NOT NULL, n SMALLINT NULL, rms_ns INT, max_abs_ns INT, mean_ns INT, state VARCHAR(16), freq_ppb INT, path_delay_ns INT, KEY k_ts (ts), KEY k_host_ts (host, ts))")
            cur.execute("CREATE TABLE IF NOT EXISTS epoch_stream(id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL, host VARCHAR(16) NOT NULL, phc_minus_rt_ns BIGINT, window_ns INT, method VARCHAR(32), tightest_samples SMALLINT, tai_minus_utc_s INT, epoch_ok TINYINT, refclock_selected TINYINT, KEY k_ts (ts), KEY k_host_ts (host, ts))")
        return self.c
    def insert(self, sql, args):
        """Never blocks the caller: enqueue, dropping the oldest row if the DB has been away long enough to fill the queue."""
        try: self.q.put_nowait((sql, args))
        except queue.Full:
            try: self.q.get_nowait(); self.dropped += 1; self.q.put_nowait((sql, args))
            except Exception: pass
    def writer(self):
        while True:
            sql, args = self.q.get()
            try: self.conn().cursor().execute(sql, args)
            except Exception as e:
                print("db:", str(e)[:120], "(queue", self.q.qsize(), "dropped", self.dropped, ")", flush=True)
                try: self.c.close()
                except Exception: pass
                self.c = None; time.sleep(5)          # back off; this row is lost (best-effort sink), the ring has it
db = DB(); host = os.uname().nodename.split(".")[0]

# PHC - CLOCK_REALTIME from one kernel call that brackets each PHC read with system-clock reads (tightest window kept,
# samples within 1 % of it averaged): PTP_SYS_OFFSET_PRECISE, else _EXTENDED, else PTP_SYS_OFFSET; same code as stamp_probe
# (ERR-024). On p550 both edges come from the 1 us system clock, so the value is bounded by +/- window/2 (notebook #228).
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

_PHC_FD = None
def phc_offset():
    """(offset_ns, window_ns, method, tightest_samples)."""
    global _PHC_FD
    if _PHC_FD is None: _PHC_FD = os.open(PHC, os.O_RDONLY)
    try: off, win, tied, method, _n = phc_minus_realtime(_PHC_FD)
    except Exception:
        os.close(_PHC_FD); _PHC_FD = None; raise
    return off, win, method, tied
def tai_minus_utc():
    """struct timex.tai (int at byte 160 on 64-bit Linux; verified on p550: adjtimex long index 20 == 37). 0 (unset, k3) -> 37 constant."""
    try:
        import ctypes, struct
        libc = ctypes.CDLL(None, use_errno=True); buf = ctypes.create_string_buffer(512); libc.adjtimex(buf)
        v = struct.unpack_from("i", buf.raw, 160)[0]; return v if 30 <= v <= 60 else 37
    except Exception: return 37
def refclock_selected():
    try:
        src = subprocess.run(["chronyc", "-n", "sources"], capture_output=True, text=True, timeout=8).stdout
        line = [l for l in src.splitlines() if l.split()[1:2] == [REFID]]; return bool(line and line[0].strip().startswith("#*"))
    except Exception: return None

def loop_epoch():
    while True:
        try:
            d, win, method, tied = phc_offset(); tai = tai_minus_utc(); sel = refclock_selected()
            ok = abs(d / 1e9 - tai) < 0.5
            row = {"t": time.time(), "host": host, "phc_minus_rt_ns": d, "window_ns": win, "method": method, "tightest_samples": tied,
                   "tai_minus_utc_s": tai, "epoch_ok": ok, "refclock_selected": sel}
            ring_append("epoch", row); db.insert("INSERT INTO epoch_stream (ts,host,phc_minus_rt_ns,window_ns,method,tightest_samples,tai_minus_utc_s,epoch_ok,refclock_selected) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (now_ms(), host, d, win, method, tied, tai, int(ok), None if sel is None else int(sel)))
        except Exception as e: print("epoch:", e, flush=True)
        time.sleep(1.0)

def loop_ts2phc():
    pat = re.compile(r"offset\s+(-?\d+)\s+(s\d)\s+freq\s+([-+]?\d+)"); last = None
    while True:
        try:
            txt = open("/run/ts2phc-f9t.status").read(); m = pat.search(txt); u = re.search(r"updated\s*:\s*(.+)", txt)
            if m and u and u.group(1).strip() != last:
                last = u.group(1).strip(); row = {"t": time.time(), "host": host, "offset_ns": int(m.group(1)), "state": m.group(2), "freq_ppb": int(m.group(3)), "updated": last}
                ring_append("ts2phc", row); db.insert("INSERT INTO ts2phc_stream (ts,host,offset_ns,state,freq_ppb) VALUES (%s,%s,%s,%s,%s)", (now_ms(), host, row["offset_ns"], row["state"], row["freq_ppb"]))
        except FileNotFoundError: pass
        except Exception as e: print("ts2phc:", e, flush=True)
        time.sleep(0.25)

def loop_mesh():
    pat = re.compile(r"master offset\s+(-?\d+)\s+(s\d)\s+freq\s+([-+]?\d+)\s+path delay\s+(-?\d+)"); last = None
    while True:
        try:
            txt = open("/run/bmc-phc.status").read(); m = pat.search(txt); u = re.search(r"updated\s*:\s*(.+)", txt); h = re.search(r"health\s*:\s*(.+)", txt)
            if m and u and u.group(1).strip() != last:
                last = u.group(1).strip(); row = {"t": time.time(), "host": host, "offset_ns": int(m.group(1)), "state": m.group(2), "freq_ppb": int(m.group(3)), "path_delay_ns": int(m.group(4)), "health": h.group(1).strip() if h else None, "updated": last}
                ring_append("mesh", row)          # DB: gmmon.service already writes gmmon_stream from the same file
        except FileNotFoundError: pass
        except Exception as e: print("mesh:", e, flush=True)
        time.sleep(0.25)

def ptp4l_unit():
    """The one steering ptp4l on this host: PTP4L_UNIT, else whichever of ptp4l-slave/ptp4l-bmc is active."""
    u = os.environ.get("PTP4L_UNIT")
    if u: return u
    for u in ("ptp4l-slave", "ptp4l-bmc"):
        if subprocess.run(["systemctl", "is-active", "--quiet", u]).returncode == 0: return u
    return None

def ptp4l_port_state(unit):
    """The port state this ptp4l run last announced ('port 1 (end0): UNCALIBRATED to SLAVE on ...'), from its own journal."""
    inv = subprocess.run(["systemctl", "show", "-p", "InvocationID", "--value", unit], capture_output=True, text=True).stdout.strip()
    if not inv: return None
    j = subprocess.run(["journalctl", "-o", "cat", "_SYSTEMD_INVOCATION_ID=" + inv], capture_output=True, text=True).stdout
    st = PORT_PAT.findall(j)
    return st[-1] if st else None

PORT_PAT = re.compile(r"port \d+(?: \([^)]*\))?: \S+ to (\S+)")

def loop_ptp4l():
    """Follow ptp4l's journal: one ring row and one ptp4l_summary row per 1 s summary line. Accepts both the stdout
    ('[t] rms ...') and syslog ('ptp4l[t]: rms ...') forms and keeps one copy per ptp4l timestamp."""
    pat = re.compile(r"^(?:ptp4l)?\[([\d.]+)\]:? rms\s+(\d+)\s+max\s+(\d+)\s+freq\s+([-+]?\d+)\s+\+/-\s+(\d+)(?:\s+delay\s+(-?\d+)\s+\+/-\s+\d+)?")
    while True:
        try:
            unit = ptp4l_unit()
            if unit is None: time.sleep(10); continue
            state = ptp4l_port_state(unit); last = None
            p = subprocess.Popen(["journalctl", "-f", "-n", "0", "-u", unit, "-o", "cat"], stdout=subprocess.PIPE, text=True)
            for line in p.stdout:
                ps = PORT_PAT.search(line)
                if ps: state = ps.group(1); continue
                m = pat.search(line)
                if not m or m.group(1) == last: continue
                last = m.group(1)
                row = {"t": time.time(), "host": host, "rms_ns": int(m.group(2)), "max_abs_ns": int(m.group(3)), "freq_ppb": int(m.group(4)),
                       "freq_sd_ppb": int(m.group(5)), "path_delay_ns": int(m.group(6)) if m.group(6) else None, "port_state": state}
                ring_append("ptp4l", row)
                db.insert("INSERT INTO ptp4l_summary (ts,host,n,rms_ns,max_abs_ns,mean_ns,state,freq_ppb,path_delay_ns) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                          (now_ms(), host, None, row["rms_ns"], row["max_abs_ns"], None, state, row["freq_ppb"], row["path_delay_ns"]))
        except Exception as e: print("ptp4l:", e, flush=True)
        time.sleep(2)

def loop_trim():
    while True:
        for n in ("epoch", "ts2phc", "mesh", "ptp4l"): ring_trim(n)
        time.sleep(60)

if __name__ == "__main__":
    loops = [loop_epoch, loop_trim, db.writer, loop_ptp4l] + ([loop_ts2phc, loop_mesh] if ROLE == "time" else [])
    print(f"clocklog: role {ROLE} host {host} phc {PHC} rings {RING_DIR}", flush=True)
    ts = [threading.Thread(target=f, daemon=True) for f in loops]; [t.start() for t in ts]
    while True: time.sleep(3600)
