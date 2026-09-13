#!/usr/bin/env python3
"""clocklog.py — log a host's clock evidence at SOURCE rate, so a statement can be made in milliseconds from data that
already exists (Bill, 2026-09-13: "if something isn't logged we need for stats, let's do it").

  p550 (ROLE=time):    ts2phc discipline (offset/state/freq per PPS)   -> ring ts2phc.jsonl  + DB timehat.ts2phc_stream
                       i210's observation of the BMC GM (bmc-phc.status) -> ring mesh.jsonl  + DB timehat.gmmon_stream (existing table)
                       epoch guard (PHC - CLOCK_REALTIME - TAI, chrony refclock selection) -> ring epoch.jsonl + DB timehat.epoch_stream
  k3   (ROLE=witness): ptp4l discipline (master offset/state/freq/path delay per sync) -> ring ptp4l.jsonl + DB timehat.ptp4l_stream
                       epoch guard as above

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
def ring_append(name, row):
    p = os.path.join(RING_DIR, name + ".jsonl")
    with open(p, "a") as f: f.write(json.dumps(row, separators=(",", ":")) + "\n")
    try: os.chmod(p, 0o644)
    except Exception: pass
def ring_trim(name):
    p = os.path.join(RING_DIR, name + ".jsonl")
    try:
        lines = open(p).read().splitlines(); cutoff = time.time() - RING_S
        keep = [l for l in lines if json.loads(l).get("t", 0) >= cutoff]
        if len(keep) != len(lines): open(p + ".tmp", "w").write("\n".join(keep) + ("\n" if keep else "")); os.replace(p + ".tmp", p); os.chmod(p, 0o644)
    except FileNotFoundError: pass
    except Exception as e: print("trim", name, e, flush=True)

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
            cur.execute("CREATE TABLE IF NOT EXISTS epoch_stream (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME(3) NOT NULL, host VARCHAR(16) NOT NULL, phc_minus_rt_ns BIGINT, tai_minus_utc_s INT, epoch_ok TINYINT, refclock_selected TINYINT, KEY k_ts (ts), KEY k_host_ts (host, ts))")
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

def phc_minus_realtime_ns():
    """phc_ctl <dev> cmp -> 'offset from CLOCK_REALTIME is <n>ns' (sign: PHC - REALTIME)."""
    out = subprocess.run(["phc_ctl", PHC, "cmp"], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"offset from CLOCK_REALTIME is (-?\d+)ns", out); return -int(m.group(1)) if m else None   # phc_ctl reports REALTIME - PHC
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
            d = phc_minus_realtime_ns(); tai = tai_minus_utc(); sel = refclock_selected()
            ok = None if d is None else (abs(d / 1e9 - tai) < 0.5)
            row = {"t": time.time(), "host": host, "phc_minus_rt_ns": d, "tai_minus_utc_s": tai, "epoch_ok": ok, "refclock_selected": sel}
            ring_append("epoch", row); db.insert("INSERT INTO epoch_stream (ts,host,phc_minus_rt_ns,tai_minus_utc_s,epoch_ok,refclock_selected) VALUES (%s,%s,%s,%s,%s,%s)", (now_ms(), host, d, tai, None if ok is None else int(ok), None if sel is None else int(sel)))
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

def loop_ptp4l():
    """Follow ptp4l's journal (k3 runs ptp4l -m -> stdout -> journal): one row per 'master offset' line."""
    pat = re.compile(r"master offset\s+(-?\d+)\s+(s\d)\s+freq\s+([-+]?\d+)\s+path delay\s+(-?\d+)")
    while True:
        try:
            p = subprocess.Popen(["journalctl", "-f", "-n", "0", "-u", "ptp4l-bmc", "-o", "cat"], stdout=subprocess.PIPE, text=True)
            for line in p.stdout:
                m = pat.search(line)
                if not m: continue
                row = {"t": time.time(), "host": host, "offset_ns": int(m.group(1)), "state": m.group(2), "freq_ppb": int(m.group(3)), "path_delay_ns": int(m.group(4))}
                ring_append("ptp4l", row); db.insert("INSERT INTO ptp4l_stream (ts,host,offset_ns,state,freq_ppb,path_delay_ns) VALUES (%s,%s,%s,%s,%s,%s)", (now_ms(), host, row["offset_ns"], row["state"], row["freq_ppb"], row["path_delay_ns"]))
        except Exception as e: print("ptp4l:", e, flush=True)
        time.sleep(2)

def loop_trim():
    while True:
        for n in ("epoch", "ts2phc", "mesh", "ptp4l"): ring_trim(n)
        time.sleep(60)

if __name__ == "__main__":
    loops = [loop_epoch, loop_trim, db.writer] + ([loop_ts2phc, loop_mesh] if ROLE == "time" else [loop_ptp4l])
    print(f"clocklog: role {ROLE} host {host} phc {PHC} rings {RING_DIR}", flush=True)
    ts = [threading.Thread(target=f, daemon=True) for f in loops]; [t.start() for t in ts]
    while True: time.sleep(3600)
