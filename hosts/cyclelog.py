#!/usr/bin/env python3
"""cyclelog.py - one row per beacon cycle into the timehat DB (Bill, 2026-09-13: "can we not just pull stats from timehat db").

The clock streams (ptp4l_stream, epoch_stream, ts2phc_stream, gmmon_stream) already live there at source rate; this adds the
cycle itself so latency questions become one SQL query: trigger stamps on p550, k3's start, the datagram's kernel and userspace
receive, host statements, commit push, Rekor, relay serve delay, reveal start and push. Every number is read from what the
cycle left behind - the pulse files, trigger/anchor-NNNN.json and cycle.log - never from live probing, so it can run after
the cycle, detached, and a DB outage changes nothing about the beacon.

    cyclelog.py --seq 110               one commit (and its resolving pulse, if present) -> upsert
    cyclelog.py --backfill [--from 98]  every commit from that seq that has a file
    cyclelog.py --dry-run ...           print the rows, write nothing

Table: timehat.beacon_cycle_stream (created if missing). Credentials: TIMEHAT_DB_ENV (default ~/beacon/timehat-db.env, the
same KEY=VALUE file clocklog.py uses). Times after the instant are integers in ns unless the name says _s."""
import os, sys, json, re, glob, time

REPO = os.environ.get("BEACON_REPO", os.path.expanduser("~/qrng-beacon"))
LOG = os.path.join(REPO, "cycle.log"); TRIG = os.path.join(REPO, "trigger"); CHAIN = os.path.join(REPO, "chain")
DB_ENV = os.environ.get("TIMEHAT_DB_ENV", os.path.expanduser("~/beacon/timehat-db.env"))
TABLE = "beacon_cycle_stream"
PERIOD = 3

DDL = f"""CREATE TABLE IF NOT EXISTS {TABLE} (
  seq INT NOT NULL PRIMARY KEY,
  instant_unix_s BIGINT NOT NULL,
  instant_utc DATETIME NOT NULL,
  aggregator VARCHAR(16),
  start_source VARCHAR(24),
  lead_rounds INT,
  release_unix_s BIGINT,
  resolving_seq INT NULL,
  resolving_type VARCHAR(12) NULL,
  p550_edge_after_instant_ns BIGINT NULL,
  p550_woke_after_edge_ns BIGINT NULL,
  p550_issued_after_instant_ns BIGINT NULL,
  datagram_kernel_rx_after_instant_ns BIGINT NULL,
  datagram_user_rx_after_instant_ns BIGINT NULL,
  k3_wake_after_instant_ns BIGINT NULL,
  main_thread_at_gate_after_instant_ns BIGINT NULL,
  pulse_py_start_after_instant_ns BIGINT NULL,
  stmt_entropy_after_instant_ns BIGINT NULL,
  stmt_gnss_after_instant_ns BIGINT NULL,
  stmt_time_after_instant_ns BIGINT NULL,
  stmt_witness_after_instant_ns BIGINT NULL,
  commit_pushed_after_instant_ms INT NULL,
  rekor_integrated_after_instant_s INT NULL,
  rekor_upload_ms INT NULL,
  relay_first_served_after_release_ms INT NULL,
  reveal_started_after_release_ms INT NULL,
  reveal_pushed_after_release_ms INT NULL,
  usable_after_instant_ms INT NULL,
  trigger_rejected VARCHAR(120) NULL,
  cadence_source VARCHAR(64) NULL,
  chain_head_commit VARCHAR(12) NULL,
  logged_utc DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""

def _i(x):
    try: return None if x is None else int(x)
    except Exception: return None

def log_lines():
    try: return open(LOG, errors="replace").read().splitlines()
    except Exception: return []

def row_for(seq, lines):
    p = os.path.join(CHAIN, f"pulse-{seq:04d}.json")
    if not os.path.exists(p): return None
    c = json.load(open(p))["core"]
    if c.get("type") != "commit": return None
    cad = c.get("cadence") or {}; sw = cad.get("self_trigger") or {}; tr = (cad.get("trigger") or {}).get("statement") or {}; hw = tr.get("hw_event") or {}
    d = c.get("derived") or {}; rel = _i(d.get("target_release_unix_s")); lead = _i(d.get("lead_rounds"))
    t0 = _i(sw.get("scheduled_unix_s")) or _i(tr.get("scheduled_unix_s"))
    if t0 is None and rel is not None and lead is not None: t0 = rel - lead * PERIOD            # think era: instant = release - lead
    if t0 is None: return None
    T = t0 * 10**9
    def after(ns): v = _i(ns); return None if v is None else v - T
    st = c.get("statements") or {}
    def stmt(n):
        try: return after(st[n]["statement"]["issued_unix_ns"])
        except Exception: return None
    r = {"seq": seq, "instant_unix_s": t0, "instant_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t0)), "aggregator": c.get("aggregator_host"),
         "start_source": sw.get("start_source") or ("timer" if not cad else None), "lead_rounds": lead, "release_unix_s": rel,
         "p550_edge_after_instant_ns": _i(hw.get("edge_after_instant_ns")), "p550_woke_after_edge_ns": _i(hw.get("woke_after_edge_ns")),
         "p550_issued_after_instant_ns": after(tr.get("issued_unix_ns")) if tr else None,
         "datagram_kernel_rx_after_instant_ns": after(cad.get("datagram_kernel_rx_unix_ns") or sw.get("datagram_kernel_rx_unix_ns")),
         "datagram_user_rx_after_instant_ns": after(cad.get("received_unix_ns") or sw.get("datagram_rx_unix_ns")),
         "k3_wake_after_instant_ns": _i((sw.get("wake") or {}).get("late_ns")), "main_thread_at_gate_after_instant_ns": after(sw.get("main_thread_at_gate_unix_ns")),
         "pulse_py_start_after_instant_ns": after(cad.get("aggregator_start_unix_ns")),
         "stmt_entropy_after_instant_ns": stmt("entropy"), "stmt_gnss_after_instant_ns": stmt("gnss"), "stmt_time_after_instant_ns": stmt("time"), "stmt_witness_after_instant_ns": stmt("witness"),
         "trigger_rejected": (cad.get("trigger_rejected") or None), "cadence_source": cad.get("source"), "chain_head_commit": None,
         "logged_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}
    # resolving pulse
    q = os.path.join(CHAIN, f"pulse-{seq + 1:04d}.json")
    if os.path.exists(q):
        rc = json.load(open(q))["core"]
        if rc.get("type") in ("reveal", "failure") and _i((rc.get("derived") or {}).get("commit_seq") or seq) == seq or rc.get("type") in ("reveal", "failure"):
            r["resolving_seq"] = seq + 1; r["resolving_type"] = rc.get("type")
            s_ = (rc.get("cadence") or {}).get("started_after_release_s")
            if s_ is not None:
                try: r["reveal_started_after_release_ms"] = int(round(float(s_) * 1000))
                except Exception: pass
    # anchor record written at mint
    a = os.path.join(TRIG, f"anchor-{seq:04d}.json")
    if os.path.exists(a):
        try:
            aj = json.load(open(a)); it = _i((aj.get("rekor") or {}).get("integratedTime"))
            if it is not None: r["rekor_integrated_after_instant_s"] = it - t0
            up = aj.get("upload_s") or aj.get("upload_seconds")
            if up is not None: r["rekor_upload_ms"] = int(round(float(up) * 1000))
        except Exception: pass
    # cycle.log lines for this commit / reveal
    for ln in lines:
        if f"committed seq {seq} " in ln:
            m = re.search(r"release in (\d+)s", ln)
        elif "commit pushed" in ln and _near(ln, t0, 0, 120):
            m = re.search(r"pushed ([\d.]+)s before release", ln)
            if m and rel is not None: r["commit_pushed_after_instant_ms"] = int(round((rel - t0 - float(m.group(1))) * 1000))
        elif "anchored in Rekor at mint" in ln and _near(ln, t0, 0, 120):
            m = re.search(r"integratedTime (\d+)", ln); u = re.search(r"upload ([\d.]+) s", ln)
            if m: r["rekor_integrated_after_instant_s"] = int(m.group(1)) - t0
            if u: r["rekor_upload_ms"] = int(round(float(u.group(1)) * 1000))
        elif "first served by" in ln and rel is not None and _near(ln, rel, 0, 30):
            m = re.search(r"([\d.]+) s after release", ln)
            if m: r["relay_first_served_after_release_ms"] = int(round(float(m.group(1)) * 1000))
        elif f"revealed seq {seq + 1} " in ln:
            m = re.search(r"pushed ([\d.]+)s after release", ln)
            if m: r["reveal_pushed_after_release_ms"] = int(round(float(m.group(1)) * 1000))
    if r.get("reveal_pushed_after_release_ms") is not None and rel is not None:
        r["usable_after_instant_ms"] = (rel - t0) * 1000 + r["reveal_pushed_after_release_ms"]
    return r

def _near(line, t, lo, hi):
    """log line timestamp within [t+lo, t+hi] seconds"""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z", line)
    if not m: return False
    import calendar
    ts = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    return t + lo <= ts <= t + hi

def db_connect():
    import pymysql
    env = dict(l.strip().split("=", 1) for l in open(DB_ENV) if "=" in l and not l.startswith("#"))
    return pymysql.connect(host=env["TIMEHAT_DB_HOST"], port=int(env["TIMEHAT_DB_PORT"]), user=env["TIMEHAT_DB_USER"], password=env.get("TIMEHAT_DB_PASS") or env.get("TIMEHAT_DB_PASSWORD"),
                           database=env.get("TIMEHAT_DB_NAME", "timehat"), connect_timeout=5, read_timeout=10, write_timeout=10, autocommit=True)

def upsert(conn, rows):
    cols = list(rows[0].keys())
    sql = f"INSERT INTO {TABLE} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) ON DUPLICATE KEY UPDATE " + ", ".join(f"{c}=VALUES({c})" for c in cols if c != "seq")
    with conn.cursor() as cur:
        cur.execute(DDL)
        for r in rows: cur.execute(sql, [r.get(c) for c in cols])

def main():
    a = sys.argv[1:]; dry = "--dry-run" in a; lines = log_lines(); rows = []
    if "--backfill" in a:
        lo = int(a[a.index("--from") + 1]) if "--from" in a else 12
        seqs = sorted(int(os.path.basename(p)[6:10]) for p in glob.glob(os.path.join(CHAIN, "pulse-????.json")))
        for s in seqs:
            if s < lo: continue
            r = row_for(s, lines)
            if r: rows.append(r)
    else:
        s = int(a[a.index("--seq") + 1]); r = row_for(s, lines)
        if r: rows.append(r)
    keys = ["seq", "instant_utc", "start_source", "p550_edge_after_instant_ns", "datagram_kernel_rx_after_instant_ns", "k3_wake_after_instant_ns", "stmt_time_after_instant_ns",
            "commit_pushed_after_instant_ms", "rekor_integrated_after_instant_s", "relay_first_served_after_release_ms", "reveal_pushed_after_release_ms", "usable_after_instant_ms"]
    # every row carries the same columns so one INSERT statement fits all
    allcols = []
    for r in rows:
        for k in r:
            if k not in allcols: allcols.append(k)
    rows = [{k: r.get(k) for k in allcols} for r in rows]
    if dry or not rows:
        for r in rows: print(json.dumps({k: r.get(k) for k in keys}))
        print(f"{len(rows)} row(s){' (dry run, nothing written)' if dry else ''}"); return
    try:
        conn = db_connect(); upsert(conn, rows); conn.close(); print(f"{TABLE}: {len(rows)} row(s) upserted")
    except Exception as e:
        print(f"{TABLE}: not written ({type(e).__name__}: {str(e)[:120]})"); sys.exit(0)          # never a failure for the cycle

if __name__ == "__main__": main()
