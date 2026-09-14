#!/usr/bin/env python3
"""netprobe.py - the probe that finds ERR-020 (2026-09-14): sticky per-flow loss that ping, PTP, chrony and every kept
socket cannot see. Every run opens N fresh sockets toward the router and the internet and counts the ones that never
answer; a row goes to timehat.netprobe_stream (if TIMEHAT_DB_ENV is readable) and one line to stdout/journald.
Zero lost is normal. A nonzero count on a healthy WAN means a device on the path is dropping new flows.

    netprobe.py                 one run (30 fresh UDP DNS to the gateway, 15 fresh TCP connects to 1.1.1.1:443, 5 pings)
    netprobe.py --gw 192.168.68.1 --dns-n 30 --tcp-n 15"""
import socket, struct, random, time, subprocess, re, os, sys, argparse, platform
ap = argparse.ArgumentParser(); ap.add_argument("--gw", default="192.168.68.1"); ap.add_argument("--dns-n", type=int, default=30); ap.add_argument("--tcp-n", type=int, default=15)
ap.add_argument("--tcp-target", default="1.1.1.1:443"); a = ap.parse_args()
def q(name):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", random.randrange(65535), 0x0100, 1, 0, 0, 0) + qn + struct.pack(">HH", 1, 1)
dns_lost = 0
for i in range(a.dns_n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0)
    try: s.sendto(q("r%d.example.com" % random.randrange(10**6)), (a.gw, 53)); s.recv(1500)
    except Exception: dns_lost += 1
    s.close()
th, tp = a.tcp_target.rsplit(":", 1); tcp_fail = 0
for i in range(a.tcp_n):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3.0)
    try: s.connect((th, int(tp)))
    except Exception: tcp_fail += 1
    s.close()
rtt = None
try:
    out = subprocess.run(["ping", "-q", "-c", "5", "-i", "0.2", "-W", "1", a.gw], capture_output=True, text=True, timeout=10).stdout
    m = re.search(r"= [\d.]+/([\d.]+)/", out); rtt = float(m.group(1)) if m else None
except Exception: pass
host = platform.node().split(".")[0]; ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
status = "ok" if dns_lost == 0 and tcp_fail == 0 else "LOSS"
print("netprobe %s %s: fresh DNS flows lost %d/%d, fresh TCP connects failed %d/%d, gw rtt %s ms -> %s" % (host, ts, dns_lost, a.dns_n, tcp_fail, a.tcp_n, "%.2f" % rtt if rtt is not None else "n/a", status), flush=True)
env_path = os.environ.get("TIMEHAT_DB_ENV", os.path.expanduser("~/beacon/timehat-db.env"))
if os.path.exists(env_path):
    try:
        import pymysql
        env = dict(l.strip().split("=", 1) for l in open(env_path) if "=" in l and not l.startswith("#"))
        c = pymysql.connect(host=env["TIMEHAT_DB_HOST"], port=int(env["TIMEHAT_DB_PORT"]), user=env["TIMEHAT_DB_USER"], password=env.get("TIMEHAT_DB_PASS") or env.get("TIMEHAT_DB_PASSWORD"),
                            database=env.get("TIMEHAT_DB_NAME", "timehat"), connect_timeout=5, read_timeout=10, write_timeout=10, autocommit=True)
        with c.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS netprobe_stream (id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME NOT NULL, host VARCHAR(32) NOT NULL,
                           gw VARCHAR(45), dns_lost INT, dns_n INT, tcp_fail INT, tcp_n INT, tcp_target VARCHAR(64), gw_rtt_ms FLOAT NULL, status VARCHAR(8), INDEX (ts), INDEX (host, ts)) ENGINE=InnoDB""")
            cur.execute("INSERT INTO netprobe_stream (ts, host, gw, dns_lost, dns_n, tcp_fail, tcp_n, tcp_target, gw_rtt_ms, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (ts, host, a.gw, dns_lost, a.dns_n, tcp_fail, a.tcp_n, a.tcp_target, rtt, status))
        c.close()
    except Exception as e: print("netprobe: db row not written (%s: %s)" % (type(e).__name__, str(e)[:80]), flush=True)
sys.exit(0)
