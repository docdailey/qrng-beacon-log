#!/usr/bin/env python3
"""gnss_probe.py — return a HARDWARE-ANCHORED time reference for one pulse.

The anchor is a GNSS epoch (week + tow) whose TP1 edge was latched in i210 SILICON by
ts2phc on SDP0. Its uncertainty is set by the receiver sawtooth and the servo residual,
NOT by what it costs software to read a clock afterwards.
"""
import sys, struct, json, os, glob
# runs as whichever OS user owns the role (the confined `beacon` user under hosts/ISOLATION.md): look in THAT user's home
for _sp in glob.glob(os.path.expanduser("~/.local/lib/python3*/site-packages")): sys.path.insert(0, _sp)
import pymysql

GPS_EPOCH_UNIX = 315964800          # 1980-01-06T00:00:00Z
TAI_MINUS_GPS  = 19                 # fixed by definition

d = {}
for l in open(os.path.expanduser("~/timehat-db.env")):
    if "=" in l:
        k, v = l.strip().split("=", 1); d[k] = v
c = pymysql.connect(host=d["TIMEHAT_DB_HOST"], port=int(d["TIMEHAT_DB_PORT"]),
                    user=d["TIMEHAT_DB_USER"], password=d["TIMEHAT_DB_PASS"],
                    database=d["TIMEHAT_DB_NAME"])
cur = c.cursor()

out = {"database": {"host": d["TIMEHAT_DB_HOST"], "port": int(d["TIMEHAT_DB_PORT"]),
                    "schema": d["TIMEHAT_DB_NAME"], "receiver_src": "f9t",
                    "tables": ["qerr_stream", "rawx_stream"]}}

# ---- the anchoring epoch: the most recent TP1 pulse the receiver reported on ----
cur.execute("""SELECT ts, week, tow_ms, qerr_ps, flags FROM qerr_stream
               WHERE src='f9t' ORDER BY id DESC LIMIT 1""")
ts, week, tow_ms, qerr_ps, flags = cur.fetchone()

# leapS as broadcast by the satellites (GPS-UTC), from the nearest RAWX epoch
cur.execute("""SELECT frame, tow_ms, ts FROM rawx_stream
               WHERE src='f9t' AND kind='rawx' ORDER BY id DESC LIMIT 1""")
fr, rtow, rts = cur.fetchone()
b = bytes(fr); off = 6 if b[:2] == b"\xb5\x62" else 0
rcvTow, rweek, leapS, numMeas, recStat, ver = struct.unpack_from("<dHbBBB", b, off)
names = {0: "GPS", 1: "SBAS", 2: "Galileo", 3: "BeiDou", 5: "QZSS", 6: "GLONASS"}
con = {}
for i in range(numMeas):
    m = off + 16 + 32 * i
    if m + 32 > len(b): break
    nm = names.get(b[m + 20], "id%d" % b[m + 20]); con[nm] = con.get(nm, 0) + 1

# UBX-TIM-TP flags bit0 = timeBase: 0 => tow is GPS time, 1 => tow is ALREADY UTC.
# Getting this wrong costs exactly one leap-second offset (18 s today).
time_base_utc = bool(flags & 0x01)
utc_avail     = bool(flags & 0x02)
wk_s = week * 604800 + tow_ms / 1000.0
if time_base_utc:
    unix_utc = GPS_EPOCH_UNIX + wk_s
    unix_tai = unix_utc + leapS + TAI_MINUS_GPS
else:
    unix_utc = GPS_EPOCH_UNIX + wk_s - leapS
    unix_tai = GPS_EPOCH_UNIX + wk_s + TAI_MINUS_GPS
gps_s = wk_s

out["anchor"] = {
    "what": "A GNSS second whose TP1 on-time edge - the FALLING edge, per the F9T's TP-POL_TP1=0 and "
            "the i210/igb latching only falling edges - was captured by the i210 timestamping unit on "
            "SDP0 (ts2phc EXTTS). The capture timestamp is taken in hardware at the instant of the edge.",
    "gps_week": week, "gps_tow_ms": tow_ms,
    "tow_time_base": "UTC" if time_base_utc else "GPS",
    "tow_time_base_flag_note": "UBX-TIM-TP flags bit0. When set, towMS is already UTC and no leap "
                               "subtraction applies; subtracting one anyway is an 18 s error.",
    "utc_available_flag": utc_avail,
    "week_tow_seconds": round(gps_s, 3),
    "utc_unix_s": round(unix_utc, 3),
    "tai_unix_s": round(unix_tai, 3),
    "leap_seconds_gps_minus_utc": leapS,
    "tai_minus_utc_s": leapS + TAI_MINUS_GPS,
    "leap_note": "leapS is GPS-UTC as broadcast by the satellites; TAI-GPS is a fixed 19 s, "
                 "so TAI-UTC = leapS + 19. Derived from the constellation, not from the host OS.",
    "sawtooth_qerr_ns_this_epoch": round(qerr_ps / 1000.0, 3),
    "sawtooth_flags": flags,
    "sawtooth_meaning": "Deviation of THIS epoch's TP1 edge from its ideal instant, as reported "
                        "by the receiver for this exact week/tow. Logged, NOT applied to the servo.",
    "db_row_ts": str(ts),
    "db_row_minus_anchor_s": None,
    "anchor_is_independent_of_software_read": True,
}

# ---- window statistics that qualify the anchor ----
cur.execute("""SELECT COUNT(*), ROUND(AVG(qerr_ps)/1000.0,3), ROUND(STDDEV(qerr_ps)/1000.0,3),
               ROUND(MIN(qerr_ps)/1000.0,2), ROUND(MAX(qerr_ps)/1000.0,2)
               FROM qerr_stream WHERE src='f9t' AND ts > NOW() - INTERVAL 15 MINUTE""")
n, mean, sd, mn, mx = cur.fetchone()
out["anchor_quality"] = {
    "sawtooth_window": "15 min", "samples": int(n), "expected_at_1Hz": 900,
    "coverage_pct": round(100.0 * int(n) / 900.0, 1),
    "sawtooth_mean_ns": float(mean), "sawtooth_sd_ns": float(sd),
    "sawtooth_min_ns": float(mn), "sawtooth_max_ns": float(mx),
    "gnss_fix": {"num_measurements": numMeas, "constellations": con,
                 "rec_stat": "0x%02x" % recStat, "rawx_tow_ms": rtow, "rawx_week": rweek},
}
import datetime
out["anchor"]["db_row_minus_anchor_s"] = round(
    ts.replace(tzinfo=datetime.timezone.utc).timestamp() - unix_utc, 3)
out["anchor"]["sanity_check"] = (
    "db_row_minus_anchor_s is the lag between the anchoring epoch and the moment the logger "
    "wrote the row. UBX-TIM-TP describes the NEXT pulse, so a value within about +/-2 s is "
    "expected. A value near 18 s would mean the leap handling is wrong.")
print(json.dumps(out))
