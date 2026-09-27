#!/usr/bin/env python3
"""gnss_probe.py — return a GNSS time reference (week + tow + sawtooth) for one pulse.

Since 2026-09-27 (ERR-022) the receiver is the LEA-M8T inside the GFS-8A GPSDO at timehat
(src='m8t'). Its epoch is the receiver's own time solution as logged to the timehat DB; it is
NOT captured in hardware on this host. The F9T/i210 hardware-captured anchor used through
pulse 0155 has been unavailable since 2026-09-14 (the F9T's serial link failed).
The probe REFUSES (non-zero exit) rather than report a stale or implausible epoch.
"""
import sys, struct, json, os, glob, datetime
# runs as whichever OS user owns the role (the confined `beacon` user under hosts/ISOLATION.md): look in THAT user's home
for _sp in glob.glob(os.path.expanduser("~/.local/lib/python3*/site-packages")): sys.path.insert(0, _sp)
import pymysql

GPS_EPOCH_UNIX = 315964800          # 1980-01-06T00:00:00Z
TAI_MINUS_GPS  = 19                 # fixed by definition
RECEIVER       = "m8t"              # timehat.qerr_stream / rawx_stream src
MAX_ROW_AGE_S  = 10                 # the newest qErr row must be this fresh
MAX_QERR_PS    = 50000              # |qErr| beyond 50 ns is not a sawtooth value (see ERR-022: no UBX checksum in this logger)
MAX_LAG_S      = 2.0                # TIM-TP describes the NEXT pulse: row-vs-epoch lag must be within +/-2 s

def refuse(why):
    raise RuntimeError("gnss_probe refuses: " + why)

d = {}
for l in open(os.path.expanduser("~/timehat-db.env")):
    if "=" in l:
        k, v = l.strip().split("=", 1); d[k] = v
c = pymysql.connect(host=d["TIMEHAT_DB_HOST"], port=int(d["TIMEHAT_DB_PORT"]),
                    user=d["TIMEHAT_DB_USER"], password=d["TIMEHAT_DB_PASS"],
                    database=d["TIMEHAT_DB_NAME"])
cur = c.cursor()

out = {"database": {"host": d["TIMEHAT_DB_HOST"], "port": int(d["TIMEHAT_DB_PORT"]),
                    "schema": d["TIMEHAT_DB_NAME"], "receiver_src": RECEIVER,
                    "tables": ["qerr_stream", "rawx_stream"]}}

# ---- the anchoring epoch: the most recent TP1 pulse the receiver reported on ----
cur.execute("""SELECT ts, week, tow_ms, qerr_ps, flags,
                      TIMESTAMPDIFF(MICROSECOND, ts, UTC_TIMESTAMP(3)) / 1e6
               FROM qerr_stream WHERE src=%s ORDER BY id DESC LIMIT 1""", (RECEIVER,))
row = cur.fetchone()
if row is None: refuse("no qerr_stream rows for src=%s" % RECEIVER)
ts, week, tow_ms, qerr_ps, flags, age_s = row
if age_s is None or float(age_s) > MAX_ROW_AGE_S: refuse("newest %s qErr row is %s s old (> %d s)" % (RECEIVER, age_s, MAX_ROW_AGE_S))
if abs(qerr_ps) > MAX_QERR_PS: refuse("newest %s qErr %.3f ns is implausible (> %d ns)" % (RECEIVER, qerr_ps / 1000.0, MAX_QERR_PS // 1000))

# leapS as broadcast by the satellites (GPS-UTC), from the nearest RAWX epoch
cur.execute("""SELECT frame, tow_ms, ts FROM rawx_stream
               WHERE src=%s AND kind='rawx' ORDER BY id DESC LIMIT 1""", (RECEIVER,))
rr = cur.fetchone()
if rr is None: refuse("no rawx_stream rows for src=%s" % RECEIVER)
fr, rtow, rts = rr
b = bytes(fr); off = 6 if b[:2] == b"\xb5\x62" else 0
rcvTow, rweek, leapS, numMeas, recStat, ver = struct.unpack_from("<dHbBBB", b, off)
if not (recStat & 0x01): refuse("RAWX recStat 0x%02x: leapS not determined" % recStat)
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
    "what": "A GNSS second as reported by the u-blox LEA-M8T timing receiver inside the GFS-8A GPSDO at "
            "timehat: UBX-TIM-TP week/tow and quantization error (qErr) for the next time pulse, logged to "
            "timehat.qerr_stream (src='m8t'). This epoch is the receiver's own time solution; it is NOT "
            "captured in hardware on the aggregator's clock path. (Through pulse 0155 the anchor was the "
            "ZED-F9T's TP1 edge captured by the p550 i210 via ts2phc; that path has been unavailable since "
            "2026-09-14 - see ERR-022.)",
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
    "sawtooth_meaning": "Deviation of THIS epoch's time-pulse edge from its ideal instant, as reported "
                        "by the receiver for this exact week/tow. Logged, NOT applied to any servo.",
    "db_row_ts": str(ts),
    "db_row_age_s": round(float(age_s), 3),
    "db_row_minus_anchor_s": None,
    "anchor_is_independent_of_software_read": True,
    "hardware_captured_on_aggregator_path": False,
}

# ---- window statistics that qualify the anchor ----
cur.execute("""SELECT COUNT(*), ROUND(AVG(qerr_ps)/1000.0,3), ROUND(STDDEV(qerr_ps)/1000.0,3),
               ROUND(MIN(qerr_ps)/1000.0,2), ROUND(MAX(qerr_ps)/1000.0,2)
               FROM qerr_stream WHERE src=%s AND ts > UTC_TIMESTAMP() - INTERVAL 15 MINUTE""", (RECEIVER,))
n, mean, sd, mn, mx = cur.fetchone()
if not n or mean is None: refuse("no %s qErr rows in the last 15 min" % RECEIVER)
out["anchor_quality"] = {
    "sawtooth_window": "15 min", "samples": int(n), "expected_at_1Hz": 900,
    "coverage_pct": round(100.0 * int(n) / 900.0, 1),
    "sawtooth_mean_ns": float(mean), "sawtooth_sd_ns": float(sd or 0),
    "sawtooth_min_ns": float(mn), "sawtooth_max_ns": float(mx),
    "gnss_fix": {"num_measurements": numMeas, "constellations": con,
                 "rec_stat": "0x%02x" % recStat, "rawx_tow_ms": rtow, "rawx_week": rweek},
}
lag = ts.replace(tzinfo=datetime.timezone.utc).timestamp() - unix_utc
if abs(lag) > MAX_LAG_S: refuse("db row is %.3f s from its epoch (> +/-%.0f s): leap or logger fault" % (lag, MAX_LAG_S))
out["anchor"]["db_row_minus_anchor_s"] = round(lag, 3)
out["anchor"]["sanity_check"] = (
    "db_row_minus_anchor_s is the lag between the anchoring epoch and the moment the logger "
    "wrote the row. UBX-TIM-TP describes the NEXT pulse, so a value within about +/-2 s is "
    "expected (the probe refuses outside it). A value near 18 s would mean the leap handling is wrong.")
print(json.dumps(out))
