#!/usr/bin/env python3
"""
beacon-cycle.py — one full commit -> publish -> wait -> reveal -> publish cycle. Run hourly by systemd.

Contract (CADENCE.md):
  * commit is TSA-stamped at mint and PUSHED at least PUBLISH_MARGIN_S before its target round
  * reveal is minted and PUSHED within REVEAL_DEADLINE_S after the round releases
  * any breach writes a pulse-NNNN.FAILED.json into the chain and pushes it. Failures are public.
Everything fails closed; nothing is retried silently.
Cadence (2026-09-13): `beacon-cycle.py --at next` is started by a timer ~40 s before the hour; it pulls, recovers, warms
the SSH connections, listens for the time host's signed UDP trigger, sleeps to :00:00.000 on the aggregator's
PHC-disciplined clock and mints at once (core.cadence.self_trigger; the time host's trigger, when it arrives, is
core.cadence.trigger). A plain `beacon-cycle.py` (the :02 fallback timer) runs the old path and says so in the pulse
(core.cadence.source = "<host>-timer"). One cycle per hour either way (.cycle-hour), one process at a time (.cycle.lock).
"""
import subprocess, json, sys, os, time, glob, urllib.request
REPO = os.path.dirname(os.path.abspath(__file__))
LEAD, PUBLISH_MARGIN_S, REVEAL_DEADLINE_S = 100, 120, 600
LOG = os.path.join(REPO, "cycle.log")
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

def log(msg):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime(time.time())) + msg
    print(line, flush=True); open(LOG, "a").write(line + "\n")

def run(*a, check=True, timeout=600):
    r = subprocess.run(a, cwd=REPO, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(a[:3])} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()

def drand_latest_round():
    with urllib.request.urlopen(f"https://api.drand.sh/{CHAIN_HASH}/public/latest", timeout=15) as r:
        return json.load(r)["round"]

def checkpoint():
    """TLOG.md: sign the new tree head so the pulse and the checkpoint covering it travel in ONE commit. Never blocks
    publication: a signing failure is logged and CI reports the stale checkpoint (keys/CHECKPOINT.json must be enabled)."""
    try:
        out = run("python3", "tlog.py", "publish-checkpoint"); log("checkpoint: " + out.strip()[:120])
    except Exception as e:
        if "not enabled" in str(e): return
        log(f"checkpoint NOT written: {str(e)[:200]}")

def push_with_rebase(attempts=3):
    """Someone else (docs, the site) may push to main while a cycle runs. Our commits touch only chain/ and the
    checkpoint files, so rebasing onto the new head is conflict-free; a rejected push is retried after a rebase
    instead of costing a reveal (ERR-010, 2026-09-12 16:00Z cycle)."""
    for i in range(attempts):
        r = subprocess.run(["git", "push", "-q", "origin", "main"], cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if r.returncode == 0: return
        msg = (r.stderr or r.stdout).strip().splitlines(); log(f"push rejected ({msg[-1][:80] if msg else '?'}); rebasing onto origin/main and retrying ({i+1}/{attempts})")
        rb = subprocess.run(["git", "pull", "-q", "--rebase", "origin", "main"], cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if rb.returncode != 0:
            subprocess.run(["git", "rebase", "--abort"], cwd=REPO, capture_output=True); raise RuntimeError("rebase onto origin/main failed: " + (rb.stderr or rb.stdout).strip()[:200])
    raise RuntimeError(f"git push rejected {attempts} times")

def publish(msg):
    run("git", "add", "-A", "chain")
    if run("git", "status", "--porcelain", "chain", check=False):
        checkpoint(); run("git", "add", "-A", "chain", "checkpoint", "checkpoints", check=False)
        run("git", "commit", "-q", "-m", msg)
        push_with_rebase()
    return time.time()

def fail(seq, reason, extra=None):
    """v0.5: a failure is a SIGNED CHAIN EVENT. The entropy host abandons E and signs that; the aggregator
    mints a failure pulse chained after the commit. Nothing is hidden and nothing is unsigned."""
    log(f"FAILED seq {seq}: {reason} {extra or ''}")
    try:
        out = run("python3", "pulse.py", "fail", f"{reason} {json.dumps(extra) if extra else ''}".strip())
        log("failure pulse minted: " + out.strip().replace("\n", " ")[:160])
    except Exception as e:
        log(f"could not mint failure pulse: {e}")
    try:
        publish(f"FAILURE pulse for commit {seq}: {reason}")
        log("finalize: " + run("python3", "pulse.py", "finalize", check=False).strip()[:120])
    except Exception as e: log(f"could not publish failure pulse: {e}")
    sys.exit(1)

def skip(reason):
    """v0.5.1: a refused commit is a public, signed, timestamped chain event (skip pulse), not a silent gap."""
    try:
        out = run("python3", "pulse.py", "skip", reason[:400])
        log("skip pulse minted: " + out.strip().replace("\n", " ")[:160])
        publish(f"SKIP pulse: {json.loads(out).get('refused_by', '?')} refused the commit")
    except Exception as e:
        log(f"could not mint/publish skip pulse: {e}")

STAMP = os.path.join(REPO, ".cycle-hour"); LOCK = os.path.join(REPO, ".cycle.lock")
UDP_PORT = int(os.environ.get("CADENCE_UDP_PORT", "5510")); PHC_DEV = os.environ.get("BEACON_PHC_DEV", "/dev/ptp1")
HOST = os.environ.get("BEACON_AGGREGATOR_HOST") or os.uname().nodename.split(".")[0]
def hour_of(t): return time.strftime("%Y-%m-%dT%H", time.gmtime(t))
def utc(t): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

def claim_hour(hour):
    """One cycle per hour. The tick-started cycle (--at) claims the hour at the instant; the :02 fallback timer must not start
    a second attempt (a second skip pulse, or a commit racing a live cycle)."""
    prev = open(STAMP).read().strip() if os.path.exists(STAMP) else ""
    if prev == hour: return False
    open(STAMP, "w").write(hour); return True

def take_lock():
    """Exactly one cycle process at a time (the fallback timer can fire while a tick-started cycle is still running)."""
    import fcntl
    fh = open(LOCK, "w")
    try: fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError: return None
    return fh

# ---- absolute-time wake and the aggregator's own wake record (k3: CLOCK_REALTIME is chrony-disciplined from the PTP PHC)
import ctypes, ctypes.util
class _TS(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.clock_nanosleep.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_TS), ctypes.POINTER(_TS)]
def sleep_until(t_ns, spin_ns=1_500_000):
    """Absolute sleep on CLOCK_REALTIME to t_ns - spin_ns, then spin on the clock for the last stretch: 90-100 us of
    scheduler lateness becomes 1-5 us (X3, k3, 2026-09-13). A chrony slew or step moves the wake with the clock."""
    while True:
        ts = _TS((t_ns - spin_ns) // 10**9, (t_ns - spin_ns) % 10**9); r = _libc.clock_nanosleep(0, 1, ctypes.byref(ts), None)   # CLOCK_REALTIME, TIMER_ABSTIME
        if r == 0: break
        if r != 4: raise OSError(r, os.strerror(r))
    while time.clock_gettime_ns(time.CLOCK_REALTIME) < t_ns: pass

def self_trigger(t0):
    """Sleep to the instant on CLOCK_REALTIME, then record wake time and a PHC reading. Written to trigger/self.json."""
    fd = None
    try: fd = os.open(PHC_DEV, os.O_RDONLY)
    except OSError: pass
    sleep_until(t0 * 10**9)
    wake = time.clock_gettime_ns(time.CLOCK_REALTIME); rec = {"host": HOST, "scheduled_unix_s": t0,
           "wake": {"clock": "CLOCK_REALTIME", "unix_ns": str(wake), "late_ns": wake - t0 * 10**9, "how": "clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME) to T-1.5 ms, then a spin on the clock, in the aggregator process"}}
    if fd is not None:
        clk = ((~fd) << 3) | 3; best = None
        for _ in range(5):
            a = time.clock_gettime_ns(time.CLOCK_REALTIME); p = time.clock_gettime_ns(clk); b = time.clock_gettime_ns(time.CLOCK_REALTIME)
            if best is None or b - a < best[2] - best[0]: best = (a, p, b)
        a, p, b = best; os.close(fd)
        rec["phc"] = {"device": PHC_DEV, "unix_ns": str(p), "realtime_mid_unix_ns": str((a + b) // 2), "phc_minus_realtime_ns": p - (a + b) // 2, "bracket_ns": b - a,
                      "meaning": "the aggregator's PTP PHC (TAI) read at wake; not a host-signed statement - covered by the aggregator signature only"}
    d = os.path.join(REPO, "trigger"); os.makedirs(d, mode=0o700, exist_ok=True); path = os.path.join(d, "self.json")
    json.dump(rec, open(path, "w")); return path, rec

def udp_listener(t0, until):
    """Accept the time host's signed cadence trigger for t0 as a UDP datagram (no session, no handshake: the signature is the
    authentication). Verified here against keys/KEYS.json (p550's active time_attester key), then written to
    trigger/pending.json for pulse.py, which verifies it again with the seq in hand."""
    import socket, threading, base64, hashlib
    sys.path.insert(0, os.path.join(REPO, "hosts")); import attest_lib as A
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    keys = [k for k in json.load(open(os.path.join(REPO, "keys", "KEYS.json")))["keys"] if k["role"] == "time_attester" and k["host"] == "p550" and k.get("valid_to_seq") is None]
    def ok(signed):
        st, sig = signed["statement"], signed["signature"]
        if st.get("kind") != "cadence-trigger" or st.get("host") != "p550" or st.get("role") != "time_attester" or st.get("scheduled_unix_s") != t0: return False, "wrong kind/host/instant"
        if not any(k["public_key_b64"] == sig.get("public_key_b64") for k in keys): return False, "not p550's active time_attester key"
        Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key_b64"])).verify(base64.b64decode(sig["sig_b64"]), A.canon(st)); return True, "ok"
    def run_():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", UDP_PORT)); s.settimeout(1.0)
        while time.time() < until:
            try: data, addr = s.recvfrom(65535)
            except socket.timeout: continue
            rx = time.time_ns()
            if len(data) < 200: continue                                              # ARP warm-up datagram or noise
            try: signed = json.loads(data); good, why = ok(signed)
            except Exception as e: good, why = False, f"{type(e).__name__}"
            if not good: log(f"udp trigger from {addr[0]} rejected: {why}"); continue
            d = os.path.join(REPO, "trigger"); os.makedirs(d, mode=0o700, exist_ok=True); tmp = os.path.join(d, ".pending.tmp")
            json.dump({"received_unix_ns": str(rx), "from": addr[0], "delivery": "udp", "trigger": signed}, open(tmp, "w")); os.replace(tmp, os.path.join(d, "pending.json"))
            st = signed["statement"]; log(f"udp trigger from {addr[0]} for {t0}: p550 woke {st['wake']['late_ns'] / 1000:.1f} us after the instant, received {(rx - t0 * 10**9) / 1e6:.1f} ms after"); return
        log("no udp trigger arrived from the time host (the pulse will carry the aggregator's own wake record only)")
    threading.Thread(target=run_, daemon=True).start()

def catch_up():
    """Anything minted but not pushed (a previous cycle lost connectivity after sealing) is published before we
    reason about the head; otherwise require_synced refuses forever and the beacon stalls on its own unpushed file."""
    if run("git", "status", "--porcelain", "chain", check=False):
        try: publish("catch-up: chain files minted by an earlier cycle but not pushed"); log("catch-up: pushed unpublished chain files")
        except Exception as e: log(f"catch-up push failed: {e}")

def prepare():
    """pull, catch up, recover. Returns None (ready to commit) or (seq, target, release) of an unresolved commit to resume."""
    run("git", "pull", "-q", "--ff-only", "origin", "main")
    catch_up()
    r = subprocess.run(["python3", "pulse.py", "recover"], cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    log("recover: " + (r.stdout.strip() or r.stderr.strip())[:200])
    if r.returncode == 3:
        hp = json.load(open(sorted(glob.glob(os.path.join(REPO, "chain", "pulse-????.json")))[-1]))
        seq, target = hp["core"]["seq"], hp["core"]["derived"]["target_round"]; release = hp["core"]["derived"]["target_release_unix_s"]
        log(f"resuming unresolved commit seq {seq} (round {target}, release {release})"); return seq, target, release
    if r.returncode != 0:
        log("recover failed; not minting"); skip("recover failed: " + (r.stderr.strip() or r.stdout.strip())[-300:]); sys.exit(1)
    return None

def warm_connections():
    """Open the multiplexed SSH connections to the role hosts before the instant (ControlMaster in ~/.ssh/config), so the
    calls made after it cost ~0.1 s each instead of 0.5-2 s (E2, 2026-09-13). The attest hosts answer `noop` with a usage
    error; the entropy host answers `pending` - neither signs anything."""
    hosts = {"protectli": "pending", "p550": "noop", "k3": "noop", "f9t": "noop"}
    import pulse
    for n, op in hosts.items():
        try: subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", pulse.SSH[n], op], capture_output=True, timeout=20)
        except Exception as e: log(f"warm-up {n}: {e}")

def commit_phase(extra):
    try:
        out = json.loads(run("python3", "pulse.py", "commit", "--lead", str(LEAD), *extra))
    except Exception as e:
        log(f"commit refused: {e}"); skip(f"commit refused: {e}"); sys.exit(1)      # nothing committed; the refusal itself is published
    seq, target = out["seq"], out["target_round"]
    release = json.load(open(os.path.join(REPO, "chain", f"pulse-{seq:04d}.json")))["core"]["derived"]["target_release_unix_s"]
    log(f"committed seq {seq} -> round {target}, release in {release-time.time():.0f}s, tsa={out.get('tsa_tokens')}")
    pushed = publish(f"COMMIT pulse {seq} -> drand round {target}")
    margin = release - pushed
    log(f"commit pushed {margin:.1f}s before release")
    if margin < PUBLISH_MARGIN_S:
        fail(seq, "commit-published-late", {"margin_s": round(margin, 1), "required_s": PUBLISH_MARGIN_S})
    return seq, target, release

RELAYS = ["api.drand.sh", "api2.drand.sh", "api3.drand.sh", "drand.cloudflare.com"]
def await_round(target, release, seq):
    """The relays publish a round 1.13-1.38 s after its release, in a varying order (X1c, 2026-09-13). Open one TLS
    connection per relay before the instant, sleep to release+1.0 s, then poll all of them every 20 ms and take the
    first document with round >= target. Written to trigger/drand-<seq>.json for pulse.py, which BLS-verifies it."""
    import http.client, ssl, threading, json as _json
    ctx = ssl.create_default_context(); conns = {}
    for h in RELAYS:
        try: c = http.client.HTTPSConnection(h, timeout=5, context=ctx); c.connect(); conns[h] = c
        except Exception as e: log(f"relay {h}: connect failed ({type(e).__name__})")
    if release + 1.0 - time.time() > 0: sleep_until(int((release + 1.0) * 10**9))
    found = {}; stop = threading.Event()
    def poll(h, c):
        while not stop.is_set():
            try:
                c.request("GET", f"/{CHAIN_HASH}/public/latest", headers={"Connection": "keep-alive", "User-Agent": "qrng-beacon-log/beacon-cycle"})
                r = c.getresponse(); doc = _json.loads(r.read())
                if doc.get("round", 0) >= target:
                    found.setdefault("doc", (doc, h, time.time())); stop.set(); return
            except Exception:
                try: c.close(); c = http.client.HTTPSConnection(h, timeout=5, context=ctx); c.connect()
                except Exception: time.sleep(0.5)
            stop.wait(0.02)
    ts = [threading.Thread(target=poll, args=(h, c), daemon=True) for h, c in conns.items()]; [t.start() for t in ts]
    while not stop.is_set():
        if time.time() > release + REVEAL_DEADLINE_S - 60:
            stop.set(); fail(seq, "round-never-observed", {"last_check_utc": time.strftime("%H:%M:%SZ", time.gmtime(time.time()))})
        stop.wait(0.05)
    doc, h, at = found["doc"]; path = os.path.join(REPO, "trigger", f"drand-{seq:04d}.json"); os.makedirs(os.path.dirname(path), exist_ok=True)
    _json.dump({"doc": doc, "base": f"https://{h}", "fetched_unix_s": round(at, 3)}, open(path, "w"))
    log(f"round {doc['round']} first served by {h} {at - release:.3f} s after release")
    for c in conns.values():
        try: c.close()
        except Exception: pass
    return path

def reveal_phase(seq, target, release):
    # ---- WAIT for the round: pre-open connections, sleep to release+1.0 s, race the relays ----
    drand_file = await_round(target, release, seq)
    # ---- REVEAL (only if it can still be published inside the deadline; otherwise a signed failure) ----
    if time.time() > release + REVEAL_DEADLINE_S - 90:
        fail(seq, "reveal-window-missed", {"now_minus_release_s": round(time.time() - release, 1)})
    try:
        rout = json.loads(run("python3", "pulse.py", "reveal", "--drand", drand_file))
    except Exception as e:
        fail(seq, "reveal-refused", {"error": str(e)[:200]})
    pushed = publish(f"REVEAL pulse {rout['seq']} (commit {seq}, drand round {target})")
    late = pushed - release
    log(f"revealed seq {rout['seq']} value {rout['attested_value'][:16]}..., pushed {late:.1f}s after release")
    try: log("finalize: " + run("python3", "pulse.py", "finalize").strip()[:120])
    except Exception as e: log(f"finalize deferred (E stays recoverable on the entropy host): {e}")
    log("cycle complete")

def main():
    """Fallback / plain path (a timer started this process): claim the hour, prepare, then commit and reveal."""
    log("cycle start (timer)")
    if not claim_hour(hour_of(time.time())): log("a cycle already started in this hour; this run is the timer fallback and exits"); return
    log(f"no tick-started cycle ran this hour: {HOST}'s timer started this one (fallback); the pulse will say so")
    resume = prepare()
    if resume: reveal_phase(*resume); return
    reveal_phase(*commit_phase(["--trigger-dir", "trigger"]))

def precise_main(t0, commit_only=False):
    """Tick-started path (k3): prepare BEFORE the instant, wake ON it, mint at once. Started by a timer ~40 s early."""
    log(f"prepare for {utc(t0)}: pull, recover, warm connections, listen for the time host's trigger")
    resume = prepare()
    if resume:
        log("an unresolved commit is at the head; resuming it now instead of waiting for the instant")
        if claim_hour(hour_of(t0)): reveal_phase(*resume)
        return
    warm_connections(); udp_listener(t0, until=t0 + 240)
    if time.time() > t0: log(f"instant {utc(t0)} already passed during preparation ({time.time() - t0:.1f} s); minting now"); 
    path, rec = self_trigger(t0)
    log(f"instant {utc(t0)}: woke {rec['wake']['late_ns'] / 1000:.1f} us late" + (f"; PHC-REALTIME {rec['phc']['phc_minus_realtime_ns']} ns" if "phc" in rec else ""))
    if not claim_hour(hour_of(t0)): log("this hour was already claimed (a cycle is running); exiting"); return
    seq, target, release = commit_phase(["--self-trigger", path, "--trigger-dir", "trigger"])
    if commit_only: log("commit-only mode: stopping before the reveal (staging)"); return
    reveal_phase(seq, target, release)

if __name__ == "__main__":
    a = sys.argv[1:]
    lock = take_lock()
    if lock is None: log("another cycle process holds the lock; exiting"); sys.exit(0)
    try:
        if "--at" in a:
            v = a[a.index("--at") + 1]; t0 = int(v) if v != "next" else (int(time.time()) // 3600 + 1) * 3600
            precise_main(t0, commit_only="--commit-only" in a)
        else: main()
    except SystemExit: raise
    except Exception as e:
        log(f"UNHANDLED: {type(e).__name__}: {e}")
        # if a commit exists without a reveal, mark it (the pending commit is whatever the chain head is, if it is a commit)
        try:
            hp = json.load(open(sorted(glob.glob(os.path.join(REPO, "chain", "pulse-????.json")))[-1]))
            if hp["core"].get("type") == "commit": fail(hp["core"]["seq"], "cycle-crashed", {"error": str(e)[:200]})
        except Exception: pass
        sys.exit(1)
