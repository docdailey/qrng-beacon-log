#!/usr/bin/env python3
"""
beacon-cycle.py — one full commit -> publish -> wait -> reveal -> publish cycle. Run hourly by systemd.

Contract (CADENCE.md):
  * commit is TSA-stamped at mint and PUSHED at least PUBLISH_MARGIN_S before its target round
  * reveal is minted and PUSHED within REVEAL_DEADLINE_S after the round releases
  * any breach writes a pulse-NNNN.FAILED.json into the chain and pushes it. Failures are public.
Everything fails closed; nothing is retried silently.
Cadence (2026-09-13): the time host's clock starts the cycle (beacon-cadence.py on p550 -> beacon-trigger.py here ->
`systemctl --user start qrng-beacon.service`); the systemd timer at :02 is the fallback and a fallback cycle says so in
the pulse (core.cadence.source = "think-timer"). One cycle per hour either way (.cycle-hour).
"""
import subprocess, json, sys, os, time, glob, urllib.request
REPO = os.path.dirname(os.path.abspath(__file__))
LEAD, PUBLISH_MARGIN_S, REVEAL_DEADLINE_S = 100, 120, 600
LOG = os.path.join(REPO, "cycle.log")
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

def log(msg):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + msg
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

HOUR = time.strftime("%Y-%m-%dT%H", time.gmtime()); STAMP = os.path.join(REPO, ".cycle-hour")
def claim_hour():
    """One cycle per hour. Since 2026-09-13 the time host (p550) starts the cycle at :00:00 by its i210-disciplined clock
    (hosts/beacon-cadence.py -> beacon-trigger.py); the systemd timer at :02 is only a fallback and must not start a
    second attempt (a second skip pulse, or a commit racing a live cycle)."""
    prev = open(STAMP).read().strip() if os.path.exists(STAMP) else ""
    if prev == HOUR: return False
    open(STAMP, "w").write(HOUR); return True

def take_trigger():
    """The signed cadence trigger the time host delivered for THIS cycle (trigger/pending.json), if any. Consumed once."""
    p = os.path.join(REPO, "trigger", "pending.json")
    if not os.path.exists(p): return None
    last = os.path.join(REPO, "trigger", "last.json"); os.replace(p, last)
    try:
        j = json.load(open(last)); st = j["trigger"]["statement"]; t0 = st["scheduled_unix_s"]
        if time.time() - t0 > 300: log(f"trigger for {t0} is stale ({time.time() - t0:.0f} s old); ignoring it"); return None
        log(f"trigger from {st['host']} for {t0}: p550 woke {st['wake']['late_ns'] / 1000:.1f} us after the instant, think received it "
            f"{int(j['received_unix_ns']) / 1e9 - t0:.3f} s after, cycle start {time.time() - t0:.3f} s after")
        return last
    except Exception as e:
        log(f"unreadable trigger: {e}"); return None

def catch_up():
    """Anything minted but not pushed (a previous cycle lost connectivity after sealing) is published before we
    reason about the head; otherwise require_synced refuses forever and the beacon stalls on its own unpushed file."""
    if run("git", "status", "--porcelain", "chain", check=False):
        try: publish("catch-up: chain files minted by an earlier cycle but not pushed"); log("catch-up: pushed unpublished chain files")
        except Exception as e: log(f"catch-up push failed: {e}")

def main():
    log("cycle start")
    if not claim_hour():
        log(f"a cycle already started in hour {HOUR}Z (trigger path); this run is the timer fallback and exits"); return
    trig = take_trigger()
    if trig is None: log("no host trigger for this cycle: think's timer started it (fallback); the pulse will say so")
    run("git", "pull", "-q", "--ff-only", "origin", "main")
    catch_up()
    # ---- RECOVER: derive state from the published chain before doing anything new ----
    r = subprocess.run(["python3", "pulse.py", "recover"], cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    log("recover: " + (r.stdout.strip() or r.stderr.strip())[:200])
    if r.returncode == 3:
        # an unresolved commit is at the head (a previous cycle died): RESUME it instead of committing again
        hp = json.load(open(sorted(glob.glob(os.path.join(REPO, "chain", "pulse-????.json")))[-1]))
        seq, target = hp["core"]["seq"], hp["core"]["derived"]["target_round"]; release = hp["core"]["derived"]["target_release_unix_s"]
        log(f"resuming unresolved commit seq {seq} (round {target}, release {release})")
    elif r.returncode != 0:
        log("recover failed; not minting"); skip("recover failed: " + (r.stderr.strip() or r.stdout.strip())[-300:]); sys.exit(1)
    else:
        # ---- COMMIT ----
        try:
            out = json.loads(run("python3", "pulse.py", "commit", "--lead", str(LEAD), *(["--trigger", trig] if trig else [])))
        except Exception as e:
            log(f"commit refused: {e}"); skip(f"commit refused: {e}"); sys.exit(1)      # nothing committed; the refusal itself is published
        seq, target = out["seq"], out["target_round"]
        release = json.load(open(os.path.join(REPO, "chain", f"pulse-{seq:04d}.json")))["core"]["derived"]["target_release_unix_s"]
        log(f"committed seq {seq} -> round {target}, release in {release-time.time():.0f}s, tsa={out.get('tsa_tokens')}")
        pushed = publish(f"COMMIT pulse {seq} -> drand round {target}")
        margin = release - pushed
        log(f"commit pushed {margin:.0f}s before release")
        if margin < PUBLISH_MARGIN_S:
            fail(seq, "commit-published-late", {"margin_s": round(margin, 1), "required_s": PUBLISH_MARGIN_S})
    # ---- WAIT for the round: sleep to the known release instant, then let drand itself confirm it ----
    wait = release + 0.2 - time.time()
    if wait > 0: time.sleep(wait)
    while True:
        try:
            if drand_latest_round() >= target: break
        except Exception as e: log(f"drand poll error: {e}")
        if time.time() > release + REVEAL_DEADLINE_S - 60:
            fail(seq, "round-never-observed", {"last_check_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
        time.sleep(0.5)
    # ---- REVEAL (only if it can still be published inside the deadline; otherwise a signed failure) ----
    if time.time() > release + REVEAL_DEADLINE_S - 90:
        fail(seq, "reveal-window-missed", {"now_minus_release_s": round(time.time() - release, 1)})
    try:
        rout = json.loads(run("python3", "pulse.py", "reveal"))
    except Exception as e:
        fail(seq, "reveal-refused", {"error": str(e)[:200]})
    pushed = publish(f"REVEAL pulse {rout['seq']} (commit {seq}, drand round {target})")
    late = pushed - release
    log(f"revealed seq {rout['seq']} value {rout['attested_value'][:16]}..., pushed {late:.0f}s after release")
    try: log("finalize: " + run("python3", "pulse.py", "finalize").strip()[:120])
    except Exception as e: log(f"finalize deferred (E stays recoverable on the entropy host): {e}")
    log("cycle complete")

if __name__ == "__main__":
    try: main()
    except SystemExit: raise
    except Exception as e:
        log(f"UNHANDLED: {type(e).__name__}: {e}")
        # if a commit exists without a reveal, mark it
        # v0.5: the pending commit is whatever the chain head is, if it is a commit
        try:
            hp = json.load(open(sorted(glob.glob(os.path.join(REPO, "chain", "pulse-????.json")))[-1]))
            if hp["core"].get("type") == "commit": fail(hp["core"]["seq"], "cycle-crashed", {"error": str(e)[:200]})
        except Exception: pass
        sys.exit(1)
