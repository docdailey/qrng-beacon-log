#!/usr/bin/env python3
"""
beacon-cycle.py — one full commit -> publish -> wait -> reveal -> publish cycle. Run hourly by systemd.

Contract (CADENCE.md):
  * commit is TSA-stamped at mint and PUSHED at least PUBLISH_MARGIN_S before its target round
  * reveal is minted and PUSHED within REVEAL_DEADLINE_S after the round releases
  * any breach writes a pulse-NNNN.FAILED.json into the chain and pushes it. Failures are public.
Everything fails closed; nothing is retried silently.
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
    r = subprocess.run(a, cwd=REPO, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(a[:3])} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()

def drand_latest_round():
    with urllib.request.urlopen(f"https://api.drand.sh/{CHAIN_HASH}/public/latest", timeout=15) as r:
        return json.load(r)["round"]

def publish(msg):
    run("git", "add", "-A", "chain")
    if run("git", "status", "--porcelain", "chain", check=False):
        run("git", "commit", "-q", "-m", msg)
        run("git", "push", "-q", "origin", "main")
    return time.time()

def fail(seq, reason, extra=None):
    log(f"FAILED seq {seq}: {reason} {extra or ''}")
    run("python3", "pulse.py", "fail", str(seq), reason, check=False)
    try: publish(f"FAILED pulse {seq}: {reason}")
    except Exception as e: log(f"could not publish failure marker: {e}")
    sys.exit(1)

def main():
    log("cycle start")
    run("git", "pull", "-q", "--ff-only", "origin", "main")
    # ---- COMMIT ----
    try:
        out = json.loads(run("python3", "pulse.py", "commit", "--lead", str(LEAD)))
    except Exception as e:
        log(f"commit refused: {e}"); sys.exit(1)      # nothing minted -> nothing to mark
    seq, target, release = out["seq"], out["target_round"], None
    cpath = os.path.join(REPO, "chain", f"pulse-{seq:04d}.json")
    release = json.load(open(cpath))["core"]["commitment"]["target_release_unix_s"]
    log(f"committed seq {seq} -> round {target}, release in {release-time.time():.0f}s, tsa={out.get('tsa_tokens')}")
    pushed = publish(f"COMMIT pulse {seq} -> drand round {target}")
    margin = release - pushed
    log(f"commit pushed {margin:.0f}s before release")
    if margin < PUBLISH_MARGIN_S:
        fail(seq, "commit-published-late", {"margin_s": round(margin, 1), "required_s": PUBLISH_MARGIN_S})
    # ---- WAIT for the round, judged by drand itself ----
    while True:
        try:
            if drand_latest_round() >= target: break
        except Exception as e: log(f"drand poll error: {e}")
        if time.time() > release + REVEAL_DEADLINE_S - 60:
            fail(seq, "round-never-observed", {"last_check_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
        time.sleep(3)
    # ---- REVEAL ----
    try:
        rout = json.loads(run("python3", "pulse.py", "reveal"))
    except Exception as e:
        fail(seq, "reveal-refused", {"error": str(e)[:200]})
    pushed = publish(f"REVEAL pulse {rout['seq']} (commit {seq}, drand round {target})")
    late = pushed - release
    log(f"revealed seq {rout['seq']} value {rout['attested_value'][:16]}..., pushed {late:.0f}s after release")
    if late > REVEAL_DEADLINE_S:
        fail(seq, "reveal-published-late", {"late_s": round(late, 1), "deadline_s": REVEAL_DEADLINE_S})
    log("cycle complete")

if __name__ == "__main__":
    try: main()
    except SystemExit: raise
    except Exception as e:
        log(f"UNHANDLED: {type(e).__name__}: {e}")
        # if a commit exists without a reveal, mark it
        pend = sorted(glob.glob(os.path.join(REPO, "chain", "pending", "*.secret")))
        if pend: fail(json.load(open(pend[0]))["seq"], "cycle-crashed", {"error": str(e)[:200]})
        sys.exit(1)
