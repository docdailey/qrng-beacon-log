#!/usr/bin/env python3
"""
watcher.py — independent auditor for a qrng-beacon-log. Anyone can run it; it needs no access to the
operator's systems. It reads the public log via git (not the 1,000-entry Contents API), takes its clock
from drand rounds it BLS-verifies itself, runs the strict verifier before believing any reveal, and
publishes three kinds of signed records under ITS OWN key to a repo the operator does not control:

  COMMIT-RECEIPT   "I saw commitment C for round R when drand had only reached round X < R"  <- pre-round
                   observation: this is what turns TSA 'existence' into evidence of PUBLIC commitment
  REVEAL-OBSERVED  a reveal that passed the strict verifier against its commit
  NON-REVEAL       a commit past target_release + REVEAL_DEADLINE_S with neither reveal nor signed failure

    pip install cryptography py_ecc
    WATCH_REPO=docdailey/qrng-beacon-log OUT_DIR=~/beacon-watch python3 watcher.py      # every 1-5 min
"""
import os, sys, json, time, base64, hashlib, subprocess, urllib.request, glob, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REPO = os.environ.get("WATCH_REPO", "docdailey/qrng-beacon-log")
OUT = os.path.expanduser(os.environ.get("OUT_DIR", "~/beacon-watch"))
DEADLINE = int(os.environ.get("REVEAL_DEADLINE_S", "600"))
LOG = os.path.join(OUT, "log")                      # git clone of the watched repo
RELAYS = ["https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh"]
CH, GENESIS, PERIOD = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", 1692803367, 3
def rel(r): return GENESIS + (int(r) - 1) * PERIOD

def sh(*a, cwd=None, check=True):
    r = subprocess.run(a, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0: raise RuntimeError(f"{a[:2]}: {r.stderr.strip()[:200]}")
    return r.stdout
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "qrng-beacon-watcher/2"}), timeout=20) as r: return json.loads(r.read().decode())

def key():
    os.makedirs(OUT, exist_ok=True); kp = os.path.join(OUT, "watcher.key")
    if os.path.exists(kp): return serialization.load_pem_private_key(open(kp, "rb").read(), None)
    k = Ed25519PrivateKey.generate()
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); os.close(fd)
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    json.dump({"alg": "ed25519", "key_id": hashlib.sha256(pub).hexdigest()[:16], "public_key_b64": base64.b64encode(pub).decode(), "role": "watcher", "watching": REPO},
              open(os.path.join(OUT, "watcher.pub"), "w"), indent=2)
    return k
def signed(k, doc):
    body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(); pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"record": doc, "record_sha256": hashlib.sha256(body).hexdigest(),
            "signature": {"alg": "ed25519", "key_id": hashlib.sha256(pub).hexdigest()[:16], "public_key_b64": base64.b64encode(pub).decode(), "sig_b64": base64.b64encode(k.sign(body)).decode()}}
def write(kind, seq, k, doc, new):
    d = os.path.join(OUT, kind); os.makedirs(d, exist_ok=True); p = os.path.join(d, f"pulse-{seq:04d}.json")
    if os.path.exists(p): return
    json.dump(signed(k, doc), open(p, "w"), indent=2); new.append(p); print(kind, os.path.basename(p))

def drand_clock():
    """Latest round agreed by >= 2 relays, BLS-verified under the pinned key from the watched repo."""
    sys.path.insert(0, LOG)
    import bls_drand
    seen = {}
    for b in RELAYS:
        try: d = get(f"{b}/{CH}/public/latest"); seen[b] = d
        except Exception: pass
    if len(seen) < 2: raise RuntimeError("fewer than two drand relays answered")
    best = max(seen.values(), key=lambda d: d["round"])
    ok, why = bls_drand.verify_pinned(best["round"], best["signature"], CH)
    if not ok: raise RuntimeError("drand latest round failed BLS: " + why)
    return best["round"], sorted(seen.keys())

def main():
    k = key()
    if not os.path.isdir(os.path.join(LOG, ".git")): sh("git", "clone", "-q", f"https://github.com/{REPO}.git", LOG)
    else: sh("git", "pull", "-q", "--ff-only", cwd=LOG)
    head = sh("git", "rev-parse", "HEAD", cwd=LOG).strip()
    dround, relays = drand_clock(); dnow = rel(dround)
    files = sorted(f for f in glob.glob(os.path.join(LOG, "chain", "pulse-*.json")) if re.search(r"pulse-\d{4}\.json$", f))
    P = {json.load(open(f))["core"]["seq"]: (f, json.load(open(f))) for f in files}
    new = []
    for seq, (f, p) in sorted(P.items()):
        c = p["core"]; typ = c.get("type")
        if typ != "commit": continue
        v05 = c.get("v") == "0.5"
        R = c["derived"]["target_round"] if v05 else c["commitment"]["target_round"]
        C = c["derived"]["entropy_commitment"] if v05 else c["commitment"]["entropy_commitment"]
        nxt = P.get(seq + 1); resolved = nxt and nxt[1]["core"].get("type") in ("reveal", "failure")
        base = {"watched_repo": REPO, "log_head": head, "commit_seq": seq, "commit_pulse_hash": p["pulse_hash"], "entropy_commitment": C,
                "target_round": R, "target_release_unix_s": rel(R), "drand_round_at_observation": dround, "drand_relays": relays,
                "drand_time_at_observation_unix_s": dnow, "observed_unix": int(time.time())}
        if dround < R:
            write("commit-receipt", seq, k, {"kind": "COMMIT-RECEIPT", **base,
                  "statement": f"This commitment was PUBLIC in the log at commit {head[:12]} while drand had reached only round {dround} < {R}."}, new)
            continue
        if resolved:
            rf, rp = nxt
            if rp["core"].get("type") == "reveal":
                rc = subprocess.run(["python3", "verify.py", rf, "--prev", f, "--pin", "keys"], cwd=LOG, capture_output=True, text=True)
                write("observed", seq, k, {"kind": "REVEAL-OBSERVED", **base, "reveal_seq": rp["core"]["seq"], "reveal_pulse_hash": rp["pulse_hash"],
                      "strict_verifier_exit": rc.returncode, "strict_verifier_passed": rc.returncode == 0,
                      "verifier_tail": rc.stdout.strip().splitlines()[-1] if rc.stdout.strip() else ""}, new)
            else:
                write("observed", seq, k, {"kind": "FAILURE-OBSERVED", **base, "failure_seq": rp["core"]["seq"], "reason": rp["core"]["derived"].get("reason")}, new)
            continue
        if dnow >= rel(R) + DEADLINE:
            write("non-reveal", seq, k, {"kind": "NON-REVEAL", **base, "reveal_deadline_s": DEADLINE,
                  "statement": (f"The operator published a commitment to drand round {R} and did not publish a matching reveal or a signed failure within "
                                f"{DEADLINE} s of that round's release, as judged by a BLS-verified drand round. Treat this pulse as failed.")}, new)
    if new and os.path.isdir(os.path.join(OUT, ".git")):
        sh("git", "add", "-A", cwd=OUT); sh("git", "commit", "-q", "-m", f"watcher: {len(new)} record(s) at drand round {dround}, log {head[:12]}", cwd=OUT, check=False); sh("git", "push", "-q", cwd=OUT, check=False)
    print(json.dumps({"log_head": head[:12], "drand_round": dround, "pulses": len(P), "new_records": len(new)}))

if __name__ == "__main__":
    main()
