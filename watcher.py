#!/usr/bin/env python3
"""
watcher.py v3 — independent auditor for a qrng-beacon-log. Trusts NOTHING from the repository it audits.

  * verifier, schema, BLS code, drand group-key pin and operator key history come from the watcher's OWN pinned
    directory (see watcher/make_pins.py); every pinned file's SHA-256 is checked on every run
  * the watched repo is read as DATA ONLY (git clone/reset; pulse JSON files) — no code is imported or executed from it
  * clock = a drand round agreed by >= 2 relays and BLS-verified under the watcher's own pinned key
  * COMMIT-RECEIPT only after the commit pulse passes the pinned strict verifier
  * a reveal/failure counts as a resolution ONLY if it passes the pinned strict verifier against its commit;
    otherwise INVALID-RESOLUTION is recorded and the commit stays unresolved -> NON-REVEAL after the deadline

    pip install cryptography py_ecc
    python3 watcher/make_pins.py <reviewed checkout> ~/beacon-watch/pins        # once, deliberately
    WATCH_REPO=docdailey/qrng-beacon-log OUT_DIR=~/beacon-watch python3 watcher.py   # every 1-5 min
"""
import os, sys, json, time, base64, hashlib, subprocess, urllib.request, glob, re

REPO = os.environ.get("WATCH_REPO", "docdailey/qrng-beacon-log")
OUT = os.path.expanduser(os.environ.get("OUT_DIR", "~/beacon-watch"))
PINS = os.environ.get("PINS_DIR", os.path.join(OUT, "pins"))
DEADLINE = int(os.environ.get("REVEAL_DEADLINE_S", "600"))
LOG = os.path.join(OUT, "log")
RELAYS = ["https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh"]
UA = {"User-Agent": "qrng-beacon-watcher/3"}

def sh(*a, cwd=None, check=True):
    r = subprocess.run(a, cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if check and r.returncode != 0: raise RuntimeError(f"{a[:2]}: {r.stderr.strip()[:200]}")
    return r.stdout
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r: return json.loads(r.read().decode())

# ---------------- pins: the only code and keys the watcher trusts ----------------
def check_pins():
    p = json.load(open(os.path.join(PINS, "PINS.json")))
    for f, h in p["files"].items():
        got = hashlib.sha256(open(os.path.join(PINS, f), "rb").read()).hexdigest()
        if got != h: raise SystemExit(f"PIN MISMATCH: {f} {got[:16]} != {h[:16]} — refusing to run")
    return p
def pinned_release(rnd):
    d = json.load(open(os.path.join(PINS, "keys", "drand-quicknet.json")))
    return d["genesis_time"] + (int(rnd) - 1) * d["period_s"], d["chain_hash"]
def strict_verify(pulse_path, prev_path=None):
    args = ["python3", os.path.join(PINS, "verify.py"), pulse_path, "--pin", os.path.join(PINS, "keys")] + (["--prev", prev_path] if prev_path else [])
    r = subprocess.run(args, capture_output=True, text=True, cwd=PINS, stdin=subprocess.DEVNULL,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return r.returncode == 0, (r.stdout.strip().splitlines() or [""])[-1][:160]

# ---------------- watcher identity ----------------
def key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
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
    from cryptography.hazmat.primitives import serialization
    body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(); pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"record": doc, "record_sha256": hashlib.sha256(body).hexdigest(),
            "signature": {"alg": "ed25519", "key_id": hashlib.sha256(pub).hexdigest()[:16], "public_key_b64": base64.b64encode(pub).decode(), "sig_b64": base64.b64encode(k.sign(body)).decode()}}
def write(kind, seq, k, doc, new):
    d = os.path.join(OUT, kind); os.makedirs(d, exist_ok=True); p = os.path.join(d, f"pulse-{seq:04d}.json")
    if os.path.exists(p): return
    json.dump(signed(k, doc), open(p, "w"), indent=2); new.append(p); print(kind, os.path.basename(p))

# ---------------- clock: BLS-verified drand round under the WATCHER's pin ----------------
def drand_clock():
    sys.path.insert(0, PINS)
    import importlib, bls_drand; importlib.reload(bls_drand)
    bls_drand.PIN_FILE = os.path.join(PINS, "keys", "drand-quicknet.json")
    ch = json.load(open(bls_drand.PIN_FILE))["chain_hash"]
    seen = {}
    for b in RELAYS:
        try: seen[b] = get(f"{b}/{ch}/public/latest")
        except Exception: pass
    if len(seen) < 2: raise RuntimeError("fewer than two drand relays answered")
    best = max(seen.values(), key=lambda d: d["round"])
    ok, why = bls_drand.verify_pinned(best["round"], best["signature"], ch)
    if not ok: raise RuntimeError("drand latest round failed BLS under the watcher's pinned key: " + why)
    return best["round"], sorted(seen)

def main():
    pins = check_pins(); k = key()
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"; sys.dont_write_bytecode = True
    if not os.path.isdir(os.path.join(LOG, ".git")): sh("git", "clone", "-q", f"https://github.com/{REPO}.git", LOG)
    else:
        sh("git", "fetch", "-q", "origin", "main", cwd=LOG); sh("git", "reset", "-q", "--hard", "origin/main", cwd=LOG); sh("git", "clean", "-fdq", cwd=LOG)
    head = sh("git", "rev-parse", "HEAD", cwd=LOG).strip()
    dround, relays = drand_clock(); dnow, _ = pinned_release(dround)
    files = sorted(f for f in glob.glob(os.path.join(LOG, "chain", "pulse-*.json")) if re.search(r"pulse-\d{4}\.json$", f))
    P = {}
    for f in files:
        try: P[json.load(open(f))["core"]["seq"]] = (f, json.load(open(f)))
        except Exception: pass                                   # malformed data is just data
    new = []
    for seq, (f, p) in sorted(P.items()):
        c = p["core"]; typ = c.get("type")
        if typ != "commit": continue
        v05 = c.get("v") == "0.5"
        R = (c.get("derived") or c.get("commitment") or {}).get("target_round"); C = (c.get("derived") or c.get("commitment") or {}).get("entropy_commitment")
        if R is None: continue
        rel, _ = pinned_release(R)
        prevf = P.get(seq - 1, (None,))[0]
        base = {"watched_repo": REPO, "log_head": head, "commit_seq": seq, "commit_pulse_hash": p["pulse_hash"], "entropy_commitment": C,
                "target_round": R, "target_release_unix_s": rel, "drand_round_at_observation": dround, "drand_relays": relays,
                "drand_time_at_observation_unix_s": dnow, "observed_unix": int(time.time()), "pins": pins["files"]}
        c_ok, c_tail = strict_verify(f, prevf) if v05 else (None, "legacy pulse: pinned strict verifier not applicable")
        if v05 and not c_ok:
            write("invalid-commit", seq, k, {"kind": "INVALID-COMMIT", **base, "verifier_tail": c_tail}, new); continue
        nxt = P.get(seq + 1)
        if dround < R:
            write("commit-receipt", seq, k, {"kind": "COMMIT-RECEIPT", **base, "commit_verified_by_pinned_verifier": c_ok,
                  "statement": f"This commitment was PUBLIC in the log at {head[:12]} while drand had reached only round {dround} < {R}."}, new)
            continue
        resolved = False
        if nxt and nxt[1]["core"].get("type") in ("reveal", "failure"):
            rf, rp = nxt; r_ok, r_tail = strict_verify(rf, f)
            if r_ok:
                resolved = True
                write("observed", seq, k, {"kind": "REVEAL-OBSERVED" if rp["core"]["type"] == "reveal" else "FAILURE-OBSERVED", **base,
                      "resolving_seq": rp["core"]["seq"], "resolving_pulse_hash": rp["pulse_hash"], "pinned_verifier_passed": True, "verifier_tail": r_tail}, new)
            else:
                write("invalid-resolution", seq, k, {"kind": "INVALID-RESOLUTION", **base, "resolving_seq": rp["core"]["seq"],
                      "resolving_pulse_hash": rp["pulse_hash"], "verifier_tail": r_tail,
                      "statement": "The pulse that claims to resolve this commit does not pass the watcher's pinned verifier; the commit remains UNRESOLVED."}, new)
        if not resolved and dnow >= rel + DEADLINE:
            write("non-reveal", seq, k, {"kind": "NON-REVEAL", **base, "reveal_deadline_s": DEADLINE,
                  "statement": (f"No VALID reveal or failure for this commitment within {DEADLINE} s of drand round {R}'s release, as judged by a "
                                f"BLS-verified drand round under the watcher's own pinned key. Treat this pulse as failed.")}, new)
    if new and os.path.isdir(os.path.join(OUT, ".git")):
        sh("git", "add", "-A", cwd=OUT); sh("git", "commit", "-q", "-m", f"watcher: {len(new)} record(s) at drand round {dround}, log {head[:12]}", cwd=OUT, check=False); sh("git", "push", "-q", cwd=OUT, check=False)
    print(json.dumps({"log_head": head[:12], "drand_round": dround, "pulses": len(P), "new_records": len(new), "pins_ok": True}))

if __name__ == "__main__":
    main()
