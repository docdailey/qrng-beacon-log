#!/usr/bin/env python3
"""CI: verify the ENTIRE published chain — every pulse, every link, every commit/reveal pair,
every RFC 3161 token, and the archive Merkle root. Exit non-zero on the first failure."""
import subprocess, sys, glob, json, os, re
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pulses = sorted(f for f in glob.glob(f"{ROOT}/chain/pulse-*.json") if re.search(r"pulse-\d{4}\.json$", f))
fails = 0
def run(*a):
    r = subprocess.run(a, cwd=ROOT, capture_output=True, text=True); return r.returncode, r.stdout + r.stderr
prev = None
for p in pulses:
    args = ["python3", "verify.py", p, "--pin", "keys"]
    if prev: args += ["--prev", prev]
    if os.environ.get("REFETCH") == "1": args.append("--refetch")
    rc, out = run(*args)
    tag = "PASS" if rc == 0 else "FAIL"; print(f"[{tag}] {os.path.basename(p)}"); fails += rc != 0
    if rc: print(out)
    if glob.glob(p + ".*.tsr"):
        rc, out = run("python3", "tsa.py", "verify", p)
        print(f"[{'PASS' if rc == 0 else 'FAIL'}]   RFC3161 tokens for {os.path.basename(p)}"); fails += rc != 0
        if rc: print(out)
    prev = p
# every commit must have a reveal or a FAILED marker if its deadline has passed
import time
for p in pulses:
    d = json.load(open(p)); c = d["core"]
    if c.get("type") != "commit": continue
    seq = c["seq"]; rel = c["commitment"]["target_release_unix_s"]
    has_reveal = any(json.load(open(q))["core"].get("reveals", {}).get("commit_seq") == seq for q in pulses)
    has_failed = os.path.exists(f"{ROOT}/chain/pulse-{seq:04d}.FAILED.json")
    if not has_reveal and not has_failed and time.time() > rel + 600:
        print(f"[FAIL] commit {seq}: reveal deadline passed with neither reveal nor FAILED marker (withheld reveal)"); fails += 1
rc, out = run("python3", "merkle/merkle_proof.py", "root"); print(f"[{'PASS' if rc == 0 else 'FAIL'}] archive Merkle root recomputes"); fails += rc != 0
rc, out = run("python3", "merkle/merkle_proof.py", "verify", "merkle/proof_quantum_20251115_054715.json"); print(f"[{'PASS' if rc == 0 else 'FAIL'}] sample inclusion proof"); fails += rc != 0
print(f"\n{len(pulses)} pulses checked, {fails} failures"); sys.exit(1 if fails else 0)
