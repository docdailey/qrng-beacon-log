#!/usr/bin/env python3
"""CI: verify the ENTIRE published chain and SHOW what was verified.

Every pulse, every prev_hash link, every commit/reveal pair, every RFC 3161 token, every drand round's
BLS signature under the pinned group key, the withheld-reveal rule, and the archive Merkle root.
Prints a per-check tally and writes it to $GITHUB_STEP_SUMMARY so the Actions page shows the counts.
REQUIRE_BLS=1 makes a skipped BLS check a FAILURE (default in CI): green must mean fully verified.
Exit non-zero on any failure."""
import subprocess, sys, glob, json, os, re, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ_BLS = os.environ.get("REQUIRE_BLS", "1") == "1"
REFETCH = os.environ.get("REFETCH") == "1"
pulses = sorted(f for f in glob.glob(f"{ROOT}/chain/pulse-*.json") if re.search(r"pulse-\d{4}\.json$", f))
tally = {"pulses": 0, "signatures": 0, "chain_links": 0, "commit_pulses": 0, "reveal_pulses": 0,
         "commit_reveal_pairs": 0, "bls_verified": 0, "bls_skipped": 0, "drand_refetched": 0,
         "tsa_tokens": 0, "failures": 0}
lines = []
def say(s): print(s); lines.append(s)
def run(*a):
    r = subprocess.run(a, cwd=ROOT, capture_output=True, text=True); return r.returncode, r.stdout + r.stderr
prev = None
for p in pulses:
    args = ["python3", "verify.py", p, "--pin", "keys"] + (["--prev", prev] if prev else []) + (["--refetch"] if REFETCH else [])
    rc, out = run(*args)
    core = json.load(open(p))["core"]; typ = core.get("type", "legacy")
    tally["pulses"] += 1
    tally["signatures"] += len(re.findall(r"\[PASS\] \w+ signature by", out))
    tally["chain_links"] += out.count("[PASS] chains to previous pulse")
    tally["bls_verified"] += out.count("[full BLS, offline]") if "[PASS] drand round" in out else 0
    tally["bls_skipped"] += out.count("[WARN] BLS verification skipped")
    tally["drand_refetched"] += out.count("re-fetched live from the League of Entropy and matches")
    if typ == "commit": tally["commit_pulses"] += 1
    if typ == "reveal": tally["reveal_pulses"] += 1; tally["commit_reveal_pairs"] += out.count("[PASS] predecessor pulse IS the referenced commit")
    bad = rc != 0 or (REQ_BLS and "[WARN] BLS verification skipped" in out)
    tally["failures"] += bad
    say(f"[{'FAIL' if bad else 'PASS'}] {os.path.basename(p)}  ({typ}, "
        f"{out.count('[full BLS, offline]')} BLS, {out.count('re-fetched live')} refetch)")
    if bad: print(out)
    if glob.glob(p + ".*.tsr"):
        rc, out = run("python3", "tsa.py", "verify", p)
        n = out.count("[PASS] RFC3161"); tally["tsa_tokens"] += n; tally["failures"] += rc != 0
        say(f"[{'PASS' if rc == 0 else 'FAIL'}]   {n} RFC 3161 token(s) for {os.path.basename(p)}")
        if rc: print(out)
    prev = p
for p in pulses:  # withheld-reveal rule
    c = json.load(open(p))["core"]
    if c.get("type") != "commit": continue
    seq, rel = c["seq"], c["commitment"]["target_release_unix_s"]
    has_reveal = any(json.load(open(q))["core"].get("reveals", {}).get("commit_seq") == seq for q in pulses)
    has_failed = os.path.exists(f"{ROOT}/chain/pulse-{seq:04d}.FAILED.json")
    if not has_reveal and not has_failed and time.time() > rel + 600:
        say(f"[FAIL] commit {seq}: reveal deadline passed with neither reveal nor FAILED marker (withheld reveal)"); tally["failures"] += 1
rc, _ = run("python3", "merkle/merkle_proof.py", "root"); say(f"[{'PASS' if rc == 0 else 'FAIL'}] archive Merkle root recomputes from leaves.tsv"); tally["failures"] += rc != 0
rc, _ = run("python3", "merkle/merkle_proof.py", "verify", "merkle/proof_quantum_20251115_054715.json"); say(f"[{'PASS' if rc == 0 else 'FAIL'}] sample inclusion proof verifies"); tally["failures"] += rc != 0
if REQ_BLS and tally["bls_skipped"]: say(f"[FAIL] BLS was skipped {tally['bls_skipped']} time(s) but REQUIRE_BLS=1")
say("\n=== verification tally ===")
for k, v in tally.items(): say(f"  {k:20s} {v}")
summ = os.environ.get("GITHUB_STEP_SUMMARY")
if summ:
    with open(summ, "a") as f:
        f.write("## verify-chain\n\n| check | count |\n|---|---|\n" + "".join(f"| {k} | {v} |\n" for k, v in tally.items()))
        f.write(f"\n**{'FAILED' if tally['failures'] else 'ALL VERIFIED'}** — {tally['pulses']} pulses, {tally['bls_verified']} drand rounds BLS-verified under the pinned group key, "
                f"{tally['tsa_tokens']} RFC 3161 tokens, {tally['commit_reveal_pairs']} commit/reveal pairs, refetch={'on' if REFETCH else 'off'}.\n")
sys.exit(1 if tally["failures"] else 0)
