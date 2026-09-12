#!/usr/bin/env python3
"""CI: verify the ENTIRE published chain and SHOW what was verified. Green must mean fully verified.

Per pulse: verify.py (strict for v0.5, legacy otherwise) with --prev and --pin; RFC 3161 tokens.
Across the chain: the v0.5 state machine (commit -> reveal|failure -> commit), TSA contract for every
v0.5 commit (>= 2 tokens, each token time <= release - 120 s), no legacy FAILED.json markers in the
v0.5 era, withheld-reveal rule, archive Merkle root. Tally to stdout and $GITHUB_STEP_SUMMARY."""
import subprocess, sys, glob, json, os, re, time, datetime, email.utils
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hosts")); sys.path.insert(0, ROOT)
import schema as S
REQ_BLS = os.environ.get("REQUIRE_BLS", "1") == "1"; REFETCH = os.environ.get("REFETCH") == "1"
V05_FROM = 18
KNOWN = json.load(open(os.path.join(ROOT, "ci", "KNOWN_NONCOMPLIANT.json"))).get("pulses", {})
pulses = sorted(f for f in glob.glob(f"{ROOT}/chain/pulse-*.json") if re.search(r"pulse-\d{4}\.json$", f))
T = dict(pulses=0, known_noncompliant=0, unexpected_pass_of_listed=0, v05_pulses=0, signatures=0, host_statements=0, chain_links=0, commit_pulses=0, reveal_pulses=0, failure_pulses=0,
         commit_reveal_pairs=0, bls_verified=0, bls_skipped=0, drand_refetched=0, tsa_tokens=0, tsa_min_margin_s=None,
         err004_warnings=0, tooling_drift_warnings=0, state_machine_violations=0, failures=0)
lines = []
def say(s): print(s); lines.append(s)
def run(*a):
    r = subprocess.run(a, cwd=ROOT, capture_output=True, text=True); return r.returncode, r.stdout + r.stderr
def tsa_time(s):
    m = re.search(r"RFC3161 \w+: (.+)", s); return datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp() if m else None
prev = None; prev_core = None
for p in pulses:
    core = json.load(open(p))["core"]; typ = core.get("type", "legacy"); v05 = (core.get("v") == "0.5")
    args = ["python3", "verify.py", p, "--pin", "keys"] + (["--prev", prev] if prev else []) + (["--refetch"] if REFETCH else [])
    rc, out = run(*args)
    T["pulses"] += 1; T["v05_pulses"] += v05
    T["signatures"] += len(re.findall(r"\[PASS\] \w+ signature by", out)) + out.count("[PASS] aggregator signature")
    T["host_statements"] += out.count("signature verifies over canon(statement)")
    T["chain_links"] += out.count("[PASS] chains to previous pulse")
    T["bls_verified"] += out.count("[full BLS, offline]") if "[PASS] drand round" in out else 0
    T["bls_skipped"] += out.count("[WARN] BLS verification skipped")
    T["drand_refetched"] += out.count("re-fetched live from the League of Entropy and matches")
    T["err004_warnings"] += out.count("[WARN] ERR-004"); T["tooling_drift_warnings"] += out.count("tooling drift")
    T[f"{typ}_pulses"] = T.get(f"{typ}_pulses", 0) + (typ in ("commit", "reveal", "failure"))
    if typ == "reveal": T["commit_reveal_pairs"] += out.count("predecessor IS the referenced commit")
    bad = rc != 0 or (REQ_BLS and "[WARN] BLS verification skipped" in out)
    kn = KNOWN.get(str(core["seq"]))
    if kn and bad and kn["expected_failure"] in out:
        T["known_noncompliant"] += 1; bad = False
        say(f"[KNOWN-NONCOMPLIANT {kn['erratum']}] {os.path.basename(p)} fails as documented: {kn['expected_failure']}")
    elif kn and not bad:
        T["unexpected_pass_of_listed"] += 1; bad = True
        say(f"[FAIL] {os.path.basename(p)} is listed under {kn['erratum']} but PASSED - the list or the verifier is wrong")
    # state machine across the chain (v0.5 era)
    if prev_core is not None and (v05 or prev_core.get("v") == "0.5"):
        pt = prev_core.get("type", "legacy")
        legal = (typ == "commit" and pt in ("legacy", "reveal", "failure")) or (typ in ("reveal", "failure") and pt == "commit")
        if not legal: say(f"[FAIL] state machine: {pt} (seq {prev_core['seq']}) -> {typ} (seq {core['seq']}) is not a legal transition"); T["state_machine_violations"] += 1; bad = True
    T["failures"] += bad
    say(f"[{'FAIL' if bad else 'PASS'}] {os.path.basename(p)}  ({typ}{', v0.5' if v05 else ''}, {out.count('[full BLS, offline]')} BLS, {out.count('signature verifies over canon')} host stmts)")
    if bad: print(out)
    # TSA contract
    toks = glob.glob(p + ".*.tsr")
    if toks or (v05 and typ == "commit"):
        rc, out = run("python3", "tsa.py", "verify", p); n = out.count("[PASS] RFC3161"); T["tsa_tokens"] += n
        ok = rc == 0 and n >= 1
        if v05 and typ == "commit":
            rel = core["derived"]["target_release_unix_s"]
            times = [tsa_time(l) for l in out.splitlines() if "[PASS] RFC3161" in l]
            margins = [rel - t for t in times if t]
            if margins:
                T["tsa_min_margin_s"] = min(margins) if T["tsa_min_margin_s"] is None else min(T["tsa_min_margin_s"], min(margins))
            ok = ok and n >= S.MIN_TSA_TOKENS and margins and min(margins) >= S.PUBLISH_MARGIN_S
            say(f"[{'PASS' if ok else 'FAIL'}]   TSA contract: {n} token(s) >= {S.MIN_TSA_TOKENS}, earliest margin {min(margins) if margins else '?'} s >= {S.PUBLISH_MARGIN_S} s")
        else:
            say(f"[{'PASS' if ok else 'FAIL'}]   {n} RFC 3161 token(s) verify")
        T["failures"] += not ok
        if not ok: print(out)
    prev, prev_core = p, core
# withheld-reveal rule + legacy markers in the v0.5 era
for p in pulses:
    c = json.load(open(p))["core"]
    if c.get("type") != "commit": continue
    seq = c["seq"]; rel = (c.get("derived") or c.get("commitment"))["target_release_unix_s"] if c.get("v") == "0.5" else S.release_time(c["commitment"]["target_round"])
    nxt = [q for q in pulses if json.load(open(q))["core"]["seq"] == seq + 1]
    resolved = bool(nxt) and json.load(open(nxt[0]))["core"].get("type") in ("reveal", "failure")
    if not resolved and time.time() > rel + S.REVEAL_DEADLINE_S:
        say(f"[FAIL] commit {seq}: reveal deadline passed with neither a reveal nor a signed failure pulse (withheld reveal)"); T["failures"] += 1
stale = [f for f in glob.glob(f"{ROOT}/chain/pulse-*.FAILED.json") if int(re.search(r"pulse-(\d{4})", f).group(1)) >= V05_FROM]
if stale: say(f"[FAIL] unsigned legacy FAILED.json markers exist in the v0.5 era: {[os.path.basename(x) for x in stale]}"); T["failures"] += 1
rc, _ = run("python3", "merkle/merkle_proof.py", "root"); say(f"[{'PASS' if rc == 0 else 'FAIL'}] archive Merkle root recomputes from leaves.tsv"); T["failures"] += rc != 0
rc, _ = run("python3", "merkle/merkle_proof.py", "verify", "merkle/proof_quantum_20251115_054715.json"); say(f"[{'PASS' if rc == 0 else 'FAIL'}] sample inclusion proof verifies"); T["failures"] += rc != 0
if REQ_BLS and T["bls_skipped"]: say(f"[FAIL] BLS skipped {T['bls_skipped']} time(s) with REQUIRE_BLS=1"); T["failures"] += 1
say("\n=== verification tally ===")
for k, v in T.items(): say(f"  {k:24s} {v}")
summ = os.environ.get("GITHUB_STEP_SUMMARY")
if summ:
    with open(summ, "a") as f:
        f.write("## verify-chain\n\n| check | count |\n|---|---|\n" + "".join(f"| {k} | {v} |\n" for k, v in T.items()))
        f.write(f"\n**{'FAILED' if T['failures'] else 'ALL VERIFIED'}** — {T['pulses']} pulses ({T['v05_pulses']} v0.5), {T['host_statements']} host-signed statements, "
                f"{T['bls_verified']} drand rounds BLS-verified, {T['tsa_tokens']} RFC 3161 tokens (min commit margin {T['tsa_min_margin_s']} s), refetch={'on' if REFETCH else 'off'}.\n")
sys.exit(1 if T["failures"] else 0)
