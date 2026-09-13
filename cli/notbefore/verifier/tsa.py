#!/usr/bin/env python3
"""
tsa.py — RFC 3161 trusted timestamps for pulses, from public Time-Stamping Authorities.

  tsa.py stamp  <pulse.json>            request tokens from >= 2 independent TSAs -> <pulse>.<tsa>.tsr
  tsa.py verify <pulse.json>            verify every token found next to the pulse; print TSA times

Why: a signature proves WHO, git history proves publication only as far as GitHub's timestamps are
trusted. An RFC 3161 token is a third party's signed statement "this digest existed at time T".
Two TSAs from different operators mean no single party — us included — can move the time. This is
a standards-track notary (RFC 3161), not a blockchain.

A token taken AT COMMIT (before the target round) proves the commitment predates the round.
A token taken later only proves the file existed before the token time; such tokens are labelled
"retroactive" and must be described that way.
"""
import subprocess, sys, os, json, hashlib, re, urllib.request, time

TSAS = {
    "freetsa":  {"url": "https://freetsa.org/tsr"},          # trust anchors: keys/tsa/PINS.json (pinned, never fetched)
    "digicert": {"url": "http://timestamp.digicert.com"},
}
HERE = os.path.dirname(os.path.abspath(__file__))
# Pinned trust anchors (keys/tsa/PINS.json). The verifier trusts these files and nothing else: no system store, no
# download. Missing pin => that TSA's token FAILS. See ERR-014.
PIN_DIR = os.path.join(HERE, "keys", "tsa")
def _pins():
    p = os.path.join(PIN_DIR, "PINS.json")
    return json.load(open(p))["tsas"] if os.path.exists(p) else {}

def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)

def stamp(pulse_path, label=None):
    q = pulse_path + ".tsq"
    r = sh("openssl", "ts", "-query", "-data", pulse_path, "-sha256", "-cert", "-out", q)
    if r.returncode != 0: raise RuntimeError("tsq: " + r.stderr[:200])
    got = []; query = open(q, "rb").read()
    def one(item):
        """One TSA request. The TSAs are asked CONCURRENTLY (2026-09-13: 0.41 s in sequence from k3, ~0.25 s together)."""
        name, cfg = item; out = f"{pulse_path}.{name}.tsr"
        try:
            req = urllib.request.Request(cfg["url"], data=query, headers={"Content-Type": "application/timestamp-query"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                body = resp.read()
            open(out, "wb").write(body)
            txt = sh("openssl", "ts", "-reply", "-in", out, "-text").stdout
            if "Status: Granted" not in txt:
                os.remove(out); return None
            t = re.search(r"Time stamp:\s*(.+)", txt).group(1).strip()
            return {"tsa": name, "file": os.path.basename(out), "time": t}
        except Exception as e:
            sys.stderr.write(f"[tsa] {name}: {type(e).__name__}: {str(e)[:80]}\n"); return None
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=max(1, len(TSAS))) as ex:
        got = [r for r in ex.map(one, list(TSAS.items())) if r]                    # TSAS order preserved
    os.remove(q)
    meta = {"pulse": os.path.basename(pulse_path), "sha256": hashlib.sha256(open(pulse_path, "rb").read()).hexdigest(),
            "tokens": got, "label": label or "at-commit", "requested_unix": int(time.time())}
    json.dump(meta, open(pulse_path + ".tsa.json", "w"), indent=2)
    return meta

def verify(pulse_path):
    ok_all, results = True, []
    for name, cfg in TSAS.items():
        tsr = f"{pulse_path}.{name}.tsr"
        if not os.path.exists(tsr): continue
        txt = sh("openssl", "ts", "-reply", "-in", tsr, "-text").stdout
        t = (re.search(r"Time stamp:\s*(.+)", txt) or [None, "?"])[1].strip() if "Time stamp" in txt else "?"
        pin = _pins().get(name); root = pin and os.path.join(PIN_DIR, pin["root"]); inter = [os.path.join(PIN_DIR, i) for i in (pin or {}).get("intermediates", [])]
        if not pin or not os.path.exists(root) or not all(os.path.exists(i) for i in inter):
            results.append({"tsa": name, "time": t, "digest_and_chain_verified": False, "detail": "pinned trust root for this TSA is missing from keys/tsa (fail closed; ERR-014)"}); ok_all = False; continue
        # `openssl ts` builds its store from -CAfile/-CApath/-CAstore ONLY (apps/ts.c never loads the default paths), so
        # -CAfile <pinned root> alone is strict: tested — offering the wrong root fails even when the right one sits in /etc/ssl.
        args = ["openssl", "ts", "-verify", "-data", pulse_path, "-in", tsr, "-CAfile", root]
        for i in inter: args += ["-untrusted", i]
        v = sh(*args)
        full = "Verification: OK" in (v.stdout + v.stderr)
        results.append({"tsa": name, "time": t, "digest_and_chain_verified": full,
                        "detail": None if full else (v.stderr.strip().splitlines() or ["?"])[-1][:120]})
        ok_all &= full
    return ok_all, results

if __name__ == "__main__":
    cmd, path = sys.argv[1], sys.argv[2]
    label = sys.argv[3] if len(sys.argv) > 3 else None
    if cmd == "stamp":
        print(json.dumps(stamp(path, label), indent=2))
    else:
        ok, res = verify(path)
        for r in res: print(f"[{'PASS' if r['digest_and_chain_verified'] else 'FAIL'}] RFC3161 {r['tsa']}: {r['time']}" + ("" if r['digest_and_chain_verified'] else f"  ({r['detail']})"))
        print("ALL TSA TOKENS VERIFIED" if ok and res else ("NO TOKENS" if not res else "TSA VERIFICATION FAILED")); sys.exit(0 if ok and res else 1)
