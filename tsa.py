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
    "freetsa":  {"url": "https://freetsa.org/tsr",
                 "ca":  "https://freetsa.org/files/cacert.pem", "tsa_cert": "https://freetsa.org/files/tsa.crt"},
    "digicert": {"url": "http://timestamp.digicert.com", "ca": None, "tsa_cert": None},   # chain in system roots
}
HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "tsa-certs"); os.makedirs(CACHE, exist_ok=True)
SYS_CA = "/opt/homebrew/etc/openssl@3/cert.pem" if os.path.exists("/opt/homebrew/etc/openssl@3/cert.pem") else "/etc/ssl/cert.pem"

def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)

def _fetch(url, name):
    p = os.path.join(CACHE, name)
    if not os.path.exists(p):
        urllib.request.urlretrieve(url, p)
    return p

def stamp(pulse_path, label=None):
    q = pulse_path + ".tsq"
    r = sh("openssl", "ts", "-query", "-data", pulse_path, "-sha256", "-cert", "-out", q)
    if r.returncode != 0: raise RuntimeError("tsq: " + r.stderr[:200])
    got = []
    for name, cfg in TSAS.items():
        out = f"{pulse_path}.{name}.tsr"
        try:
            req = urllib.request.Request(cfg["url"], data=open(q, "rb").read(),
                                         headers={"Content-Type": "application/timestamp-query"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                body = resp.read()
            open(out, "wb").write(body)
            txt = sh("openssl", "ts", "-reply", "-in", out, "-text").stdout
            if "Status: Granted" not in txt:
                os.remove(out); continue
            t = re.search(r"Time stamp:\s*(.+)", txt).group(1).strip()
            got.append({"tsa": name, "file": os.path.basename(out), "time": t})
        except Exception as e:
            sys.stderr.write(f"[tsa] {name}: {type(e).__name__}: {str(e)[:80]}\n")
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
        args = ["openssl", "ts", "-verify", "-data", pulse_path, "-in", tsr]
        if cfg["ca"]:
            args += ["-CAfile", _fetch(cfg["ca"], f"{name}-ca.pem"), "-untrusted", _fetch(cfg["tsa_cert"], f"{name}-tsa.crt")]
        else:
            args += ["-CAfile", SYS_CA]
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
