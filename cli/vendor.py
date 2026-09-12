#!/usr/bin/env python3
"""vendor.py — copy the published verifier, keys and expected-config files from the repo root into notbefore/verifier/,
pinning them to the repo commit. Re-run (and bump the package version) whenever the protocol or keys change.
The freetsa CA + TSA certificates are fetched once here so the package pins them instead of trusting first use."""
import os, shutil, hashlib, json, subprocess, time, urllib.request, sys
CLI = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(CLI); DST = os.path.join(CLI, "notbefore", "verifier")
FILES = ["verify.py", "bls_drand.py", "drand_anchor.py", "schema.py", "tsa.py", "tlog.py",
         "hosts/attest_lib.py", "hosts/attest_host.py", "hosts/entropy_host.py", "hosts/gnss_probe.py", "hosts/stamp_probe.py", "hosts/EXPECTED.json",
         "ci/anchor_lib.py", "ci/KNOWN_NONCOMPLIANT.json"]
FILES += sorted("keys/" + f for f in os.listdir(os.path.join(ROOT, "keys")) if not f.startswith(".") and os.path.isfile(os.path.join(ROOT, "keys", f)) and "private" not in f)
CERTS = {"tsa-certs/freetsa-ca.pem": "https://freetsa.org/files/cacert.pem", "tsa-certs/freetsa-tsa.crt": "https://freetsa.org/files/tsa.crt"}
if os.path.isdir(DST): shutil.rmtree(DST)
manifest = {}
for f in FILES:
    s, d = os.path.join(ROOT, f), os.path.join(DST, f); os.makedirs(os.path.dirname(d), exist_ok=True); shutil.copy2(s, d)
    manifest[f] = hashlib.sha256(open(d, "rb").read()).hexdigest()
for f, url in CERTS.items():
    d = os.path.join(DST, f); os.makedirs(os.path.dirname(d), exist_ok=True)
    cached = os.path.join(ROOT, f)
    if os.path.exists(cached): shutil.copy2(cached, d)
    else: urllib.request.urlretrieve(url, d)
    manifest[f] = hashlib.sha256(open(d, "rb").read()).hexdigest()
sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
dirty = bool(subprocess.run(["git", "status", "--porcelain", "--"] + [f for f in FILES], cwd=ROOT, capture_output=True, text=True).stdout.strip())
meta = {"log_repo": "https://github.com/docdailey/qrng-beacon-log", "git_sha": sha + ("-dirty" if dirty else ""), "vendored_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Verifier, keys and expected-config pinned at this commit. The CLI executes ONLY these files; the log is read as data.", "files": manifest}
json.dump(meta, open(os.path.join(DST, "VENDORED.json"), "w"), indent=1, sort_keys=True)
open(os.path.join(DST, "__init__.py"), "w").write(""); open(os.path.join(DST, "hosts", "__init__.py"), "w").write(""); open(os.path.join(DST, "ci", "__init__.py"), "w").write("")
print(f"vendored {len(manifest)} files at {meta['git_sha'][:12]} -> {os.path.relpath(DST, CLI)}")
