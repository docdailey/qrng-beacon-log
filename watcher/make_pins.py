#!/usr/bin/env python3
"""make_pins.py — snapshot the verifier the WATCHER will trust, from a checkout the WATCHER OPERATOR has reviewed.

  python3 make_pins.py <reviewed-checkout> <pins-dir>

Copies verify.py, bls_drand.py, schema.py, hosts/attest_lib.py, keys/KEYS.json, keys/drand-quicknet.json into
<pins-dir> and writes PINS.json with their SHA-256s. The watcher refuses to run if any pinned file's hash changes.
Updating pins is a deliberate act by the watcher operator — never automatic, never from the watched repo at run time.
"""
import sys, os, shutil, hashlib, json, time
src, dst = sys.argv[1], sys.argv[2]
FILES = ["verify.py", "bls_drand.py", "schema.py", "hosts/attest_lib.py", "keys/KEYS.json", "keys/drand-quicknet.json"]
pins = {}
for f in FILES:
    os.makedirs(os.path.dirname(os.path.join(dst, f)) or dst, exist_ok=True)
    shutil.copy(os.path.join(src, f), os.path.join(dst, f))
    pins[f] = hashlib.sha256(open(os.path.join(dst, f), "rb").read()).hexdigest()
json.dump({"pinned_unix": int(time.time()), "from_checkout": os.path.abspath(src), "files": pins,
           "note": "The watcher trusts ONLY these bytes. Review them before pinning; re-run make_pins.py to update."},
          open(os.path.join(dst, "PINS.json"), "w"), indent=2)
print(json.dumps(pins, indent=2))
