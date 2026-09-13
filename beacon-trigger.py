#!/usr/bin/env python3
"""beacon-trigger.py — forced command on the AGGREGATOR (think) for the time host's cadence trigger (hosts/beacon-cadence.py).

  ~/.ssh/authorized_keys on think:
    restrict,from="192.168.68.44",command="/usr/bin/python3 /home/willy/qrng-beacon/beacon-trigger.py" ssh-ed25519 <p550 cadence key>

Accepts exactly one operation, `trigger`, with one signed cadence-trigger statement on stdin (<= 16 KiB). It verifies the
statement against keys/KEYS.json (the active time_attester key of p550), requires the scheduled instant to be recent,
writes trigger/pending.json and starts qrng-beacon.service. Nothing else is reachable through this key. A refused
trigger is logged (trigger.log) and the :02 fallback timer still runs the hour - the pulse then says think's timer started it.
"""
import os, sys, json, time, base64, hashlib, subprocess
REPO = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(REPO, "hosts"))
import attest_lib as A
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
MAX_AGE_S, MAX_BYTES, CHAIN_HASH = 120, 16384, "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

def log(m):
    with open(os.path.join(REPO, "trigger.log"), "a") as f: f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + m + "\n")
def refuse(m):
    log("REFUSED: " + m); print(json.dumps({"accepted": False, "reason": m})); sys.exit(2)
def key_ok(pk_b64):
    for k in json.load(open(os.path.join(REPO, "keys", "KEYS.json")))["keys"]:
        if k["role"] == "time_attester" and k["host"] == "p550" and k["public_key_b64"] == pk_b64 and k.get("valid_to_seq") is None: return True
    return False

def main():
    received = time.time_ns()
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip() != "trigger": refuse("only `trigger` is accepted")
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: refuse("payload too large")
    try: signed = json.loads(raw); st, sig = signed["statement"], signed["signature"]
    except Exception as e: refuse(f"not a signed statement: {type(e).__name__}")
    if st.get("v") != "0.5" or st.get("kind") != "cadence-trigger" or st.get("role") != "time_attester" or st.get("host") != "p550" or st.get("chain_hash") != CHAIN_HASH:
        refuse("wrong v/kind/role/host/chain")
    try:
        pk = base64.b64decode(sig["public_key_b64"])
        if sig.get("alg") != "ed25519" or hashlib.sha256(pk).hexdigest()[:16] != sig.get("key_id"): refuse("bad key_id")
        if not key_ok(sig["public_key_b64"]): refuse("key is not the active time_attester key of p550")
        Ed25519PublicKey.from_public_bytes(pk).verify(base64.b64decode(sig["sig_b64"]), A.canon(st))
    except SystemExit: raise
    except Exception: refuse("signature does not verify")
    t0 = st.get("scheduled_unix_s")
    if not isinstance(t0, int) or not (-5 <= received / 1e9 - t0 <= MAX_AGE_S): refuse(f"scheduled instant {t0} is not within the last {MAX_AGE_S} s")
    d = os.path.join(REPO, "trigger"); os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = os.path.join(d, ".pending.tmp")
    with open(tmp, "w") as f: json.dump({"received_unix_ns": str(received), "trigger": signed}, f)
    os.chmod(tmp, 0o600); os.replace(tmp, os.path.join(d, "pending.json"))
    if os.environ.get("BEACON_TRIGGER_DRY"):          # local test only: never set through sshd (no PermitUserEnvironment)
        print(json.dumps({"accepted": True, "dry": True, "received_after_ms": round((received / 1e9 - t0) * 1000, 1)})); return
    r = subprocess.run(["systemctl", "--user", "start", "--no-block", "qrng-beacon.service"], capture_output=True, text=True, timeout=20)
    started = r.returncode == 0; after_ms = round((received / 1e9 - t0) * 1000, 1)
    log(f"accepted trigger for {t0}: received {after_ms} ms after the instant (woke {st.get('wake', {}).get('late_ns')} ns late on p550); "
        f"qrng-beacon.service start {'ok' if started else 'FAILED: ' + (r.stderr or r.stdout).strip()[:200]}")
    print(json.dumps({"accepted": True, "received_unix_ns": str(received), "received_after_ms": after_ms, "cycle_started": started}))
    sys.exit(0 if started else 3)

if __name__ == "__main__": main()
