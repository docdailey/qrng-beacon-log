#!/usr/bin/env python3
"""
drand_anchor.py — fetch an external randomness anchor from the League of Entropy.

Network: **quicknet** (beaconID "quicknet"), chain hash
  52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
  period 3 s · genesis_time 1692803367 · schemeID bls-unchained-g1-rfc9380 · UNCHAINED

Unchained means each round is signed over the round number alone, so there is no
`previous_signature` field and rounds are independently verifiable. `randomness` is
defined as SHA-256(signature) — which is checkable with no crypto library at all.

Round R is released at  genesis_time + (R - 1) * period  (UTC seconds): ROUND 1 IS AT GENESIS.
(ERR-004: earlier code used R * period and was 3 s late on every release time.)
"""
import json, hashlib, urllib.request, time

CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
PERIOD = 3
GENESIS = 1692803367
# Independent operators; we try them in order so one operator being down is not fatal.
ENDPOINTS = ["https://api.drand.sh", "https://api2.drand.sh",
             "https://api3.drand.sh", "https://drand.cloudflare.com"]

def _get(path, timeout=10):
    last = None
    for base in ENDPOINTS:
        try:
            with urllib.request.urlopen(f"{base}/{CHAIN}{path}", timeout=timeout) as r:
                return json.loads(r.read().decode()), base
        except Exception as e:
            last = f"{base}: {type(e).__name__}: {e}"
    raise RuntimeError(f"all drand endpoints failed; last={last}")

def round_time(rnd):
    return GENESIS + (int(rnd) - 1) * PERIOD

def fetch(rnd=None):
    """Fetch `latest` (default) or a specific round. Returns a dict ready to embed in a pulse."""
    t0 = time.time()
    doc, base = _get("/public/latest" if rnd is None else f"/public/{int(rnd)}")
    t1 = time.time()
    sig = bytes.fromhex(doc["signature"])
    rand = bytes.fromhex(doc["randomness"])
    # dependency-free integrity check: randomness MUST be sha256(signature)
    ok = hashlib.sha256(sig).digest() == rand
    return {
        "network": "drand League of Entropy — quicknet",
        "beacon_id": "quicknet",
        "chain_hash": CHAIN,
        "scheme": "bls-unchained-g1-rfc9380",
        "period_s": PERIOD,
        "genesis_time": GENESIS,
        "round": doc["round"],
        "randomness": doc["randomness"],
        "signature": doc["signature"],
        "round_release_unix_s": round_time(doc["round"]),
        "randomness_equals_sha256_signature": ok,
        "fetched_from": base,
        "fetch_unix_s": round(t0, 3),
        "fetch_latency_s": round(t1 - t0, 3),
        "reverify": (f"curl -s https://api.drand.sh/{CHAIN}/public/{doc['round']}  "
                     "-> must return this exact round/randomness/signature. "
                     "randomness == sha256(signature) is checkable offline. Full BLS threshold "
                     "verification requires a drand client and the chain public key from "
                     f"https://api.drand.sh/{CHAIN}/info"),
    }

if __name__ == "__main__":
    import sys
    print(json.dumps(fetch(int(sys.argv[1]) if len(sys.argv) > 1 else None), indent=2))
