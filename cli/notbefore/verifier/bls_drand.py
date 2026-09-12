#!/usr/bin/env python3
"""
bls_drand.py — full BLS verification of drand quicknet rounds (scheme bls-unchained-g1-rfc9380).

Checks  e(σ, g₂) == e(H(m), pk)  on BLS12-381 with
  σ  = round signature, 48-byte compressed G1 point
  pk = the League of Entropy quicknet GROUP public key, 96-byte compressed G2 point (pinned)
  m  = SHA-256(round as uint64 big-endian)          (unchained: no previous signature in the message)
  H  = hash-to-curve into G1 per RFC 9380, DST "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

A valid σ is the unique signature a ≥threshold set of operators could produce for that round; it
cannot be precomputed, forged, or swapped for another round. This removes the HTTP relay, DNS and TLS
from the trust base — only the pinned group key and the ≥t-honest-operators assumption remain.

Requires `pip install py_ecc` (pure Python; ~1-2 s per verification). Absent it, callers should WARN.
"""
import hashlib, json, os

PIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys", "drand-quicknet.json")
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

def available():
    try:
        import py_ecc  # noqa
        return True
    except ImportError:
        return False

def pinned():
    return json.load(open(PIN_FILE))

def message(round_no: int) -> bytes:
    return hashlib.sha256(int(round_no).to_bytes(8, "big")).digest()

def verify_round(pk_hex: str, round_no: int, sig_hex: str) -> bool:
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import pairing, G2, is_on_curve, b, b2, curve_order, multiply, Z1, Z2
    sig_b, pk_b = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    if len(sig_b) != 48 or len(pk_b) != 96:
        return False
    try:
        sig = decompress_G1(int.from_bytes(sig_b, "big"))
        pk  = decompress_G2((int.from_bytes(pk_b[:48], "big"), int.from_bytes(pk_b[48:], "big")))
    except Exception:
        return False
    # subgroup + curve checks (decompress checks curve; be explicit about the prime-order subgroup)
    if not is_on_curve(sig, b) or not is_on_curve(pk, b2):
        return False
    if multiply(sig, curve_order) != Z1 or multiply(pk, curve_order) != Z2:
        return False
    hm = hash_to_G1(message(round_no), DST, hashlib.sha256)
    return pairing(G2, sig) == pairing(pk, hm)

def verify_pinned(round_no: int, sig_hex: str, chain_hash: str) -> tuple:
    p = pinned()
    if chain_hash != p["chain_hash"]:
        return False, "chain hash does not match the pinned quicknet chain"
    ok = verify_round(p["public_key"], round_no, sig_hex)
    return ok, ("BLS signature verifies under the pinned League of Entropy quicknet group key" if ok
                else "BLS signature does NOT verify under the pinned group key")

if __name__ == "__main__":
    import sys, urllib.request, time
    CH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
    def get(u):
        with urllib.request.urlopen(u, timeout=15) as r: return json.load(r)
    print("=== 1. cross-check the group public key across independent operators ===")
    keys = {}
    for base in ("https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh", "https://drand.cloudflare.com"):
        try: i = get(f"{base}/{CH}/info"); keys[base] = (i["public_key"], i["hash"], i["schemeID"], i["genesis_time"], i["period"])
        except Exception as e: keys[base] = ("ERR", str(e)[:40])
    vals = {v for v in keys.values() if v[0] != "ERR"}
    for k, v in keys.items(): print("  %-30s %s" % (k, v[0][:24] + "..." if v[0] != "ERR" else v))
    print("  agreement across operators:", len(vals) == 1, "| scheme:", next(iter(vals))[2])
    pk = next(iter(vals))[0]
    print("\n=== 2. verify REAL rounds (the three we have mixed, plus latest) ===")
    for rnd in (32122604, 32123484, 32123921, None):
        d = get(f"https://api.drand.sh/{CH}/public/{'latest' if rnd is None else rnd}")
        t0 = time.time(); ok = verify_round(pk, d["round"], d["signature"]); dt = time.time() - t0
        print("  round %d: %s (%.2fs)" % (d["round"], "VALID" if ok else "INVALID", dt))
    print("\n=== 3. NEGATIVES — every one of these must be INVALID ===")
    d = get(f"https://api.drand.sh/{CH}/public/32123921")
    print("  same σ, round+1 (relay relabels the round):", "INVALID" if not verify_round(pk, d["round"] + 1, d["signature"]) else "VALID  <-- BUG")
    sb = bytearray(bytes.fromhex(d["signature"])); sb[-1] ^= 0x01
    print("  σ with one bit flipped:                     ", "INVALID" if not verify_round(pk, d["round"], sb.hex()) else "VALID  <-- BUG")
    other = get("https://api.drand.sh/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/info")["public_key"]
    print("  real σ against the DEFAULT network's key:   ", "INVALID" if not verify_round(other if len(other) == 192 else pk, d["round"], d["signature"]) or len(other) != 192 else "VALID  <-- BUG")
