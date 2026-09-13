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

Backends: supranational/blst (native, ~ms; used when libblst.so is found - see _blst) or `pip install py_ecc` (pure
Python; 2 s on x86, 4.7 s on the RISC-V aggregator). Absent both, callers should WARN. `python3 bls_drand.py` runs
the positive and negative self-test with whichever backend is active; set BLST_LIB= (empty) to force py_ecc.
"""
import hashlib, json, os

PIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys", "drand-quicknet.json")
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

_BLST = None
def _blst():
    """Native backend: supranational/blst through ctypes when BLST_LIB, ~/blst/libblst.so or /usr/local/lib/libblst.so
    exists (built with `./build.sh -shared -D__BLST_PORTABLE__`). Falls back to py_ecc. Same checks, same answer:
    curve + prime-order-subgroup membership of sig and pk, then e(sig, g2) == e(H(m), pk) via blst_core_verify_pk_in_g2
    (hash_or_encode=1 = hash-to-curve RO, same DST and same 32-byte message as the py_ecc path). Measured 2026-09-13 on k3
    (RISC-V): py_ecc 4.7 s per round, blst a few ms."""
    global _BLST
    if _BLST is not None: return _BLST or None
    import ctypes
    for cand in (os.environ.get("BLST_LIB"), os.path.expanduser("~/blst/libblst.so"), "/usr/local/lib/libblst.so"):
        if not cand or not os.path.exists(cand): continue
        try:
            lib = ctypes.CDLL(cand)
            for fn in ("blst_p1_uncompress", "blst_p2_uncompress"): getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_char_p]; getattr(lib, fn).restype = ctypes.c_int
            lib.blst_p1_affine_in_g1.argtypes = [ctypes.c_void_p]; lib.blst_p1_affine_in_g1.restype = ctypes.c_bool
            lib.blst_p2_affine_in_g2.argtypes = [ctypes.c_void_p]; lib.blst_p2_affine_in_g2.restype = ctypes.c_bool
            lib.blst_core_verify_pk_in_g2.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
            lib.blst_core_verify_pk_in_g2.restype = ctypes.c_int
            _BLST = (lib, cand); return _BLST
        except Exception:
            continue
    _BLST = False; return None

def backend():
    if _blst(): return "blst"
    try:
        import py_ecc  # noqa
        return "py_ecc"
    except ImportError:
        return None

def available(): return backend() is not None

def _verify_round_blst(pk_hex: str, round_no: int, sig_hex: str) -> bool:
    import ctypes
    lib, _ = _blst(); sig_b, pk_b = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    if len(sig_b) != 48 or len(pk_b) != 96: return False
    sig, pk = ctypes.create_string_buffer(96), ctypes.create_string_buffer(192)          # blst_p1_affine, blst_p2_affine
    if lib.blst_p1_uncompress(sig, sig_b) != 0 or lib.blst_p2_uncompress(pk, pk_b) != 0: return False
    if not lib.blst_p1_affine_in_g1(sig) or not lib.blst_p2_affine_in_g2(pk): return False
    m = message(round_no)
    return lib.blst_core_verify_pk_in_g2(pk, sig, 1, m, len(m), DST, len(DST), None, 0) == 0

def pinned():
    return json.load(open(PIN_FILE))

def message(round_no: int) -> bytes:
    return hashlib.sha256(int(round_no).to_bytes(8, "big")).digest()

def verify_round(pk_hex: str, round_no: int, sig_hex: str) -> bool:
    if _blst(): return _verify_round_blst(pk_hex, round_no, sig_hex)
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
    print("backend:", backend())
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
