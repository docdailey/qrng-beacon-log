#!/usr/bin/env python3
"""attest_lib.py — shared by every role host. Canonical encoding, normalisation, signing, tool binding.

CANONICAL FORM (PROTOCOL v0.5): RFC 8785-compatible JSON produced by
  json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
over a value domain that contains NO floats and NO integers outside [-(2^53-1), 2^53-1]. normalize()
rewrites every float and every out-of-range integer as a decimal STRING before signing, so any
JSON library in any language reproduces the same bytes. canon() REFUSES anything else.
"""
import json, hashlib, base64, os, time, math
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SAFE = 2**53 - 1

def normalize(x):
    if isinstance(x, bool) or x is None or isinstance(x, str): return x
    if isinstance(x, int): return x if -SAFE <= x <= SAFE else str(x)
    if isinstance(x, float):
        if math.isnan(x) or math.isinf(x): raise ValueError("non-finite float")
        return repr(x)                                  # shortest round-trip decimal string
    if isinstance(x, dict): return {str(k): normalize(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [normalize(v) for v in x]
    raise TypeError(f"unsupported type {type(x).__name__}")

def _check(x, path="$"):
    if isinstance(x, bool) or x is None or isinstance(x, str): return
    if isinstance(x, int):
        if not (-SAFE <= x <= SAFE): raise ValueError(f"{path}: integer outside 2^53 range")
        return
    if isinstance(x, float): raise ValueError(f"{path}: float not allowed in canonical form")
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str): raise ValueError(f"{path}: non-string key")
            _check(v, f"{path}.{k}")
        return
    if isinstance(x, list):
        for i, v in enumerate(x): _check(v, f"{path}[{i}]")
        return
    raise TypeError(f"{path}: unsupported type {type(x).__name__}")

def canon(obj) -> bytes:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def file_sha256(path) -> str: return sha256_hex(open(path, "rb").read())
def now_ns_str() -> str: return str(time.time_ns())

def load_private(role):
    return serialization.load_pem_private_key(open(os.path.expanduser(f"~/beacon/{role}.key"), "rb").read(), None)

def pub_of(priv):
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, base64.b64encode(raw).decode(), sha256_hex(raw)[:16]

def sign_statement(role, statement: dict) -> dict:
    """Return {statement, signature} where signature is ed25519 over canon(statement)."""
    st = normalize(statement)
    priv = load_private(role); raw, b64, kid = pub_of(priv)
    sig = priv.sign(canon(st))
    return {"statement": st, "signature": {"alg": "ed25519", "key_id": kid, "public_key_b64": b64,
                                           "sig_b64": base64.b64encode(sig).decode(),
                                           "over": "canon(statement)"}}

def tool_binding(*paths):
    """Version-bind the code that produced a statement: name + sha256 of each script."""
    return [{"name": os.path.basename(p), "sha256": file_sha256(p)} for p in paths]

def base_statement(role, host, seq, phase, binding, chain_hash, tools):
    return {"v": "0.5", "role": role, "host": host, "seq": int(seq), "phase": phase,
            "binding": binding, "chain_hash": chain_hash, "issued_unix_ns": now_ns_str(), "tools": tools}
