#!/usr/bin/env python3
"""gen_vectors.py — conformance vectors for worker/test_local.mjs: the CT test vectors (RFC 6962), canonical-JSON parity
with the Python side, and a decision statement signed by a throwaway consumer key. Usage: python3 worker/gen_vectors.py > v.json"""
import sys, os, json, base64
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "cli"))
import tlog as T
from notbefore import identity as I, decisionlog as DL
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
leaves, roots = T.CT_LEAVES, T.CT_ROOTS
cons = [[m, n, list(p)] for (m, n), p in T.CT_CONSISTENCY.items()]
inc = [[m, n, [x.hex() for x in T.inclusion_path(m, leaves[:n])]] for n in (1, 2, 3, 5, 8) for m in range(n)]
priv = Ed25519PrivateKey.generate(); pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
st = DL.statement("ab" * 32, "trial:2026/q4@v1", I.key_id_of(pub_raw), base64.b64encode(pub_raw).decode(), "notbefore/contract/3")
obj = {"z": 1, "a": {"c": [1, "two", {"y": True, "x": None}], "b": "ü — unicode/slash"}, "m": "tab\there \"q\" \\"}
json.dump({"ct_leaves_hex": [l.hex() for l in leaves], "ct_roots_hex": roots, "ct_consistency": cons, "ct_inclusion": inc,
           "canon_obj": obj, "canon_str": DL.canon(obj).decode(), "statement": st, "signature_b64": DL.sign_statement(priv, st)}, sys.stdout)
