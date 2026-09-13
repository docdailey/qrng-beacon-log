#!/usr/bin/env python3
"""rpc.py — the aggregator's side of beacon-agentd (hosts/agentd.py): one signed request per TCP connection, no session.

call(host, op, *args) -> the text the host script printed (what the SSH forced command used to return on stdout).
The request is an Ed25519 statement signed with the aggregator key; it carries an ephemeral X25519 public key so the
host can seal a response that contains a secret (reveal-prepare) to this process alone. The response is the host's
own signed statement, verified by the caller exactly as before (pulse.check_statement)."""
import os, json, time, socket, secrets, base64, hashlib
import attest_lib as A
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

AGENTS = {"protectli": ("192.168.70.1", 5520), "p550": ("192.168.68.44", 5520), "k3": ("192.168.68.24", 5520), "f9t": ("192.168.68.46", 5520)}
AGG_HOST = os.environ.get("BEACON_AGGREGATOR_HOST") or os.uname().nodename.split(".")[0]

def _recv(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: raise RuntimeError("short header")
        hdr += c
    n = int.from_bytes(hdr, "big"); buf = b""
    while len(buf) < n:
        c = sock.recv(min(65536, n - len(buf)))
        if not c: raise RuntimeError("short body")
        buf += c
    return buf

def call(host, op, *args, timeout=150):
    ip, port = AGENTS[host]
    eph = X25519PrivateKey.generate()
    req = {"v": 1, "to": host, "op": op, "args": [str(x) for x in args], "from": AGG_HOST, "ts": int(time.time()),
           "nonce": secrets.token_hex(16), "epk": base64.b64encode(eph.public_key().public_bytes_raw()).decode()}
    signed = A.sign_statement("aggregator", req); wire = json.dumps({"req": signed["statement"], "sig": signed["signature"]}, separators=(",", ":")).encode()
    with socket.create_connection((ip, port), timeout=10) as s:
        s.settimeout(timeout); s.sendall(len(wire).to_bytes(4, "big") + wire); resp = json.loads(_recv(s))
    if not resp.get("ok"): raise RuntimeError(f"{host} agentd: {resp.get('error', 'refused')}")
    if "sealed" in resp:
        sd = resp["sealed"]; shared = eph.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(sd["spk"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"beacon-agentd/v1").derive(shared)
        return ChaCha20Poly1305(key).decrypt(base64.b64decode(sd["nonce"]), base64.b64decode(sd["ct"]), A.canon(signed["statement"])).decode()
    return resp["stdout"]
