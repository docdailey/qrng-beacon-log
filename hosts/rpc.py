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

_CONN = {}; _LOCK = __import__("threading").Lock()
SEALED_OPS = {"reveal-prepare"}
def _conn(host):
    """One kept connection per host in this process (opened on first use or by warm()); dropped on any error. No call is
    ever repeated automatically after an ambiguous failure: the caller's protocol handles that (pulse.py rollback/recover)."""
    with _LOCK:
        s = _CONN.get(host)
        if s is None:
            ip, port = AGENTS[host]; s = socket.create_connection((ip, port), timeout=10); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); _CONN[host] = s
        return s
def _drop(host):
    with _LOCK:
        s = _CONN.pop(host, None)
    if s is not None:
        try: s.close()
        except Exception: pass
def warm(host):
    """Open (or confirm) the connection before the instant; nothing is sent."""
    _conn(host)

def call(host, op, *args, timeout=150):
    # an ephemeral X25519 key only where the protocol seals the response (89-186 us per generation otherwise wasted)
    eph = X25519PrivateKey.generate() if op in SEALED_OPS else None
    req = {"v": 1, "to": host, "op": op, "args": [str(x) for x in args], "from": AGG_HOST, "ts": int(time.time()), "nonce": secrets.token_hex(16),
           "epk": base64.b64encode(eph.public_key().public_bytes_raw()).decode() if eph else ""}
    signed = A.sign_statement("aggregator", req); wire = json.dumps({"req": signed["statement"], "sig": signed["signature"]}, separators=(",", ":")).encode()
    with _LOCK: reused = host in _CONN
    s = _conn(host)
    try:
        s.settimeout(timeout); s.sendall(len(wire).to_bytes(4, "big") + wire); resp = json.loads(_recv(s))
    except RuntimeError as e:
        # A kept connection the server had already closed (a daemon that serves one request per connection, an idle
        # timeout) fails with EOF before any response byte; such a request was never read, so ONE fresh attempt is safe.
        # Anything after a byte of response, or on a fresh connection, propagates: the caller's protocol decides.
        _drop(host)
        if reused and str(e) == "short header":
            s = _conn(host)
            try:
                s.settimeout(timeout); s.sendall(len(wire).to_bytes(4, "big") + wire); resp = json.loads(_recv(s))
            except Exception:
                _drop(host); raise
        else: raise
    except Exception:
        _drop(host); raise
    if not resp.get("ok"): raise RuntimeError(f"{host} agentd: {resp.get('error', 'refused')}")
    if "sealed" in resp:
        if eph is None: raise RuntimeError(f"{host} agentd sealed a response to an operation that carries no key")
        sd = resp["sealed"]; shared = eph.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(sd["spk"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"beacon-agentd/v1").derive(shared)
        return ChaCha20Poly1305(key).decrypt(base64.b64decode(sd["nonce"]), base64.b64decode(sd["ct"]), A.canon(signed["statement"])).decode()
    return resp["stdout"]
