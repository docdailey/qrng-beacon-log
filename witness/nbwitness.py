#!/usr/bin/env python3
"""nbwitness.py — a minimal c2sp.org/tlog-witness@v1.0.0 witness (single file, stdlib + cryptography).

A witness holds ONE checkpoint per log, accepts a new checkpoint only with a valid consistency proof from the head it
holds, and returns a timestamped cosignature (c2sp.org/tlog-cosignature@v1.0.1). It never downloads a log.

  nbwitness.py keygen  <name> <keyfile>          -> Ed25519 key; prints the cosignature verifier key to configure in logs
  nbwitness.py serve   --name N --key K --logs logs.json --state DIR [--listen 0.0.0.0:8477]
  logs.json: {"logs": ["<log verifier key string>", ...]}        e.g. notbefore.net/log+8b627e7f+AQ...

HTTP:  POST /add-checkpoint   body = "old <size>\\n" + proof lines (base64) + "\\n" + signed note
       200 -> cosignature line(s) | 409 -> witness's size for this log (body) | 403 -> proof invalid / rollback
       404 -> unknown log | 422 -> malformed or bad log signature
       GET  /                 -> status JSON (name, verifier key, logs, sizes)
Same-sponsor disclosure: a witness run by the log's operator is a SECOND SYSTEM, not an independent party. Say so.
"""
import sys, os, json, base64, hashlib, re, time, argparse, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def H(b): return hashlib.sha256(b).digest()
def node(l, r): return H(b"\x01" + l + r)
def verify_consistency(m, n, proof, old_root, new_root):          # RFC 9162 §2.1.4.2
    if m == n: return proof == [] and old_root == new_root
    if m == 0: return proof == []
    if m > n or not proof: return False
    if m & (m - 1) == 0: proof = [old_root] + proof
    fn, sn = m - 1, n - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if (fn & 1) or fn == sn:
            fr = node(c, fr); sr = node(c, sr)
            while not (fn & 1) and fn != 0: fn >>= 1; sn >>= 1
        else: sr = node(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

def parse_note(note):
    text, _, sigs = note.partition("\n\n"); text += "\n"; out = []
    for l in sigs.splitlines():
        m = re.match(r"^— (\S+) (\S+)$", l)
        if m: blob = base64.b64decode(m.group(2)); out.append((m.group(1), blob[:4], blob[4:]))
    return text, out
def parse_verifier_key(s):
    name, kh, b64 = s.strip().split("+", 2); blob = base64.b64decode(b64)      # base64 may itself contain "+": split on the first two only
    if H(name.encode() + b"\n" + blob)[:4].hex() != kh: raise ValueError("verifier key hash mismatch: " + s)
    return name, blob[0], blob[1:]
def log_key_id(name, pub): return H(name.encode() + b"\n" + b"\x01" + pub)[:4]
def cosig_key_id(name, pub): return H(name.encode() + b"\n" + b"\x04" + pub)[:4]

class State:
    def __init__(self, d): self.d = d; os.makedirs(d, exist_ok=True); self.lock = threading.Lock()
    def path(self, origin): return os.path.join(self.d, re.sub(r"[^A-Za-z0-9._-]", "_", origin) + ".json")
    def get(self, origin):
        p = self.path(origin); return json.load(open(p)) if os.path.exists(p) else {"size": 0, "root_b64": None}
    def put(self, origin, size, root, note):
        tmp = self.path(origin) + ".tmp"; json.dump({"size": size, "root_b64": base64.b64encode(root).decode(), "note": note, "updated_unix": int(time.time())}, open(tmp, "w")); os.replace(tmp, self.path(origin))

class Witness:
    def __init__(self, name, priv, logs, state):
        self.name, self.priv, self.state = name, priv, state
        self.pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.logs = {}
        for s in logs:
            n, alg, pub = parse_verifier_key(s)
            if alg != 1: raise SystemExit(f"log key {n}: only Ed25519 note keys (alg 0x01) are supported")
            self.logs[n] = pub
    def verifier_key(self): return f"{self.name}+{cosig_key_id(self.name, self.pub).hex()}+{base64.b64encode(b'\x04' + self.pub).decode()}"
    def cosign(self, text):
        ts = int(time.time()); sig = self.priv.sign(f"cosignature/v1\ntime {ts}\n".encode() + text.encode())
        return "— " + self.name + " " + base64.b64encode(cosig_key_id(self.name, self.pub) + ts.to_bytes(8, "big") + sig).decode() + "\n"
    def add_checkpoint(self, body):
        """Returns (status, body)."""
        try:
            head, _, note = body.partition("\n\n")
            lines = head.split("\n")
            if not lines or not lines[0].startswith("old "): return 400, "missing 'old <size>' line\n"
            old = int(lines[0][4:]); proof = [base64.b64decode(l) for l in lines[1:] if l.strip()]
            text, sigs = parse_note(note); tl = text.split("\n"); origin, size, root = tl[0], int(tl[1]), base64.b64decode(tl[2])
        except Exception as e: return 400, f"malformed request: {e}\n"
        pub = self.logs.get(origin)
        if pub is None: return 404, "unknown log\n"
        kid = log_key_id(origin, pub); ok = False
        for name, k, sig in sigs:
            if name == origin and k == kid:
                try: Ed25519PublicKey.from_public_bytes(pub).verify(sig, text.encode()); ok = True
                except InvalidSignature: pass
        if not ok: return 422, "checkpoint signature does not verify under the configured log key\n"
        with self.state.lock:
            st = self.state.get(origin); known = st["size"]; known_root = base64.b64decode(st["root_b64"]) if st["root_b64"] else None
            if old != known: return 409, f"{known}\n"
            if size < known: return 409, f"{known}\n"
            if size == known:
                if root != known_root: return 403, "same size, different root: split view refused\n"
                return 200, self.cosign(text)
            if known == 0 and not proof: pass                                   # first sight of this log
            elif not verify_consistency(known, size, proof, known_root, root): return 403, "consistency proof does not verify: refusing to move the head\n"
            cs = self.cosign(text); self.state.put(origin, size, root, note.rstrip("\n") + "\n" + cs)
            return 200, cs
    def status(self):
        return {"witness": self.name, "verifier_key": self.verifier_key(), "spec": "c2sp.org/tlog-witness@v1.0.0", "disclosure": "operated by the log's sponsor: a second system, not an independent party",
                "logs": {o: self.state.get(o) for o in self.logs}}

def serve(w, listen):
    host, port = listen.rsplit(":", 1)
    class Hn(BaseHTTPRequestHandler):
        def log_message(self, f, *a): sys.stderr.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + (f % a) + "\n")
        def _send(self, code, body, ctype="text/plain; charset=utf-8"):
            b = body.encode() if isinstance(body, str) else body; self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if self.path in ("/", "/status"): self._send(200, json.dumps(w.status(), indent=1), "application/json")
            else: self._send(404, "not found\n")
        def do_POST(self):
            if self.path != "/add-checkpoint": return self._send(404, "not found\n")
            n = int(self.headers.get("Content-Length", "0"))
            if n > 1_000_000: return self._send(413, "too large\n")
            code, body = w.add_checkpoint(self.rfile.read(n).decode("utf-8", "replace")); self._send(code, body)
    ThreadingHTTPServer((host, int(port)), Hn).serve_forever()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter); sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen"); kg.add_argument("name"); kg.add_argument("keyfile")
    sv = sub.add_parser("serve"); sv.add_argument("--name", required=True); sv.add_argument("--key", required=True); sv.add_argument("--logs", required=True); sv.add_argument("--state", required=True); sv.add_argument("--listen", default="0.0.0.0:8477")
    a = ap.parse_args()
    if a.cmd == "keygen":
        priv = Ed25519PrivateKey.generate(); open(a.keyfile, "wb").write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); os.chmod(a.keyfile, 0o600)
        w = Witness(a.name, priv, [], State(os.path.dirname(os.path.abspath(a.keyfile)) + "/.nbwitness-keygen-state")); print(w.verifier_key())
    else:
        priv = serialization.load_pem_private_key(open(a.key, "rb").read(), None)
        w = Witness(a.name, priv, json.load(open(a.logs))["logs"], State(a.state)); sys.stderr.write(f"nbwitness {a.name} on {a.listen}; verifier key {w.verifier_key()}\n"); serve(w, a.listen)
