#!/usr/bin/env python3
"""beacon-agentd — machine-to-machine service on every role host; replaces the SSH forced command (2026-09-13).

Bill: "machine to machine communication... not ssh." Runs as the confined `beacon` user (the one that owns this host's
signing key and, on the entropy host, the held entropy). Listens on TCP (LAN) and answers exactly the operations the
forced command answered - attest / commit / reveal-prepare / abandon-prepare / finalize / pending - with the same
argument validation and the same per-phase monotonic sequence file (~beacon/state.json), so a request can never make
this host sign a lower seq than it already signed.

Authentication is per message, not per session: a request is an Ed25519-signed statement by an AGGREGATOR key pinned
in /etc/beacon/agentd.json (the same keys keys/KEYS.json lists), addressed to this host, fresh (+-MAX_SKEW_S) and with
an unseen nonce. Anything else is dropped. There is no shell, no file access, no other operation, no TLS handshake
and no login. Responses that carry a secret (reveal-prepare: the entropy E) are SEALED to the requester's ephemeral
X25519 key from the signed request (HKDF-SHA256 -> ChaCha20-Poly1305, AAD = the request bytes), so E is not readable
on the wire even though it becomes public in the reveal pulse seconds later.

Wire: one request per TCP connection: 4-byte big-endian length + JSON {"req": {...}, "sig": {...}}; response the same
framing: {"ok": true, "stdout": "<what the host script printed>"} | {"ok": true, "sealed": {...}} | {"ok": false, "error"}.
The host scripts (attest_host.py, entropy_host.py) run as subprocesses exactly as under beacon-cmd, with BEACON_VIA=agentd
so their `execution` self-report says how they were invoked (schema.execution_ok accepts either path against the pinned
hashes in hosts/EXPECTED.json).
"""
import os, sys, json, re, time, base64, hashlib, socket, socketserver, subprocess, fcntl, threading, collections
sys.path.insert(0, os.path.expanduser("~beacon/beacon")); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest_lib as A
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CFG = json.load(open("/etc/beacon/host.json"))                     # role, host, probe, kind - fixed on the host, never from the caller
ACFG = json.load(open("/etc/beacon/agentd.json"))                  # listen, port, aggregators[{host, public_key_b64}], max_skew_s
HOME = os.path.expanduser("~beacon"); STATE = os.path.join(HOME, "state.json"); BEACON = os.path.join(HOME, "beacon")
HEX64 = re.compile(r"^[0-9a-f]{64}$"); PHASES = ("commit", "reveal", "failure"); MAX_SKEW = int(ACFG.get("max_skew_s", 30))
PINNED = {a["public_key_b64"]: a["host"] for a in ACFG["aggregators"]}
SEALED_OPS = {"reveal-prepare"}
_seen = collections.OrderedDict(); _seen_lock = threading.Lock()
def log(m): print(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime(time.time())) + m, file=sys.__stdout__, flush=True)   # immune to the in-process stdout capture

def monotonic(phase, seq):
    """Same file, same rule as beacon-cmd: never sign a lower seq than already signed for this phase."""
    with open(STATE, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX); f.seek(0); st = json.loads(f.read() or "{}")
        if seq < st.get(phase, 0): raise ValueError(f"seq {seq} < last signed {st.get(phase, 0)} for phase {phase}")
        st[phase] = seq; f.seek(0); f.truncate(); f.write(json.dumps(st))

INPROC = bool(ACFG.get("inproc", True)); _exec_lock = threading.Lock(); _mods = {}
def _module(name):
    """Import a host script once (attest_host / entropy_host) so a request does not pay the interpreter and library
    start-up: measured 0.45 s per call on protectli (Celeron J3160) for `entropy_host.py pending` as a subprocess."""
    import importlib.util
    if name not in _mods:
        spec = importlib.util.spec_from_file_location(name, os.path.join(BEACON, name + ".py")); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); _mods[name] = m
    return _mods[name]

def run(cmd, nonce):
    """Run a host script for this request. In-process (default): the same file, same user, same code path as under the
    forced command, with its stdout captured and its sys.exit turned into an error; requests are serialised. Subprocess
    (inproc=false in agentd.json): identical to beacon-cmd."""
    if not INPROC or cmd[1].endswith(("attest_host.py", "entropy_host.py")) is False:
        env = dict(os.environ, BEACON_VIA="agentd", BEACON_REQUEST_NONCE=nonce, HOME=HOME)
        r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=150, env=env)
        if r.returncode != 0: raise RuntimeError((r.stderr or r.stdout).strip()[:400] or f"exit {r.returncode}")
        return r.stdout
    import io as _io, contextlib
    name = os.path.basename(cmd[1])[:-3]; argv = cmd[2:]
    with _exec_lock:
        os.environ["BEACON_VIA"] = "agentd"; os.environ["BEACON_REQUEST_NONCE"] = nonce; os.environ["HOME"] = HOME
        m = _module(name); out, err = _io.StringIO(), _io.StringIO(); old_argv = sys.argv
        try:
            sys.argv = [cmd[1]] + argv
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                if name == "attest_host": m.main()
                else:
                    a = argv
                    {"commit": lambda: m.cmd_commit(a[1], a[2], a[3]), "reveal-prepare": lambda: m.cmd_reveal(a[1], a[2]),
                     "abandon-prepare": lambda: m.cmd_abandon(a[1], a[2], " ".join(a[3:]) or "unspecified"),
                     "finalize": lambda: m.cmd_finalize(a[1], a[2]), "pending": lambda: print(json.dumps(m.glob_pending()))}[a[0]]()
        except SystemExit as e:
            if e.code not in (0, None): raise RuntimeError((err.getvalue() or out.getvalue()).strip()[:400] or f"exit {e.code}")
        finally:
            sys.argv = old_argv
        return out.getvalue()

def dispatch(op, a, nonce):
    """The allow-list of beacon-cmd, verbatim in behaviour."""
    if CFG["kind"] == "attest":
        if op != "attest" or len(a) != 4: raise ValueError("usage: attest <phase> <seq> <binding> <chain_hash>")
        phase, seq, binding, chain = a
        if phase not in PHASES or not seq.isdigit() or not HEX64.match(binding) or not HEX64.match(chain): raise ValueError("bad argument")
        monotonic(phase, int(seq))
        return run(["python3", os.path.join(BEACON, "attest_host.py"), CFG["role"], CFG["host"], seq, phase, binding, chain, "--"] + CFG["probe"], nonce)
    if CFG["kind"] == "entropy":
        E = os.path.join(BEACON, "entropy_host.py")
        if op == "commit" and len(a) == 3 and a[0].isdigit() and a[1].isdigit() and HEX64.match(a[2]):
            monotonic("commit", int(a[0])); return run(["python3", E, "commit", a[0], a[1], a[2]], nonce)
        if op == "reveal-prepare" and len(a) == 2 and a[0].isdigit() and HEX64.match(a[1]):
            monotonic("reveal", int(a[0])); return run(["python3", E, "reveal-prepare", a[0], a[1]], nonce)
        if op == "abandon-prepare" and len(a) >= 3 and a[0].isdigit() and HEX64.match(a[1]):
            reason = re.sub(r"[^A-Za-z0-9 ._:{}\",=-]", "", " ".join(a[2:]))[:200]
            monotonic("failure", int(a[0])); return run(["python3", E, "abandon-prepare", a[0], a[1], reason], nonce)
        if op == "finalize" and len(a) == 2 and a[0].isdigit() and HEX64.match(a[1]): return run(["python3", E, "finalize", a[0], a[1]], nonce)
        if op == "pending" and len(a) == 0: return run(["python3", E, "pending"], nonce)
        raise ValueError("operation not allowed: " + op)
    raise ValueError("misconfigured host")

def authenticate(msg):
    """Signed by a pinned aggregator key, addressed to me, fresh, nonce unseen. Returns (req, aggregator_host)."""
    req, sig = msg["req"], msg["sig"]
    if req.get("v") != 1 or req.get("to") != CFG["host"]: raise ValueError("not addressed to this host")
    pk_b64 = sig.get("public_key_b64")
    if pk_b64 not in PINNED: raise ValueError("signer is not a pinned aggregator key")
    if sig.get("alg") != "ed25519" or hashlib.sha256(base64.b64decode(pk_b64)).hexdigest()[:16] != sig.get("key_id"): raise ValueError("bad key_id")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_b64)).verify(base64.b64decode(sig["sig_b64"]), A.canon(req))
    if not isinstance(req.get("ts"), int) or abs(time.time() - req["ts"]) > MAX_SKEW: raise ValueError("request timestamp outside the skew window")
    nonce = req.get("nonce", "")
    if not re.match(r"^[0-9a-f]{16,64}$", nonce): raise ValueError("bad nonce")
    with _seen_lock:
        if nonce in _seen: raise ValueError("nonce already used")
        _seen[nonce] = time.time()
        while len(_seen) > 4096: _seen.popitem(last=False)
    if not isinstance(req.get("args"), list) or not all(isinstance(x, str) and len(x) <= 300 for x in req["args"]) or len(req["args"]) > 8: raise ValueError("bad args")
    return req, PINNED[pk_b64]

def seal(plaintext: bytes, epk_b64: str, aad: bytes):
    eph = X25519PrivateKey.generate(); shared = eph.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(epk_b64)))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"beacon-agentd/v1").derive(shared)
    nonce = os.urandom(12); ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return {"alg": "x25519+hkdf-sha256+chacha20poly1305", "spk": base64.b64encode(eph.public_key().public_bytes_raw()).decode(),
            "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode(), "aad": "canon(req)"}

def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: raise ValueError("short header")
        hdr += c
    n = int.from_bytes(hdr, "big")
    if n > 65536: raise ValueError("request too large")
    buf = b""
    while len(buf) < n:
        c = sock.recv(min(65536, n - len(buf)))
        if not c: raise ValueError("short body")
        buf += c
    return buf
def send_msg(sock, obj):
    b = json.dumps(obj, separators=(",", ":")).encode(); sock.sendall(len(b).to_bytes(4, "big") + b)

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        t0 = time.time(); peer = self.client_address[0]; self.request.settimeout(160)
        try:
            raw = recv_msg(self.request); msg = json.loads(raw)
            req, who = authenticate(msg)
        except Exception as e:
            log(f"REFUSED from {peer}: {type(e).__name__}: {str(e)[:80]}")
            try: send_msg(self.request, {"ok": False, "error": f"refused: {type(e).__name__}"})
            except Exception: pass
            return
        try:
            out = dispatch(req["op"], req["args"], req["nonce"])
            if req["op"] in SEALED_OPS:
                resp = {"ok": True, "sealed": seal(out.encode(), req["epk"], A.canon(req))}
            else: resp = {"ok": True, "stdout": out}
            send_msg(self.request, resp)
            log(f"{who}@{peer} {req['op']} {' '.join(req['args'][:2])}: ok in {time.time() - t0:.3f} s")
        except Exception as e:
            log(f"{who}@{peer} {req['op']} {' '.join(req['args'][:2])}: {type(e).__name__}: {str(e)[:120]}")
            try: send_msg(self.request, {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}"})
            except Exception: pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True

if __name__ == "__main__":
    addr = (ACFG.get("listen", "0.0.0.0"), int(ACFG.get("port", 5520)))
    log(f"beacon-agentd: {CFG['kind']} {CFG.get('role')} @ {CFG['host']} listening on {addr[0]}:{addr[1]}; pinned aggregators: {sorted(set(PINNED.values()))}")
    with Server(addr, Handler) as srv: srv.serve_forever()
