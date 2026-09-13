#!/usr/bin/env python3
"""m2m_bench.py — lab benchmark of the aggregator <-> role host hop: our length-prefixed TCP protocol vs ZeroMQ.

Same work on every transport: the client sends an Ed25519-SIGNED request (~700 B, a real statement shape), the server
verifies it, builds a statement-sized response (RESP_BYTES, default 6000 B, like an attest statement), signs it, and the
client verifies the response. What differs is only the transport:

  tcp-per-call    our beacon-agentd framing: connect, one request, one response, close      (what runs today)
  tcp-persistent  same framing over one connection kept open                              (an obvious variant)
  zmq-req         ZeroMQ REQ/REP over tcp, one persistent socket
  zmq-req-percall ZeroMQ REQ/REP, a new socket + connect per call
  zmq-curve       ZeroMQ REQ/REP with CurveZMQ (built-in encryption + server auth) on a persistent socket
  udp-oneway      one-way p550 -> k3 style datagram: sender stamps t_send, receiver stamps t_recv (synchronised clocks)
  zmq-pubsub      one-way ZeroMQ PUB/SUB over tcp, same stamps

  server:  m2m_bench.py server [--port 5531] [--resp-bytes 6000]        (runs tcp on port, zmq-rep on port+1, curve on port+2, pub on port+3)
  client:  m2m_bench.py client <host> [--port 5531] [--n 200] [--resp-bytes 6000]
  oneway:  m2m_bench.py recv-oneway [--port 5540] / send-oneway <host> [--port 5540] [--n 200]
"""
import sys, os, json, time, socket, base64, hashlib, secrets, statistics, argparse, threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
CLIENT_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"bench-client").digest()); CLIENT_PUB = CLIENT_KEY.public_key()
SERVER_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"bench-server").digest()); SERVER_PUB = SERVER_KEY.public_key()

def make_request(host):
    req = {"v": 1, "to": host, "op": "attest", "args": ["commit", "96", "ab" * 32, "cd" * 32], "from": "k3", "ts": int(time.time()),
           "nonce": secrets.token_hex(16), "epk": base64.b64encode(os.urandom(32)).decode()}
    return json.dumps({"req": req, "sig": base64.b64encode(CLIENT_KEY.sign(canon(req))).decode()}, separators=(",", ":")).encode()
def check_request(b):
    m = json.loads(b); CLIENT_PUB.verify(base64.b64decode(m["sig"]), canon(m["req"])); return m["req"]
def make_response(req, n):
    st = {"v": "0.5", "role": "time_attester", "host": req["to"], "seq": 96, "phase": "commit", "nonce": req["nonce"], "measurement": "x" * max(0, n - 300)}
    return json.dumps({"statement": st, "signature": base64.b64encode(SERVER_KEY.sign(canon(st))).decode()}, separators=(",", ":")).encode()
def check_response(b):
    m = json.loads(b); SERVER_PUB.verify(base64.b64decode(m["signature"]), canon(m["statement"])); return m

# ---- our framing
def send_msg(sock, b): sock.sendall(len(b).to_bytes(4, "big") + b)
def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: raise RuntimeError("eof")
        hdr += c
    n = int.from_bytes(hdr, "big"); buf = b""
    while len(buf) < n:
        c = sock.recv(min(65536, n - len(buf)))
        if not c: raise RuntimeError("eof")
        buf += c
    return buf

def tcp_server(port, resp_bytes):
    import socketserver
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                while True:
                    req = check_request(recv_msg(self.request)); send_msg(self.request, make_response(req, resp_bytes))
            except Exception: pass
    class S(socketserver.ThreadingTCPServer): allow_reuse_address = True; daemon_threads = True
    S(("0.0.0.0", port), H).serve_forever()

def zmq_rep_server(port, resp_bytes, curve=False):
    import zmq
    ctx = zmq.Context.instance(); s = ctx.socket(zmq.REP)
    if curve:
        pub, sec = curve_server_keys()
        s.curve_secretkey = sec; s.curve_publickey = pub; s.curve_server = True
    s.bind(f"tcp://0.0.0.0:{port}")
    while True:
        req = check_request(s.recv()); s.send(make_response(req, resp_bytes))

def curve_server_keys():
    """Deterministic CurveZMQ server keypair (z85 of a fixed 32-byte seed) so the client can pin it without a side channel."""
    import zmq
    from zmq.utils import z85
    sec = z85.encode(hashlib.sha256(b"bench-curve-server").digest()); pub = zmq.curve_public(sec)
    return pub, sec

def client(host, port, n, resp_bytes):
    ip = HOSTS.get(host, host); res = {}
    def stats(lat): 
        lat = sorted(lat); return {"n": len(lat), "min_ms": round(lat[0], 3), "p50_ms": round(lat[len(lat)//2], 3), "p90_ms": round(lat[int(len(lat)*0.9)], 3), "p99_ms": round(lat[int(len(lat)*0.99)], 3), "max_ms": round(lat[-1], 3)}
    # tcp per call (today's beacon-agentd)
    lat = []
    for i in range(n):
        t = time.perf_counter_ns()
        with socket.create_connection((ip, port), timeout=5) as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); send_msg(s, make_request(host)); check_response(recv_msg(s))
        lat.append((time.perf_counter_ns() - t) / 1e6)
    res["tcp-per-call"] = stats(lat)
    # tcp persistent
    lat = []
    with socket.create_connection((ip, port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(n):
            t = time.perf_counter_ns(); send_msg(s, make_request(host)); check_response(recv_msg(s)); lat.append((time.perf_counter_ns() - t) / 1e6)
    res["tcp-persistent"] = stats(lat)
    try:
        import zmq
        ctx = zmq.Context.instance()
        # zmq req persistent
        s = ctx.socket(zmq.REQ); s.setsockopt(zmq.LINGER, 0); s.connect(f"tcp://{ip}:{port+1}"); lat = []
        for i in range(n):
            t = time.perf_counter_ns(); s.send(make_request(host)); check_response(s.recv()); lat.append((time.perf_counter_ns() - t) / 1e6)
        s.close(); res["zmq-req"] = stats(lat)
        # zmq req, socket per call
        lat = []
        for i in range(n):
            t = time.perf_counter_ns(); s = ctx.socket(zmq.REQ); s.setsockopt(zmq.LINGER, 0); s.connect(f"tcp://{ip}:{port+1}"); s.send(make_request(host)); check_response(s.recv()); s.close(); lat.append((time.perf_counter_ns() - t) / 1e6)
        res["zmq-req-percall"] = stats(lat)
        # curve
        pub, _ = curve_server_keys(); cpub, csec = zmq.curve_keypair()
        s = ctx.socket(zmq.REQ); s.setsockopt(zmq.LINGER, 0); s.curve_secretkey = csec; s.curve_publickey = cpub; s.curve_serverkey = pub; s.connect(f"tcp://{ip}:{port+2}"); lat = []
        for i in range(n):
            t = time.perf_counter_ns(); s.send(make_request(host)); check_response(s.recv()); lat.append((time.perf_counter_ns() - t) / 1e6)
        s.close(); res["zmq-curve"] = stats(lat)
        lat = []
        for i in range(n):
            t = time.perf_counter_ns(); s = ctx.socket(zmq.REQ); s.setsockopt(zmq.LINGER, 0); s.curve_secretkey = csec; s.curve_publickey = cpub; s.curve_serverkey = pub; s.connect(f"tcp://{ip}:{port+2}"); s.send(make_request(host)); check_response(s.recv()); s.close(); lat.append((time.perf_counter_ns() - t) / 1e6)
        res["zmq-curve-percall"] = stats(lat)
    except ImportError:
        res["zmq"] = "pyzmq not installed on the client"
    return res

HOSTS = {"protectli": "192.168.70.1", "p550": "192.168.68.44", "k3": "192.168.68.24", "f9t": "192.168.68.46"}

def recv_oneway(port, n):
    """UDP and ZMQ SUB receivers; prints one-way latency stats using CLOCK_REALTIME on both ends (PHC-disciplined hosts)."""
    import zmq
    out = {}
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", port)); u.settimeout(30)
    lat = []
    for i in range(n):
        try: d, _ = u.recvfrom(65535)
        except socket.timeout: break
        if not d[:1].isdigit(): continue                                   # warm-up datagram
        lat.append((time.clock_gettime_ns(time.CLOCK_REALTIME) - int(d.split(b"|")[0])) / 1e3)
    out["udp-oneway_us"] = {"n": len(lat), "p50": round(statistics.median(lat), 1) if lat else None, "p90": round(sorted(lat)[int(len(lat)*0.9)], 1) if lat else None, "max": round(max(lat), 1) if lat else None}
    ctx = zmq.Context.instance(); s = ctx.socket(zmq.SUB); s.setsockopt(zmq.SUBSCRIBE, b""); s.setsockopt(zmq.RCVTIMEO, 30000); s.bind(f"tcp://0.0.0.0:{port+1}")
    lat = []
    for i in range(n):
        try: d = s.recv()
        except Exception: break
        lat.append((time.clock_gettime_ns(time.CLOCK_REALTIME) - int(d.split(b"|")[0])) / 1e3)
    out["zmq-pubsub-oneway_us"] = {"n": len(lat), "p50": round(statistics.median(lat), 1) if lat else None, "p90": round(sorted(lat)[int(len(lat)*0.9)], 1) if lat else None, "max": round(max(lat), 1) if lat else None}
    print(json.dumps(out))

def send_oneway(host, port, n):
    import zmq
    ip = HOSTS.get(host, host); payload = b"x" * 1900
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.sendto(b"warm", (ip, port)); time.sleep(0.2)
    for i in range(n): u.sendto(str(time.clock_gettime_ns(time.CLOCK_REALTIME)).encode() + b"|" + payload, (ip, port)); time.sleep(0.01)
    time.sleep(0.5)
    ctx = zmq.Context.instance(); s = ctx.socket(zmq.PUB); s.connect(f"tcp://{ip}:{port+1}"); time.sleep(0.5)   # let the connection come up
    for i in range(n): s.send(str(time.clock_gettime_ns(time.CLOCK_REALTIME)).encode() + b"|" + payload); time.sleep(0.01)
    time.sleep(0.5); s.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("mode"); ap.add_argument("host", nargs="?"); ap.add_argument("--port", type=int, default=5531); ap.add_argument("--n", type=int, default=200); ap.add_argument("--resp-bytes", type=int, default=6000)
    a = ap.parse_args()
    if a.mode == "server":
        threading.Thread(target=tcp_server, args=(a.port, a.resp_bytes), daemon=True).start()
        try:
            import zmq
            threading.Thread(target=zmq_rep_server, args=(a.port + 1, a.resp_bytes, False), daemon=True).start()
            threading.Thread(target=zmq_rep_server, args=(a.port + 2, a.resp_bytes, True), daemon=True).start()
        except ImportError: print("server: pyzmq missing, tcp only", flush=True)
        print(f"bench server up: tcp {a.port}, zmq-rep {a.port+1}, zmq-curve {a.port+2}, resp {a.resp_bytes} B", flush=True)
        while True: time.sleep(3600)
    elif a.mode == "client": print(json.dumps({"host": a.host, "resp_bytes": a.resp_bytes, **client(a.host, a.port, a.n, a.resp_bytes)}, indent=1))
    elif a.mode == "recv-oneway": recv_oneway(a.port, a.n)
    elif a.mode == "send-oneway": send_oneway(a.host, a.port, a.n)
