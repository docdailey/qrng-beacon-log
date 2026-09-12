#!/usr/bin/env python3
"""entropy_host.py — runs ON THE ENTROPY HOST (protectli). The host generates E, HOLDS it, and signs
its own statements. The aggregator never sees E before the reveal and cannot fabricate a commitment
the host did not make.

  entropy_host.py commit  <seq> <target_round> <chain_hash>   -> signed commit statement (no E)
  entropy_host.py reveal-prepare  <seq> <commit_pulse_hash>          -> signed reveal statement (with E); secret kept as .revealing
  entropy_host.py abandon-prepare <seq> <commit_pulse_hash> <reason> -> signed failure statement bound to the commit pulse; secret kept as .abandoning
  entropy_host.py finalize        <seq> <resolving_pulse_hash>       -> ONLY after the resolving pulse is durable+published: .revealing->.revealed / .abandoning->.abandoned
  (prepare is idempotent: a crash between prepare and finalize leaves E recoverable; nothing is finalized on a promise)
"""
import sys, os, json, base64, hashlib, urllib.request, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest_lib as A

ROLE, HOST = "entropy_signer", "protectli"
API = "http://127.0.0.1:8080/api/v1"
PEND = os.path.expanduser("~/beacon/pending"); os.makedirs(PEND, exist_ok=True); os.chmod(PEND, 0o700)
COMMIT_DOMAIN = b"grok_antics/commit/v1"
TOOLS = A.tool_binding(__file__, os.path.join(os.path.dirname(os.path.abspath(__file__)), "attest_lib.py"))

def die(m): sys.stderr.write("entropy_host: " + m + "\n"); sys.exit(2)

def device_info():
    with urllib.request.urlopen(API + "/info", timeout=10) as r: d = json.load(r)["data"]
    return {"manufacturer": d["manufacturer"], "product": d["product"], "serial": d["serial_number"],
            "board_version": d["board_version"], "data_rate_bps": d["data_rate"]}

def fresh_entropy(n=32):
    with urllib.request.urlopen(f"{API}/random/bytes?count={n}&format=base64&correction=none", timeout=20) as r:
        d = json.load(r)
    if not d.get("success"): die("QRNG API error")
    b = base64.b64decode(d["data"]["bytes"])
    if len(b) != n: die("short read")
    return b

def cmd_commit(seq, target_round, chain_hash):
    sp = os.path.join(PEND, f"{int(seq):04d}.secret")
    if os.path.exists(sp): die(f"seq {seq} already has a held secret; reveal or abandon it first")
    if glob_pending(): die("another commit is pending on this host: " + ", ".join(glob_pending()))
    E = fresh_entropy(32)
    commitment = hashlib.sha256(COMMIT_DOMAIN + E).hexdigest()
    st = A.base_statement(ROLE, HOST, seq, "commit", commitment, chain_hash, TOOLS)
    st.update({"entropy_commitment": commitment, "commitment_scheme": "SHA256(domain||E)",
               "commit_domain": COMMIT_DOMAIN.decode(), "entropy_len_bytes": 32,
               "target_round": int(target_round), "device": device_info(), "correction": "none",
               "custody": "E generated and held on this host; released only by this host's reveal"})
    signed = A.sign_statement(ROLE, st)
    fd = os.open(sp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps({"seq": int(seq), "E": E.hex(), "commitment": commitment,
                             "target_round": int(target_round), "chain_hash": chain_hash,
                             "statement_sig": signed["signature"]["sig_b64"]}).encode()); os.close(fd)
    print(json.dumps(signed))

def _find(seq, states):
    for st in states:
        p = os.path.join(PEND, f"{int(seq):04d}.{st}")
        if os.path.exists(p): return p, st
    return None, None

def cmd_reveal(seq, commit_pulse_hash):          # reveal-prepare
    sp, st = _find(seq, ("secret", "revealing"))
    if not sp: die(f"no held or revealing secret for seq {seq}")
    if st == "secret": os.replace(sp, sp.replace(".secret", ".revealing")); sp = sp.replace(".secret", ".revealing")
    sec = json.load(open(sp)); E = bytes.fromhex(sec["E"])
    if hashlib.sha256(COMMIT_DOMAIN + E).hexdigest() != sec["commitment"]: die("held E does not match commitment")
    # host-side check that the target round has actually been released (drand's own clock)
    released = None
    for base in ("https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh"):
        try:
            with urllib.request.urlopen(f"{base}/{sec['chain_hash']}/public/latest", timeout=10) as r:
                released = json.load(r)["round"]; break
        except Exception: continue
    if released is None: die("cannot reach drand to confirm the target round is released")
    if released < sec["target_round"]: die(f"drand at round {released}; target {sec['target_round']} not yet released")
    st = A.base_statement(ROLE, HOST, seq, "reveal", commit_pulse_hash, sec["chain_hash"], TOOLS)
    st.update({"commit_seq": int(seq), "commit_pulse_hash": commit_pulse_hash, "entropy_hex": E.hex(),
               "entropy_commitment": sec["commitment"], "target_round": sec["target_round"],
               "drand_latest_round_seen_by_host": released,
               "commit_statement_sig_b64": sec["statement_sig"]})
    signed = A.sign_statement(ROLE, st)
    print(json.dumps(signed))                    # NOT finalized here: see cmd_finalize

def cmd_abandon(seq, commit_pulse_hash, reason):  # abandon-prepare; binds to the COMMIT PULSE HASH per PROTOCOL v0.5
    sp, st0 = _find(seq, ("secret", "revealing", "abandoning"))
    if not sp: die(f"no secret for seq {seq}")
    if st0 != "abandoning": os.replace(sp, os.path.join(PEND, f"{int(seq):04d}.abandoning")); sp = os.path.join(PEND, f"{int(seq):04d}.abandoning")
    sec = json.load(open(sp))
    st = A.base_statement(ROLE, HOST, seq, "failure", commit_pulse_hash, sec["chain_hash"], TOOLS)
    st.update({"commit_seq": int(seq), "commit_pulse_hash": commit_pulse_hash, "entropy_commitment": sec["commitment"],
               "target_round": sec["target_round"], "reason": reason,
               "custody": "E retired unrevealed; this host will never disclose it"})
    print(json.dumps(A.sign_statement(ROLE, st)))

def cmd_finalize(seq, resolving_pulse_hash):
    """Called by the aggregator ONLY after the reveal/failure pulse is written AND pushed. Idempotent."""
    sp, st = _find(seq, ("revealing", "abandoning", "revealed", "abandoned"))
    if not sp: die(f"nothing to finalize for seq {seq}")
    if st in ("revealed", "abandoned"): print(json.dumps({"seq": int(seq), "state": st, "already": True})); return
    final = sp.replace(".revealing", ".revealed").replace(".abandoning", ".abandoned")
    sec = json.load(open(sp)); sec["resolved_by_pulse_hash"] = resolving_pulse_hash; sec["finalized_unix"] = int(time.time())
    if st == "revealing": pass                                  # E may remain on disk; it is public now
    json.dump(sec, open(sp, "w")); os.replace(sp, final)
    print(json.dumps({"seq": int(seq), "state": os.path.basename(final).split(".")[-1], "resolved_by": resolving_pulse_hash}))

def glob_pending():
    return sorted(f for f in os.listdir(PEND) if f.endswith((".secret", ".revealing", ".abandoning")))

if __name__ == "__main__":
    a = sys.argv[1:]
    {"commit": lambda: cmd_commit(a[1], a[2], a[3]),
     "reveal-prepare": lambda: cmd_reveal(a[1], a[2]),
     "abandon-prepare": lambda: cmd_abandon(a[1], a[2], " ".join(a[3:]) or "unspecified"),
     "finalize": lambda: cmd_finalize(a[1], a[2]),
     "pending": lambda: print(json.dumps(glob_pending()))}[a[0]]()
