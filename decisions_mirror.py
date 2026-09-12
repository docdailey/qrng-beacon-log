#!/usr/bin/env python3
"""decisions_mirror.py — mirror notbefore.net/decisions into this repository (decisions/), verify it, and have the
witnesses cosign its checkpoint. Runs on the minting host from a systemd timer at :20 and :50 (never inside the
:00–:07 minting window). The Worker is the writer; this is the second publication surface plus the witness path.

  decisions/entries/NNNNNNNN.json   canonical leaf bytes exactly as served (RFC 6962 leaves, index = NNNNNNNN)
  decisions/checkpoint              latest note: log signature (verified against keys/decisions.pub) + witness cosignatures
  decisions/checkpoints/NNNNNNNN    every checkpoint size mirrored (anchored into Rekor by ci/anchor_pulses.py)
  decisions/INDEX.json              {"size", "namespaces": {"<key_id>/<decision_id>": [indices in seq order]}}

Nothing is trusted from the network: each leaf must be canonical, its statement must verify, the tree must recompute
to the checkpoint root, and the new checkpoint must be consistent with the previous mirrored one. Any failure leaves
the mirror untouched and exits non-zero. Exit 0 with output "changed" or "unchanged"; --push commits and pushes."""
import os, sys, json, base64, hashlib, re, time, subprocess, urllib.request, argparse
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "cli"))
import tlog as T
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

D = os.path.join(HERE, "decisions"); IDENT = json.load(open(os.path.join(HERE, "keys", "DECISIONS.json")))
ORIGIN = IDENT["origin"]; BASE = os.environ.get("NOTBEFORE_DECISIONS_URL") or IDENT["base_url"]
PUB = T.load_pub_raw(os.path.join(HERE, "keys", os.path.basename(IDENT["public_key_file"])))
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def get(path):
    with urllib.request.urlopen(urllib.request.Request(BASE.rstrip("/") + path, headers={"User-Agent": "notbefore-decisions-mirror"}), timeout=25) as r: return r.read()
def log(m): sys.stderr.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + m + "\n")

def verify_leaf(b, expect_index):
    j = json.loads(b)
    if canon(j) != b: raise ValueError(f"leaf {expect_index} not canonical")
    if j.get("spec") != "notbefore/decision-leaf/1" or j.get("index") != expect_index: raise ValueError(f"leaf {expect_index}: bad spec/index")
    st, sig = j["statement"], base64.b64decode(j["signature_b64"]); pub = base64.b64decode(st["public_key_b64"])
    if hashlib.sha256(pub).hexdigest()[:16] != st["key_id"]: raise ValueError(f"leaf {expect_index}: key_id mismatch")
    try: Ed25519PublicKey.from_public_bytes(pub).verify(sig, canon(st))
    except InvalidSignature: raise ValueError(f"leaf {expect_index}: statement signature invalid")
    return j

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--push", action="store_true", help="commit and push if anything changed"); a = ap.parse_args()
    os.makedirs(os.path.join(D, "entries"), exist_ok=True); os.makedirs(os.path.join(D, "checkpoints"), exist_ok=True)
    have = sorted(int(f[:8]) for f in os.listdir(os.path.join(D, "entries")) if re.fullmatch(r"\d{8}\.json", f))
    if have != list(range(len(have))): sys.exit(f"mirror has a gap in decisions/entries: {have[:3]}…")
    leaves = [open(os.path.join(D, "entries", f"{i:08d}.json"), "rb").read() for i in have]
    note = get("/decisions/checkpoint").decode()
    ok, text = T.verify_note(note, ORIGIN, PUB)
    if not ok: sys.exit("served checkpoint does NOT verify under keys/decisions.pub — refusing to mirror")
    o, size, root = T.parse_checkpoint(text)
    if o != ORIGIN: sys.exit(f"origin line {o!r} != {ORIGIN!r}")
    if size < len(leaves): sys.exit(f"served size {size} < mirrored {len(leaves)}: ROLLBACK at the log — keep this mirror as evidence")
    # fetch new leaves in pages; verify each
    i = len(leaves)
    while i < size:
        page = json.loads(get(f"/decisions/leaves?from={i}&to={min(size, i + 500)}"))
        got = page["leaves"]
        if not got: sys.exit(f"log served no leaves from {i} though size is {size}")
        for lt in got:
            b = lt.encode(); verify_leaf(b, i); leaves.append(b); i += 1
    if T.mth(leaves[:size]) != root: sys.exit(f"tree of {size} mirrored leaves does not recompute to the served root")
    # consistency with the previous mirrored checkpoint (append-only across time, from our own record)
    prev_p = os.path.join(D, "checkpoint"); prev = open(prev_p).read() if os.path.exists(prev_p) else None
    if prev:
        pok, ptext = T.verify_note(prev, ORIGIN, PUB); _, psize, proot = T.parse_checkpoint(ptext)
        if not pok or not T.verify_consistency(psize, size, T.consistency_proof(psize, leaves[:size]) if 0 < psize < size else [], proot, root):
            if not (psize == size and proot == root): sys.exit(f"served checkpoint (size {size}) is NOT consistent with the previously mirrored one (size {psize}) — split view; refusing")
    changed = False
    for idx in range(len(have), size):
        open(os.path.join(D, "entries", f"{idx:08d}.json"), "wb").write(leaves[idx]); changed = True
    # witness cosignatures on the log-signed note (the log's own signature line stays first)
    cos = ""
    try:
        cos = T.gather_cosignatures(note, leaves[:size], HERE, log=log) if size > 0 else ""
    except Exception as e: log(f"witness cosignature round failed: {e}")
    full = note + (cos or "")
    cp = os.path.join(D, "checkpoints", f"{size:08d}")
    if not os.path.exists(cp) or (prev or "") != full:
        open(cp, "w").write(full); open(prev_p, "w").write(full); changed = True
    ns = {}
    for idx, b in enumerate(leaves[:size]):
        st = json.loads(b)["statement"]; ns.setdefault(f"{st['key_id']}/{st['decision_id']}", []).append(idx)
    index = {"origin": ORIGIN, "size": size, "root_b64": base64.b64encode(root).decode(), "mirrored_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "namespaces": ns,
             "note": "first index in each namespace list is the authoritative preregistration (seq_in_namespace 1); later indices are amendments"}
    ip = os.path.join(D, "INDEX.json"); new_index = json.dumps(index, indent=1, sort_keys=True) + "\n"
    if not os.path.exists(ip) or json.load(open(ip)).get("size") != size or json.load(open(ip)).get("namespaces") != ns:
        open(ip, "w").write(new_index); changed = True
    print("changed" if changed else "unchanged")
    if changed and a.push:
        subprocess.run(["git", "add", "-A", "decisions"], cwd=HERE, check=True)
        if subprocess.run(["git", "status", "--porcelain", "decisions"], cwd=HERE, capture_output=True, text=True).stdout.strip():
            subprocess.run(["git", "commit", "-q", "-m", f"DECISIONS mirror: size {size}"], cwd=HERE, check=True)
            for attempt in range(3):
                if subprocess.run(["git", "push", "-q", "origin", "main"], cwd=HERE, stdin=subprocess.DEVNULL).returncode == 0: break
                subprocess.run(["git", "pull", "-q", "--rebase", "origin", "main"], cwd=HERE, check=True, stdin=subprocess.DEVNULL)
            else: sys.exit("push rejected 3 times")
    return 0

if __name__ == "__main__": sys.exit(main())
