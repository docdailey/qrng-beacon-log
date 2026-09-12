#!/usr/bin/env python3
"""tlog.py — RFC 6962 Merkle tree over the pulse chain, C2SP checkpoints and signed notes (TLOG.md).

Leaf n (0-based index = seq - 1) = canonical(J) where J is the complete parsed JSON of chain/pulse-NNNN.json and
canonical = json.dumps(sort_keys, separators=(",",":"), ensure_ascii=False) as UTF-8. Tree = RFC 6962 §2.1 exactly:
leaf hash SHA-256(0x00||d), node SHA-256(0x01||L||R), split k = largest power of two strictly less than n.
NOT the archive tree in merkle/ (that one promotes odd nodes and has a different leaf preimage; it is kept, not reused).

  tlog.py root                        root hash + size over chain/
  tlog.py inclusion <seq>             audit path for one pulse (JSON)
  tlog.py consistency <m> <n>         consistency proof between sizes m < n (JSON)
  tlog.py checkpoint --origin O       unsigned checkpoint body for the current size
  tlog.py sign --origin O --key K     signed note (checkpoint + Ed25519 signature line)
  tlog.py verify <checkpoint-file> --origin O --pub P.pub [--old <older-checkpoint>]
                                      verify signature, recompute root at its size, and consistency with an older one
  tlog.py keygen <path>               new Ed25519 checkpoint key (PEM) + .pub
  tlog.py selftest                    RFC 6962 / CT test vectors and signed-note round trip
"""
import sys, os, json, base64, hashlib, glob, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__)); CHAIN = os.path.join(HERE, "chain")
def canonical(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def H(b): return hashlib.sha256(b).digest()
def leaf_hash(d): return H(b"\x00" + d)
def node_hash(l, r): return H(b"\x01" + l + r)
def largest_pow2_below(n):                       # k: largest power of two strictly less than n (n >= 2)
    k = 1
    while k * 2 < n: k *= 2
    return k

# ---------------------------------------------------------------- RFC 6962 §2.1
def mth(leaves):
    n = len(leaves)
    if n == 0: return H(b"")
    if n == 1: return leaf_hash(leaves[0])
    k = largest_pow2_below(n); return node_hash(mth(leaves[:k]), mth(leaves[k:]))

def inclusion_path(m, leaves):                  # PATH(m, D[0:n]) §2.1.1
    n = len(leaves)
    if n == 1: return []
    k = largest_pow2_below(n)
    return (inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]) if m < k else (inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])])

def consistency_proof(m, leaves):               # PROOF(m, D[0:n]) §2.1.2
    n = len(leaves)
    if m == n or m == 0: return []
    return _subproof(m, leaves, True)
def _subproof(m, D, b):
    n = len(D)
    if m == n: return [] if b else [mth(D)]
    k = largest_pow2_below(n)
    if m <= k: return _subproof(m, D[:k], b) + [mth(D[k:])]
    return _subproof(m - k, D[k:], False) + [mth(D[:k])]

def verify_inclusion(leaf_h, index, size, path, root):      # RFC 9162 §2.1.3.2
    fn, sn, r = index, size - 1, leaf_h
    for p in path:
        if sn == 0: return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0: fn >>= 1; sn >>= 1
        else: r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

def verify_consistency(m, n, proof, old_root, new_root):    # RFC 9162 §2.1.4.2
    if m == n: return proof == [] and old_root == new_root
    if m == 0: return proof == []                   # nothing to prove; any tree is consistent with the empty tree
    if m > n or not proof: return False
    if m & (m - 1) == 0: proof = [old_root] + proof # m is a power of two: its root is implied
    fn, sn = m - 1, n - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0: fn >>= 1; sn >>= 1
        else: sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

# ---------------------------------------------------------------- the chain as leaves
def chain_leaves(chain_dir=CHAIN, upto=None):
    files = sorted(f for f in glob.glob(os.path.join(chain_dir, "pulse-*.json")) if re.search(r"pulse-\d{4}\.json$", f))
    leaves = []
    for i, f in enumerate(files):
        j = json.load(open(f)); seq = j["core"]["seq"]
        if seq != i + 1: raise SystemExit(f"seq gap: expected {i+1}, found {seq} in {os.path.basename(f)} — leaf index = seq-1 requires dense seqs")
        leaves.append(canonical(j))
    return leaves[:upto] if upto else leaves

# ---------------------------------------------------------------- checkpoint + signed note (c2sp.org/tlog-checkpoint, signed-note)
def checkpoint_body(origin, size, root): return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
def key_id(origin, pub_raw): return H(origin.encode() + b"\n" + b"\x01" + pub_raw)[:4]      # Ed25519 alg byte 0x01
def sign_note(text, origin, priv):
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(text.encode()); line = "— " + origin + " " + base64.b64encode(key_id(origin, pub_raw) + sig).decode()
    return text + "\n" + line + "\n"
def parse_note(note):
    text, _, sigs = note.partition("\n\n"); text += "\n"
    out = []
    for l in sigs.splitlines():
        m = re.match(r"^— (\S+) (\S+)$", l)
        if m: blob = base64.b64decode(m.group(2)); out.append((m.group(1), blob[:4], blob[4:]))
    return text, out
def verify_note(note, origin, pub_raw):
    text, sigs = parse_note(note); kid = key_id(origin, pub_raw); pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    for name, k, sig in sigs:
        if name == origin and k == kid:
            try: pub.verify(sig, text.encode()); return True, text
            except InvalidSignature: return False, text
    return False, text
def parse_checkpoint(text):
    lines = text.split("\n"); return lines[0], int(lines[1]), base64.b64decode(lines[2])

def load_priv(path): return serialization.load_pem_private_key(open(path, "rb").read(), None)
def load_pub_raw(path):
    k = serialization.load_pem_public_key(open(path, "rb").read()); return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# ---------------------------------------------------------------- self-test against RFC 6962 / certificate-transparency test vectors
CT_LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", b"\x50\x51\x52\x53\x54\x55\x56\x57",
             b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"]
CT_ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
CT_CONSISTENCY = {(1, 1): [], (1, 8): ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
                  (6, 8): ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"],
                  (2, 5): ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]}
# PROOF(2, D[0:5]) = [MTH(D[2:4]), MTH(D[4:5])] by RFC 6962 §2.1.2 (m=2 <= k=4 -> SUBPROOF(2, D[0:4], true) ++ MTH(D[4:5]);
# SUBPROOF(2, D[0:4], true) = SUBPROOF(2, D[0:2], true) ++ MTH(D[2:4]) = {} ++ ...). Two elements; a size-5 root never appears in it.
def selftest():
    ok = True
    def t(c, msg):
        nonlocal ok; ok &= bool(c); print(f"[{'PASS' if c else 'FAIL'}] {msg}")
    t(mth([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty tree root = SHA-256(\"\")")
    for n in range(1, 9): t(mth(CT_LEAVES[:n]).hex() == CT_ROOTS[n - 1], f"CT vector: root at size {n}")
    for (m, n), want in CT_CONSISTENCY.items():
        got = [h.hex() for h in consistency_proof(m, CT_LEAVES[:n])]; t(got == want, f"CT vector: consistency proof ({m} -> {n})")
    allc = all(verify_consistency(m, n, consistency_proof(m, CT_LEAVES[:n]), mth(CT_LEAVES[:m]), mth(CT_LEAVES[:n])) for n in range(1, 9) for m in range(0, n + 1))
    t(allc, "every consistency proof (m <= n <= 8) verifies against the two roots")
    alli = all(verify_inclusion(leaf_hash(CT_LEAVES[i]), i, n, inclusion_path(i, CT_LEAVES[:n]), mth(CT_LEAVES[:n])) for n in range(1, 9) for i in range(n))
    t(alli, "every inclusion path (i < n <= 8) verifies")
    bad = verify_consistency(3, 7, consistency_proof(3, CT_LEAVES[:7]), mth(CT_LEAVES[:3]), mth(CT_LEAVES[:6]))
    t(not bad, "a consistency proof against the wrong new root is rejected")
    priv = Ed25519PrivateKey.generate(); pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    note = sign_note(checkpoint_body("example.org/log", 45, mth(CT_LEAVES)), "example.org/log", priv)
    t(note.count("— example.org/log ") == 1 and "\n\n" in note and note.endswith("\n"), "signed note format: em dash, blank line, trailing newline")
    t(verify_note(note, "example.org/log", pub_raw)[0], "signed note verifies with the origin-bound key ID")
    t(not verify_note(note.replace("45", "46"), "example.org/log", pub_raw)[0], "a tampered note does not verify")
    t(len(key_id("example.org/log", pub_raw)) == 4, "key ID is 4 bytes = SHA-256(origin || 0x0A || 0x01 || pubkey)[:4]")
    print("\nSELFTEST " + ("PASSED" if ok else "FAILED")); return 0 if ok else 1

# ---------------------------------------------------------------- CLI
def main(a):
    if not a or a[0] in ("-h", "--help"): print(__doc__); return 2
    cmd = a[0]; opt = lambda k, d=None: a[a.index(k) + 1] if k in a else d
    if cmd == "selftest": return selftest()
    if cmd == "keygen":
        priv = Ed25519PrivateKey.generate(); p = a[1]
        open(p, "wb").write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); os.chmod(p, 0o600)
        open(p + ".pub", "wb").write(priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)); print(f"wrote {p} and {p}.pub"); return 0
    leaves = chain_leaves(opt("--chain", CHAIN)); n = len(leaves)
    if cmd == "root": print(json.dumps({"size": n, "root_sha256": mth(leaves).hex(), "root_b64": base64.b64encode(mth(leaves)).decode()})); return 0
    if cmd == "inclusion":
        seq = int(a[1]); i = seq - 1; path = inclusion_path(i, leaves)
        print(json.dumps({"seq": seq, "leaf_index": i, "tree_size": n, "leaf_hash": leaf_hash(leaves[i]).hex(), "path": [h.hex() for h in path], "root": mth(leaves).hex(),
                          "verifies": verify_inclusion(leaf_hash(leaves[i]), i, n, path, mth(leaves))}, indent=1)); return 0
    if cmd == "consistency":
        m, n2 = int(a[1]), int(a[2]); pr = consistency_proof(m, leaves[:n2])
        print(json.dumps({"old_size": m, "new_size": n2, "old_root": mth(leaves[:m]).hex(), "new_root": mth(leaves[:n2]).hex(), "proof": [h.hex() for h in pr],
                          "verifies": verify_consistency(m, n2, pr, mth(leaves[:m]), mth(leaves[:n2]))}, indent=1)); return 0
    origin = opt("--origin")
    if cmd == "checkpoint":
        if not origin: raise SystemExit("--origin required (the log's permanent identity; see TLOG.md §4.1)")
        sys.stdout.write(checkpoint_body(origin, n, mth(leaves))); return 0
    if cmd == "sign":
        if not origin or not opt("--key"): raise SystemExit("--origin and --key required")
        sys.stdout.write(sign_note(checkpoint_body(origin, n, mth(leaves)), origin, load_priv(opt("--key")))); return 0
    if cmd == "verify":
        note = open(a[1]).read(); pub_raw = load_pub_raw(opt("--pub"))
        ok, text = verify_note(note, origin, pub_raw); o, size, root = parse_checkpoint(text)
        print(f"[{'PASS' if ok else 'FAIL'}] signature by {origin} key {key_id(origin, pub_raw).hex()}")
        print(f"[{'PASS' if o == origin else 'FAIL'}] origin line is {o!r}")
        rr = mth(leaves[:size]) if size <= n else None
        print(f"[{'PASS' if rr == root else 'FAIL'}] root at size {size} recomputes from chain/ ({'ok' if rr == root else 'MISMATCH or size > chain'})")
        good = ok and o == origin and rr == root
        if opt("--old"):
            old_ok, old_text = verify_note(open(opt("--old")).read(), origin, pub_raw); oo, osize, oroot = parse_checkpoint(old_text)
            cons = old_ok and verify_consistency(osize, size, consistency_proof(osize, leaves[:size]), oroot, root)
            print(f"[{'PASS' if cons else 'FAIL'}] consistent with older checkpoint at size {osize} (append-only)"); good &= cons
        print("CHECKPOINT " + ("VALID" if good else "INVALID")); return 0 if good else 1
    print(__doc__); return 2

if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
