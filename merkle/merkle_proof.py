#!/usr/bin/env python3
"""merkle_proof.py — inclusion proofs for the quantum_cache archive commitment.

  merkle_proof.py root   [--rehashed]           recompute the root from leaves.tsv (or leaves-rehashed.tsv), compare to the manifest
  merkle_proof.py prove  <filename> [--rehashed] emit a JSON inclusion proof for one archived block
  merkle_proof.py verify <proof.json>            verify a proof against the root in the proof (no leaf list needed)

Two manifests exist (ERR-006): manifest.json / leaves.tsv commit to the CAPTURE-TIME SIDECAR hashes (wrong for 1,217
blocks); manifest-rehashed.json / leaves-rehashed.tsv commit to the RECOMPUTED bytes of every block and carry a per-leaf
sidecar_concordance flag. --rehashed selects the latter, which is the archive root to cite.

Leaf = SHA256(0x00 || filename || 0x00 || sha256_hex); Node = SHA256(0x01 || left || right);
an odd node at any level is promoted unchanged. Leaves sorted by filename.
"""
import sys, json, hashlib, os
HERE = os.path.dirname(os.path.abspath(__file__))
REHASHED = "--rehashed" in sys.argv
LEAVES = "leaves-rehashed.tsv" if REHASHED else "leaves.tsv"
MANIFEST = "manifest-rehashed.json" if REHASHED else "manifest.json"
def H(b): return hashlib.sha256(b).digest()
def load_leaves():
    """Rows: (filename, hash, size, relpath[, sidecar_hash, concordance]) — the rehashed file has a header and 6 cols."""
    out = []
    for l in open(os.path.join(HERE, LEAVES)):
        r = l.rstrip("\n").split("\t")
        if r[0] == "filename": continue
        if REHASHED: out.append([r[0], r[1], r[3], r[4], r[2], r[5]])      # filename, recomputed, size, relpath, sidecar, concordance
        else: out.append(r)
    out.sort(key=lambda r: r[0]); return out
def leaf_hash(name, sha): return H(b"\x00" + name.encode() + b"\x00" + sha.encode())
def build_levels(leaves):
    levels = [[leaf_hash(r[0], r[1]) for r in leaves]]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(H(b"\x01" + cur[i] + cur[i+1]) if i + 1 < len(cur) else cur[i])
        levels.append(nxt)
    return levels
def cmd_root():
    m = json.load(open(os.path.join(HERE, MANIFEST)))
    lv = build_levels(load_leaves()); root = lv[-1][0].hex()
    print("recomputed root:", root); print("manifest root:  ", m["root"]); print("MATCH" if root == m["root"] else "MISMATCH")
    return 0 if root == m["root"] else 1
def cmd_prove(name):
    leaves = load_leaves(); idx = next((i for i, r in enumerate(leaves) if r[0] == name), None)
    if idx is None: print("not in manifest:", name); return 1
    lv = build_levels(leaves); path = []; i = idx
    for level in lv[:-1]:
        sib = i ^ 1
        if sib < len(level): path.append({"side": "right" if sib > i else "left", "hash": level[sib].hex()})
        else: path.append(None)          # odd node promoted: no sibling at this level
        i //= 2
    m = json.load(open(os.path.join(HERE, MANIFEST)))
    proof = {"scheme": m["scheme"], "manifest": MANIFEST, "root": m["root"], "leaves": m["leaves"], "index": idx,
             "filename": name, "sha256": leaves[idx][1], "size_bytes": int(leaves[idx][2]),
             "relpath": leaves[idx][3], "path": path,
             "verify": "python3 merkle_proof.py verify <this file>",
             **({"sidecar_sha256": leaves[idx][4], "sidecar_concordance": leaves[idx][5] == "true",
                 "provenance": ("capture-time sidecar matches the bytes: provenance chain intact from 2025" if leaves[idx][5] == "true"
                                else "capture-time sidecar does NOT match the bytes: provenance dated 2026-09-12 (re-hash) only; no capture-time claim")} if REHASHED else {}),
             "what_this_proves": ("This block (filename + sha256) is one of the %d leaves committed under root %s. "
                                  "Hash the block yourself and compare to sha256 to bind the bytes to the commitment."
                                  % (m["leaves"], m["root"]))}
    print(json.dumps(proof, indent=2)); return 0
def cmd_verify(path):
    pr = json.load(open(path)); h = leaf_hash(pr["filename"], pr["sha256"])
    for step in pr["path"]:
        if step is None: continue
        s = bytes.fromhex(step["hash"]); h = H(b"\x01" + (h + s if step["side"] == "right" else s + h))
    ok = h.hex() == pr["root"]
    print("recomputed:", h.hex()); print("root:      ", pr["root"]); print("PROOF VALID" if ok else "PROOF INVALID"); return 0 if ok else 1
if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if x != "--rehashed"]
    sys.exit({"root": lambda: cmd_root(), "prove": lambda: cmd_prove(a[1]), "verify": lambda: cmd_verify(a[1])}[a[0]]())
