#!/usr/bin/env python3
"""anchor_lib.py — publication anchors for the pulse chain (shared by ci/anchor_pulses.py and ci/verify_anchors.py).

WHY. The chain is a single-writer transparency log. Nothing inside it can stop the operator from producing two
different valid pulse-N's on the same prev_hash and showing each to a different audience (a split view). What
exposes that is an append-only record OUTSIDE the operator's control in which every published pulse is entered:
  * Rekor (https://rekor.sigstore.dev), the public Sigstore transparency log: a hashedrekord entry = SHA-256 of the
    canonical anchor statement below + a signature by the beacon's dedicated ANCHOR KEY (keys/anchor.pub).
    Rekor returns a signed inclusion proof, a signed checkpoint, and an integratedTime from Rekor's own clock.
    Anyone can enumerate every entry ever made under the anchor key; an entry that does not correspond to a
    published pulse is public evidence of a hidden branch.
  * OpenTimestamps: the same statement digest is committed into the Bitcoin block chain through free calendar
    servers. This is a timestamp proof (a Merkle path to a public block header); no coins are held, bought, or paid.

The STATEMENT is derivable from the pulse file alone, so a verifier can recompute it, hash it, and ask Rekor for
that hash without trusting anything in the `anchors` branch.
"""
import json, base64, hashlib, urllib.request, urllib.error, os, re, subprocess, time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

ANCHOR_VERSION = "qrng-beacon-log/anchor/1"
REPO = "github.com/docdailey/qrng-beacon-log"
GENESIS_PULSE_HASH = "31f2ff09899f5f60b9c9e5e6990ddd2202380709fb43e89c67dbceeb9510925b"   # pulse-0001
REKOR = os.environ.get("REKOR_URL", "https://rekor.sigstore.dev")
REKOR_LOG_ID = os.environ.get("REKOR_LOG_ID", "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d")   # sha256(DER SPKI of keys/rekor.pub); env override is for staging tests only
PULSE_RE = re.compile(r"pulse-(\d{4})\.json$")

def sha256(b): return hashlib.sha256(b).hexdigest()
def canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# ------------------------------------------------------------------ statement
def statement_for(pulse_path):
    """Canonical anchor statement bytes for one published pulse file. Deterministic: same file -> same bytes."""
    raw = open(pulse_path, "rb").read(); p = json.loads(raw); core = p["core"]
    st = {"anchor": ANCHOR_VERSION, "repo": REPO, "genesis": GENESIS_PULSE_HASH,
          "seq": int(core["seq"]), "type": core.get("type", "legacy"),
          "pulse_hash": p["pulse_hash"], "prev_hash": core["prev_hash"], "file_sha256": sha256(raw)}
    return canon(st), st

# ------------------------------------------------------------------ keys
def load_priv(pem): return serialization.load_pem_private_key(pem, password=None)
def load_pub(pem): return serialization.load_pem_public_key(pem)
def pub_pem(pub): return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
def key_id(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo); return sha256(der)
def sign(priv, data): return priv.sign(data, ec.ECDSA(hashes.SHA256()))
def verify_sig(pub, sig, data):
    try: pub.verify(sig, data, ec.ECDSA(hashes.SHA256())); return True
    except InvalidSignature: return False

# ------------------------------------------------------------------ Rekor REST
def _req(path, obj=None, timeout=40):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(REKOR + path, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, json.load(r)

def rekor_upload(statement, sig, anchor_pub_pem):
    body = {"apiVersion": "0.0.1", "kind": "hashedrekord",
            "spec": {"data": {"hash": {"algorithm": "sha256", "value": sha256(statement)}},
                     "signature": {"content": base64.b64encode(sig).decode(),
                                   "publicKey": {"content": base64.b64encode(anchor_pub_pem).decode()}}}}
    try:
        st, resp = _req("/api/v1/log/entries", body)
    except urllib.error.HTTPError as e:
        if e.code == 409:                       # already in the log: the Location header names the existing entry
            loc = e.headers.get("Location", ""); uuid = loc.rstrip("/").split("/")[-1]
            return uuid, rekor_get(uuid), "existing"
        raise
    uuid = next(iter(resp)); return uuid, resp[uuid], "created"

def rekor_get(uuid):
    st, resp = _req(f"/api/v1/log/entries/{uuid}"); return resp[uuid]

def rekor_search_by_key(anchor_pub_pem):
    st, resp = _req("/api/v1/index/retrieve", {"publicKey": {"format": "x509", "content": base64.b64encode(anchor_pub_pem).decode()}}); return resp

def rekor_search_by_hash(hexdigest):
    st, resp = _req("/api/v1/index/retrieve", {"hash": "sha256:" + hexdigest}); return resp

# ------------------------------------------------------------------ Rekor proofs (offline, against keys/rekor.pub)
def verify_set(entry, rekor_pub):
    """Signed Entry Timestamp: Rekor's ECDSA-P256/SHA-256 signature over the JCS of {body, integratedTime, logID, logIndex}."""
    payload = canon({"body": entry["body"], "integratedTime": entry["integratedTime"], "logID": entry["logID"], "logIndex": entry["logIndex"]})
    return verify_sig(rekor_pub, base64.b64decode(entry["verification"]["signedEntryTimestamp"]), payload)

def _h(b): return hashlib.sha256(b).digest()
def root_from_inclusion(leaf_hash, index, size, path):
    """RFC 9162 §2.1.3.2. Returns the computed root or None."""
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0: return None
        if (fn & 1) or fn == sn:
            r = _h(b"\x01" + p + r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0: fn >>= 1; sn >>= 1
        else:
            r = _h(b"\x01" + r + p)
        fn >>= 1; sn >>= 1
    return r if sn == 0 else None

def parse_checkpoint(text):
    """Signed-note format: '<origin>\\n<size>\\n<root_b64>\\n' + '\\n' + '— <origin> <b64(keyhash4||sig)>\\n'."""
    body, _, sigs = text.partition("\n\n")
    lines = body.split("\n"); origin, size, root_b64 = lines[0], int(lines[1]), lines[2]
    out = []
    for l in sigs.strip().split("\n"):
        m = re.match(r"^— (\S+) (\S+)$", l)
        if m: blob = base64.b64decode(m.group(2)); out.append((m.group(1), blob[:4], blob[4:]))
    return {"origin": origin, "size": size, "root": base64.b64decode(root_b64), "signed_text": (body + "\n").encode(), "sigs": out}

def verify_inclusion(entry, rekor_pub):
    """Leaf = sha256(0x00 || canonical body); path to the checkpoint root; checkpoint signed by Rekor. Returns (ok, why)."""
    ip = entry["verification"]["inclusionProof"]
    leaf = _h(b"\x00" + base64.b64decode(entry["body"]))
    path = [bytes.fromhex(x) for x in ip["hashes"]]
    root = root_from_inclusion(leaf, int(ip["logIndex"]), int(ip["treeSize"]), path)
    if root is None or root.hex() != ip["rootHash"]: return False, "inclusion path does not reach rootHash"
    cp = parse_checkpoint(ip["checkpoint"])
    if cp["size"] != int(ip["treeSize"]) or cp["root"] != root: return False, "checkpoint size/root differ from the inclusion proof"
    if not any(verify_sig(rekor_pub, sig, cp["signed_text"]) for _, _, sig in cp["sigs"]): return False, "checkpoint signature does not verify with keys/rekor.pub"
    return True, f"leaf {ip['logIndex']} in tree of {ip['treeSize']}, checkpoint '{cp['origin']}' signed by Rekor"

def entry_hash_and_key(entry):
    b = json.loads(base64.b64decode(entry["body"]))
    if b.get("kind") != "hashedrekord": return None, None
    spec = b["spec"]; return spec["data"]["hash"]["value"], base64.b64decode(spec["signature"]["publicKey"]["content"])

def entry_sig(entry):
    b = json.loads(base64.b64decode(entry["body"])); return base64.b64decode(b["spec"]["signature"]["content"])

# ------------------------------------------------------------------ OpenTimestamps
def ots_bin():
    for c in ("ots", os.path.expanduser("~/Library/Python/3.12/bin/ots"), os.path.expanduser("~/.local/bin/ots")):
        if subprocess.run(["which", c], capture_output=True).returncode == 0 or os.path.exists(c): return c
    return None

def ots_stamp(path):
    ots = ots_bin()
    if not ots: return False, "ots client not installed"
    r = subprocess.run([ots, "stamp", path], capture_output=True, text=True, timeout=180)
    return os.path.exists(path + ".ots"), (r.stdout + r.stderr).strip()[-300:]

def ots_upgrade(ots_path):
    """Returns 'complete' | 'pending' | 'error'. Upgrade rewrites the proof in place once a calendar has a Bitcoin attestation."""
    ots = ots_bin()
    if not ots: return "error"
    r = subprocess.run([ots, "upgrade", ots_path], capture_output=True, text=True, timeout=180); out = r.stdout + r.stderr
    for bak in (ots_path + ".bak",):
        if os.path.exists(bak): os.remove(bak)
    return "complete" if ots_status(ots_path) == "complete" else ("pending" if "Pending" in out or r.returncode != 0 or "not" in out.lower() else ots_status(ots_path))

def ots_attestations(ots_path):
    """[(kind, detail, msg_bytes)] — kind 'bitcoin' carries the block height; msg is the Merkle root committed to (header byte order)."""
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    with open(ots_path, "rb") as f: dt = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    out = []
    for msg, att in dt.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation): out.append(("bitcoin", att.height, msg))
        elif isinstance(att, PendingAttestation): out.append(("pending", att.uri, msg))
        else: out.append(("other", type(att).__name__, msg))
    return out, dt.file_digest

def ots_status(ots_path):
    try: atts, _ = ots_attestations(ots_path)
    except Exception: return "error"
    return "complete" if any(k == "bitcoin" for k, _, _ in atts) else "pending"

def bitcoin_header_merkle_root(height):
    """Merkle root (header byte order) of the block at `height` from two independent public header sources; a verifier
    who does not trust either should use their own node (`ots verify` against bitcoind)."""
    for base in ("https://blockstream.info/api", "https://mempool.space/api"):
        try:
            with urllib.request.urlopen(f"{base}/block-height/{height}", timeout=30) as r: bh = r.read().decode().strip()
            with urllib.request.urlopen(f"{base}/block/{bh}/header", timeout=30) as r: hdr = bytes.fromhex(r.read().decode().strip())
            if len(hdr) == 80: return hdr[36:68], base
        except Exception: continue
    return None, None

def verify_ots(ots_path, statement):
    """(status, why). 'complete' only if a Bitcoin attestation's committed Merkle root equals the public block header's."""
    atts, digest = ots_attestations(ots_path)
    if digest != hashlib.sha256(statement).digest(): return "fail", "proof is for a different file digest"
    btc = [(h, msg) for k, h, msg in atts if k == "bitcoin"]
    if not btc: return "pending", f"{len(atts)} calendar attestation(s), none in Bitcoin yet"
    for height, msg in btc:
        root, src = bitcoin_header_merkle_root(height)
        if root is None: return "unchecked", f"attested in Bitcoin block {height} but no header source reachable"
        if root == msg: return "complete", f"Bitcoin block {height} Merkle root matches (header via {src.split('/')[2]})"
    return "fail", f"Bitcoin attestation at height {btc[0][0]} does not match the block header"

def pulse_files(chain_dir):
    return sorted(os.path.join(chain_dir, f) for f in os.listdir(chain_dir) if PULSE_RE.search(f))
