"""The NotBefore decision log (DECISION-LOG.md, NOTBEFORE.md §7.12): a public, write-once, append-only log of signed
decision statements, served by notbefore.net/decisions and mirrored into this repository under decisions/.

  statement  {"spec": "notbefore/decision/1", "decision_id", "key_id", "public_key_b64", "contract_sha256", "contract_spec", "created_utc"}
  signature  Ed25519 by the consumer's identity key over canonical(statement)
  namespace  (key_id, decision_id) is WRITE-ONCE: the first valid entry is the authoritative preregistration; later
             entries for the same tuple are appended as amendments (seq_in_namespace 2, 3, ...) and can never be the
             one `execute` uses for the original randomization.
  leaf       {"spec": "notbefore/decision-leaf/1", "index", "received_utc", "seq_in_namespace", "statement", "signature_b64",
              "tsa_sha256": {tsa: sha256 of the token}, "contract_disclosed": bool}   (canonical JSON; RFC 6962 leaf)
  checkpoint c2sp signed note under origin notbefore.net/decisions (key vendored: keys/decisions.pub, keys/DECISIONS.json)

Everything the client trusts is vendored: the origin, the key, the base URL. Anything the server says is verified
against those (note signature, inclusion proof, leaf contents) before it counts."""
import os, sys, json, base64, hashlib, re, time, urllib.request, urllib.error
from .check import VENDOR, KEYS
from . import identity as I
sys.path.insert(0, VENDOR)
import tlog as T

DECISION_SPEC, LEAF_SPEC = "notbefore/decision/1", "notbefore/decision-leaf/1"
ID_RE = re.compile(r"^[A-Za-z0-9._:/=@+-]{1,256}$")

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def utcnow(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def parse_utc(s): import calendar; return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))

def identity():
    p = os.path.join(KEYS, "DECISIONS.json")
    return json.load(open(p)) if os.path.exists(p) else None
def enabled(): i = identity(); return bool(i and i.get("enabled"))
def origin(): return identity()["origin"]
def base_url(): return os.environ.get("NOTBEFORE_DECISIONS_URL") or identity()["base_url"]
def pub_raw(): return T.load_pub_raw(os.path.join(KEYS, os.path.basename(identity()["public_key_file"])))

def validate_decision_id(s):
    if not ID_RE.match(s or ""): raise ValueError("decision_id must match ^[A-Za-z0-9._:/=@+-]{1,256}$")
    return s

# ---------------------------------------------------------------- statements
def statement(contract_sha256, decision_id, key_id, pub_b64, contract_spec):
    return {"spec": DECISION_SPEC, "decision_id": validate_decision_id(decision_id), "key_id": key_id, "public_key_b64": pub_b64,
            "contract_sha256": contract_sha256, "contract_spec": contract_spec, "created_utc": utcnow()}
def sign_statement(priv, st): return I.sign(priv, canon(st))
def verify_statement(st, sig_b64):
    """Signature verifies under st.public_key_b64 AND key_id is that key's id AND the shape is right."""
    try:
        if st.get("spec") != DECISION_SPEC: return False, "not a notbefore/decision/1 statement"
        pub = base64.b64decode(st["public_key_b64"])
        if len(pub) != 32 or I.key_id_of(pub) != st["key_id"]: return False, "key_id is not SHA256(public_key)[:16]"
        if not re.fullmatch(r"[0-9a-f]{64}", st.get("contract_sha256", "")): return False, "contract_sha256 is not 64 hex"
        validate_decision_id(st.get("decision_id"))
        return (True, "ok") if I.verify(pub, sig_b64, canon(st)) else (False, "Ed25519 signature does not verify over the canonical statement")
    except Exception as e: return False, f"malformed statement: {type(e).__name__}: {e}"

def sig_path(contract_path): return contract_path + ".sig.json"
def receipt_path(contract_path): return contract_path + ".log.json"
def write_signature(contract_path, st, sig_b64): json.dump({"statement": st, "signature_b64": sig_b64}, open(sig_path(contract_path), "w"), indent=1, sort_keys=True)
def read_signature(contract_path):
    p = sig_path(contract_path)
    if not os.path.exists(p): return None, None
    j = json.load(open(p)); return j["statement"], j["signature_b64"]

# ---------------------------------------------------------------- HTTP
def _get(path, timeout=20):
    req = urllib.request.Request(base_url().rstrip("/") + path, headers={"User-Agent": "notbefore-cli", "Accept": "application/json, text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.read()
def _post(path, obj, timeout=30):
    req = urllib.request.Request(base_url().rstrip("/") + path, data=canon(obj), method="POST", headers={"User-Agent": "notbefore-cli", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"decision log HTTP {e.code}: {body}")

def submit(st, sig_b64, tsa_files=None, contract_obj=None):
    """Append (or find, idempotently) the statement. Returns the server receipt, VERIFIED (raises if it does not verify)."""
    body = {"statement": st, "signature_b64": sig_b64}
    if tsa_files: body["tsa_tokens"] = {n: base64.b64encode(open(p, "rb").read()).decode() for n, p in tsa_files.items() if os.path.exists(p)}
    if contract_obj is not None: body["contract"] = contract_obj
    rcpt = _post("/decisions/submit", body)
    ok, why = verify_receipt(rcpt, st)
    if not ok: raise RuntimeError("decision log returned a receipt that does NOT verify: " + why)
    return rcpt

def lookup(key_id, decision_id):
    import urllib.parse
    return json.loads(_get("/decisions/lookup?" + urllib.parse.urlencode({"key_id": key_id, "decision_id": decision_id})))

# ---------------------------------------------------------------- verification (everything against vendored trust)
def verify_note(note):
    ok, text = T.verify_note(note, origin(), pub_raw())
    if not ok: return False, None, None
    o, size, root = T.parse_checkpoint(text)
    return o == origin(), size, root

def parse_leaf(leaf_text):
    """-> (leaf dict, leaf bytes). Refuses a non-canonical leaf (the hash would not be reproducible from the fields)."""
    b = leaf_text.encode() if isinstance(leaf_text, str) else leaf_text; j = json.loads(b)
    if canon(j) != b: raise ValueError("leaf is not canonical JSON")
    if j.get("spec") != LEAF_SPEC: raise ValueError("not a decision leaf")
    return j, b

def verify_receipt(rcpt, st=None):
    """A receipt = {index, size, checkpoint (note), leaf (text), proof [b64], seq_in_namespace, authoritative, received_utc}.
    Checks: note signed by the vendored key for the vendored origin; leaf canonical, well-formed, statement-signed (and equal
    to `st` if given); leaf included at `index` under the note's root via the proof."""
    try:
        ok, size, root = verify_note(rcpt["checkpoint"])
        if not ok: return False, "checkpoint note does not verify under the vendored decisions key"
        if int(rcpt["size"]) != size: return False, "receipt size differs from its checkpoint"
        leaf, lb = parse_leaf(rcpt["leaf"]); idx = int(rcpt["index"])
        if leaf["index"] != idx: return False, "leaf index differs from receipt index"
        sok, why = verify_statement(leaf["statement"], leaf["signature_b64"])
        if not sok: return False, "leaf statement: " + why
        if st is not None and canon(leaf["statement"]) != canon(st): return False, "leaf carries a different statement than the one submitted"
        if not (0 <= idx < size): return False, "index outside the checkpointed tree"
        path = [base64.b64decode(p) for p in rcpt["proof"]]
        if not T.verify_inclusion(T.leaf_hash(lb), idx, size, path, root): return False, "inclusion proof does not verify"
        return True, "ok"
    except Exception as e: return False, f"{type(e).__name__}: {e}"

def check_authoritative(st, offline=False, src=None):
    """Is `st` THE preregistration for (key_id, decision_id)? Consults the live log (or, offline, the mirror in the log
    checkout). Returns a dict: status in {authoritative, superseded, unregistered, unreachable, disabled, mirror-absent},
    plus entry/received_unix/size/root_b64/why. Never raises."""
    R = {"origin": origin() if identity() else None, "status": "disabled", "why": "decision log not enabled in this release", "index": None, "received_unix": None, "size": None, "root_b64": None, "seq_in_namespace": None, "verified": False}
    if not enabled(): return R
    key_id, did = st["key_id"], st["decision_id"]
    if offline:
        return _check_mirror(st, src, R)
    try: L = lookup(key_id, did)
    except Exception as e: R.update(status="unreachable", why=f"decision log not reachable: {type(e).__name__}: {str(e)[:100]}"); return R
    ents = L.get("entries") or []
    if not ents: R.update(status="unregistered", why="no entry for this (key_id, decision_id) in the decision log"); return R
    first = ents[0]; auth = L.get("authoritative") or {}
    rc = {"index": first["index"], "size": L.get("size"), "checkpoint": L.get("checkpoint"), "leaf": auth.get("leaf"), "proof": auth.get("proof", [])}
    ok, why = verify_receipt(rc, None)
    if not ok: R.update(status="unreachable", why="log answered but the answer does not verify: " + why); return R
    leaf, _ = parse_leaf(rc["leaf"]); _, size, root = verify_note(rc["checkpoint"])
    R.update(index=first["index"], received_unix=parse_utc(leaf["received_utc"]), size=size, root_b64=base64.b64encode(root).decode(), seq_in_namespace=leaf["seq_in_namespace"], verified=True, entries=len(ents))
    if leaf["seq_in_namespace"] != 1: R.update(status="unreachable", why="log's 'first' entry is not seq_in_namespace 1 — refusing to trust this answer"); return R
    if leaf["statement"]["contract_sha256"] == st["contract_sha256"] and leaf["statement"]["key_id"] == key_id:
        R.update(status="authoritative", why=f"first entry for ({key_id}, {did}) is this contract: index {first['index']}, received {leaf['received_utc']}, tree size {size}")
    else:
        R.update(status="superseded", why=f"a DIFFERENT contract ({leaf['statement']['contract_sha256'][:16]}…) was registered first for ({key_id}, {did}) at {leaf['received_utc']} (index {first['index']}); this one is at best an amendment")
    return R

def _check_mirror(st, src, R):
    """Offline: the repository mirror decisions/ (written by decisions_mirror.py). Same checks; 'first' comes from INDEX.json."""
    try:
        idx_b = src._read_bytes("decisions/INDEX.json") if src else None
        if idx_b is None: R.update(status="mirror-absent", why="offline and the log checkout has no decisions/ mirror"); return R
        note_b = src._read_bytes("decisions/checkpoint"); ok, size, root = verify_note(note_b.decode())
        if not ok: R.update(status="unreachable", why="mirror checkpoint does not verify under the vendored key"); return R
        idx = json.loads(idx_b); lst = idx.get("namespaces", {}).get(f"{st['key_id']}/{st['decision_id']}")
        if not lst: R.update(status="unregistered", why="no entry for this (key_id, decision_id) in the mirrored decision log"); return R
        first = int(lst[0]); leaf_b = src._read_bytes(f"decisions/entries/{first:08d}.json"); leaf, lb = parse_leaf(leaf_b)
        sok, why = verify_statement(leaf["statement"], leaf["signature_b64"])
        if not sok or first >= size: R.update(status="unreachable", why="mirror leaf does not verify: " + why); return R
        leaves = [src._read_bytes(f"decisions/entries/{i:08d}.json") for i in range(size)]
        if any(l is None for l in leaves) or T.mth(leaves) != root: R.update(status="unreachable", why="mirror tree does not recompute to the mirrored checkpoint"); return R
        R.update(index=first, received_unix=parse_utc(leaf["received_utc"]), size=size, root_b64=base64.b64encode(root).decode(), seq_in_namespace=leaf["seq_in_namespace"], verified=True, source="mirror")
        if leaf["statement"]["contract_sha256"] == st["contract_sha256"]: R.update(status="authoritative", why=f"(mirror) first entry for the namespace is this contract: index {first}, received {leaf['received_utc']}")
        else: R.update(status="superseded", why=f"(mirror) a different contract was registered first at {leaf['received_utc']} (index {first})")
        return R
    except Exception as e: R.update(status="unreachable", why=f"mirror check failed: {type(e).__name__}: {e}"); return R
