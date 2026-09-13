"""Transparency-log checks for the client (TLOG.md §8): verify the log's signed checkpoint with the VENDORED origin and
key, recompute the tree from the pulses actually read, prove the pair's inclusion, and compare against the last head
this machine saw — a client that remembers its last checkpoint detects a split view by itself, without asking anyone."""
import os, sys, json, subprocess, tarfile, io, time, re
from .check import VENDOR, KEYS
sys.path.insert(0, VENDOR)
import tlog as T   # vendored copy of the repo's tlog.py

def identity():
    p = os.path.join(KEYS, "CHECKPOINT.json")
    return json.load(open(p)) if os.path.exists(p) else None

def heads_dir():
    d = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "notbefore", "heads"); os.makedirs(d, exist_ok=True); return d

def _chain_leaves_from_source(src):
    """All pulse files at the pinned ref, as canonical leaves in seq order. Uses `git archive` (one process) when possible."""
    if src.mode == "dir" and src.ref is None: return T.chain_leaves(os.path.join(src.dir, "chain"))
    r = subprocess.run(["git", "archive", "--format=tar", src.ref, "chain"], cwd=src.dir, capture_output=True)
    if r.returncode: raise RuntimeError("git archive failed: " + r.stderr.decode()[:200])
    files = {}
    with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
        for m in tf.getmembers():
            if re.search(r"chain/pulse-\d{4}\.json$", m.name): files[m.name] = tf.extractfile(m).read()
    leaves = []
    for i, name in enumerate(sorted(files)):
        j = json.loads(files[name])
        if j["core"]["seq"] != i + 1: raise RuntimeError(f"seq gap at {name}")
        leaves.append(T.canonical(j))
    return leaves

def fetch_site_checkpoint(url, timeout=15):
    import urllib.request
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "notbefore-cli"}), timeout=timeout) as r: return r.read().decode()

MAX_SITE_AHEAD = 12          # pulses the site may be ahead of a log copy and still be reconciled from the site itself

def fetch_site_pulse(base, seq, timeout=15):
    import urllib.request
    with urllib.request.urlopen(urllib.request.Request(f"{base}/chain/pulse-{seq:04d}.json", headers={"User-Agent": "notbefore-cli"}), timeout=timeout) as r:
        return json.loads(r.read().decode())

def _extend_from_site(leaves, need, url):
    """The site is ahead of this log copy: a pulse landed after the copy was taken, which is routine around a mint
    (2026-09-13: every consumer with a copy a minute old halted for the length of the mint). Fetch the missing pulses
    from the site, require each to chain to the previous pulse and to hash to its own pulse_hash, and append them so
    the consistency proof runs over one tree. Nothing is trusted: the site's leaves must then recompute the root in
    the site's own signed checkpoint, and the git head must be a prefix of it."""
    import hashlib
    base = url.rsplit("/", 1)[0]; got = list(leaves)
    prev_hash = json.loads(got[-1])["pulse_hash"] if got else None
    for n in range(len(got) + 1, need + 1):
        j = fetch_site_pulse(base, n)
        if j["core"]["seq"] != n or (prev_hash and j["core"]["prev_hash"] != prev_hash): raise RuntimeError(f"pulse {n:04d} from the site does not chain to pulse {n-1:04d}")
        if hashlib.sha256(T.canonical(j["core"])).hexdigest() != j["pulse_hash"]: raise RuntimeError(f"pulse {n:04d} from the site: pulse_hash != SHA256(canon(core))")
        prev_hash = j["pulse_hash"]; got.append(T.canonical(j))
    return got

def cross_check_site(R, ident, pub_raw, git_note, git_size, git_root, leaves, url=None):
    """The site (notbefore.net) and git are two publication surfaces of the same log. Fetch the site's checkpoint and
    require it to be the same head or an append-only relative of the git head. Unreachable -> WARN; different -> FAIL."""
    origin = ident["origin"]; url = url or ident.get("site_checkpoint_url")
    if not url: return "no site"
    try: note = fetch_site_checkpoint(url)
    except Exception as e: R.say(True, f"site checkpoint {url} not fetched ({str(e)[:80]}); git head stands alone", "WARN"); return "unreachable"
    ok, text = T.verify_note(note, origin, pub_raw)
    if not ok: R.say(False, f"site checkpoint at {url} does NOT verify under {origin}'s key"); return "bad site signature"
    o, ssize, sroot = T.parse_checkpoint(text)
    if note == git_note: R.say(True, f"site {url} serves the same checkpoint as git (size {ssize})"); return "same"
    lo, hi = (ssize, git_size) if ssize <= git_size else (git_size, ssize)
    if hi > len(leaves):
        missing = hi - len(leaves)
        if ssize > git_size and missing <= MAX_SITE_AHEAD:
            try:
                leaves = _extend_from_site(leaves, hi, url)
                R.say(True, f"site is {missing} pulse(s) ahead of this log copy (a mint landed after the copy was taken); fetched them from the site, chain-linked, to reconcile the two heads", "INFO")
            except Exception as e:
                R.say(False, f"site checkpoint size {ssize} exceeds the pulses available ({len(leaves)}) and the missing pulses could not be fetched from the site ({str(e)[:90]}); cannot reconcile"); return "site ahead"
        else:
            R.say(False, f"site checkpoint size {ssize} exceeds the pulses available ({len(leaves)}); cannot reconcile"); return "site ahead"
    oroot, nroot = (sroot, git_root) if ssize <= git_size else (git_root, sroot)
    cons = T.verify_consistency(lo, hi, T.consistency_proof(lo, leaves[:hi]), oroot, nroot)
    R.say(cons, f"site checkpoint (size {ssize}) and git checkpoint (size {git_size}) are consistent heads of one log" if cons else
               f"SPLIT VIEW between publication surfaces: site {url} (size {ssize}, root {sroot.hex()[:16]}…) vs git (size {git_size}, root {git_root.hex()[:16]}…) are not append-only relatives")
    return "consistent" if cons else "SPLIT VIEW"

def check(src, seqs, R, refetch=True, site_url=None):
    """Appends [PASS]/[FAIL]/[WAIT] lines to R (a CheckResult). Returns a status string."""
    ident = identity()
    if not ident: R.say(True, "transparency log: no checkpoint identity vendored in this release — skipped", "INFO"); return "no identity"
    if not ident.get("enabled"): R.say(True, f"transparency log: identity {ident['origin']} vendored but checkpoints not yet enabled by the operator — skipped", "INFO"); return "no identity"
    origin = ident["origin"]; pub_raw = T.load_pub_raw(os.path.join(KEYS, os.path.basename(ident["public_key_file"])))
    note_b = src._read_bytes("checkpoint")
    if note_b is None:
        first = int(ident.get("first_checkpoint_size") or 0)
        if first and seqs and max(seqs) >= first:            # every pulse from the first checkpoint on MUST be provably included (R5)
            R.say(False, f"transparency log ({origin}): no `checkpoint` in this log source although pulses >= {first} are checkpointed — a copy without its checkpoint cannot be verified"); return "absent"
        R.say(True, f"transparency log ({origin}): no `checkpoint` published at {R.log_ref} yet", "WAIT"); return "absent"
    note = note_b.decode()
    ok, text = T.verify_note(note, origin, pub_raw); R.say(ok, f"checkpoint signature by {origin} (vendored key id {T.key_id(origin, pub_raw).hex()})")
    if not ok: return "bad signature"
    o, size, root = T.parse_checkpoint(text); R.say(o == origin, f"checkpoint origin line is {o!r}")
    try: leaves = _chain_leaves_from_source(src)
    except Exception as e: R.say(False, f"could not rebuild the tree from the log: {e}"); return "tree error"
    R.say(size <= len(leaves), f"checkpoint size {size} <= {len(leaves)} pulses read from the log")
    if size > len(leaves): return "size"
    recomputed = T.mth(leaves[:size]); R.say(recomputed == root, f"root at size {size} recomputes from the pulses actually read ({recomputed.hex()[:16]}…)")
    if recomputed != root: return "root mismatch"
    for s in seqs:
        i = s - 1
        if i < size:
            inc = T.verify_inclusion(T.leaf_hash(leaves[i]), i, size, T.inclusion_path(i, leaves[:size]), root)
            R.say(inc, f"pulse {s:04d} is included in the checkpointed tree (leaf {i}, RFC 6962 inclusion proof)")
        else: R.say(True, f"pulse {s:04d} is newer than the published checkpoint (size {size}); inclusion not yet provable", "WAIT")
    # cosignatures (c2sp tlog-cosignature v1.0.1) against the VENDORED witness list; same-sponsor witnesses are named as such
    try:
        wj = json.load(open(os.path.join(KEYS, "WITNESSES.json"))) if os.path.exists(os.path.join(KEYS, "WITNESSES.json")) else {}
        cos = {}
        for w in wj.get("witnesses", []) + wj.get("independent_witnesses", []):
            n, alg, pub = T.parse_verifier_key(w["verifier_key"])
            if alg == 4: cos[n] = pub
        indep = {w["name"] for w in wj.get("independent_witnesses", [])}
        good = T.verify_cosignatures(note, cos); R.cosignatures = [n for n, _ in good]; R.independent_cosignatures = [n for n in R.cosignatures if n in indep]
        for n, ts in good: R.say(True, f"checkpoint cosigned by witness {n} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))}{'' if n in indep else ' (same sponsor as the log — a second system, not an independent party)'}")
        if not good: R.say(True, "checkpoint carries no cosignature from a known witness", "INFO")
        q = int(os.environ.get("NOTBEFORE_WITNESS_QUORUM", "0") or 0)
        if q: R.say(len(R.independent_cosignatures) >= q, f"{len(R.independent_cosignatures)} independent cosignature(s) >= quorum {q}")
    except Exception as e: R.say(True, f"cosignature check unavailable: {e}", "WARN")
    if refetch: cross_check_site(R, ident, pub_raw, note, size, root, leaves, site_url)
    # cached head: the client's own split-view detector
    hp = os.path.join(heads_dir(), re.sub(r"[^A-Za-z0-9._-]", "_", origin) + ".checkpoint")
    status = "ok"
    if os.path.exists(hp):
        old = open(hp).read(); ook, otext = T.verify_note(old, origin, pub_raw)
        if ook:
            _, osize, oroot = T.parse_checkpoint(otext)
            if osize > len(leaves) or (osize <= size and not T.verify_consistency(osize, size, T.consistency_proof(osize, leaves[:size]), oroot, root)) or (osize > size):
                R.say(False, f"SPLIT VIEW / ROLLBACK: the head this machine saw before (size {osize}, root {oroot.hex()[:16]}…) is NOT a prefix of the head now served (size {size}). Keep {hp} as evidence.")
                return "SPLIT VIEW"
            R.say(True, f"consistent with the head this machine last saw (size {osize} -> {size}; append-only)")
        else: R.say(True, f"cached head at {hp} does not verify; replacing it", "WARN")
    else: R.say(True, f"first checkpoint seen on this machine for {origin}; caching it as the reference head", "INFO")
    if not os.path.exists(hp) or size >= T.parse_checkpoint(T.verify_note(open(hp).read(), origin, pub_raw)[1])[1]:
        open(hp, "w").write(note)
    return status
