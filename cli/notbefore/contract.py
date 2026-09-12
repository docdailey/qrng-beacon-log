"""Decision contracts (NOTBEFORE.md §7.11): the consumer's commitment, made BEFORE the pulse exists.

  plan     -> a canonical contract {selection rule, purpose, operation, parameters, input sha256}, its hash, and RFC 3161
              tokens from two public TSAs over the contract bytes (third-party evidence of WHEN it existed).
  execute  -> takes ONLY the contract: verifies the tokens, selects the pulse by the contract's rule (first eligible reveal
              whose drand round released at or after `after`), requires every token to predate that release, runs the
              operation with the contract's parameters on the same input bytes, and writes a transcript naming the contract.

NotBefore commits its entropy before the public randomizer; the user commits their decision before the NotBefore value.
Neither side chooses after seeing the thing that matters.
"""
import os, sys, json, hashlib, time, re, subprocess
from . import __version__, SPEC, FIRST_ELIGIBLE_REVEAL
from .check import VENDOR, check_pair, known_noncompliant
from . import derive as D

CONTRACT_SPEC = "notbefore/contract/1"
RULE = "first-eligible-reveal-released-at-or-after"
OPS = {"sample": ("k",), "split": ("frac",), "assign": ("arms",), "shuffle": (), "id": ("hexlen",), "range": ("lo", "hi"), "bytes": ("n",), "seed": ()}

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def parse_utc(s):
    s = s.strip().replace("Z", "+00:00")
    from datetime import datetime, timezone
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())

def make(after_utc, purpose, operation, params, input_path=None, note=None):
    if operation not in OPS: raise ValueError(f"operation must be one of {sorted(OPS)}")
    missing = [k for k in OPS[operation] if k not in params]
    if missing: raise ValueError(f"{operation} needs parameters {missing}")
    P = D.normalize_purpose(purpose).decode()
    c = {"spec": CONTRACT_SPEC, "log": {"origin": "notbefore.net/log", "repo": "github.com/docdailey/qrng-beacon-log"},
         "selection": {"rule": RULE, "after_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(parse_utc(after_utc))), "after_unix_s": parse_utc(after_utc),
                       "eligibility": f"reveal, protocol v0.5, seq >= {FIRST_ELIGIBLE_REVEAL}, not KNOWN-NONCOMPLIANT, pair verifies under the pinned verifier; skip/failure hours are never selected"},
         "purpose": P, "operation": operation, "params": {k: params[k] for k in OPS[operation]},
         "derive_domain": D.D_DERIVE.decode(), "spec_version": SPEC, "cli_version": __version__,
         "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if note: c["note"] = str(note)[:500]
    if operation in ("sample", "split", "assign", "shuffle", "id"):
        if not input_path: raise ValueError(f"{operation} needs an input file")
        recs, _ = read_records(input_path)
        c["input"] = {"file": os.path.basename(input_path), "sha256": sha256_file(input_path), "record_count": len(recs)}
        if operation == "sample" and not (0 <= int(params["k"]) <= len(recs)): raise ValueError("k exceeds the record count")
    return c

def read_records(path):
    raw = open(path, "rb").read(); recs = raw.decode("utf-8").split("\n")
    if recs and recs[-1] == "": recs.pop()
    return [r.rstrip("\r") for r in recs], hashlib.sha256(raw).hexdigest()

def write(contract, path):
    b = canon(contract); open(path, "wb").write(b); return hashlib.sha256(b).hexdigest()

def register(path):
    """RFC 3161 tokens from the vendored tsa.py (freetsa + DigiCert) over the contract FILE bytes. Returns the tsa.json meta."""
    r = subprocess.run([sys.executable, os.path.join(VENDOR, "tsa.py"), "stamp", path, "decision-contract"], capture_output=True, text=True)
    meta = os.path.exists(path + ".tsa.json") and json.load(open(path + ".tsa.json"))
    return meta or {"tokens": [], "error": (r.stderr or r.stdout)[-200:]}

def verify_registration(path):
    """(earliest_token_unix, [(tsa, time_str)], ok). ok requires >= 1 verifying token; 2 is the norm."""
    r = subprocess.run([sys.executable, os.path.join(VENDOR, "tsa.py"), "verify", path], capture_output=True, text=True); out = r.stdout + r.stderr
    toks = []
    import email.utils, datetime
    for m in re.finditer(r"\[PASS\] RFC3161 (\w+): (.+)", out):
        t = datetime.datetime.strptime(m.group(2).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()
        toks.append((m.group(1), m.group(2).strip(), int(t)))
    return (min(t for _, _, t in toks) if toks else None), toks, bool(toks) and "[FAIL]" not in out

def select_pulse(src, after_unix_s, refetch, anchors, R_lines):
    """The contract's rule: walk reveals in seq order; the first one whose round released at/after `after` AND whose pair
    verifies is THE pulse. Deterministic given the log; a failure/skip hour or a bad pair is passed over by rule."""
    knc = known_noncompliant(); seq = FIRST_ELIGIBLE_REVEAL; tried = 0
    while src.has_pulse(seq):
        p = src.pulse(seq); c = p["core"]
        if c.get("type") == "reveal" and c.get("v") == "0.5" and seq not in knc and (seq - 1) not in knc:
            rel = int(c["derived"]["round_release_unix_s"])
            if rel >= after_unix_s:
                tried += 1
                R = check_pair(seq, src, refetch=refetch, anchors=anchors)
                if R.ok: return seq, rel, R
                R_lines.append(f"[INFO] reveal {seq:04d} released at/after `after` but does not verify — passed over by rule")
                if tried >= 5: break
        seq += 1
    return None, None, None

def run_operation(contract, S, input_path):
    op, prm = contract["operation"], contract["params"]
    if op == "seed": return S.hex() + "\n", {}
    if op == "range": v = D.rand_range(S, int(prm["lo"]), int(prm["hi"])); return f"{v}\n", {"value": v}
    if op == "bytes": return D.rand_bytes(S, int(prm["n"])).hex() + "\n", {}
    recs, in_sha = read_records(input_path)
    if in_sha != contract["input"]["sha256"]: raise ValueError(f"input file sha256 {in_sha[:16]}… differs from the contract's {contract['input']['sha256'][:16]}…: not the committed bytes")
    if op == "shuffle": out = D.shuffle(recs, S); return "\n".join(out) + "\n", {}
    if op == "sample": out = D.sample(recs, S, int(prm["k"])); return "\n".join(out) + "\n", {}
    if op == "assign": pairs = D.assign(recs, S, int(prm["arms"])); return "".join(f"{r}\t{a}\n" for r, a in pairs), {"arm_sizes": [sum(1 for _, a in pairs if a == i) for i in range(int(prm["arms"]))]}
    if op == "id": return "\n".join(D.pseudonym(r, S, int(prm["hexlen"])) for r in recs) + "\n", {}
    if op == "split":
        A_, B_ = D.split(recs, S, float(prm["frac"])); return "\n".join(A_) + "\n", {"B": B_, "A_count": len(A_), "B_count": len(B_)}
    raise ValueError(op)
