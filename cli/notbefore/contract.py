"""Decision contracts (NOTBEFORE.md §7.11): the consumer's commitment, made BEFORE the pulse exists.

  plan     -> a canonical contract {selection rule, purpose, operation, parameters, input sha256}, its hash, and RFC 3161
              tokens from two public TSAs over the contract bytes (third-party evidence of WHEN it existed).
  execute  -> takes ONLY the contract: verifies the tokens, selects the pulse by the contract's rule (first eligible reveal
              whose drand round released at or after `after`), requires every token to predate that release, runs the
              operation with the contract's parameters on the same input bytes, and writes a transcript naming the contract.

NotBefore commits its entropy before the public randomizer; the user commits their decision before the NotBefore value.
Neither side chooses after seeing the thing that matters.

TIMESTAMPING, THEN REGISTRATION: RFC 3161 tokens prove these bytes existed at T. Since contract/2 the contract also
names its SIGNER (the consumer's Ed25519 identity, identity.py) and a DECISION_ID, and `plan` signs a decision
statement over the contract hash and appends it to the write-once decision log (decisionlog.py, DECISION-LOG.md):
the first statement for (key_id, decision_id) is the authoritative preregistration, so a consumer cannot quietly
timestamp several contracts and publish the favourable one. Canonical form is RFC 8785 JCS; a contract contains only
strings, integers, objects and arrays (no floats: fractions are decimal strings), so this serialization is
byte-identical to JCS.
"""
import os, sys, json, hashlib, time, re, subprocess
from . import __version__, SPEC, FIRST_ELIGIBLE_REVEAL
from .check import VENDOR, check_pair, known_noncompliant
from . import derive as D

CONTRACT_SPEC = "notbefore/contract/3"                # /3 = /2 + value rule "commit-bound" (V*, FALLBACK.md); /2 = /1 + signer + decision_id
SIGNED_SPECS = ("notbefore/contract/2", "notbefore/contract/3")
ACCEPTED_SPECS = ("notbefore/contract/1", "notbefore/contract/2", "notbefore/contract/3")   # /1 (unsigned) and /2 (reveal-based) still execute, labelled
RULE3 = "first-eligible-commit-released-at-or-after"
VALUE_RULE = {"rule": "commit-bound", "domain": "notbefore/commit-bound/v1", "formula": "SHA256(domain || C || rho_R || chain_hash || R_be8)"}
RULE = "first-eligible-reveal-released-at-or-after"
sys.path.insert(0, VENDOR)
import tsa as _tsa                                    # vendored: TSAS = {"freetsa": ..., "digicert": ...}
EXPECTED_TSAS = frozenset(_tsa.TSAS.keys())           # BOTH must timestamp a contract; both must verify; ALL must predate the round
from fractions import Fraction
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

def make(after_utc, purpose, operation, params, input_path=None, note=None, signer=None, decision_id=None):
    """signer = (key_id, public_key_b64) from identity.load(); decision_id defaults to the purpose string (the namespace the
    write-once rule applies to). signer=None writes a legacy unsigned contract/1 (discouraged; execute labels it)."""
    if operation not in OPS: raise ValueError(f"operation must be one of {sorted(OPS)}")
    missing = [k for k in OPS[operation] if k not in params]
    if missing: raise ValueError(f"{operation} needs parameters {missing}")
    P = D.normalize_purpose(purpose).decode()
    c = {"spec": CONTRACT_SPEC, "log": {"origin": "notbefore.net/log", "repo": "github.com/docdailey/qrng-beacon-log"},
         "selection": {"rule": RULE, "after_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(parse_utc(after_utc))), "after_unix_s": parse_utc(after_utc),
                       "eligibility": f"reveal, protocol v0.5, seq >= {FIRST_ELIGIBLE_REVEAL}, not KNOWN-NONCOMPLIANT, pair verifies under the pinned verifier; skip/failure hours are never selected"},
         "purpose": P, "operation": operation, "params": {k: _param(operation, k, params[k]) for k in OPS[operation]},
         "derive_domain": D.D_DERIVE.decode(), "spec_version": SPEC, "cli_version": __version__,
         "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if signer:
        from . import decisionlog as DL
        c["signer"] = {"alg": "ed25519", "key_id": signer[0], "public_key_b64": signer[1]}
        c["decision_id"] = DL.validate_decision_id(decision_id or P)
        c["value"] = dict(VALUE_RULE)
        c["selection"]["rule"] = RULE3
        c["selection"]["eligibility"] = f"commit, protocol v0.5, seq >= {FIRST_ELIGIBLE_REVEAL - 1}, not KNOWN-NONCOMPLIANT, verifies under the pinned verifier, both RFC 3161 tokens strictly before its round, Rekor-anchored before its round; the value is V* = SHA256(commit-bound domain || C || rho_R || chain_hash || R) whether or not the operator reveals (FULL-ATTESTED / COMMITMENT-FALLBACK)"
    else: c["spec"] = "notbefore/contract/1"
    if note: c["note"] = str(note)[:500]
    if operation in ("sample", "split", "assign", "shuffle", "id"):
        if not input_path: raise ValueError(f"{operation} needs an input file")
        recs, _ = read_records(input_path)
        c["input"] = {"file": os.path.basename(input_path), "sha256": sha256_file(input_path), "record_count": len(recs)}
        if operation == "sample" and not (0 <= int(params["k"]) <= len(recs)): raise ValueError("k exceeds the record count")
    return c

def _param(op, k, v):
    """Contract parameters are integers or decimal STRINGS — never floats (RFC 8785 portability)."""
    if k == "frac":
        fr = Fraction(str(v))
        if not (0 < fr < 1): raise ValueError("frac must be in (0, 1)")
        return str(v) if isinstance(v, str) else format(float(v), "g")
    return int(v)

def read_records(path):
    raw = open(path, "rb").read(); recs = raw.decode("utf-8").split("\n")
    if recs and recs[-1] == "": recs.pop()
    return [r.rstrip("\r") for r in recs], hashlib.sha256(raw).hexdigest()

def write(contract, path):
    b = canon(contract); open(path, "wb").write(b); return hashlib.sha256(b).hexdigest()

def timestamp(path):
    """Request an RFC 3161 token from EVERY expected TSA that does not already have one beside the contract. Idempotent:
    re-running after a TSA outage fills only the missing token. Returns {tsa: time_str} of tokens now present."""
    import urllib.request
    q = path + ".tsq"
    r = _tsa.sh("openssl", "ts", "-query", "-data", path, "-sha256", "-cert", "-out", q)
    if r.returncode != 0: raise RuntimeError("tsq: " + r.stderr[:200])
    got = {}
    try:
        for name, cfg in _tsa.TSAS.items():
            out = f"{path}.{name}.tsr"
            if os.path.exists(out): got[name] = "existing"; continue
            try:
                req = urllib.request.Request(cfg["url"], data=open(q, "rb").read(), headers={"Content-Type": "application/timestamp-query"})
                with urllib.request.urlopen(req, timeout=25) as resp: body = resp.read()
                open(out, "wb").write(body); txt = _tsa.sh("openssl", "ts", "-reply", "-in", out, "-text").stdout
                if "Status: Granted" not in txt: os.remove(out); continue
                got[name] = re.search(r"Time stamp:\s*(.+)", txt).group(1).strip()
            except Exception as e: sys.stderr.write(f"[tsa] {name}: {type(e).__name__}: {str(e)[:80]}\n")
    finally:
        if os.path.exists(q): os.remove(q)
    toks, _ = verify_timestamps(path)
    json.dump({"contract": os.path.basename(path), "sha256": sha256_file(path), "label": "decision-contract", "requested_unix": int(time.time()),
               "tokens": [{"tsa": n, "file": f"{os.path.basename(path)}.{n}.tsr", "time": t} for n, t, _ in toks],
               "note": "timestamping, not registration: proves these bytes existed at these times; publish the sha256 where it cannot be withdrawn"},
              open(path + ".tsa.json", "w"), indent=2)
    return got

def verify_timestamps(path):
    """Verify every token beside the contract with the vendored tsa.py. Returns (tokens[(tsa, time_str, unix)], any_failed)."""
    r = subprocess.run([sys.executable, os.path.join(VENDOR, "tsa.py"), "verify", path], capture_output=True, text=True); out = r.stdout + r.stderr
    toks = []
    import datetime
    for m in re.finditer(r"\[PASS\] RFC3161 (\w+): (.+)", out):
        t = datetime.datetime.strptime(m.group(2).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()
        toks.append((m.group(1), m.group(2).strip(), int(t)))
    return toks, ("[FAIL]" in out)

def timestamp_verdict(toks, any_failed, release_unix_s, require_all=True):
    """The normative gate (NOTBEFORE.md §7.11), as a pure function so it can be tested exhaustively:
    every expected TSA must be present and verify, no token may fail, and the LATEST token must be strictly before the
    selected round's release. require_all=False (a labelled --allow-unregistered dry run) waives only the
    completeness checks — a failing or late token is refused regardless. Returns (ok, reason, latest_unix)."""
    names = {n for n, _, _ in toks}
    latest = max((t for _, _, t in toks), default=None)
    if any_failed: return False, "a timestamp token beside the contract does NOT verify (corrupt or forged token)", latest
    extra = sorted(names - EXPECTED_TSAS)
    if extra: return False, f"unexpected TSA identity {extra}", latest
    missing = sorted(EXPECTED_TSAS - names)
    if missing and require_all: return False, f"contract lacks a verifying token from {', '.join(missing)}: both TSAs ({', '.join(sorted(EXPECTED_TSAS))}) are required", latest
    if latest is None and release_unix_s is not None: return (not require_all), "no timestamp token at all: nothing but the user's word says when this decision existed", None
    if release_unix_s is not None and not (latest < release_unix_s):
        return False, f"the latest timestamp ({latest}) is not strictly before the selected round's release ({release_unix_s}): the decision could have been made with knowledge of V", latest
    return True, f"both TSAs verify; latest token {latest} < round release {release_unix_s}", latest

def select_pulse(src, after_unix_s, refetch, anchors, R_lines):
    """The contract's rule: walk reveals in seq order; the first one whose round released at/after `after` AND whose pair
    verifies is THE pulse. Deterministic given the log; a failure/skip hour or a bad pair is passed over by rule."""
    knc = known_noncompliant(); seq = FIRST_ELIGIBLE_REVEAL
    while src.has_pulse(seq):                                   # no cutoff: the rule is "first eligible", however far that is
        p = src.pulse(seq); c = p["core"]
        typ = c.get("type")
        if typ in ("failure", "skip") and int((c.get("derived") or {}).get("round_release_unix_s") or c.get("derived", {}).get("attempted_unix_s") or 0) >= after_unix_s:
            R_lines.append(f"[INFO] pulse {seq:04d} is a {typ} — passed over by rule")
        if typ == "reveal" and c.get("v") == "0.5" and seq not in knc and (seq - 1) not in knc:
            rel = int(c["derived"]["round_release_unix_s"])
            if rel >= after_unix_s:
                R = check_pair(seq, src, refetch=refetch, anchors=anchors)
                if R.ok: return seq, rel, R
                R_lines.append(f"[INFO] reveal {seq:04d} released at/after `after` but does not verify — passed over by rule")
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
        A_, B_ = D.split(recs, S, Fraction(str(prm["frac"]))); return "\n".join(A_) + "\n", {"B": B_, "A_count": len(A_), "B_count": len(B_)}
    raise ValueError(op)
