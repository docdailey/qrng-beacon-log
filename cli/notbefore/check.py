"""Verify one NotBefore pair (commit N-1, reveal N) with the VENDORED verifier and keys (NOTBEFORE.md §5–6).
The log supplies data only. Exit-code discipline: a CheckResult with ok=False must never yield V or S."""
import os, sys, json, subprocess, time, base64
from . import FIRST_ELIGIBLE_REVEAL, ANCHOR_GRACE_S
from .log import LogSource

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "verifier")
KEYS = os.path.join(VENDOR, "keys")
sys.path.insert(0, os.path.join(VENDOR, "ci"))

def vendored_meta():
    try: return json.load(open(os.path.join(VENDOR, "VENDORED.json")))
    except Exception: return {}

def known_noncompliant():
    try: return {int(k): v for k, v in json.load(open(os.path.join(VENDOR, "ci", "KNOWN_NONCOMPLIANT.json"))).get("pulses", {}).items()}
    except Exception: return {}

class CheckResult:
    def __init__(self, seq):
        self.seq = seq; self.ok = True; self.lines = []; self.verbose = []
        self.commit_seq = self.pulse_hash_reveal = self.pulse_hash_commit = self.attested_value = self.drand_round = None
        self.bls_offline = False; self.tsa_pass = 0; self.anchors = "not checked"
        self.log_git_sha = self.log_ref = None; self.verifier_git_sha = vendored_meta().get("git_sha")
    def say(self, ok, msg, level=None):
        tag = level or ("PASS" if ok else "FAIL")
        if tag == "FAIL": self.ok = False
        self.lines.append(f"[{tag}] {msg}")
    def summary(self):
        return {"ok": self.ok, "bls_offline": self.bls_offline, "tsa_tokens_verified": self.tsa_pass, "anchors": self.anchors,
                "lines": self.lines}

def _run(args, cwd=None):
    r = subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True); return r.returncode, r.stdout + r.stderr

def check_pair(seq: int, src: LogSource, refetch=True, anchors=True, verbose=False) -> CheckResult:
    R = CheckResult(seq); R.log_git_sha, R.log_ref = src.log_git_sha, (src.ref or "working tree")
    knc = known_noncompliant()
    # ---- eligibility (§6) before anything is executed
    if seq < FIRST_ELIGIBLE_REVEAL: R.say(False, f"seq {seq} is below the first eligible reveal ({FIRST_ELIGIBLE_REVEAL}); pulses 1–17 are legacy (ERR-005), 18–19 KNOWN-NONCOMPLIANT (ERR-007)")
    for s in (seq, seq - 1):
        if s in knc: R.say(False, f"seq {s} is KNOWN-NONCOMPLIANT ({knc[s].get('erratum')}): {knc[s].get('reason')}")
    if not R.ok: return R
    rev = src.pulse(seq); com = src.pulse(seq - 1)
    if rev is None: R.say(False, f"pulse {seq:04d} is not in the log at {R.log_ref}"); return R
    if com is None: R.say(False, f"predecessor pulse {seq-1:04d} is not in the log"); return R
    rc_, cc_ = rev["core"], com["core"]
    R.pulse_hash_reveal, R.pulse_hash_commit = rev["pulse_hash"], com["pulse_hash"]
    R.say(rc_.get("v") == "0.5", f"reveal {seq:04d} is protocol v0.5 (got {rc_.get('v') or rc_.get('version') or 'legacy'})")
    R.say(rc_.get("type") == "reveal", f"pulse {seq:04d} is a reveal (type {rc_.get('type')})")
    R.say(cc_.get("type") == "commit", f"pulse {seq-1:04d} is a commit (type {cc_.get('type')})")
    R.say((rc_.get("derived") or {}).get("commit_seq") == seq - 1, f"reveal names commit_seq {seq-1} (derived.commit_seq = {(rc_.get('derived') or {}).get('commit_seq')})")
    if not R.ok: return R
    R.commit_seq = seq - 1; R.attested_value = rc_["derived"]["attested_value"]; R.drand_round = rc_["drand"]["round"]
    # ---- materialize the pair (+ the commit's predecessor for its chain link) and run the vendored verifier
    p_rev, p_com = src.materialize(seq), src.materialize(seq - 1)
    p_pp = src.materialize(seq - 2) if src.has_pulse(seq - 2) else None
    vpy = os.path.join(VENDOR, "verify.py"); extra = ["--refetch"] if refetch else []
    rc, out = _run([vpy, p_com, "--pin", KEYS] + (["--prev", p_pp] if p_pp else []) + extra); R.verbose.append(out)
    R.say(rc == 0 and "ALL CHECKS PASSED" in out, f"commit {seq-1:04d}: vendored verify.py (pinned keys{', chained to %04d' % (seq-2) if p_pp else ''}{', drand refetched' if refetch else ''})")
    _bls_c = "[full BLS, offline]" in out and "BLS verification skipped" not in out
    rc, out = _run([vpy, p_rev, "--pin", KEYS, "--prev", p_com] + extra); R.verbose.append(out)
    R.say(rc == 0 and "ALL CHECKS PASSED" in out, f"reveal {seq:04d}: vendored verify.py (pinned keys, chained to {seq-1:04d}, C = SHA256(D_commit||E), V recomputed, timing contract{', drand refetched' if refetch else ''})")
    R.bls_offline = _bls_c and "[full BLS, offline]" in out and "BLS verification skipped" not in out
    R.say(R.bls_offline, "drand round BLS-verified offline under the pinned quicknet group key (py_ecc)")
    if f"Attested value {R.attested_value}" not in out: R.say(False, "verifier's attested value differs from the pulse's derived.attested_value")
    # ---- RFC 3161 on the commit
    rc, out = _run([os.path.join(VENDOR, "tsa.py"), "verify", p_com]); R.verbose.append(out)
    R.tsa_pass = out.count("[PASS] RFC3161")
    R.say(R.tsa_pass >= 2 and "[FAIL]" not in out, f"commit {seq-1:04d}: {R.tsa_pass} RFC 3161 token(s) verify (need ≥ 2: freetsa + DigiCert)")
    # ---- publication anchors (SHOULD; missing anchors fail once the pulse is older than the grace period)
    if anchors:
        R.anchors = _check_anchors(R, src, (seq - 1, seq), rc_, refetch)
    else: R.anchors = "skipped (--no-anchors)"
    return R

def _check_anchors(R, src, seqs, rev_core, refetch):
    if not src.anchors_available():
        R.say(True, "publication anchors: no anchors branch reachable from this log source — not checked", "WARN"); return "unavailable"
    try:
        import anchor_lib as L
    except Exception as e:
        R.say(True, f"publication anchors: vendored anchor_lib unavailable ({e})", "WARN"); return "unavailable"
    anchor_pub = L.load_pub(open(os.path.join(KEYS, "anchor.pub"), "rb").read()); rekor_pub = L.load_pub(open(os.path.join(KEYS, "rekor.pub"), "rb").read())
    age = time.time() - float((rev_core.get("derived") or {}).get("round_release_unix_s") or time.time())
    status = []
    for s in seqs:
        rec, stmt = src.anchor(s)
        if rec is None:
            if age > ANCHOR_GRACE_S: R.say(False, f"pulse {s:04d}: no publication anchor {age/60:.0f} min after its round (grace {ANCHOR_GRACE_S//60} min)")
            else: R.say(True, f"pulse {s:04d}: anchor pending ({age:.0f} s since its round)", "WARN")
            status.append("missing"); continue
        pf = os.path.join(src.tmp, "chain", f"pulse-{s:04d}.json")
        want, _ = L.statement_for(pf); entry = rec["rekor"]["entry"]
        ok = stmt == want and rec["statement_sha256"] == L.sha256(want)
        h, k = L.entry_hash_and_key(entry)
        ok &= h == L.sha256(want) and k is not None and L.key_id(L.load_pub(k)) == L.key_id(anchor_pub)
        ok &= L.verify_sig(anchor_pub, base64.b64decode(rec["signature_b64"]), want)
        ok &= entry.get("logID") == L.REKOR_LOG_ID and L.verify_set(entry, rekor_pub)
        inc, why = L.verify_inclusion(entry, rekor_pub); ok &= inc
        live = ""
        if refetch and ok:
            try:
                e2 = L.rekor_get(rec["rekor"]["uuid"]); ok &= e2["body"] == entry["body"] and e2["integratedTime"] == entry["integratedTime"]; live = ", re-fetched live"
            except Exception as ex: R.say(True, f"pulse {s:04d}: Rekor refetch failed ({ex}); offline proof stands", "WARN")
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry["integratedTime"]))
        R.say(ok, f"pulse {s:04d}: Rekor anchor logIndex {entry['logIndex']} @ {when} — statement, signature, SET, inclusion proof + checkpoint verified offline against pinned keys{live}; OTS {rec.get('ots', {}).get('status')}")
        status.append("ok" if ok else "FAIL")
    if all(x == "ok" for x in status):
        rel = float((rev_core.get("derived") or {}).get("round_release_unix_s") or 0); rec_c, _ = src.anchor(seqs[0])
        it = rec_c["rekor"]["entry"]["integratedTime"]
        if it < rel: R.say(True, f"commit {seqs[0]:04d}: Rekor time precedes the drand release by {rel-it:.0f} s (third independent clock on the commit)")
        else: R.say(True, f"commit {seqs[0]:04d}: Rekor time is {it-rel:.0f} s AFTER the drand release — a retroactive anchor (pulses ≤ 0041 were anchored 2026-09-12 12:47 UTC); the RFC 3161 tokens are the commit-time proof", "WARN")
    return "/".join(status)
