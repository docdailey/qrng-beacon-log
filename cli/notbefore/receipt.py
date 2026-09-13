"""receipt.py — the decision receipt, the verification bundle, and the bundle checker (WORKFLOW.md; NOTBEFORE.md §8).

  notbefore receipt <contract>       one page, human-readable: who committed, to what, when, that it was the authoritative
                                     preregistration, which pulse, the result, how to re-verify. Every line is re-derived
                                     from the artifacts and re-verified here — the receipt is a rendering, not a claim.
  notbefore bundle  <contract>       a self-contained directory (or .zip): the contract and its sidecars, the transcript,
                                     the pulse pair (+ the commit's predecessor for its chain link) with tokens, checkpoint,
                                     inclusion proofs, anchor records, the decision-log leaf/proof/checkpoint, the vendored
                                     public keys, README = the receipt, MANIFEST.json with every file's SHA-256.
  notbefore check-bundle <dir|zip>   re-verifies a bundle OFFLINE with the installed release's pinned keys and roots:
                                     manifest, contract, statement, RFC 3161 tokens, decision-log receipt, transcript
                                     binding, the pair's host signatures + BLS + chain links (vendored verify.py), the
                                     commit's tokens, checkpoint signature + inclusion proofs + cosignatures, Rekor anchors.

Sensitive data stays out by default: the input file and the outputs are represented by their SHA-256s; --include-input /
--include-output add them. Trust always comes from the INSTALLED package (its vendored keys and TSA roots), never from
the bundle's own copy of them — that copy is for the record."""
import os, sys, json, hashlib, time, shutil, zipfile, base64, re, tempfile, subprocess
from . import __version__, SPEC
from .check import VENDOR, KEYS, CheckResult, check_pair, check_commit, vendored_meta, _check_anchors, _run
from . import contract as C, decisionlog as DL, derive as D
sys.path.insert(0, VENDOR)
import tlog as T

BUNDLE_SPEC = "notbefore/bundle/1"
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
def _sha12(x): x = str(x or "?"); return x[:12] if all(ch in "0123456789abcdef" for ch in x[:12]) else x
def utc(x): return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(float(x)))) if x is not None else "—"
def parse_tsa_time(s):
    import datetime; return int(datetime.datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp())

class Facts(dict):
    """Everything the receipt says, each item carrying its own verification verdict; `lines` is the audit trail."""
    def __init__(self): super().__init__(); self["lines"] = []; self["ok"] = True
    def say(self, ok, msg, level=None):
        tag = level or ("PASS" if ok else "FAIL")
        if tag == "FAIL": self["ok"] = False
        self["lines"].append(f"[{tag}] {msg}")

def find_transcript(contract_path, explicit=None, csha=None):
    if explicit: return explicit if os.path.exists(explicit) else None
    cands = [f"notbefore-executed-{csha[:16]}.json", os.path.join(os.path.dirname(contract_path) or ".", f"notbefore-executed-{csha[:16]}.json")]
    return next((c for c in cands if os.path.exists(c)), None)

# ---------------------------------------------------------------- gather + verify
def gather(contract_path, transcript=None, src=None, verify_pair=True, refetch=True, live_log=True):
    F = Facts(); F["generated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    F["tool"] = {"cli_version": __version__, "spec": SPEC, "verifier_git_sha": vendored_meta().get("git_sha")}
    raw = open(contract_path, "rb").read(); c = json.loads(raw); csha = hashlib.sha256(raw).hexdigest()
    F["contract"] = {"path": contract_path, "name": os.path.basename(contract_path), "sha256": csha, "obj": c, "spec": c.get("spec"), "canonical": C.canon(c) == raw}
    F.say(c.get("spec") in C.ACCEPTED_SPECS, f"contract spec {c.get('spec')}")
    F.say(F["contract"]["canonical"], f"contract is canonical JSON; SHA-256 {csha}")
    # statement
    st, sig = DL.read_signature(contract_path); S = {"present": st is not None}
    if st is not None:
        ok, why = DL.verify_statement(st, sig); signer = c.get("signer") or {}
        bound = st["contract_sha256"] == csha and st["key_id"] == signer.get("key_id") and st["public_key_b64"] == signer.get("public_key_b64") and st["decision_id"] == c.get("decision_id")
        S.update(ok=ok and bound, why=why if not ok else ("ok" if bound else "statement names a different contract, key or decision_id"), key_id=st["key_id"], public_key_b64=st["public_key_b64"], decision_id=st["decision_id"], created_utc=st["created_utc"], statement=st, signature_b64=sig)
        F.say(S["ok"], f"decision statement by key {st['key_id']} for decision_id {st['decision_id']!r}: {S['why']}")
    elif c.get("spec") == C.CONTRACT_SPEC: S.update(ok=False, why="signed contract without its .sig.json"); F.say(False, "signed contract/2 but no .sig.json beside it")
    else: S.update(ok=None, why="legacy unsigned contract/1"); F.say(True, "legacy unsigned contract/1: no signer, no decision-log namespace", "WARN")
    F["statement"] = S
    # RFC 3161
    toks, bad = C.verify_timestamps(contract_path); ok_t, why_t, latest = C.timestamp_verdict(toks, bad, None)
    F["tsa"] = {"tokens": [{"tsa": n, "time": t, "unix": u} for n, t, u in toks], "any_failed": bad, "complete": ok_t, "why": why_t, "latest_unix": latest}
    F.say(ok_t, f"RFC 3161: {why_t}" if ok_t else f"RFC 3161: {why_t}", None if ok_t else ("FAIL" if bad else "WARN"))
    # decision log: the stored receipt, verified offline; the live namespace, if allowed
    L = {"receipt_present": False}
    rp = DL.receipt_path(contract_path)
    if os.path.exists(rp) and st is not None:
        try:
            rj = json.load(open(rp)); rc = rj["receipt"]; ok, why = DL.verify_receipt(rc, st); leaf, _ = DL.parse_leaf(rc["leaf"]); _, size, root = DL.verify_note(rc["checkpoint"])
            L.update(receipt_present=True, receipt_ok=ok, why=why, index=rc["index"], seq_in_namespace=leaf["seq_in_namespace"], size=size, root_b64=base64.b64encode(root).decode() if root else None,
                     received_utc=leaf["received_utc"], received_unix=DL.parse_utc(leaf["received_utc"]), authoritative=leaf["seq_in_namespace"] == 1, receipt=rc, origin=DL.origin())
            F.say(ok, f"decision-log receipt: entry {rc['index']} of {size}, seq_in_namespace {leaf['seq_in_namespace']}, received {leaf['received_utc']} — {why}")
        except Exception as e: L.update(receipt_present=True, receipt_ok=False, why=f"{type(e).__name__}: {e}"); F.say(False, f"decision-log receipt unreadable: {e}")
    elif st is not None: F.say(True, "no decision-log receipt beside the contract (not registered, or registered by another machine)", "WARN")
    if st is not None and live_log and DL.enabled():
        live = DL.check_authoritative(st, offline=False); L["live"] = live
        lvl = "PASS" if live["status"] == "authoritative" else ("FAIL" if live["status"] == "superseded" else "WARN")
        F.say(lvl != "FAIL", f"decision log now: {live['why']}", lvl)
    F["log"] = L
    # transcript + the pulse
    tp = find_transcript(contract_path, transcript, csha); X = {"path": tp}
    if tp:
        t = json.load(open(tp)); X.update(obj=t, bound=t.get("contract_sha256") == csha, seq=t.get("seq"), commit_seq=t.get("commit_seq"), drand_round=t.get("drand_round"), attested_value=t.get("attested_value"),
                 value_rule=t.get("value_rule", "reveal"), provenance=t.get("provenance", "FULL-ATTESTED"), commit_bound_value=t.get("commit_bound_value"), drand=t.get("drand"), entropy_commitment=t.get("entropy_commitment"), publication_evidence=t.get("publication_evidence"), reveal_seq=t.get("reveal_seq"),
                 derived_seed=t.get("derived_seed"), operation=t.get("operation"), output_sha256=t.get("output_sha256"), A=t.get("A"), B=t.get("B"), value=t.get("value"), arm_sizes=t.get("arm_sizes"),
                 log_git_sha=t.get("log_git_sha"), verified_utc=t.get("verified_utc"), timestamping_complete=t.get("timestamping_complete"), decision_log=t.get("decision_log"), cli_version=t.get("cli_version"))
        F.say(X["bound"], f"transcript {os.path.basename(tp)} names this contract" if X["bound"] else f"transcript {os.path.basename(tp)} names a DIFFERENT contract ({str(t.get('contract_sha256'))[:16]}…)")
        F["status"] = "executed"
    else: F["status"] = "committed"; F.say(True, "not executed yet (no transcript): the receipt covers the commitment only", "INFO")
    F["transcript"] = X
    # the pair, re-verified now (this is what makes "the result" more than a copied number)
    P = {"verified": None}
    if tp and X.get("bound") and src is not None and X.get("value_rule") == "commit-bound":
        from . import commitbound as CB
        n = int(X["commit_seq"]); com = src.pulse(n)
        if com is None: F.say(False, f"commit {n:04d} is not in the log this receipt was generated against")
        else:
            cc = com["core"]; P["release_unix"] = int(cc["derived"]["target_release_unix_s"]); P["commit_utc"] = cc["derived"].get("anchor_utc_unix_s")
            d = X.get("drand") or {}
            ok, rho = CB.verify_round(cc["derived"]["target_round"], d.get("signature", ""), cc["chain_hash"]) if d.get("signature") else (False, "no drand signature in the transcript")
            F.say(ok and rho == d.get("randomness"), f"drand round {cc['derived']['target_round']} signature (from the transcript) BLS-verifies under the pinned quicknet key" if ok else f"drand signature: {rho}")
            if ok:
                vs = CB.value(cc["derived"]["entropy_commitment"], rho, cc["chain_hash"], cc["derived"]["target_round"]); P["same_value"] = vs == X.get("commit_bound_value")
                F.say(P["same_value"], "commit-bound value V* recomputes from the commit's C, rho_R, chain_hash and R" if P["same_value"] else "transcript's commit-bound value does NOT recompute from the commit and the round")
            if verify_pair:
                Rc = check_commit(n, src, refetch=refetch, anchors=True); P.update(verified=Rc.ok, lines=Rc.lines, log_git_sha=Rc.log_git_sha, cosignatures=Rc.cosignatures, independent_cosignatures=Rc.independent_cosignatures, anchors=Rc.anchors, tlog=Rc.tlog, tsa_pass=Rc.tsa_pass, bls_offline=True)
                F.say(Rc.ok, f"commit {n:04d} re-verified now (host signatures, {Rc.tsa_pass} TSA tokens, anchors {Rc.anchors}, transparency log {Rc.tlog}) at log {str(Rc.log_git_sha)[:12]}")
                if X.get("reveal_seq"):
                    Rr = check_pair(int(X["reveal_seq"]), src, refetch=refetch, anchors=True); P["reveal_verified"] = Rr.ok; F.say(Rr.ok, f"reveal {int(X['reveal_seq']):04d} re-verified: provenance FULL-ATTESTED stands" if Rr.ok else f"reveal {int(X['reveal_seq']):04d} no longer verifies")
                pe = X.get("publication_evidence") or {}
                if pe.get("present"): F.say(int(pe["integrated_unix"]) < P["release_unix"], f"Rekor logged the commit {pe.get('before_release_s')} s before its round (logIndex {pe.get('logIndex')}): publication before the round is third-party evidenced")
            if latest is not None: F.say(latest < P["release_unix"], f"latest RFC 3161 token {utc(latest)} is {P['release_unix'] - latest} s before the round release {utc(P['release_unix'])}" if latest < P["release_unix"] else "latest RFC 3161 token is AT/AFTER the round release")
            if L.get("received_unix") is not None: F.say(L["received_unix"] < P["release_unix"], f"decision-log registration {L['received_utc']} is {P['release_unix'] - L['received_unix']} s before the round release" if L["received_unix"] < P["release_unix"] else "decision-log registration is AT/AFTER the round release")
            try: P["seed_recomputes"] = D.seed(X.get("commit_bound_value"), c["purpose"]).hex() == X.get("derived_seed"); F.say(P["seed_recomputes"], "derived seed recomputes from V* and the contract's purpose")
            except Exception as e: F.say(True, f"seed recomputation skipped: {e}", "WARN")
    elif tp and X.get("bound") and src is not None:
        seq = int(X["seq"]); rev = src.pulse(seq)
        if rev is None: F.say(False, f"pulse {seq:04d} is not in the log this receipt was generated against")
        else:
            P["release_unix"] = int(rev["core"]["derived"]["round_release_unix_s"]); P["reveal_utc"] = rev["core"]["derived"].get("anchor_utc_unix_s")
            com = src.pulse(seq - 1); P["commit_utc"] = (com or {}).get("core", {}).get("derived", {}).get("anchor_utc_unix_s")
            P["same_value"] = rev["core"]["derived"]["attested_value"] == X["attested_value"]
            F.say(P["same_value"], f"the log's pulse {seq:04d} carries the transcript's attested value" if P["same_value"] else f"pulse {seq:04d} in the log carries a DIFFERENT attested value than the transcript")
            if verify_pair:
                R = check_pair(seq, src, refetch=refetch, anchors=True); P.update(verified=R.ok, lines=R.lines, log_git_sha=R.log_git_sha, cosignatures=R.cosignatures, independent_cosignatures=R.independent_cosignatures, anchors=R.anchors, tlog=R.tlog, tsa_pass=R.tsa_pass, bls_offline=R.bls_offline)
                F.say(R.ok, f"pulse pair {seq-1:04d}/{seq:04d} re-verified now (host signatures, BLS offline, {R.tsa_pass} TSA tokens, anchors {R.anchors}, transparency log {R.tlog}) at log {str(R.log_git_sha)[:12]}")
            # the two clocks against the round
            if latest is not None: F.say(latest < P["release_unix"], f"latest RFC 3161 token {utc(latest)} is {P['release_unix'] - latest} s before the round release {utc(P['release_unix'])}" if latest < P["release_unix"] else f"latest RFC 3161 token is AT/AFTER the round release")
            if L.get("received_unix") is not None: F.say(L["received_unix"] < P["release_unix"], f"decision-log registration {L['received_utc']} is {P['release_unix'] - L['received_unix']} s before the round release" if L["received_unix"] < P["release_unix"] else "decision-log registration is AT/AFTER the round release")
            # reproduce S from V and the purpose (the derive layer is deterministic)
            try: P["seed_recomputes"] = D.seed(rev["core"]["derived"]["attested_value"], c["purpose"]).hex() == X.get("derived_seed"); F.say(P["seed_recomputes"], "derived seed recomputes from V and the contract's purpose")
            except Exception as e: F.say(True, f"seed recomputation skipped: {e}", "WARN")
    F["pair"] = P
    return F

# ---------------------------------------------------------------- render
def _result_line(X):
    op = X.get("operation"); o = X.get("obj") or {}
    if op == "split": return f"split A {X['A']['count']} / B {X['B']['count']} (A sha256 {X['A']['sha256'][:16]}…, B sha256 {X['B']['sha256'][:16]}…)"
    if op == "sample": return f"sample of k = {o.get('k')} from {o.get('record_count')} records; output sha256 {str(X.get('output_sha256'))[:16]}…"
    if op == "assign": return f"assignment to {o.get('arms')} arms (sizes {X.get('arm_sizes')}); output sha256 {str(X.get('output_sha256'))[:16]}…"
    if op == "range": return f"integer {X.get('value')} in [{o.get('lo')}, {o.get('hi')}]"
    if op == "bytes": return f"{o.get('n')} public bytes, sha256 {str(X.get('output_sha256'))[:16]}…"
    if op == "id": return f"pseudonyms ({o.get('hexlen')} hex) for {o.get('record_count')} records; output sha256 {str(X.get('output_sha256'))[:16]}…"
    if op == "shuffle": return f"shuffle of {o.get('record_count')} records; output sha256 {str(X.get('output_sha256'))[:16]}…"
    if op == "seed": return f"derived seed {X.get('derived_seed')}"
    return f"{op}: output sha256 {str(X.get('output_sha256'))[:16]}…"

def render(F):
    c = F["contract"]["obj"]; S, Tk, L, X, P = F["statement"], F["tsa"], F["log"], F["transcript"], F["pair"]
    sel = c.get("selection", {}); prm = ", ".join(f"{k} = {v}" for k, v in (c.get("params") or {}).items()) or "none"; inp = c.get("input")
    out = [f"# NotBefore decision receipt — {c.get('decision_id') or c.get('purpose')}", ""]
    out.append(f"**Status:** {'EXECUTED' if F['status'] == 'executed' else 'COMMITTED, not yet executed'} · **all checks:** {'PASS' if F['ok'] else 'FAIL — see the verification trail'} · generated {F['generated_utc']} by notbefore {__version__} ({SPEC})")
    out += ["", "## Who committed", ""]
    if S.get("present"): out.append(f"- Key id `{S['key_id']}` (Ed25519 public key `{S['public_key_b64']}`), statement signed {S['created_utc']} — signature {'verifies' if S['ok'] else 'does NOT verify: ' + S['why']}.")
    else: out.append(f"- Legacy unsigned contract/1: no signer identity ({S.get('why')}).")
    out += ["", "## To what", "",
            f"- Contract `{F['contract']['name']}`, SHA-256 `{F['contract']['sha256']}` ({c.get('spec')}, canonical JSON).",
            f"- Decision id `{c.get('decision_id', '—')}`; purpose `{c.get('purpose')}`.",
            f"- Operation **{c.get('operation')}** with parameters {prm}." + (f" Input `{inp['file']}`: {inp['record_count']} records, SHA-256 `{inp['sha256']}`." if inp else ""),
            f"- Selection rule `{sel.get('rule')}` with after = {sel.get('after_utc')}: the first eligible NotBefore reveal whose drand round released at or after that instant.",
            f"- Contract created {c.get('created_utc')} with notbefore {c.get('cli_version')} ({c.get('spec_version')})."]
    out += ["", "## When (two independent clocks, plus the log)", ""]
    for t in Tk["tokens"]: out.append(f"- RFC 3161 token from **{t['tsa']}**: {t['time']} — verifies against the trust root pinned in this release.")
    if not Tk["complete"]: out.append(f"- ⚠ {Tk['why']}")
    if L.get("receipt_present"):
        out.append(f"- Decision log `{L.get('origin')}`: entry **{L['index']}** (tree size {L['size']}, root `{L['root_b64']}`), received {L['received_utc']}, seq_in_namespace {L['seq_in_namespace']} → **{'AUTHORITATIVE: the first registration for this key and decision id' if L['authoritative'] else 'an AMENDMENT — an earlier registration owns this decision id'}**. Receipt {'verifies' if L.get('receipt_ok') else 'does NOT verify: ' + str(L.get('why'))} (checkpoint signature under the pinned log key, Merkle inclusion proof).")
    elif S.get("present"): out.append("- Decision log: no receipt on this machine (not registered, or registered elsewhere).")
    if L.get("live"): out.append(f"- Decision log now ({F['generated_utc']}): {L['live']['status']} — {L['live']['why']}")
    out += ["", "## The randomness", ""]
    if F["status"] == "executed" and X.get("bound") and X.get("value_rule") == "commit-bound":
        out.append(f"- **Commit-bound value** (contract/3): NotBefore commit **{X['commit_seq']}**, drand quicknet round {X['drand_round']} released {utc(P.get('release_unix'))}; V* = SHA-256(\"notbefore/commit-bound/v1\" ‖ C ‖ ρ ‖ chain ‖ R) = `{X['commit_bound_value']}`.")
        out.append(f"- Provenance **{X['provenance']}**: " + ("the operator revealed the QRNG preimage in pulse %s and it verifies (V = `%s`)." % (X.get('reveal_seq'), X.get('attested_value')) if X.get("provenance") == "FULL-ATTESTED" else "the operator did not reveal; V* stands unchanged — a withheld reveal cannot change or void the value — but QRNG provenance is not demonstrated for this hour."))
        pe = X.get("publication_evidence") or {}
        if pe.get("present"): out.append(f"- The commit was Rekor-logged {pe.get('before_release_s')} s before its round (logIndex {pe.get('logIndex')}, {pe.get('integrated_utc')}): it was public before the randomness existed, by a clock the operator does not run.")
        if Tk.get("latest_unix") is not None and P.get("release_unix"): out.append(f"- Latest consumer timestamp precedes the round release by **{P['release_unix'] - Tk['latest_unix']} s**" + (f"; decision-log registration precedes it by **{P['release_unix'] - L['received_unix']} s**." if L.get("received_unix") is not None else "."))
        if P.get("verified") is not None: out.append(f"- Commit re-verified while writing this receipt: **{'PASS' if P['verified'] else 'FAIL'}** (host signatures, {P.get('tsa_pass')} TSA tokens, anchors {P.get('anchors')}, transparency log {P.get('tlog')}) at log commit `{_sha12(P.get('log_git_sha'))}`.")
    elif F["status"] == "executed" and X.get("bound"):
        out.append(f"- NotBefore pulse **{X['seq']}** (commit {X['commit_seq']}), drand quicknet round {X['drand_round']} released {utc(P.get('release_unix'))}; value V = `{X['attested_value']}`.")
        if P.get("commit_utc"): out.append(f"- The log committed its entropy at {utc(P['commit_utc'])} and revealed at {utc(P.get('reveal_utc'))}: the operator fixed its contribution before the round, the consumer fixed the decision before the round.")
        if Tk.get("latest_unix") is not None and P.get("release_unix"): out.append(f"- Latest consumer timestamp precedes the round release by **{P['release_unix'] - Tk['latest_unix']} s**" + (f"; decision-log registration precedes it by **{P['release_unix'] - L['received_unix']} s**." if L.get("received_unix") is not None else "."))
        if P.get("verified") is not None: out.append(f"- Pair re-verified while writing this receipt: **{'PASS' if P['verified'] else 'FAIL'}** (host signatures, BLS offline, {P.get('tsa_pass')} TSA tokens on the commit, anchors {P.get('anchors')}, transparency log {P.get('tlog')}" + (f", cosigned by {', '.join(P['cosignatures'])}" if P.get("cosignatures") else "") + f") at log commit `{_sha12(P.get('log_git_sha'))}`.")
    else: out.append(f"- Not yet: the pulse is the first eligible reveal released at or after {sel.get('after_utc')}. Run `notbefore execute {F['contract']['name']}` after that hour.")
    out += ["", "## The result", ""]
    if F["status"] == "executed" and X.get("bound"):
        out.append(f"- {_result_line(X)}")
        out.append(f"- Derived seed S = SHA-256(\"notbefore/derive/v1\" ‖ {'V*' if X.get('value_rule') == 'commit-bound' else 'V'} ‖ purpose) = `{X.get('derived_seed')}`" + (" (recomputed here)" if P.get("seed_recomputes") else "") + ".")
        out.append(f"- Transcript `{os.path.basename(X['path'])}` (executed {X.get('verified_utc')} with notbefore {X.get('cli_version')}); reproduce with `notbefore execute {F['contract']['name']} --input <the committed file>`.")
    else: out.append("- None yet.")
    out += ["", "## How to check this yourself", "",
            f"1. `pip install notbefore` (any release ≥ 0.9.0), then `notbefore check-bundle <this bundle>` — offline: manifest, contract, statement, tokens, log receipt, pulse pair, checkpoint, anchors.",
            f"2. `notbefore verify {X.get('seq') or (int(X['commit_seq']) + 1 if X.get('commit_seq') else '<seq>')}` — the pulse pair against the live public log, drand and Rekor" + (" (for a COMMITMENT-FALLBACK hour there is no reveal: the commit and the drand round are what the bundle carries)." if X.get("provenance") == "COMMITMENT-FALLBACK" else "."),
            f"3. `notbefore execute {F['contract']['name']} --input <file>` — the same output from the same contract, or a refusal with the reason.",
            "4. Compare `decision_id` and `key_id` with the registry entry / protocol your institution holds (NotBefore cannot tell two names for one experiment apart).",
            "", "## Verification trail", ""]
    out += [f"    {l}" for l in F["lines"]]
    out += ["", f"_Spec NOTBEFORE.md 0.6 §7.11–7.12; log github.com/docdailey/qrng-beacon-log; decision log DECISION-LOG.md. Verifier vendored from `{str(F['tool']['verifier_git_sha'])[:12]}`._", ""]
    return "\n".join(out)

# ---------------------------------------------------------------- bundle
def bundle(F, out, src=None, include_input=False, include_output=False):
    """Write the verification bundle. `out` = directory (created) or a path ending in .zip. Returns the path written."""
    zipped = out.endswith(".zip"); root = tempfile.mkdtemp(prefix="nb-bundle-") if zipped else out
    if not zipped:
        if os.path.exists(root) and os.listdir(root): raise FileExistsError(f"{root} exists and is not empty")
        os.makedirs(root, exist_ok=True)
    files = {}
    def put(rel, data=None, srcpath=None):
        p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        if srcpath: shutil.copy2(srcpath, p)
        else: open(p, "wb").write(data if isinstance(data, bytes) else data.encode())
        files[rel] = sha256_file(p)
    cp = F["contract"]["path"]; cname = F["contract"]["name"]
    put(f"contract/{cname}", srcpath=cp)
    for ext in (".sig.json", ".tsa.json", ".log.json", *[f".{n}.tsr" for n in sorted(C.EXPECTED_TSAS)]):
        if os.path.exists(cp + ext): put(f"contract/{cname}{ext}", srcpath=cp + ext)
    c = F["contract"]["obj"]; X = F["transcript"]
    if include_input and c.get("input"):
        ip = os.path.join(os.path.dirname(cp) or ".", c["input"]["file"])
        if os.path.exists(ip) and sha256_file(ip) == c["input"]["sha256"]: put(f"input/{c['input']['file']}", srcpath=ip)
    if X.get("path"):
        put(f"transcript/{os.path.basename(X['path'])}", srcpath=X["path"])
        if include_output and c.get("input"):
            base = c["input"]["file"]
            for cand in ((base + ".A", base + ".B") if X.get("operation") == "split" else ()):
                if os.path.exists(cand): put(f"output/{cand}", srcpath=cand)
    # the pair, its predecessor, tokens, checkpoint, inclusion proofs, anchors
    anchor_seq = int(X["seq"]) if X.get("seq") else (int(X["commit_seq"]) + 1 if X.get("commit_seq") else None)   # the "reveal slot" even when empty
    if anchor_seq and src is not None:
        seq = anchor_seq
        for s in (seq - 2, seq - 1, seq):
            if s >= 1 and src.has_pulse(s):
                for side in ("", ".tsa.json", ".freetsa.tsr", ".digicert.tsr"):
                    b = src._read_bytes(f"chain/pulse-{s:04d}.json{side}")
                    if b is not None: put(f"log/chain/pulse-{s:04d}.json{side}", b)
        note = src._read_bytes("checkpoint")
        if note:
            put("log/checkpoint", note)
            try:
                from . import tlogcheck
                leaves = tlogcheck._chain_leaves_from_source(src); origin_, size, troot = T.parse_checkpoint(T.parse_note(note.decode())[0])
                proofs = {str(s): [base64.b64encode(h).decode() for h in T.inclusion_path(s - 1, leaves[:size])] for s in (seq - 1, seq) if s - 1 < size and src.has_pulse(s)}
                put("log/inclusion.json", json.dumps({"origin": origin_, "size": size, "root_b64": base64.b64encode(troot).decode(), "leaf": "canonical(pulse JSON), index = seq - 1", "proofs": proofs}, indent=1))
            except Exception as e: F.say(True, f"inclusion proofs not bundled: {e}", "WARN")
        try:
            if src.anchors_available():
                for s in (seq - 1, seq):
                    if not src.has_pulse(s): continue
                    rec, stmt = src.anchor(s)
                    if rec: put(f"log/anchors/pulse-{s:04d}.anchor.json", json.dumps(rec, indent=1, sort_keys=True)); put(f"log/anchors/pulse-{s:04d}.stmt.json", stmt)
        except Exception as e: F.say(True, f"anchor records not bundled: {e}", "WARN")
        knc = os.path.join(VENDOR, "ci", "KNOWN_NONCOMPLIANT.json")
        if os.path.exists(knc): put("log/KNOWN_NONCOMPLIANT.json", srcpath=knc)
    L = F["log"]
    if L.get("receipt_present") and L.get("receipt"):
        rc = L["receipt"]; put(f"decisions/leaf-{rc['index']}.json", rc["leaf"]); put("decisions/checkpoint", rc["checkpoint"])
        put(f"decisions/proof-{rc['index']}.json", json.dumps({"index": rc["index"], "size": rc["size"], "proof": rc["proof"]}, indent=1))
    # the release's public keys and pins, for the record (a checker must use ITS OWN installed copy)
    for dp, _, fns in os.walk(KEYS):
        for fn in fns:
            if fn.startswith("."): continue
            full = os.path.join(dp, fn); put("verifier/keys/" + os.path.relpath(full, KEYS), srcpath=full)
    put("verifier/VENDORED.json", srcpath=os.path.join(VENDOR, "VENDORED.json"))
    put("README.md", render(F))
    man = {"bundle": BUNDLE_SPEC, "generated_utc": F["generated_utc"], "tool": F["tool"], "contract_sha256": F["contract"]["sha256"], "decision_id": c.get("decision_id"), "key_id": (c.get("signer") or {}).get("key_id"),
           "seq": X.get("seq"), "commit_seq": X.get("commit_seq"), "value_rule": X.get("value_rule"), "provenance": X.get("provenance"), "status": F["status"], "all_checks_passed_at_generation": F["ok"], "files": dict(sorted(files.items()))}
    mp = os.path.join(root, "MANIFEST.json"); json.dump(man, open(mp, "w"), indent=1, sort_keys=True)
    if zipped:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for dp, _, fns in os.walk(root):
                for fn in sorted(fns): full = os.path.join(dp, fn); z.write(full, os.path.relpath(full, root))
        shutil.rmtree(root, ignore_errors=True)
    return out

# ---------------------------------------------------------------- check
class _BundleSource:
    """Just enough of LogSource for _check_anchors and the pulse files, over the bundle's log/ directory."""
    def __init__(self, root): self.root = root; self.dir = root; self.is_git = False; self.offline = True; self.tmp = os.path.join(root, "log")   # _check_anchors reads <tmp>/chain/pulse-NNNN.json
    def _read_bytes(self, rel):
        p = os.path.join(self.root, "log", rel); return open(p, "rb").read() if os.path.exists(p) else None
    def pulse(self, seq): b = self._read_bytes(f"chain/pulse-{seq:04d}.json"); return json.loads(b) if b else None
    def has_pulse(self, seq): return self._read_bytes(f"chain/pulse-{seq:04d}.json") is not None
    def anchors_available(self): return os.path.isdir(os.path.join(self.root, "log", "anchors"))
    def anchor(self, seq):
        rp = os.path.join(self.root, "log", "anchors", f"pulse-{seq:04d}.anchor.json"); sp = rp.replace(".anchor.json", ".stmt.json")
        return (json.load(open(rp)), open(sp, "rb").read()) if os.path.exists(rp) and os.path.exists(sp) else (None, None)

def check_bundle(path, verify_pulses=True):
    """Offline re-verification of a bundle with the INSTALLED release's keys and roots. Returns (ok, lines)."""
    R = CheckResult(0); tmp = None
    if zipfile.is_zipfile(path):
        tmp = tempfile.mkdtemp(prefix="nb-check-"); zipfile.ZipFile(path).extractall(tmp); root = tmp
    else: root = path
    try:
        mp = os.path.join(root, "MANIFEST.json")
        if not os.path.exists(mp): R.say(False, "no MANIFEST.json: not a NotBefore bundle"); return False, R.lines
        man = json.load(open(mp)); R.say(man.get("bundle") == BUNDLE_SPEC, f"manifest {man.get('bundle')} generated {man.get('generated_utc')} by notbefore {man.get('tool', {}).get('cli_version')}")
        bad = [rel for rel, h in man["files"].items() if not os.path.exists(os.path.join(root, rel)) or sha256_file(os.path.join(root, rel)) != h]
        R.say(not bad, f"{len(man['files'])} files match the manifest" if not bad else f"{len(bad)} file(s) missing or altered since the bundle was written: {bad[:3]}")
        extra = [os.path.relpath(os.path.join(dp, fn), root) for dp, _, fns in os.walk(root) for fn in fns if os.path.relpath(os.path.join(dp, fn), root) not in man["files"] and fn != "MANIFEST.json"]
        if extra: R.say(True, f"{len(extra)} file(s) not in the manifest (ignored): {extra[:3]}", "WARN")
        cfiles = [f for f in man["files"] if f.startswith("contract/") and f.endswith(".json") and not f.endswith((".sig.json", ".tsa.json", ".log.json"))]
        if len(cfiles) != 1: R.say(False, "expected exactly one contract in contract/"); return False, R.lines
        cp = os.path.join(root, cfiles[0]); raw = open(cp, "rb").read(); c = json.loads(raw); csha = hashlib.sha256(raw).hexdigest()
        R.say(C.canon(c) == raw and csha == man["contract_sha256"], f"contract canonical, SHA-256 {csha} == manifest")
        st, sig = DL.read_signature(cp)
        if c.get("spec") == C.CONTRACT_SPEC:
            ok, why = DL.verify_statement(st, sig) if st else (False, "no .sig.json")
            bound = bool(st) and st["contract_sha256"] == csha and st["key_id"] == c["signer"]["key_id"] and st["decision_id"] == c["decision_id"]
            R.say(ok and bound, f"decision statement by {c['signer']['key_id']} for {c['decision_id']!r}: {why if not ok else ('bound to this contract' if bound else 'NOT bound to this contract')}")
        else: R.say(True, "legacy unsigned contract/1", "WARN")
        toks, tbad = C.verify_timestamps(cp); ok_t, why_t, latest = C.timestamp_verdict(toks, tbad, None); R.say(ok_t, f"contract RFC 3161 tokens (pinned roots of this installation): {why_t}", None if ok_t else ("FAIL" if tbad else "WARN"))
        # decision-log receipt, offline
        received = None; rp = DL.receipt_path(cp)
        if os.path.exists(rp) and st:
            rc = json.load(open(rp))["receipt"]; ok, why = DL.verify_receipt(rc, st); R.say(ok, f"decision-log receipt (entry {rc['index']} of {rc['size']}, vendored key {DL.identity().get('key_id_hex') if DL.identity() else '?'}): {why}")
            if ok:
                leaf, _ = DL.parse_leaf(rc["leaf"]); received = DL.parse_utc(leaf["received_utc"])
                R.say(leaf["seq_in_namespace"] == 1, f"seq_in_namespace {leaf['seq_in_namespace']}: {'authoritative preregistration' if leaf['seq_in_namespace'] == 1 else 'an AMENDMENT, not the preregistration'}")
                dcp = os.path.join(root, "decisions", "checkpoint")
                if os.path.exists(dcp): R.say(open(dcp).read() == rc["checkpoint"], "bundled decisions/checkpoint is the receipt's checkpoint")
        # transcript + pulses
        tfiles = [f for f in man["files"] if f.startswith("transcript/")]
        if not tfiles: R.say(True, "no transcript: a commitment-only bundle (nothing executed yet)", "INFO"); return R.ok, R.lines
        t = json.load(open(os.path.join(root, tfiles[0]))); R.say(t.get("contract_sha256") == csha, "transcript names this contract")
        bs = _BundleSource(root)
        if t.get("value_rule") == "commit-bound":
            return _check_bundle_commit_bound(R, root, bs, t, c, latest, received, verify_pulses)
        seq = int(t["seq"]); rev, com = bs.pulse(seq), bs.pulse(seq - 1)
        if not rev or not com: R.say(False, f"pulse pair {seq-1:04d}/{seq:04d} not in the bundle"); return R.ok, R.lines
        for p, name in ((com, f"commit {seq-1:04d}"), (rev, f"reveal {seq:04d}")):
            R.say(hashlib.sha256(T.canonical(p["core"])).hexdigest() == p["pulse_hash"], f"{name}: pulse_hash == SHA-256(canonical core)")
        R.say(rev["core"]["derived"]["attested_value"] == t.get("attested_value") and rev["pulse_hash"] == t.get("pulse_hash_reveal") and com["pulse_hash"] == t.get("pulse_hash_commit"), "transcript's pulse hashes and attested value match the bundled pulses")
        rel = int(rev["core"]["derived"]["round_release_unix_s"])
        if latest is not None: R.say(latest < rel, f"latest contract token {utc(latest)} {'precedes' if latest < rel else 'does NOT precede'} the round release {utc(rel)}")
        if received is not None: R.say(received < rel, f"decision-log registration {utc(received)} {'precedes' if received < rel else 'does NOT precede'} the round release")
        try: R.say(D.seed(rev["core"]["derived"]["attested_value"], c["purpose"]).hex() == t.get("derived_seed"), "derived seed recomputes from V and the contract purpose")
        except Exception as e: R.say(False, f"seed recomputation failed: {e}")
        if verify_pulses:
            vpy = os.path.join(VENDOR, "verify.py"); pc, pr = os.path.join(root, "log", "chain", f"pulse-{seq-1:04d}.json"), os.path.join(root, "log", "chain", f"pulse-{seq:04d}.json")
            pp = os.path.join(root, "log", "chain", f"pulse-{seq-2:04d}.json"); pp = pp if os.path.exists(pp) else None
            rc_, out = _run([vpy, pc, "--pin", KEYS] + (["--prev", pp] if pp else [])); R.verbose.append(out); R.say(rc_ == 0 and "ALL CHECKS PASSED" in out, f"commit {seq-1:04d}: vendored verify.py offline (pinned keys{', chained to %04d' % (seq-2) if pp else ''})")
            rc_, out = _run([vpy, pr, "--pin", KEYS, "--prev", pc]); R.verbose.append(out); R.say(rc_ == 0 and "ALL CHECKS PASSED" in out, f"reveal {seq:04d}: vendored verify.py offline (pinned keys, chained to {seq-1:04d}, V recomputed, BLS {'offline' if '[full BLS, offline]' in out else 'NOT verified'})")
            rc_, out = _run([os.path.join(VENDOR, "tsa.py"), "verify", pc]); n = out.count("[PASS] RFC3161"); R.say(n >= 2 and "[FAIL]" not in out, f"commit {seq-1:04d}: {n} RFC 3161 token(s) verify against the pinned roots")
        # pulse-log checkpoint + inclusion + cosignatures
        note_p = os.path.join(root, "log", "checkpoint"); inc_p = os.path.join(root, "log", "inclusion.json")
        if os.path.exists(note_p):
            from . import tlogcheck; ident = tlogcheck.identity()
            if ident:
                pub = T.load_pub_raw(os.path.join(KEYS, os.path.basename(ident["public_key_file"]))); note = open(note_p).read(); ok, text = T.verify_note(note, ident["origin"], pub); o, size, root_h = T.parse_checkpoint(text)
                R.say(ok and o == ident["origin"], f"pulse-log checkpoint (size {size}) signed by {ident['origin']} (vendored key)")
                if ok and os.path.exists(inc_p):
                    inc = json.load(open(inc_p)); R.say(inc["size"] == size and base64.b64decode(inc["root_b64"]) == root_h, "bundled inclusion proofs are for that checkpoint")
                    for s_, path in inc["proofs"].items():
                        pj = bs.pulse(int(s_)); R.say(pj is not None and T.verify_inclusion(T.leaf_hash(T.canonical(pj)), int(s_) - 1, size, [base64.b64decode(x) for x in path], root_h), f"pulse {int(s_):04d} is included in that checkpoint (RFC 6962 proof)")
                try:
                    wj = json.load(open(os.path.join(KEYS, "WITNESSES.json"))); cos = {}
                    for w in wj.get("witnesses", []) + wj.get("independent_witnesses", []):
                        n_, alg, pk = T.parse_verifier_key(w["verifier_key"]);  cos[n_] = pk if alg == 4 else None
                    good = T.verify_cosignatures(note, {k: v for k, v in cos.items() if v}); R.say(True, f"checkpoint cosigned by {', '.join(n for n, _ in good)}" if good else "checkpoint carries no known witness cosignature", "INFO")
                except Exception as e: R.say(True, f"cosignature check skipped: {e}", "WARN")
        if bs.anchors_available():
            try: R.anchors = _check_anchors(R, bs, (seq - 1, seq), rev["core"], False)
            except Exception as e: R.say(True, f"anchor check unavailable offline: {e}", "WARN")
        # outputs, if included
        for rel_ in [f for f in man["files"] if f.startswith("output/")]:
            h = sha256_file(os.path.join(root, rel_)); expect = {t.get("A", {}).get("file") if isinstance(t.get("A"), dict) else None: (t.get("A") or {}).get("sha256"), (t.get("B") or {}).get("file") if isinstance(t.get("B"), dict) else None: (t.get("B") or {}).get("sha256")}
            R.say(h in (expect.get(os.path.basename(rel_)), t.get("output_sha256")), f"{rel_} hashes to the transcript's value")
        return R.ok, R.lines
    finally:
        if tmp: shutil.rmtree(tmp, ignore_errors=True)

def _check_bundle_commit_bound(R, root, bs, t, c, latest, received, verify_pulses):
    """contract/3: the commit is the object; the reveal is provenance. Recompute V* from the bundled commit and the
    transcript's drand signature (BLS under the pinned key); run the vendored verifier on the commit (+ reveal if present)."""
    from . import commitbound as CB
    n = int(t["commit_seq"]); com = bs.pulse(n)
    if not com: R.say(False, f"commit {n:04d} not in the bundle"); return R.ok, R.lines
    cc = com["core"]; R.say(hashlib.sha256(T.canonical(cc)).hexdigest() == com["pulse_hash"] == t.get("pulse_hash_commit"), f"commit {n:04d}: pulse_hash == SHA-256(canonical core) == transcript")
    d = t.get("drand") or {}; ok, rho = CB.verify_round(cc["derived"]["target_round"], d.get("signature", ""), cc["chain_hash"]) if d.get("signature") else (False, "no drand signature in the transcript")
    R.say(ok and rho == d.get("randomness"), f"drand round {cc['derived']['target_round']}: transcript signature BLS-verifies under the pinned quicknet key (offline)" if ok else f"drand: {rho}")
    if ok: R.say(CB.value(cc["derived"]["entropy_commitment"], rho, cc["chain_hash"], cc["derived"]["target_round"]) == t.get("commit_bound_value"), "commit-bound value V* recomputes from C, rho_R, chain_hash, R")
    rel = int(cc["derived"]["target_release_unix_s"])
    if latest is not None: R.say(latest < rel, f"latest contract token {utc(latest)} {'precedes' if latest < rel else 'does NOT precede'} the round release {utc(rel)}")
    if received is not None: R.say(received < rel, f"decision-log registration {utc(received)} {'precedes' if received < rel else 'does NOT precede'} the round release")
    try: R.say(D.seed(t.get("commit_bound_value"), c["purpose"]).hex() == t.get("derived_seed"), "derived seed recomputes from V* and the contract purpose")
    except Exception as e: R.say(False, f"seed recomputation failed: {e}")
    pe = t.get("publication_evidence") or {}
    ar = os.path.join(root, "log", "anchors", f"pulse-{n:04d}.anchor.json")
    if os.path.exists(ar):
        rec = json.load(open(ar)); it = int(rec["rekor"]["integratedTime"]); R.say(it < rel and it == int(pe.get("integrated_unix", -1)), f"bundled Rekor record: logged {rel - it} s before the round (matches the transcript's publication evidence)")
    else: R.say(True, "no Rekor record for the commit in the bundle: publication-before-round evidence not re-checkable offline", "WARN")
    rev = bs.pulse(n + 1) if os.path.exists(os.path.join(root, "log", "chain", f"pulse-{n+1:04d}.json")) else None
    prov = t.get("provenance")
    if prov == "FULL-ATTESTED":
        R.say(bool(rev) and rev["core"].get("type") == "reveal" and rev["core"]["derived"]["attested_value"] == t.get("attested_value"), f"reveal {n+1:04d} bundled and carries the transcript's attested value (FULL-ATTESTED)")
    else: R.say(True, f"provenance {prov}: no verifying reveal for commit {n:04d}; V* stands regardless", "INFO")
    if verify_pulses:
        vpy = os.path.join(VENDOR, "verify.py"); pc = os.path.join(root, "log", "chain", f"pulse-{n:04d}.json"); pp = os.path.join(root, "log", "chain", f"pulse-{n-1:04d}.json"); pp = pp if os.path.exists(pp) else None
        rc_, out = _run([vpy, pc, "--pin", KEYS] + (["--prev", pp] if pp else [])); R.verbose.append(out); R.say(rc_ == 0 and "ALL CHECKS PASSED" in out, f"commit {n:04d}: vendored verify.py offline (pinned keys{', chained to %04d' % (n-1) if pp else ''})")
        rc_, out = _run([os.path.join(VENDOR, "tsa.py"), "verify", pc]); k = out.count("[PASS] RFC3161"); R.say(k >= 2 and "[FAIL]" not in out, f"commit {n:04d}: {k} RFC 3161 token(s) verify against the pinned roots")
        if rev and rev["core"].get("type") == "reveal":
            pr = os.path.join(root, "log", "chain", f"pulse-{n+1:04d}.json"); rc_, out = _run([vpy, pr, "--pin", KEYS, "--prev", pc]); R.verbose.append(out); R.say(rc_ == 0 and "ALL CHECKS PASSED" in out, f"reveal {n+1:04d}: vendored verify.py offline (BLS {'offline' if '[full BLS, offline]' in out else 'NOT verified'})")
    note_p = os.path.join(root, "log", "checkpoint"); inc_p = os.path.join(root, "log", "inclusion.json")
    if os.path.exists(note_p):
        from . import tlogcheck; ident = tlogcheck.identity()
        if ident:
            pub = T.load_pub_raw(os.path.join(KEYS, os.path.basename(ident["public_key_file"]))); note = open(note_p).read(); ok, text = T.verify_note(note, ident["origin"], pub); o, size, root_h = T.parse_checkpoint(text)
            R.say(ok and o == ident["origin"], f"pulse-log checkpoint (size {size}) signed by {ident['origin']} (vendored key)")
            if ok and os.path.exists(inc_p):
                inc = json.load(open(inc_p))
                for s_, path in inc["proofs"].items():
                    pj = bs.pulse(int(s_)); R.say(pj is not None and T.verify_inclusion(T.leaf_hash(T.canonical(pj)), int(s_) - 1, size, [base64.b64decode(x) for x in path], root_h), f"pulse {int(s_):04d} is included in that checkpoint (RFC 6962 proof)")
    return R.ok, R.lines
