"""notbefore — CLI (NOTBEFORE.md §8).

  notbefore verify  <seq>
  notbefore value   <seq>
  notbefore seed    <seq> --purpose <P>
  notbefore shuffle <seq> --purpose <P> <file>
  notbefore split   <seq> --purpose <P> --frac 0.8 <file>
  notbefore keygen | plan | register | execute | receipt | bundle | check-bundle   (WORKFLOW.md: the preregistration path)

`value`/`seed`/`shuffle`/`split` print nothing usable unless `verify` would pass; exit 1 otherwise.
Streams: the verification transcript goes to STDERR, payloads to STDOUT — `V=$(notbefore value 45)` captures the hex
alone. `-q` silences the PASS/INFO lines; FAIL/WARN lines and the exit status remain.
The verifier and every key are vendored in this package; the log is read as data. Requires `git` and `openssl` on PATH.
"""
import sys, os, json, argparse, hashlib
from . import __version__, SPEC, DEFAULT_REPO
from .log import LogSource, LogError
from .check import check_pair, vendored_meta
from . import derive as D

def _err(msg): sys.stderr.write("notbefore: " + msg + "\n")

def build_parser():
    ap = argparse.ArgumentParser(prog="notbefore", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    ap.add_argument("--version", action="version", version=f"notbefore {__version__} ({SPEC}; verifier vendored from {vendored_meta().get('git_sha','?')[:12]})")
    g = ap.add_argument_group("log source")
    g.add_argument("--repo", default=DEFAULT_REPO, help="git URL of the log (default: the public qrng-beacon-log)")
    g.add_argument("--log-dir", help="use this local checkout/directory instead of a cached clone")
    g.add_argument("--log-ref", help="git ref/sha of the log to read (default origin/main; with --log-dir default: working tree)")
    g.add_argument("--cache", help="cache directory for the clone (default ~/.cache/notbefore/qrng-beacon-log)")
    g.add_argument("--offline", action="store_true", help="no network: no fetch, no drand/Rekor refetch (BLS + proofs still verify offline)")
    g.add_argument("--no-anchors", action="store_true", help="skip the Rekor/OpenTimestamps anchor check")
    g.add_argument("--checkpoint-url", help="cross-check the log's checkpoint served over HTTPS (default: the vendored identity's site, https://notbefore.net/checkpoint)")
    g.add_argument("--witness-quorum", type=int, default=0, help="require this many INDEPENDENT witness cosignatures on the checkpoint (default 0: report only; same-sponsor witnesses never count)")
    g.add_argument("--lock", help="read log_git_sha from this notbefore.lock (written by `pin`) and verify at exactly that log commit; ./notbefore.lock is used automatically if present")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the vendored verifier's full output")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress the PASS/INFO lines on stderr; FAIL/WARN lines and a non-zero exit still report a bad pair. Payloads were always stdout-only")
    ap.add_argument("--json", action="store_true", help="machine-readable result on stdout")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=lambda **kw: argparse.ArgumentParser(allow_abbrev=False, **kw))   # no prefix matching: --lo is not --lock
    def common(p, purpose=False, file=False):
        p.add_argument("seq", type=int, help="reveal seq N (its commit is N-1)")
        for flags, kw in ((("-v", "--verbose"), {}), (("-q", "--quiet"), {}), (("--json",), {}), (("--offline",), {}), (("--no-anchors",), {})):
            p.add_argument(*flags, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS, **kw)
        if purpose:
            p.add_argument("--purpose", required=True, help="non-secret label, ^[A-Za-z0-9._:/=@+-]+$, ≤ 256 bytes")
            p.add_argument("--transcript", help="write the transcript JSON here (default: ./notbefore-<seq>-<purpose>.json); '-' for stdout, 'none' to skip")
        if file: p.add_argument("file", help="input file, one record per line (UTF-8)")
    common(sub.add_parser("verify", help="verify the pair (commit N-1, reveal N); exit 0/1"))
    common(sub.add_parser("value", help="print the attested value V (hex) if the pair verifies"))
    common(sub.add_parser("seed", help="print the derived seed S = SHA256(D_derive || V || purpose)"), purpose=True)
    common(sub.add_parser("shuffle", help="deterministically shuffle the lines of FILE with S"), purpose=True, file=True)
    common(sub.add_parser("sample", help="shuffle FILE with S and take the first K lines (exact count)"), purpose=True, file=True); sub.choices["sample"].add_argument("--k", type=int, required=True)
    common(sub.add_parser("assign", help="shuffle FILE with S; shuffled position i -> arm i mod M (balanced arms); prints record<TAB>arm"), purpose=True, file=True); sub.choices["assign"].add_argument("--arms", type=int, required=True)
    idp = sub.add_parser("id", help="pseudonym per line of --from FILE: SHA256(notbefore/id/v1 || S || line)[:len]; output has no names"); common(idp, purpose=True)
    idp.add_argument("--from", dest="from_file", required=True); idp.add_argument("--len", dest="hexlen", type=int, default=16)
    rg = sub.add_parser("range", help="one uniform integer in [lo, hi] derived from S (rejection sampling)"); common(rg, purpose=True); rg.add_argument("--lo", type=int, required=True); rg.add_argument("--hi", type=int, required=True)
    by = sub.add_parser("bytes", help="n bytes of counter-mode SHA-256 keyed by S (public!) as hex"); common(by, purpose=True); by.add_argument("--n", type=int, required=True)
    common(sub.add_parser("explain", help="a methods-section paragraph for the pair: commit time, TSA times, round, release, V, eligibility, log commit"))
    pn = sub.add_parser("pin", help="write notbefore.lock pinning the log commit, CLI version and vendored verifier for bit-stable re-runs")
    pn.add_argument("--out", default="notbefore.lock")
    dt = sub.add_parser("diff-transcript", help="compare two transcripts: did the input, the pulse, the purpose or the tool change?"); dt.add_argument("a"); dt.add_argument("b")
    kg = sub.add_parser("keygen", help="create this consumer's Ed25519 identity (~/.config/notbefore/identity.key); it signs decision statements for the write-once decision log")
    kg.add_argument("--key", help="where to write the key (default $NOTBEFORE_KEY or ~/.config/notbefore/identity.key)"); kg.add_argument("--force", action="store_true", help="replace an existing key (its namespace is abandoned)")
    for fl in (("--json",),): kg.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    wi = sub.add_parser("whoami", help="print this consumer's key_id and public key"); wi.add_argument("--key")
    for fl in (("--json",),): wi.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    rg2 = sub.add_parser("register", help="append an existing signed contract's decision statement to the write-once decision log (idempotent); done by `plan` normally")
    rg2.add_argument("contract"); rg2.add_argument("--disclose", action="store_true", help="also publish the contract body itself in the log (default: the hash only)")
    for fl in (("--json",), ("-q", "--quiet")): rg2.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    pl = sub.add_parser("plan", help="write a decision contract (selection rule, purpose, operation, parameters, input sha256), sign it with your identity, timestamp it with two RFC 3161 TSAs and register it in the write-once decision log — all BEFORE the pulse exists")
    pl.add_argument("--key", help="identity key (default $NOTBEFORE_KEY or ~/.config/notbefore/identity.key; run `notbefore keygen` once)")
    pl.add_argument("--decision-id", help="write-once namespace under your key (default: the purpose string). For anything that matters, bind it to an artifact your peers hold: <registry id>/<protocol version>/<decision>, e.g. NCT01234567/protocol-3/randomization-1 — then a duplicate preregistration is visible outside NotBefore too")
    pl.add_argument("--unsigned", action="store_true", help="legacy contract/1 without signer or decision log (discouraged; execute labels it)")
    pl.add_argument("--no-log", action="store_true", help="sign and timestamp but do not submit to the decision log now (register later with `notbefore register`)")
    pl.add_argument("--disclose", action="store_true", help="publish the contract body in the decision log, not just its hash")
    pl.add_argument("--after", required=True, help="ISO-8601 UTC: use the first eligible reveal whose drand round released at or after this instant (e.g. 2026-10-01T00:00Z)")
    pl.add_argument("--purpose", required=True); pl.add_argument("--out", default=None, help="contract path (default notbefore-plan-<purpose>.json)")
    for name, kw in (("--sample", dict(type=int, metavar="K")), ("--split", dict(type=float, metavar="FRAC")), ("--assign", dict(type=int, metavar="ARMS")), ("--shuffle", dict(action="store_true")),
                     ("--id", dict(action="store_true")), ("--range", dict(nargs=2, type=int, metavar=("LO", "HI"))), ("--bytes", dict(type=int, metavar="N")), ("--seed", dict(action="store_true"))):
        pl.add_argument(name, **kw)
    pl.add_argument("--hexlen", type=int, default=16); pl.add_argument("--note"); pl.add_argument("--no-timestamp", "--no-register", dest="no_register", action="store_true", help="write the contract without TSA tokens (execute will refuse it unless --allow-unregistered)")
    pl.add_argument("file", nargs="?", help="input records (one per line) for sample/split/assign/shuffle/id")
    ts = sub.add_parser("timestamp", help="(re)request RFC 3161 tokens for an existing contract from any expected TSA that has not answered yet"); ts.add_argument("contract")
    ex = sub.add_parser("execute", help="run a timestamped decision contract: no choices are accepted here")
    ex.add_argument("contract"); ex.add_argument("--input", help="path of the committed input file if it moved (its sha256 must still match)")
    ex.add_argument("--allow-unregistered", action="store_true", help="DEGRADED run: accept a contract whose timestamps are missing/incomplete or whose decision-log registration cannot be confirmed (unregistered, log unreachable, or a legacy contract/1). No third party then vouches that this was THE preregistration; the transcript says so loudly. Never overrides a token AFTER the round, a superseded contract, or a registration at/after the round.")
    ex.add_argument("--require-log", action="store_true", help=argparse.SUPPRESS)   # since 0.10.0 this is the default; accepted for old scripts
    ex.add_argument("--transcript", help="transcript path (default notbefore-executed-<contract sha>.json; '-' stdout; 'none')")
    for fl in (("--json",), ("--offline",), ("-q", "--quiet"), ("--no-anchors",)): ex.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    rcpt = sub.add_parser("receipt", help="one-page human-readable decision receipt for a contract (re-verifies every line; Markdown to stdout or --out)")
    rcpt.add_argument("contract"); rcpt.add_argument("--transcript", help="the execution transcript (default: notbefore-executed-<sha16>.json beside the contract or in the cwd)"); rcpt.add_argument("--out", help="write the receipt here instead of stdout")
    rcpt.add_argument("--no-verify", action="store_true", help="do not re-verify the pulse pair (faster; the receipt says so)")
    for fl in (("--json",), ("--offline",), ("-q", "--quiet"), ("--no-anchors",)): rcpt.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    bd = sub.add_parser("bundle", help="write a self-contained verification bundle (directory, or .zip): contract + sidecars, transcript, pulse pair + tokens + checkpoint + inclusion proofs + anchors, decision-log leaf/proof, public keys, README (the receipt), MANIFEST")
    bd.add_argument("contract"); bd.add_argument("--transcript"); bd.add_argument("--out", help="directory to create, or a path ending in .zip (default notbefore-bundle-<sha16>.zip)")
    bd.add_argument("--include-input", action="store_true", help="include the committed input file (default: its SHA-256 only)"); bd.add_argument("--include-output", action="store_true", help="include the output files (default: their SHA-256s only)")
    bd.add_argument("--no-verify", action="store_true", help=argparse.SUPPRESS)
    for fl in (("--json",), ("--offline",), ("-q", "--quiet"), ("--no-anchors",)): bd.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    cb = sub.add_parser("check-bundle", help="re-verify a bundle OFFLINE with this installation's pinned keys and trust roots; exit 0/1")
    cb.add_argument("bundle"); cb.add_argument("--no-pulse-verify", action="store_true", help="skip the vendored verify.py run on the bundled pulses")
    for fl in (("--json",), ("-q", "--quiet")): cb.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    cp = sub.add_parser("checkpoint", help="show and verify the log's current signed checkpoint against the vendored identity and this machine's cached head")
    for fl in (("--json",), ("--offline",), ("-q", "--quiet")): cp.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sp = sub.add_parser("split", help="shuffle, then split FILE into A (first floor(frac·k)) and B"); common(sp, purpose=True, file=True)
    sp.add_argument("--frac", required=True, help="decimal in (0,1), e.g. 0.8 — applied exactly (floor(frac·n))"); sp.add_argument("--out-a"); sp.add_argument("--out-b")
    return ap

def _open_source(a):
    return LogSource(repo=a.repo, log_dir=a.log_dir, cache=a.cache, ref=a.log_ref, offline=a.offline)

def _print_check(R, a):
    """Verification transcript -> stderr. Payloads (V, S, shuffled lines) -> stdout, always. -q keeps only FAIL/WARN."""
    if a.json: return
    for l in R.lines:
        if not a.quiet or l.startswith(("[FAIL]", "[WARN]")): sys.stderr.write(l + "\n")
    if a.verbose:
        for v in R.verbose: sys.stderr.write("\n--- verifier output ---\n" + v)
    if not a.quiet or not R.ok:
        sys.stderr.write(("VERIFIED" if R.ok else "NOT VERIFIED") + f" — NotBefore {R.seq} (commit {R.commit_seq}), log {str(R.log_git_sha)[:12]}\n")

def _plan(a):
    from . import contract as C
    ops = [(n, v) for n, v in (("sample", a.sample), ("split", a.split), ("assign", a.assign), ("shuffle", a.shuffle or None), ("id", a.id or None), ("range", a.range), ("bytes", a.bytes), ("seed", a.seed or None)) if v not in (None, False)]
    if len(ops) != 1: _err("plan needs exactly one operation: --sample K | --split FRAC | --assign ARMS | --shuffle | --id | --range LO HI | --bytes N | --seed"); return 2
    op, v = ops[0]
    params = {"sample": lambda: {"k": v}, "split": lambda: {"frac": v}, "assign": lambda: {"arms": v}, "shuffle": lambda: {}, "id": lambda: {"hexlen": a.hexlen},
              "range": lambda: {"lo": v[0], "hi": v[1]}, "bytes": lambda: {"n": v}, "seed": lambda: {}}[op]()
    from . import identity as I, decisionlog as DL
    signer = priv = None
    if not a.unsigned:
        try: priv, _, kid, pub_b64 = I.load(a.key); signer = (kid, pub_b64)
        except I.IdentityError as e: _err(str(e) + "  (or pass --unsigned for a legacy contract with no signer and no decision-log entry)"); return 2
    try: c = C.make(a.after, a.purpose, op, params, a.file, a.note, signer=signer, decision_id=a.decision_id)
    except (ValueError, D.PurposeError, FileNotFoundError) as e: _err(str(e)); return 2
    out = a.out or f"notbefore-plan-{c['purpose'].replace('/', '_').replace(':', '_')}.json"
    h = C.write(c, out); _err(f"contract written: {out}  sha256 {h}" + (f"  signer {signer[0]}  decision_id {c['decision_id']}" if signer else "  (UNSIGNED legacy contract/1)"))
    rc = 0
    if signer:
        st = DL.statement(h, c["decision_id"], signer[0], signer[1], c["spec"]); sig = DL.sign_statement(priv, st); DL.write_signature(out, st, sig)
        _err(f"decision statement signed: {DL.sig_path(out)}")
    if not a.no_register:
        got = C.timestamp(out); toks, bad = C.verify_timestamps(out)
        for n, t, _ in toks: _err(f"timestamped: {n} {t}")
        ok, why, _ = C.timestamp_verdict(toks, bad, None)
        if not ok: _err(f"INCOMPLETE TIMESTAMPING — {why}. The contract is written; retry with: notbefore timestamp {out}"); rc = 1
    else: _err("NOT timestamped (--no-timestamp): there is no third-party evidence of when this contract existed")
    logged = None
    if signer and not a.no_log:
        logged = _register(out, c, a, quiet=False)
        if logged is None: rc = 1
    if not signer: _err("this is timestamping, not registration: publish the sha256 where it cannot be withdrawn (a commit, a registry, a dated mail), then wait for the pulse and run: notbefore execute " + out)
    elif logged is None and not a.no_log and DL.enabled(): _err("the contract is signed and timestamped but NOT registered; retry with: notbefore register " + out)
    else: _err("then wait for the pulse and run: notbefore execute " + out)
    print(json.dumps({"contract": out, "sha256": h, "after_utc": c["selection"]["after_utc"], "operation": op, "params": c["params"], "timestamped": rc == 0 or bool(a.no_register) is False and logged is not None,
                      "signer_key_id": signer[0] if signer else None, "decision_id": c.get("decision_id"), "decision_log": logged}) if a.json else h); return rc

def _register(path, c, a, quiet=False):
    """Append the contract's signed statement to the decision log. Returns the verified receipt summary, or None
    (and says why). Skips with an INFO line when the vendored identity is not enabled."""
    from . import decisionlog as DL, contract as C
    st, sig = DL.read_signature(path)
    if st is None: _err(f"no {DL.sig_path(path)} beside the contract: it was written unsigned (--unsigned) or by an older release"); return None
    if st["contract_sha256"] != hashlib.sha256(open(path, "rb").read()).hexdigest(): _err("signature file does not match this contract's bytes"); return None
    if not DL.enabled(): _err(f"[INFO] decision log ({(DL.identity() or {}).get('origin', '?')}) not enabled in this release: statement signed locally, not submitted"); return {"status": "disabled"}
    tsa = {n: f"{path}.{n}.tsr" for n in C.EXPECTED_TSAS}
    try: r = DL.submit(st, sig, tsa_files=tsa, contract_obj=(c if getattr(a, "disclose", False) else None))
    except Exception as e: _err(f"decision log: {type(e).__name__}: {str(e)[:160]}"); return None
    summ = {"status": "authoritative" if r.get("authoritative") else "amendment", "origin": DL.origin(), "index": r["index"], "seq_in_namespace": r["seq_in_namespace"], "received_utc": r["received_utc"], "size": r["size"], "existing": bool(r.get("existing"))}
    json.dump({"receipt": r, "summary": summ, "verified_against": {"origin": DL.origin(), "key_id_hex": DL.identity().get("key_id_hex")}}, open(DL.receipt_path(path), "w"), indent=1, sort_keys=True)
    if not quiet:
        _err(f"registered in {DL.origin()}: index {r['index']}, {'AUTHORITATIVE (first entry for this key_id/decision_id)' if r.get('authoritative') else 'seq_in_namespace ' + str(r['seq_in_namespace']) + ' — an AMENDMENT: an earlier contract owns this decision_id'}"
             + (", already present" if r.get("existing") else "") + f"; receipt verified (checkpoint size {r['size']}): {DL.receipt_path(path)}")
    return summ

def _execute(a, src):
    from . import contract as C
    import time as _t
    from . import decisionlog as DL
    c = json.load(open(a.contract)); raw = open(a.contract, "rb").read()
    if c.get("spec") not in C.ACCEPTED_SPECS: _err(f"not a decision contract ({'/'.join(C.ACCEPTED_SPECS)})"); return 2
    csha = hashlib.sha256(raw).hexdigest()
    if C.canon(c) != raw: _err("contract file is not in canonical form (edited by hand?) — refusing"); return 1
    lines = []
    st = sig = None; dl = {"status": "unsigned", "why": "legacy contract/1: no signer, no decision-log namespace"}
    if c["spec"] in C.SIGNED_SPECS:
        st, sig = DL.read_signature(a.contract)
        if st is None: _err(f"refusing: signed contract but no {DL.sig_path(a.contract)} beside it"); return 1
        sok, why = DL.verify_statement(st, sig)
        bound = st["contract_sha256"] == csha and st["key_id"] == c["signer"]["key_id"] and st["public_key_b64"] == c["signer"]["public_key_b64"] and st["decision_id"] == c["decision_id"]
        if not (sok and bound): _err(f"refusing: decision statement does not verify for this contract ({why if not sok else 'statement names a different contract, key or decision_id'})"); return 1
        lines.append(f"[PASS] contract signed by key {st['key_id']} for decision_id {st['decision_id']!r} (Ed25519 statement verifies)")
    legacy = c["spec"] not in C.SIGNED_SPECS
    toks, bad = C.verify_timestamps(a.contract)
    lines += [f"[PASS] contract timestamped: {n} {ts}" for n, ts, _ in toks]
    pre_ok, pre_why, _ = C.timestamp_verdict(toks, bad, None)          # presence/validity only; the time gate comes after selection
    if legacy:
        # contract/1 (0.6.0–0.7.x): unsigned and outside any decision-log namespace. Fully timestamped, it is exactly what those
        # releases promised, so it runs with a WARN (refused under --require-log); with tokens missing it needs --allow-unregistered.
        if not a.allow_unregistered: _err("refusing: legacy unsigned contract/1 has no signer and no decision-log entry (0.10.0 fails closed); pass --allow-unregistered for a labelled DEGRADED run"); return 1
        lines.append("[WARN] DEGRADED: legacy unsigned contract/1 — no signer identity and no decision-log entry (timestamps bound WHEN it existed, not that it was the only one); labelled in the transcript")
    if not pre_ok:
        if bad or not a.allow_unregistered: _err(f"refusing: {pre_why}" + ("" if bad else " (pass --allow-unregistered for a labelled dry run)")); return 1
        lines.append(f"[WARN] {pre_why} — running because --allow-unregistered; the transcript records that no third party vouches for when this decision existed")
    # ---- the decision log, part 1 (before any pulse work): is this THE preregistration for (key_id, decision_id)? FAIL CLOSED.
    if st is not None:
        dl = DL.check_authoritative(st, offline=a.offline, src=src)
        if dl["status"] == "superseded":
            lines.append(f"[FAIL] decision log {dl['origin']}: {dl['why']}"); [_err(l) for l in lines]; _err("refusing: this contract is not the first registered for its decision_id"); return 1
        if dl["status"] == "authoritative": lines.append(f"[PASS] decision log {dl['origin']}: {dl['why']}")
        elif not a.allow_unregistered:
            lines.append(f"[FAIL] decision log: {dl['why']}"); [_err(l) for l in lines]
            _err("refusing: the decision log did not confirm this contract as the authoritative preregistration (" + dl["status"] + "). A DEGRADED run is possible with --allow-unregistered; the transcript will say no third party vouches for which contract was registered."); return 1
        else: lines.append(f"[WARN] DEGRADED (--allow-unregistered): decision log {dl['status']} — {dl['why']}. Timestamps alone bound WHEN this contract existed, not that it was the only one.")
    after = int(c["selection"]["after_unix_s"])
    commit_bound = (c.get("value") or {}).get("rule") == "commit-bound"
    sel = None
    if commit_bound:
        from . import commitbound as CB
        sel = CB.select_commit(src, after, refetch=not a.offline, anchors=True, R_lines=lines)
        if sel is None: _err("\n".join(lines)); _err(f"no eligible commit released at or after {c['selection']['after_utc']} yet — wait for the hour"); return 1
        if sel["provenance"] == "WAIT": [_err(l) for l in lines]; _err(f"not yet: the reveal window for commit {sel['seq']:04d} closes at {_t.strftime('%Y-%m-%dT%H:%M:%SZ', _t.gmtime(sel['wait_until']))}; run again after that"); return 3
        if sel["provenance"] == "ERROR": [_err(l) for l in lines]; _err("refusing: the commit-bound value could not be established (see the FAIL line)"); return 1
        seq, rel, R = sel["seq"], sel["release_unix"], (sel["Rr"] or sel["Rc"])
    else:
        seq, rel, R = C.select_pulse(src, after, refetch=not a.offline, anchors=not a.no_anchors, R_lines=lines)
        if seq is None: _err("\n".join(lines)); _err(f"no eligible reveal released at or after {c['selection']['after_utc']} yet — wait for the hour"); return 1
        lines.append(f"[PASS] selected by rule '{C.RULE}': reveal {seq:04d} (round released {_t.strftime('%Y-%m-%dT%H:%M:%SZ', _t.gmtime(rel))} >= after {c['selection']['after_utc']})")
    ok_t, why_t, latest = C.timestamp_verdict(toks, bad, rel, require_all=not a.allow_unregistered)
    if toks or not ok_t:
        lines.append(f"[{'PASS' if ok_t else 'FAIL'}] {why_t}" + (f" (latest token {_t.strftime('%Y-%m-%dT%H:%M:%SZ', _t.gmtime(latest))}, {rel-latest} s before release)" if ok_t and latest else ""))
        if not ok_t: [_err(l) for l in lines]; _err("refusing: " + why_t); return 1
    # ---- the decision log, part 2: the authoritative registration must predate the round
    if st is not None and dl["status"] == "authoritative":
        early = dl["received_unix"] < rel
        if not early: lines.append(f"[FAIL] decision-log registration was received AT/AFTER the round release: the registration does not predate the value"); [_err(l) for l in lines]; _err("refusing: decision-log entry is not before the round release"); return 1
        lines.append(f"[PASS] decision-log inclusion verified (leaf {dl['index']} of {dl['size']}, log signature under the vendored key); registered {rel - dl['received_unix']} s before release")
    if a.allow_unregistered and not C.timestamp_verdict(toks, bad, rel)[0]: lines.append("[WARN] timestamping INCOMPLETE: this run is labelled as such in the transcript")
    P = c["purpose"]
    if commit_bound:
        from . import commitbound as CB
        vstar = CB.value(sel["C"], sel["rho_hex"], sel["chain_hash"], sel["target_round"]); S = D.seed(vstar, P)
        lines.append(f"[PASS] commit-bound value V* = SHA256(\"{CB.DOMAIN.decode()}\" || C || rho || chain_hash || R) = {vstar} ({sel['provenance']})")
    else: S = D.seed(R.attested_value, P)
    try: body, extra = C.run_operation(c, S, a.input or (c.get("input", {}).get("file")))
    except (ValueError, FileNotFoundError) as e: [_err(l) for l in lines]; _err(str(e)); return 1
    t = D.transcript(R, P, S, {"operation": c["operation"], **{k: v for k, v in c["params"].items()}, "contract_sha256": csha, "contract_file": os.path.basename(a.contract),
                                "contract_timestamped": [{"tsa": n, "time": ts} for n, ts, _ in toks], "contract_timestamped_latest_unix_s": latest, "timestamping_complete": C.timestamp_verdict(toks, bad, rel)[0], "selected_by_rule": C.RULE,
                                "contract_spec": c["spec"], "signer_key_id": (c.get("signer") or {}).get("key_id"), "decision_id": c.get("decision_id"), "contract_signature_verified": st is not None,
                                **({"value_rule": "commit-bound", "value_domain": "notbefore/commit-bound/v1", "commit_bound_value": vstar, "provenance": sel["provenance"], "commit_seq": sel["seq"], "reveal_seq": sel["reveal_seq"], "seq": sel["reveal_seq"],
                                    "pulse_hash_commit": sel["Rc"].pulse_hash_commit, "pulse_hash_reveal": (sel["Rr"].pulse_hash_reveal if sel["Rr"] else None), "attested_value": sel["attested_value"], "drand_round": sel["target_round"],
                                    "drand": {"round": sel["target_round"], "chain_hash": sel["chain_hash"], "randomness": sel["rho_hex"], "signature": sel["sig_hex"]}, "entropy_commitment": sel["C"],
                                    "publication_evidence": sel["pub"]} if commit_bound else {"value_rule": "reveal", "provenance": "FULL-ATTESTED"}),
                                "decision_log": {k: dl.get(k) for k in ("origin", "status", "index", "seq_in_namespace", "size", "root_b64", "received_unix", "why", "source")},
                                "after_utc": c["selection"]["after_utc"], "input_sha256": c.get("input", {}).get("sha256"), "record_count": c.get("input", {}).get("record_count"),
                                "output_sha256": D.sha256_hex(body.encode()), **({"A": {"count": extra["A_count"], "sha256": D.sha256_hex(body.encode())}, "B": {"count": extra["B_count"], "sha256": D.sha256_hex(("\n".join(extra["B"]) + "\n").encode())}} if c["operation"] == "split" else {})})
    for l in R.lines + lines:
        if not a.quiet or l.startswith(("[FAIL]", "[WARN]")): sys.stderr.write(l + "\n")
    dest = a.transcript or f"notbefore-executed-{csha[:16]}.json"
    if dest == "-": print(json.dumps(t, indent=1, sort_keys=True))
    elif dest != "none": json.dump(t, open(dest, "w"), indent=1, sort_keys=True); _err(f"transcript written: {dest}")
    if c["operation"] == "split":
        base = os.path.basename(c["input"]["file"]); open(base + ".A", "w").write(body); open(base + ".B", "w").write("\n".join(extra["B"]) + "\n"); _err(f"A: {extra['A_count']} -> {base}.A   B: {extra['B_count']} -> {base}.B")
    else: sys.stdout.write(body)
    return 0

def _explain(R, src):
    import time as _t
    com = src.pulse(R.commit_seq); rev = src.pulse(R.seq); cd, rd = com["core"]["derived"], rev["core"]["derived"]
    tsa = src._read_bytes(f"chain/pulse-{R.commit_seq:04d}.json.tsa.json"); toks = json.loads(tsa)["tokens"] if tsa else []
    rel = int(rd["round_release_unix_s"]); utc = lambda x: _t.strftime("%Y-%m-%d %H:%M:%S UTC", _t.gmtime(int(float(x))))
    tsa_s = "; ".join(f"{t['tsa']} {t['time']}" for t in toks) or "none on file"
    return (f"Randomness for this analysis was taken from NotBefore pulse {R.seq} (commit {R.commit_seq}) of the public qrng-beacon-log "
            f"(https://notbefore.net, log identity notbefore.net/log; log commit {str(R.log_git_sha)[:12]}). The commitment to the value was published at "
            f"{utc(cd['anchor_utc_unix_s'])} and timestamped by independent RFC 3161 authorities ({tsa_s}), before drand quicknet round "
            f"{R.drand_round} was released at {utc(rel)}; the value V = {R.attested_value} was revealed at {utc(rd['anchor_utc_unix_s'])}, "
            f"{float(rd['anchor_after_release_s']):.0f} s after the round. V is SHA-256 of the pre-committed entropy, the drand round randomness, the chain hash and the round number "
            f"(NOTBEFORE.md §4.2); it could not have been known before the round nor chosen after it. Verification with `notbefore verify {R.seq}` "
            f"(pinned vendored verifier, {vendored_meta().get('git_sha','?')[:12]}) passed: host signatures, offline BLS check of the drand round, "
            f"{R.tsa_pass} RFC 3161 tokens on the commit, publication anchors ({R.anchors}), transparency-log checkpoint ({R.tlog}). "
            f"Derived seeds are SHA-256(\"notbefore/derive/v1\" || V || purpose) with a purpose string committed in advance; the transcript JSON reproduces the allocation exactly.")

def _read_records(path):
    raw = open(path, "rb").read()
    text = raw.decode("utf-8")
    recs = text.split("\n")
    if recs and recs[-1] == "": recs.pop()
    return [r.rstrip("\r") for r in recs], hashlib.sha256(raw).hexdigest()

def _write_transcript(a, t, slug):
    dest = a.transcript
    if dest == "none": return None
    if dest == "-": print(json.dumps(t, indent=1, sort_keys=True)); return "-"
    dest = dest or f"notbefore-{a.seq}-{slug}.json"
    json.dump(t, open(dest, "w"), indent=1, sort_keys=True)
    if not a.quiet: _err(f"transcript written: {dest}")
    return dest

def main(argv=None):
    a = build_parser().parse_args(argv)
    for k, d in (("verbose", False), ("quiet", False), ("json", False), ("offline", False), ("no_anchors", False), ("seq", 0), ("checkpoint_url", None), ("transcript", None), ("witness_quorum", 0), ("no_verify", False), ("out", None), ("include_input", False), ("include_output", False)):
        if not hasattr(a, k): setattr(a, k, d)
    if getattr(a, "witness_quorum", 0): os.environ["NOTBEFORE_WITNESS_QUORUM"] = str(a.witness_quorum)
    lock = a.lock or ("notbefore.lock" if os.path.exists("notbefore.lock") and a.cmd != "pin" else None)
    if lock and not a.log_ref:
        try: a.log_ref = json.load(open(lock))["log_git_sha"]; _err(f"pinned by {lock}: log {a.log_ref[:12]}")
        except Exception as e: _err(f"cannot read lock {lock}: {e}"); return 2
    try:
        src = _open_source(a)
    except LogError as e:
        _err(str(e)); return 1
    try:
        if a.cmd == "plan": return _plan(a)
        if a.cmd == "keygen":
            from . import identity as I
            try: path, kid, pub = I.generate(a.key, force=a.force)
            except I.IdentityError as e: _err(str(e)); return 1
            _err(f"identity written: {path} (mode 0600). key_id {kid}. Back it up; there is no recovery. Never share the .key file — the .pub beside it is what others need.")
            print(json.dumps({"key": path, "key_id": kid, "public_key_b64": pub}) if a.json else kid); return 0
        if a.cmd == "whoami":
            from . import identity as I
            try: _, _, kid, pub = I.load(a.key)
            except I.IdentityError as e: _err(str(e)); return 1
            print(json.dumps({"key_id": kid, "public_key_b64": pub, "key": a.key or I.default_path()}) if a.json else f"{kid} ed25519 {pub}"); return 0
        if a.cmd == "register":
            from . import contract as C
            c = json.load(open(a.contract))
            if c.get("spec") not in C.SIGNED_SPECS: _err(f"only signed contracts ({', '.join(C.SIGNED_SPECS)}) can be registered; this is {c.get('spec')}"); return 2
            r = _register(a.contract, c, a); print(json.dumps(r) if a.json and r else ("" if not r else r["status"])); return 0 if r else 1
        if a.cmd == "timestamp":
            from . import contract as C
            got = C.timestamp(a.contract); toks, bad = C.verify_timestamps(a.contract)
            for n, t, _ in toks: _err(f"timestamped: {n} {t}")
            ok, why, _ = C.timestamp_verdict(toks, bad, None); _err(why if ok else "INCOMPLETE: " + why); return 0 if ok else 1
        if a.cmd == "execute": return _execute(a, src)
        if a.cmd in ("receipt", "bundle"):
            from . import receipt as RC
            try: F = RC.gather(a.contract, a.transcript, src=src, verify_pair=not a.no_verify, refetch=not a.offline, live_log=not a.offline)
            except FileNotFoundError as e: _err(str(e)); return 2
            if a.cmd == "receipt":
                md = RC.render(F)
                if a.out: open(a.out, "w").write(md); _err(f"receipt written: {a.out}")
                else: sys.stdout.write(md if not a.json else json.dumps({k: v for k, v in F.items() if k != "contract"} | {"contract": {k: v for k, v in F["contract"].items() if k != "obj"}}, indent=1, sort_keys=True, default=str))
                for l in F["lines"]:
                    if not a.quiet or l.startswith(("[FAIL]", "[WARN]", "[DEGRADED]")): _err(l)
                _err(f"receipt verdict: {F.verdict}" + (" — " + "; ".join(F["degraded"]) if F["degraded"] else ""))
                return F.exit_code
            out = a.out or f"notbefore-bundle-{F['contract']['sha256'][:16]}.zip"
            try: path = RC.bundle(F, out, src=src, include_input=a.include_input, include_output=a.include_output)
            except FileExistsError as e: _err(str(e)); return 2
            for l in F["lines"]:
                if not a.quiet or l.startswith(("[FAIL]", "[WARN]", "[DEGRADED]")): _err(l)
            _err(f"bundle written: {path} — verification {F.verdict}" + (" (" + "; ".join(F["degraded"]) + ")" if F["degraded"] else "")); print(json.dumps({"bundle": path, "verification": F.verdict, "degraded": F["degraded"], "status": F["status"]}) if a.json else path); return F.exit_code
        if a.cmd == "check-bundle":
            from . import receipt as RC
            verdict, lines, degraded = RC.check_bundle(a.bundle, verify_pulses=not a.no_pulse_verify)
            for l in lines:
                if not a.quiet or l.startswith(("[FAIL]", "[WARN]", "[DEGRADED]")): _err(l)
            _err(f"BUNDLE {verdict}" + (" (" + "; ".join(degraded) + ")" if degraded else "") + f" — {a.bundle}"); print(json.dumps({"verification": verdict, "degraded": degraded, "lines": lines}, indent=1) if a.json else verdict); from .policy import EXIT; return EXIT[verdict]
        if a.cmd == "pin":
            ident = {}
            try:
                from . import tlogcheck; ident = tlogcheck.identity() or {}
            except Exception: pass
            lockdoc = {"spec": SPEC, "cli_version": __version__, "verifier_git_sha": vendored_meta().get("git_sha"), "log_repo": a.repo,
                       "log_ref": src.ref or "working tree", "log_git_sha": src.log_git_sha, "written_utc": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())}
            note = src._read_bytes("checkpoint")
            if note:
                lines = note.decode().split("\n"); lockdoc["checkpoint"] = {"origin": lines[0], "size": int(lines[1]), "root_b64": lines[2]}
            json.dump(lockdoc, open(a.out, "w"), indent=1, sort_keys=True); _err(f"wrote {a.out}: log {src.log_git_sha[:12]} (re-run with --lock {a.out}, or leave it in the working directory)")
            print(json.dumps(lockdoc, indent=1, sort_keys=True) if a.json else src.log_git_sha); return 0
        if a.cmd == "diff-transcript":
            A_, B_ = json.load(open(a.a)), json.load(open(a.b))
            keys = ["operation", "seq", "commit_seq", "purpose", "value_rule", "provenance", "commit_bound_value", "attested_value", "derived_seed", "input_sha256", "record_count", "frac", "k", "arms", "output_sha256", "A", "B", "log_git_sha", "cli_version", "spec", "verifier_git_sha"]
            strip = lambda v: {kk: vv for kk, vv in v.items() if kk != "file"} if isinstance(v, dict) else v   # output FILE NAMES are not part of the allocation
            A_ = {k: strip(v) for k, v in A_.items()}; B_ = {k: strip(v) for k, v in B_.items()}
            diffs = [(k, A_.get(k), B_.get(k)) for k in keys if A_.get(k) != B_.get(k)]
            for k, x, y in diffs: print(f"{k:16s} {json.dumps(x)[:60]:60s} -> {json.dumps(y)[:60]}")
            why = []
            if A_.get("input_sha256") != B_.get("input_sha256"): why.append("the INPUT FILE differs (different bytes -> different ranks; order matters)")
            if (A_.get("seq"), A_.get("attested_value")) != (B_.get("seq"), B_.get("attested_value")): why.append("a different PULSE was used")
            if A_.get("purpose") != B_.get("purpose"): why.append("the PURPOSE differs (a different seed, by design)")
            if A_.get("derived_seed") == B_.get("derived_seed") and A_.get("input_sha256") == B_.get("input_sha256") and (A_.get("output_sha256"), A_.get("A"), A_.get("B")) == (B_.get("output_sha256"), B_.get("A"), B_.get("B")):
                why.append("IDENTICAL allocation" + (" (only tool/log versions differ)" if diffs else ""))
            elif not why: why.append("same inputs but different outputs — the tool changed behaviour: compare cli_version/spec and file a bug")
            print("=> " + "; ".join(why)); return 0 if "IDENTICAL" in why[-1] else 1
        if a.cmd == "checkpoint":
            from .check import CheckResult
            from . import tlogcheck
            R = CheckResult(0); R.log_git_sha, R.log_ref = src.log_git_sha, (src.ref or "working tree")
            st = tlogcheck.check(src, (), R, refetch=not getattr(a, "offline", False), site_url=a.checkpoint_url)
            note = src._read_bytes("checkpoint")
            for l in R.lines:
                if not a.quiet or l.startswith(("[FAIL]", "[WARN]")): sys.stderr.write(l + "\n")
            if note: sys.stdout.write(note.decode())
            return 0 if R.ok and st in ("ok", "absent", "no identity") else 1
        R = check_pair(a.seq, src, refetch=not a.offline, anchors=not a.no_anchors, verbose=a.verbose, site_url=a.checkpoint_url)
        _print_check(R, a)
        if a.cmd == "verify":
            if a.json: print(json.dumps(R.summary() | {"seq": R.seq, "commit_seq": R.commit_seq, "attested_value": R.attested_value if R.ok else None, "log_git_sha": R.log_git_sha}, indent=1))
            return 0 if R.ok else 1
        if not R.ok:
            _err("pair did not verify; refusing to emit a value"); return 1
        if a.cmd == "value":
            print(json.dumps({"seq": R.seq, "attested_value": R.attested_value}) if a.json else R.attested_value); return 0
        if a.cmd == "explain":
            print(_explain(R, src)); return 0
        try: P = D.normalize_purpose(a.purpose).decode()
        except D.PurposeError as e: _err(f"bad purpose: {e}"); return 2
        S = D.seed(R.attested_value, P); slug = P.replace("/", "_").replace(":", "_")
        if a.cmd == "seed":
            t = D.transcript(R, P, S); _write_transcript(a, t, slug)
            print(json.dumps({"seq": R.seq, "purpose": P, "derived_seed": S.hex()}) if a.json else S.hex()); return 0
        if a.cmd == "range":
            try: v = D.rand_range(S, a.lo, a.hi)
            except ValueError as e: _err(str(e)); return 2
            _write_transcript(a, D.transcript(R, P, S, {"operation": "range", "lo": a.lo, "hi": a.hi, "value": v}), slug); print(json.dumps({"seq": R.seq, "purpose": P, "value": v}) if a.json else v); return 0
        if a.cmd == "bytes":
            try: b = D.rand_bytes(S, a.n)
            except ValueError as e: _err(str(e)); return 2
            _write_transcript(a, D.transcript(R, P, S, {"operation": "bytes", "n": a.n, "output_sha256": D.sha256_hex(b), "note": "public bytes: never key material"}), slug); print(b.hex()); return 0
        if a.cmd == "id":
            recs, in_sha = _read_records(a.from_file)
            try: ids = [D.pseudonym(r, S, a.hexlen) for r in recs]
            except ValueError as e: _err(str(e)); return 2
            body = "\n".join(ids) + ("\n" if ids else "")
            _write_transcript(a, D.transcript(R, P, S, {"operation": "id", "hexlen": a.hexlen, "input_file": os.path.basename(a.from_file), "input_sha256": in_sha, "record_count": len(recs), "output_sha256": D.sha256_hex(body.encode()),
                                                        "note": "pseudonyms, not secrets: recomputable by anyone holding the name list and the public S"}), slug); sys.stdout.write(body); return 0
        recs, in_sha = _read_records(a.file)
        if a.cmd == "sample":
            try: out = D.sample(recs, S, a.k)
            except ValueError as e: _err(str(e)); return 2
            body = "\n".join(out) + ("\n" if out else "")
            _write_transcript(a, D.transcript(R, P, S, {"operation": "sample", "k": a.k, "input_file": os.path.basename(a.file), "input_sha256": in_sha, "record_count": len(recs), "output_sha256": D.sha256_hex(body.encode())}), slug); sys.stdout.write(body); return 0
        if a.cmd == "assign":
            try: pairs = D.assign(recs, S, a.arms)
            except ValueError as e: _err(str(e)); return 2
            body = "".join(f"{r}\t{arm}\n" for r, arm in pairs); counts = [sum(1 for _, arm in pairs if arm == i) for i in range(a.arms)]
            _write_transcript(a, D.transcript(R, P, S, {"operation": "assign", "arms": a.arms, "arm_sizes": counts, "input_file": os.path.basename(a.file), "input_sha256": in_sha, "record_count": len(recs), "output_sha256": D.sha256_hex(body.encode())}), slug); sys.stdout.write(body); return 0
        if a.cmd == "shuffle":
            out = D.shuffle(recs, S); body = "\n".join(out) + ("\n" if out else "")
            t = D.transcript(R, P, S, {"operation": "shuffle", "input_file": os.path.basename(a.file), "input_sha256": in_sha, "record_count": len(recs), "output_sha256": D.sha256_hex(body.encode())})
            _write_transcript(a, t, slug); sys.stdout.write(body); return 0
        if a.cmd == "split":
            try: A_, B_ = D.split(recs, S, a.frac)
            except (ValueError, ZeroDivisionError) as e: _err(f"bad --frac: {e}"); return 2
            oa, ob = a.out_a or a.file + ".A", a.out_b or a.file + ".B"
            ba, bb = "\n".join(A_) + ("\n" if A_ else ""), "\n".join(B_) + ("\n" if B_ else "")
            open(oa, "w").write(ba); open(ob, "w").write(bb)
            t = D.transcript(R, P, S, {"operation": "split", "frac": str(a.frac), "input_file": os.path.basename(a.file), "input_sha256": in_sha, "record_count": len(recs),
                                       "A": {"file": os.path.basename(oa), "count": len(A_), "sha256": D.sha256_hex(ba.encode())}, "B": {"file": os.path.basename(ob), "count": len(B_), "sha256": D.sha256_hex(bb.encode())}})
            _write_transcript(a, t, slug)
            if not a.quiet: _err(f"A: {len(A_)} -> {oa}   B: {len(B_)} -> {ob}")
            return 0
    finally:
        src.close()

if __name__ == "__main__": sys.exit(main())
