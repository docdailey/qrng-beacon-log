"""notbefore — CLI (NOTBEFORE.md §8).

  notbefore verify  <seq>
  notbefore value   <seq>
  notbefore seed    <seq> --purpose <P>
  notbefore shuffle <seq> --purpose <P> <file>
  notbefore split   <seq> --purpose <P> --frac 0.8 <file>

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
    cp = sub.add_parser("checkpoint", help="show and verify the log's current signed checkpoint against the vendored identity and this machine's cached head")
    for fl in (("--json",), ("--offline",), ("-q", "--quiet")): cp.add_argument(*fl, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sp = sub.add_parser("split", help="shuffle, then split FILE into A (first floor(frac·k)) and B"); common(sp, purpose=True, file=True)
    sp.add_argument("--frac", type=float, required=True); sp.add_argument("--out-a"); sp.add_argument("--out-b")
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
            f"Derived seeds are SHA-256(\"notbefore/derive/v1\" || V || purpose) with a pre-registered purpose string; the transcript JSON reproduces the allocation exactly.")

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
    for k, d in (("verbose", False), ("quiet", False), ("json", False), ("offline", False), ("no_anchors", False), ("seq", 0), ("checkpoint_url", None), ("transcript", None), ("witness_quorum", 0)):
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
            keys = ["operation", "seq", "commit_seq", "purpose", "attested_value", "derived_seed", "input_sha256", "record_count", "frac", "k", "arms", "output_sha256", "A", "B", "log_git_sha", "cli_version", "spec", "verifier_git_sha"]
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
            except ValueError as e: _err(str(e)); return 2
            oa, ob = a.out_a or a.file + ".A", a.out_b or a.file + ".B"
            ba, bb = "\n".join(A_) + ("\n" if A_ else ""), "\n".join(B_) + ("\n" if B_ else "")
            open(oa, "w").write(ba); open(ob, "w").write(bb)
            t = D.transcript(R, P, S, {"operation": "split", "frac": a.frac, "input_file": os.path.basename(a.file), "input_sha256": in_sha, "record_count": len(recs),
                                       "A": {"file": os.path.basename(oa), "count": len(A_), "sha256": D.sha256_hex(ba.encode())}, "B": {"file": os.path.basename(ob), "count": len(B_), "sha256": D.sha256_hex(bb.encode())}})
            _write_transcript(a, t, slug)
            if not a.quiet: _err(f"A: {len(A_)} -> {oa}   B: {len(B_)} -> {ob}")
            return 0
    finally:
        src.close()

if __name__ == "__main__": sys.exit(main())
