"""notbefore — CLI (NOTBEFORE.md §8).

  notbefore verify  <seq>
  notbefore value   <seq>
  notbefore seed    <seq> --purpose <P>
  notbefore shuffle <seq> --purpose <P> <file>
  notbefore split   <seq> --purpose <P> --frac 0.8 <file>

`value`/`seed`/`shuffle`/`split` print nothing usable unless `verify` would pass; exit 1 otherwise.
The verifier and every key are vendored in this package; the log is read as data. Requires `git` and `openssl` on PATH.
"""
import sys, os, json, argparse, hashlib
from . import __version__, SPEC, DEFAULT_REPO
from .log import LogSource, LogError
from .check import check_pair, vendored_meta
from . import derive as D

def _err(msg): sys.stderr.write("notbefore: " + msg + "\n")

def build_parser():
    ap = argparse.ArgumentParser(prog="notbefore", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"notbefore {__version__} ({SPEC}; verifier vendored from {vendored_meta().get('git_sha','?')[:12]})")
    g = ap.add_argument_group("log source")
    g.add_argument("--repo", default=DEFAULT_REPO, help="git URL of the log (default: the public qrng-beacon-log)")
    g.add_argument("--log-dir", help="use this local checkout/directory instead of a cached clone")
    g.add_argument("--log-ref", help="git ref/sha of the log to read (default origin/main; with --log-dir default: working tree)")
    g.add_argument("--cache", help="cache directory for the clone (default ~/.cache/notbefore/qrng-beacon-log)")
    g.add_argument("--offline", action="store_true", help="no network: no fetch, no drand/Rekor refetch (BLS + proofs still verify offline)")
    g.add_argument("--no-anchors", action="store_true", help="skip the Rekor/OpenTimestamps anchor check")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the vendored verifier's full output")
    ap.add_argument("--json", action="store_true", help="machine-readable result on stdout")
    sub = ap.add_subparsers(dest="cmd", required=True)
    def common(p, purpose=False, file=False):
        p.add_argument("seq", type=int, help="reveal seq N (its commit is N-1)")
        for flags, kw in ((("-v", "--verbose"), {}), (("--json",), {}), (("--offline",), {}), (("--no-anchors",), {})):
            p.add_argument(*flags, action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS, **kw)
        if purpose:
            p.add_argument("--purpose", required=True, help="non-secret label, ^[A-Za-z0-9._:/=@+-]+$, ≤ 256 bytes")
            p.add_argument("--transcript", help="write the transcript JSON here (default: ./notbefore-<seq>-<purpose>.json); '-' for stdout, 'none' to skip")
        if file: p.add_argument("file", help="input file, one record per line (UTF-8)")
    common(sub.add_parser("verify", help="verify the pair (commit N-1, reveal N); exit 0/1"))
    common(sub.add_parser("value", help="print the attested value V (hex) if the pair verifies"))
    common(sub.add_parser("seed", help="print the derived seed S = SHA256(D_derive || V || purpose)"), purpose=True)
    common(sub.add_parser("shuffle", help="deterministically shuffle the lines of FILE with S"), purpose=True, file=True)
    cp = sub.add_parser("checkpoint", help="show and verify the log's current signed checkpoint against the vendored identity and this machine's cached head")
    cp.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS); cp.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sp = sub.add_parser("split", help="shuffle, then split FILE into A (first floor(frac·k)) and B"); common(sp, purpose=True, file=True)
    sp.add_argument("--frac", type=float, required=True); sp.add_argument("--out-a"); sp.add_argument("--out-b")
    return ap

def _open_source(a):
    return LogSource(repo=a.repo, log_dir=a.log_dir, cache=a.cache, ref=a.log_ref, offline=a.offline)

def _print_check(R, a):
    if a.json: return
    for l in R.lines: sys.stderr.write(l + "\n")
    if a.verbose:
        for v in R.verbose: sys.stderr.write("\n--- verifier output ---\n" + v)
    sys.stderr.write(("VERIFIED" if R.ok else "NOT VERIFIED") + f" — NotBefore {R.seq} (commit {R.commit_seq}), log {str(R.log_git_sha)[:12]}\n")

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
    json.dump(t, open(dest, "w"), indent=1, sort_keys=True); _err(f"transcript written: {dest}"); return dest

def main(argv=None):
    a = build_parser().parse_args(argv)
    for k, d in (("verbose", False), ("json", False), ("offline", False), ("no_anchors", False), ("seq", 0)):
        if not hasattr(a, k): setattr(a, k, d)
    try:
        src = _open_source(a)
    except LogError as e:
        _err(str(e)); return 1
    try:
        if a.cmd == "checkpoint":
            from .check import CheckResult
            from . import tlogcheck
            R = CheckResult(0); R.log_git_sha, R.log_ref = src.log_git_sha, (src.ref or "working tree")
            st = tlogcheck.check(src, (), R, refetch=not getattr(a, "offline", False))
            note = src._read_bytes("checkpoint")
            for l in R.lines: sys.stderr.write(l + "\n")
            if note: sys.stdout.write(note.decode())
            return 0 if R.ok and st in ("ok", "absent", "no identity") else 1
        R = check_pair(a.seq, src, refetch=not a.offline, anchors=not a.no_anchors, verbose=a.verbose)
        _print_check(R, a)
        if a.cmd == "verify":
            if a.json: print(json.dumps(R.summary() | {"seq": R.seq, "commit_seq": R.commit_seq, "attested_value": R.attested_value if R.ok else None, "log_git_sha": R.log_git_sha}, indent=1))
            return 0 if R.ok else 1
        if not R.ok:
            _err("pair did not verify; refusing to emit a value"); return 1
        if a.cmd == "value":
            print(json.dumps({"seq": R.seq, "attested_value": R.attested_value}) if a.json else R.attested_value); return 0
        try: P = D.normalize_purpose(a.purpose).decode()
        except D.PurposeError as e: _err(f"bad purpose: {e}"); return 2
        S = D.seed(R.attested_value, P); slug = P.replace("/", "_").replace(":", "_")
        if a.cmd == "seed":
            t = D.transcript(R, P, S); _write_transcript(a, t, slug)
            print(json.dumps({"seq": R.seq, "purpose": P, "derived_seed": S.hex()}) if a.json else S.hex()); return 0
        recs, in_sha = _read_records(a.file)
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
            _write_transcript(a, t, slug); _err(f"A: {len(A_)} -> {oa}   B: {len(B_)} -> {ob}"); return 0
    finally:
        src.close()

if __name__ == "__main__": sys.exit(main())
