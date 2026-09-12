"""NOTBEFORE.md §14 acceptance tests, run against the repository checkout two levels up (or NOTBEFORE_LOG_DIR).
Network: drand refetch + Rekor refetch are exercised unless NOTBEFORE_OFFLINE=1."""
import os, sys, json, subprocess, shutil, tempfile, pytest
CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.environ.get("NOTBEFORE_LOG_DIR") or os.path.dirname(CLI_DIR)
OFF = ["--offline"] if os.environ.get("NOTBEFORE_OFFLINE") == "1" else []

def nb(*args, log=LOG, **kw):
    r = subprocess.run([sys.executable, "-m", "notbefore.cli", "--log-dir", log, *OFF, *args], capture_output=True, text=True, cwd=kw.get("cwd"))
    return r.returncode, r.stdout, r.stderr

def test_01_verify_23_passes():
    rc, out, err = nb("verify", "23"); assert rc == 0, err; assert "VERIFIED" in err and "NOT VERIFIED" not in err
def test_02_verify_19_fails():
    rc, out, err = nb("verify", "19"); assert rc == 1; assert "KNOWN-NONCOMPLIANT" in err or "below the first eligible" in err
def test_03_value_19_exits_1_no_hex():
    rc, out, err = nb("value", "19"); assert rc == 1 and out.strip() == ""
def test_04_seed_stable(tmp_path):
    a = nb("seed", "23", "--purpose", "demo:roster", "--transcript", "none"); b = nb("seed", "23", "--purpose", "demo:roster", "--transcript", "none")
    assert a[0] == 0 and a[1] == b[1] and len(a[1].strip()) == 64
def test_05_purpose_changes_seed():
    a = nb("seed", "23", "--purpose", "demo:roster", "--transcript", "none")[1]; b = nb("seed", "23", "--purpose", "demo:rostes", "--transcript", "none")[1]
    assert a != b
def test_06_offline_bls_no_warn():
    rc, out, err = nb("-v", "verify", "23"); assert rc == 0
    assert "[full BLS, offline]" in err and "BLS verification skipped" not in err
    assert "BLS-verified offline" in err
def test_07_two_tsa_pass_on_commit():
    rc, out, err = nb("verify", "23"); assert "2 RFC 3161 token(s) verify" in err
def _mutated_copy(mutate):
    d = tempfile.mkdtemp(prefix="nb-mut-"); os.makedirs(os.path.join(d, "chain"))
    for f in os.listdir(os.path.join(LOG, "chain")):
        if f.startswith(("pulse-0021", "pulse-0022", "pulse-0023")): shutil.copy2(os.path.join(LOG, "chain", f), os.path.join(d, "chain", f))
    p = os.path.join(d, "chain", "pulse-0023.json"); j = json.load(open(p)); mutate(j); json.dump(j, open(p, "w")); return d
def test_08_mutated_E_fails():
    def m(j): s = j["core"]["statements"]["entropy"]["statement"]; s["entropy_hex"] = ("00" if s["entropy_hex"][:2] != "00" else "11") + s["entropy_hex"][2:]
    d = _mutated_copy(m); rc, out, err = nb("verify", "23", log=d); assert rc == 1 and "NOT VERIFIED" in err
def test_09_mutated_V_fails():
    def m(j): v = j["core"]["derived"]["attested_value"]; j["core"]["derived"]["attested_value"] = ("00" if v[:2] != "00" else "11") + v[2:]
    d = _mutated_copy(m); rc, out, err = nb("verify", "23", log=d); assert rc == 1 and "NOT VERIFIED" in err
def test_10_transcript_has_log_git_sha(tmp_path):
    t = tmp_path / "t.json"; rc, out, err = nb("seed", "23", "--purpose", "demo:roster", "--transcript", str(t)); assert rc == 0
    j = json.load(open(t)); assert j["log_git_sha"] and j["seq"] == 23 and j["commit_seq"] == 22 and j["derived_seed"] == out.strip() and j["spec"] == __import__("notbefore").SPEC
def test_11_shuffle_and_split_are_deterministic(tmp_path):
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"rec{i}" for i in range(20)) + "\n")
    a = nb("shuffle", "23", "--purpose", "demo:roster", str(f), "--transcript", "none"); b = nb("shuffle", "23", "--purpose", "demo:roster", str(f), "--transcript", "none")
    assert a[0] == 0 and a[1] == b[1] and sorted(a[1].split()) == sorted(f"rec{i}" for i in range(20)) and a[1].split() != [f"rec{i}" for i in range(20)]
    rc, out, err = nb("split", "23", "--purpose", "demo:roster", "--frac", "0.8", str(f), "--transcript", str(tmp_path / "s.json")); assert rc == 0
    A = (tmp_path / "r.txt.A").read_text().split(); B = (tmp_path / "r.txt.B").read_text().split(); assert len(A) == 16 and len(B) == 4 and set(A) | set(B) == {f"rec{i}" for i in range(20)}
    assert A == a[1].split()[:16]
def test_12_worked_check_matches_spec_formula():
    import hashlib
    rc, V, _ = nb("value", "23"); rc2, S, _ = nb("seed", "23", "--purpose", "demo:roster", "--transcript", "none")
    assert S.strip() == hashlib.sha256(b"notbefore/derive/v1" + bytes.fromhex(V.strip()) + b"demo:roster").hexdigest()
def test_13_commit_after_a_skip_is_accepted_by_the_vendored_verifier():
    """Protocol v0.5.1: a synthetic skip whose pulse_hash equals commit 0022's prev_hash stands in as its predecessor.
    The vendored verifier must accept the state transition skip -> commit (0.2.0 rejected it)."""
    import notbefore.check as C
    com = json.load(open(os.path.join(LOG, "chain", "pulse-0022.json")))
    fake = {"core": {"v": "0.5", "type": "skip", "seq": 21, "prev_hash": "0" * 64, "chain_hash": com["core"]["chain_hash"], "statements": {},
                     "derived": {"reason": "synthetic", "refused_by": "unknown", "attempted_unix_s": 0}, "tooling": {}, "aggregator_host": "think"},
            "pulse_hash": com["core"]["prev_hash"], "signatures": {"aggregator": {}}}
    d = tempfile.mkdtemp(prefix="nb-skip-"); fp = os.path.join(d, "pulse-0021.json"); json.dump(fake, open(fp, "w"))
    cp = os.path.join(d, "pulse-0022.json"); shutil.copy2(os.path.join(LOG, "chain", "pulse-0022.json"), cp)
    r = subprocess.run([sys.executable, os.path.join(C.VENDOR, "verify.py"), cp, "--pin", C.KEYS, "--prev", fp, "--no-bls"], capture_output=True, text=True)
    assert "[PASS] state machine: commit follows a reveal, failure, skip or legacy pulse" in r.stdout and "[PASS] chains to previous pulse" in r.stdout, r.stdout[-800:]
    assert r.returncode == 0
def test_14_spec_version_is_0_3():
    import notbefore
    rc, out, err = nb("--version"); assert notbefore.SPEC in out and notbefore.__version__ in out
def test_15_client_side_split_view_detector(tmp_path, monkeypatch):
    """TLOG.md §8: with a (temporary) checkpoint identity, `verify` proves inclusion against the log's checkpoint and
    refuses when the served head is not an append-only extension of the head this machine saw before."""
    import notbefore.tlogcheck as TC, notbefore.check as C, notbefore.log as NL
    T = TC.T
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    log = tmp_path / "log"; (log / "chain").mkdir(parents=True)
    for f in sorted(os.listdir(os.path.join(LOG, "chain"))):
        if f.endswith(".json") and "tsa" not in f: shutil.copy2(os.path.join(LOG, "chain", f), log / "chain" / f)
    priv = T.Ed25519PrivateKey.generate(); pub_raw = priv.public_key().public_bytes(T.serialization.Encoding.Raw, T.serialization.PublicFormat.Raw)
    origin = "test.invalid/log"
    monkeypatch.setattr(TC, "identity", lambda: {"origin": origin, "public_key_file": "keys/x.pub", "enabled": True})
    monkeypatch.setattr(T, "load_pub_raw", lambda p: pub_raw)
    leaves = T.chain_leaves(str(log / "chain")); n = len(leaves)
    def publish(size, leaves_for_root): (log / "checkpoint").write_text(T.sign_note(T.checkpoint_body(origin, size, T.mth(leaves_for_root[:size])), origin, priv))
    publish(n, leaves)
    src = NL.LogSource(log_dir=str(log)); R = C.CheckResult(23)
    assert TC.check(src, (22, 23), R, refetch=False) == "ok" and R.ok, R.lines
    assert any("is included in the checkpointed tree" in l and "0023" in l for l in R.lines) and any("first checkpoint seen" in l for l in R.lines)
    # honest growth: same log, one more (fake) pulse appended -> consistent
    j = json.load(open(log / "chain" / f"pulse-{n:04d}.json")); j["core"]["seq"] = n + 1; json.dump(j, open(log / "chain" / f"pulse-{n+1:04d}.json", "w"))
    leaves2 = T.chain_leaves(str(log / "chain")); publish(n + 1, leaves2)
    R2 = C.CheckResult(23); assert TC.check(NL.LogSource(log_dir=str(log)), (22, 23), R2, refetch=False) == "ok" and any("consistent with the head this machine last saw" in l for l in R2.lines), R2.lines
    # split view: a different history of the same size (two pulses swapped), checkpoint signed by the same key
    forked = list(leaves2); forked[10], forked[11] = forked[11], forked[10]
    (log / "checkpoint").write_text(T.sign_note(T.checkpoint_body(origin, n + 1, T.mth(forked)), origin, priv))
    R3 = C.CheckResult(23); st = TC.check(NL.LogSource(log_dir=str(log)), (22, 23), R3, refetch=False)
    # the served pulses still hash to the honest root, so the forked checkpoint fails "root recomputes" before consistency:
    assert not R3.ok and any("root at size" in l and l.startswith("[FAIL]") for l in R3.lines), R3.lines
    # now serve a log whose files really are the forked order (rename two pulses' contents) -> consistency vs cached head must fail
    a, b = log / "chain" / "pulse-0011.json", log / "chain" / "pulse-0012.json"; ja, jb = json.load(open(a)), json.load(open(b))
    ja["core"]["seq"], jb["core"]["seq"] = 12, 11; json.dump(jb, open(a, "w")); json.dump(ja, open(b, "w"))
    leaves3 = T.chain_leaves(str(log / "chain")); publish(n + 1, leaves3)      # a checkpoint that honestly covers the FORKED history
    R4 = C.CheckResult(23); st4 = TC.check(NL.LogSource(log_dir=str(log)), (22, 23), R4, refetch=False)
    assert st4 == "SPLIT VIEW" and any("SPLIT VIEW / ROLLBACK" in l for l in R4.lines), R4.lines
def test_16_streams_and_quiet_mode():
    """Payload on stdout only; transcript on stderr; -q keeps stderr empty on success and still fails loudly on a bad pair."""
    rc, out, err = nb("value", "23"); assert rc == 0 and len(out.strip()) == 64 and "\n" not in out.strip() and "[PASS]" in err
    quiet_ok = lambda e: all(l.startswith(("[WARN]", "[FAIL]")) for l in e.strip().splitlines())   # -q keeps only WARN/FAIL (retroactive-anchor WARN is legitimate)
    rc, out, err = nb("-q", "value", "23"); assert rc == 0 and len(out.strip()) == 64 and quiet_ok(err) and "[PASS]" not in err, err
    rc, out, err = nb("value", "23", "-q"); assert rc == 0 and quiet_ok(err)          # flag after the subcommand too
    rc, out, err = nb("-q", "value", "19"); assert rc == 1 and out.strip() == "" and "[FAIL]" in err and "NOT VERIFIED" in err
def test_17_site_cross_check(tmp_path, monkeypatch):
    """The checkpoint served by the site must be the git head or an append-only relative of it."""
    import notbefore.tlogcheck as TC, notbefore.check as C, notbefore.log as NL
    T = TC.T; monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    log = tmp_path / "log"; (log / "chain").mkdir(parents=True)
    for f in sorted(os.listdir(os.path.join(LOG, "chain"))):
        if f.endswith(".json") and "tsa" not in f: shutil.copy2(os.path.join(LOG, "chain", f), log / "chain" / f)
    priv = T.Ed25519PrivateKey.generate(); pub_raw = priv.public_key().public_bytes(T.serialization.Encoding.Raw, T.serialization.PublicFormat.Raw); origin = "test.invalid/log"
    monkeypatch.setattr(TC, "identity", lambda: {"origin": origin, "public_key_file": "keys/x.pub", "enabled": True}); monkeypatch.setattr(T, "load_pub_raw", lambda p: pub_raw)
    leaves = T.chain_leaves(str(log / "chain")); n = len(leaves)
    def note(size, lv): return T.sign_note(T.checkpoint_body(origin, size, T.mth(lv[:size])), origin, priv)
    (log / "checkpoint").write_text(note(n, leaves))
    site = tmp_path / "site.txt"
    site.write_text(note(n, leaves)); R = C.CheckResult(23); TC.check(NL.LogSource(log_dir=str(log)), (23,), R, refetch=True, site_url=site.as_uri()); assert any("serves the same checkpoint" in l for l in R.lines), R.lines
    site.write_text(note(n - 5, leaves)); R = C.CheckResult(23); TC.check(NL.LogSource(log_dir=str(log)), (23,), R, refetch=True, site_url=site.as_uri()); assert R.ok and any("consistent heads of one log" in l for l in R.lines), R.lines
    forked = list(leaves); forked[3], forked[4] = forked[4], forked[3]
    site.write_text(note(n, forked)); R = C.CheckResult(23); TC.check(NL.LogSource(log_dir=str(log)), (23,), R, refetch=True, site_url=site.as_uri()); assert not R.ok and any("SPLIT VIEW between publication surfaces" in l for l in R.lines), R.lines

def test_18_live_checkpoint_verifies_with_the_vendored_identity():
    """The repository's published checkpoint (notbefore.net/log) verifies under the vendored key, and a verify proves inclusion against it."""
    if not os.path.exists(os.path.join(LOG, "checkpoint")): pytest.skip("no checkpoint published in this checkout")
    rc, out, err = nb("--offline", "checkpoint"); assert rc == 0, err
    assert out.startswith("notbefore.net/log\n") and "[PASS] checkpoint signature by notbefore.net/log" in err and "[PASS] root at size" in err, err
    rc, out, err = nb("--offline", "verify", "23"); assert rc == 0 and "is included in the checkpointed tree (leaf 22" in err, err
def test_19_sample_assign_id_range_bytes(tmp_path):
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"rec{i}" for i in range(20)) + "\n"); P = ["--purpose", "demo:roster", "--transcript", "none"]
    sh = nb("shuffle", "23", *P, str(f))[1].split()
    rc, out, err = nb("sample", "23", *P, "--k", "12", str(f)); assert rc == 0 and out.split() == sh[:12]
    rc, out, err = nb("assign", "23", *P, "--arms", "3", str(f)); rows = [l.split("\t") for l in out.strip().split("\n")]
    assert rc == 0 and [r[0] for r in rows] == sh and [int(r[1]) for r in rows] == [i % 3 for i in range(20)]
    rc, out, err = nb("id", "23", *P, "--from", str(f)); ids = out.split(); assert rc == 0 and len(ids) == 20 and all(len(i) == 16 for i in ids) and len(set(ids)) == 20 and "rec0" not in out
    rc, out, err = nb("range", "23", *P, "--lo", "1", "--hi", "6"); assert rc == 0 and 1 <= int(out) <= 6
    rc2, out2, _ = nb("range", "23", *P, "--lo", "1", "--hi", "6"); assert out2 == out
    rc, out, err = nb("bytes", "23", *P, "--n", "32"); assert rc == 0 and len(out.strip()) == 64
    rc, out, err = nb("sample", "23", *P, "--k", "21", str(f)); assert rc == 2 and out == ""
def test_20_explain_paragraph():
    rc, out, err = nb("explain", "23"); assert rc == 0 and "pulse 23 (commit 22)" in out and "RFC 3161" in out and "drand quicknet round" in out and "could not have been known before the round" in out
def test_21_pin_and_lock(tmp_path):
    lock = tmp_path / "notbefore.lock"; rc, out, err = nb("pin", "--out", str(lock)); assert rc == 0 and len(out.strip()) == 40
    j = json.load(open(lock)); assert j["log_git_sha"] == out.strip() and j["cli_version"] and j["verifier_git_sha"]
    rc, out, err = nb("--lock", str(lock), "value", "23"); assert rc == 0 and len(out.strip()) == 64 and "pinned by" in err
def test_22_diff_transcript(tmp_path):
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"rec{i}" for i in range(10)) + "\n"); g = tmp_path / "s.txt"; g.write_text("\n".join(f"rec{i}" for i in range(11)) + "\n")
    a, b, c = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"
    nb("sample", "23", "--purpose", "demo:roster", "--k", "3", str(f), "--transcript", str(a)); nb("sample", "23", "--purpose", "demo:roster", "--k", "3", str(f), "--transcript", str(b)); nb("sample", "23", "--purpose", "demo:roster", "--k", "3", str(g), "--transcript", str(c))
    rc, out, err = nb("diff-transcript", str(a), str(b)); assert rc == 0 and "IDENTICAL" in out
    rc, out, err = nb("diff-transcript", str(a), str(c)); assert rc == 1 and "INPUT FILE differs" in out
    d, e = tmp_path / "d.json", tmp_path / "e.json"
    nb("split", "23", "--purpose", "demo:roster", "--frac", "0.7", str(f), "--out-a", str(tmp_path / "x.A"), "--out-b", str(tmp_path / "x.B"), "--transcript", str(d))
    nb("split", "23", "--purpose", "demo:roster", "--frac", "0.7", str(f), "--out-a", str(tmp_path / "y.A"), "--out-b", str(tmp_path / "y.B"), "--transcript", str(e))
    rc, out, err = nb("diff-transcript", str(d), str(e)); assert rc == 0 and "IDENTICAL" in out, out      # different output file names, same allocation
def test_23_cosignature_reporting_and_quorum():
    """The live checkpoint carries a same-sponsor cosignature: reported, named as such, never counted toward an independent quorum."""
    if not os.path.exists(os.path.join(LOG, "checkpoint")) or "\u2014 notbefore.net/witness/" not in open(os.path.join(LOG, "checkpoint")).read(): pytest.skip("no cosigned checkpoint in this checkout")
    rc, out, err = nb("--offline", "checkpoint"); assert rc == 0 and "cosigned by witness notbefore.net/witness/" in err and "same sponsor" in err, err
    rc, out, err = nb("--offline", "--witness-quorum", "1", "verify", "23"); assert rc == 1 and "0 independent cosignature(s) >= quorum 1" in err, err

