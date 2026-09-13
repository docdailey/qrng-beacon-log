"""NOTBEFORE.md §14 acceptance tests, run against the repository checkout two levels up (or NOTBEFORE_LOG_DIR).
Network: drand refetch + Rekor refetch are exercised unless NOTBEFORE_OFFLINE=1."""
import os, sys, json, subprocess, shutil, tempfile, hashlib, re, pytest
CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.environ.get("NOTBEFORE_LOG_DIR") or os.path.dirname(CLI_DIR)
OFF = ["--offline"] if os.environ.get("NOTBEFORE_OFFLINE") == "1" else []

@pytest.fixture(autouse=True, scope="session")
def _consumer_identity(tmp_path_factory):
    """Since 0.8.0 `plan` signs with the consumer's identity; the suite uses a throwaway key, never ~/.config."""
    import notbefore.identity as I
    p = tmp_path_factory.mktemp("identity") / "identity.key"; I.generate(str(p)); os.environ["NOTBEFORE_KEY"] = str(p); yield str(p)

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
def test_14_version_flag_reports_spec_and_package():
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

def test_24_decision_contract_plan_execute(tmp_path):
    """The consumer's commitment: a canonical contract registered with two TSAs before the pulse; execute takes no choices,
    selects the pulse by rule, requires the registration to predate the round, and reproduces the allocation."""
    f = tmp_path / "eligible.txt"; f.write_text("\n".join(f"chart-{i:03d}" for i in range(30)) + "\n")
    out = tmp_path / "plan.json"
    # an `after` in the past selects a known pulse deterministically: the first eligible reveal released at/after 0022's release
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:audit", "--sample", "12", "--out", str(out), "--no-log", str(f), cwd=str(tmp_path))
    assert rc == 0 and len(o.strip()) == 64, e
    c = json.load(open(out)); assert c["operation"] == "sample" and c["params"] == {"k": 12} and c["input"]["record_count"] == 30 and c["selection"]["after_unix_s"] == 1789182000
    assert os.path.exists(str(out) + ".tsa.json"), "TSA registration files missing"
    # execute: registered today, so every token is AFTER a 2026-09-12T03:0x pulse release -> must REFUSE (decision after the value)
    rc, o, e = nb("execute", str(out), "--input", str(f), "--transcript", "none", cwd=str(tmp_path)); assert rc == 1 and "authoritative preregistration" in e, e      # fail closed: not in the log
    rc, o, e = nb("execute", str(out), "--input", str(f), "--transcript", "none", "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "not strictly before the selected round" in e, e
    # the same contract, unregistered, allowed as a dry run: deterministic selection + output
    out2 = tmp_path / "plan2.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:audit", "--sample", "12", "--out", str(out2), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0
    rc1, o1, e1 = nb("execute", str(out2), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "t1.json"), cwd=str(tmp_path)); assert rc1 == 0, e1
    rc2, o2, e2 = nb("execute", str(out2), "--input", str(f), "--allow-unregistered", "--transcript", "none", cwd=str(tmp_path)); assert o1 == o2 and len(o1.split()) == 12
    assert "selected by rule" in e1 and "commit 0042" in e1, e1           # contract/3: commits before 0042 have only RETROACTIVE anchors -> passed over; 0042 is the first with a pre-round anchor
    t = json.load(open(tmp_path / "t1.json")); assert t["contract_sha256"] and t["selected_by_rule"] and t["commit_seq"] == 42 and t["seq"] == 43 and t["provenance"] == "FULL-ATTESTED"
    # tampering with the committed input is refused
    f.write_text("\n".join(f"chart-{i:03d}" for i in range(29)) + "\nchart-999\n")
    rc, o, e = nb("execute", str(out2), "--input", str(f), "--allow-unregistered", "--transcript", "none", cwd=str(tmp_path)); assert rc == 1 and "not the committed bytes" in e
def test_25_timestamp_verdict_is_exhaustive():
    """The normative gate as a pure function: both TSAs, all verifying, LATEST strictly before release."""
    import notbefore.contract as C
    rel = 1_000_000; A = ("freetsa", "t", 900_000); B = ("digicert", "t", 950_000)
    assert C.timestamp_verdict([A, B], False, rel)[0]
    assert not C.timestamp_verdict([A], False, rel)[0]                                      # one TSA only
    assert not C.timestamp_verdict([A, B], True, rel)[0]                                    # a token failed to verify
    assert not C.timestamp_verdict([A, ("digicert", "t", 1_000_000)], False, rel)[0]        # latest == release: not strictly before
    assert not C.timestamp_verdict([A, ("digicert", "t", 1_000_001)], False, rel)[0]        # one before, one after -> refuse (max, not min)
    assert not C.timestamp_verdict([A, B, ("someone.else", "t", 1)], False, rel)[0]         # unexpected identity
    assert not C.timestamp_verdict([], False, rel)[0]
def test_26_contract_negatives(tmp_path):
    """Real files: one token deleted, a token corrupted, a contract byte edited, roster edited — each refused."""
    import shutil
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"x{i}" for i in range(10)) + "\n"); c = tmp_path / "c.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:neg", "--sample", "3", "--out", str(c), "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    assert os.path.exists(str(c) + ".freetsa.tsr") and os.path.exists(str(c) + ".digicert.tsr")
    base = [str(c), "--input", str(f), "--transcript", "none"]
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "authoritative preregistration" in e            # fail closed: --no-log contract
    rc, o, e = nb("execute", *base, "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "not strictly before" in e   # DEGRADED still gates on the round
    keep = tmp_path / "keep"; keep.mkdir(); shutil.copy2(str(c) + ".digicert.tsr", keep / "d.tsr")
    os.remove(str(c) + ".digicert.tsr"); rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "lacks a verifying token from digicert" in e, e   # one TSA only
    rc, o, e = nb("execute", *base, "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "not strictly before" in e   # dry-run flag never overrides a late token
    shutil.copy2(keep / "d.tsr", str(c) + ".digicert.tsr"); open(str(c) + ".digicert.tsr", "r+b").write(b"\x00\x00\x00\x00")
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "does NOT verify" in e, e              # corrupt token, even with --allow-unregistered:
    rc, o, e = nb("execute", *base, "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "does NOT verify" in e
    shutil.copy2(keep / "d.tsr", str(c) + ".digicert.tsr")
    raw = open(c, "rb").read(); open(c, "wb").write(raw.replace(b'"k":3', b'"k":4')); rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and ("does NOT verify" in e or "canonical" in e or "does not verify for this contract" in e)   # edited byte: since 0.8.0 the signed statement catches it before the tokens do
    open(c, "wb").write(raw)
def test_27_rule_traverses_failures_without_a_cutoff(tmp_path):
    """Six consecutive non-verifying candidates, then a good one: the rule must reach it (0.6.0 stopped after five)."""
    import shutil
    log = tmp_path / "log"; (log / "chain").mkdir(parents=True)
    for fn in os.listdir(os.path.join(LOG, "chain")):
        if fn.endswith(".json") or fn.endswith(".tsr"): shutil.copy2(os.path.join(LOG, "chain", fn), log / "chain" / fn)
    for seq in (23, 25, 27, 29, 31, 33):     # corrupt the attested value of six reveals -> each fails verification
        p = log / "chain" / f"pulse-{seq:04d}.json"; j = json.load(open(p)); v = j["core"]["derived"]["attested_value"]; j["core"]["derived"]["attested_value"] = ("00" if v[:2] != "00" else "11") + v[2:]; json.dump(j, open(p, "w"))
    f = tmp_path / "r.txt"; f.write_text("a\nb\nc\n"); c = tmp_path / "c.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:trav", "--sample", "1", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path), log=str(log)); assert rc == 0
    c2 = _as_contract2(c)                                                          # the reveal-based rule (contract/2) is what traverses failed reveals
    rc, o, e = nb("execute", str(c2), "--input", str(f), "--allow-unregistered", "--transcript", "none", "--no-anchors", cwd=str(tmp_path), log=str(log))
    assert rc == 0 and "reveal 0035" in e and e.count("passed over by rule") >= 6, e

def _as_contract2(c3_path):
    """Rewrite a contract/3 file as a signed contract/2 (reveal-based rule) beside it; returns its path."""
    import notbefore.contract as C, notbefore.decisionlog as DL, notbefore.identity as I
    j = json.load(open(c3_path)); j["spec"] = "notbefore/contract/2"; j.pop("value", None); j["selection"]["rule"] = C.RULE; j["selection"]["eligibility"] = "reveal"
    p2 = str(c3_path).replace(".json", ".v2.json"); h = C.write(j, p2)
    priv, pub, kid, pub_b64 = I.load(os.environ["NOTBEFORE_KEY"]); st = DL.statement(h, j["decision_id"], kid, pub_b64, j["spec"]); DL.write_signature(p2, st, DL.sign_statement(priv, st)); return p2

def test_28_tsa_trust_roots_are_pinned_not_borrowed(tmp_path, monkeypatch):
    """ERR-014: RFC 3161 tokens verify only against the anchors shipped in verifier/keys/tsa — never the host store,
    never a download. Real tokens, real openssl: right pins pass with the system store hidden; wrong root fails;
    missing root fails closed; no pins at all fails closed; and the vendored source carries no system-store fallback."""
    import shutil, importlib, inspect
    _tsa = importlib.import_module("notbefore.verifier.tsa")
    code = "\n".join(l.split("#", 1)[0] for l in inspect.getsource(_tsa).splitlines())      # comments may mention the host store; code may not
    for banned in ("SYS_CA", "_fetch", "/etc/ssl", "cert.pem", "cacert", "CApath", "CAstore"):      # stamp() may use the network to ask a TSA; verify() may not fetch trust
        assert banned not in code, f"vendored tsa.py still references {banned!r}"
    pin_dir = os.path.join(os.path.dirname(_tsa.__file__), "keys", "tsa"); pins = json.load(open(os.path.join(pin_dir, "PINS.json")))
    assert set(pins["tsas"]) == set(_tsa.TSAS), "every TSA we stamp with must have a pinned root"
    for name, cfg in pins["tsas"].items():
        for f in [cfg["root"], *cfg["intermediates"]]: assert os.path.exists(os.path.join(pin_dir, f)), f"{name}: pinned file {f} missing from the package"
    seq = max(int(fn[6:10]) for fn in os.listdir(os.path.join(LOG, "chain")) if fn.endswith(".digicert.tsr"))
    p = tmp_path / f"pulse-{seq:04d}.json"
    for ext in ("", ".freetsa.tsr", ".digicert.tsr"): shutil.copy2(os.path.join(LOG, "chain", p.name + ext), str(p) + ext)
    monkeypatch.setenv("SSL_CERT_FILE", os.devnull); monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "no-such-dir"))   # hide the host store from openssl
    ok, res = _tsa.verify(str(p)); assert ok and {r["tsa"] for r in res} == {"freetsa", "digicert"} and all(r["digest_and_chain_verified"] for r in res), res
    alt = tmp_path / "pins"; shutil.copytree(pin_dir, alt); monkeypatch.setattr(_tsa, "PIN_DIR", str(alt))
    bad = dict(pins); bad["tsas"] = json.loads(json.dumps(pins["tsas"])); bad["tsas"]["digicert"]["root"] = pins["tsas"]["freetsa"]["root"]   # wrong root
    json.dump(bad, open(alt / "PINS.json", "w")); ok, res = _tsa.verify(str(p)); by = {r["tsa"]: r for r in res}
    assert not ok and by["freetsa"]["digest_and_chain_verified"] and not by["digicert"]["digest_and_chain_verified"], res
    json.dump(pins, open(alt / "PINS.json", "w")); os.remove(alt / pins["tsas"]["digicert"]["root"])                        # missing root file
    ok, res = _tsa.verify(str(p)); by = {r["tsa"]: r for r in res}; assert not ok and "fail closed" in (by["digicert"]["detail"] or ""), res
    empty = tmp_path / "empty"; empty.mkdir(); monkeypatch.setattr(_tsa, "PIN_DIR", str(empty))                            # no pins at all
    ok, res = _tsa.verify(str(p)); assert not ok and len(res) == 2 and not any(r["digest_and_chain_verified"] for r in res), res
def test_29_identity_and_signed_contracts(tmp_path, monkeypatch):
    """§7.12: keygen writes a 0600 Ed25519 key; plan signs a decision statement bound to the contract bytes, signer and
    decision_id; execute verifies it and refuses a tampered statement, a swapped key, or a legacy unsigned contract
    without the labelled flag. No network beyond the log checkout (--no-timestamp, --allow-unregistered)."""
    import stat, notbefore.identity as I, notbefore.decisionlog as DL
    key = tmp_path / "id.key"; monkeypatch.setenv("NOTBEFORE_KEY", str(key))
    rc, o, e = nb("keygen"); assert rc == 0 and len(o.strip()) == 16, e
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600 and (tmp_path / "id.pub").exists()
    rc, o, e = nb("keygen"); assert rc == 1 and "exists" in e                                    # never silently replaces an identity
    rc, o, e = nb("whoami"); kid = o.split()[0]; assert rc == 0 and len(kid) == 16
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"p{i}" for i in range(9)) + "\n"); c = tmp_path / "c.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:signed", "--decision-id", "trial:abc@v1", "--sample", "2", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    import notbefore.contract as C
    j = json.load(open(c)); assert j["spec"] == C.CONTRACT_SPEC and j["signer"]["key_id"] == kid and j["decision_id"] == "trial:abc@v1"
    st, sig = DL.read_signature(str(c)); assert DL.verify_statement(st, sig)[0] and st["contract_sha256"] == hashlib.sha256(open(c, "rb").read()).hexdigest()
    base = [str(c), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "t.json"), "--no-anchors"]
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 0 and "Ed25519 statement verifies" in e and len(o.split()) == 2, e
    t = json.load(open(tmp_path / "t.json")); assert t["signer_key_id"] == kid and t["decision_id"] == "trial:abc@v1" and t["contract_signature_verified"] and t["decision_log"]["status"] in ("disabled", "unreachable", "unregistered", "authoritative")
    # tamper: statement edited -> signature fails; statement re-signed by ANOTHER key -> not the contract's signer
    sp = DL.sig_path(str(c)); good = open(sp).read()
    bad = json.loads(good); bad["statement"]["decision_id"] = "trial:xyz@v1"; json.dump(bad, open(sp, "w"))
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "does not verify" in e, e
    other = tmp_path / "other.key"; I.generate(str(other)); priv2, pub2, kid2, pub2_b64 = I.load(str(other))
    st2 = dict(st, key_id=kid2, public_key_b64=pub2_b64); DL.write_signature(str(c), st2, DL.sign_statement(priv2, st2))
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "different contract, key or decision_id" in e, e
    open(sp, "w").write(good); os.remove(sp)
    rc, o, e = nb("execute", *base, cwd=str(tmp_path)); assert rc == 1 and "no " in e and ".sig.json" in e          # signed contract without its statement file
    open(sp, "w").write(good)
    # legacy unsigned contract/1: refused unless labelled
    c1 = tmp_path / "c1.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:legacy", "--sample", "2", "--out", str(c1), "--no-timestamp", "--unsigned", str(f), cwd=str(tmp_path)); assert rc == 0
    assert json.load(open(c1))["spec"] == "notbefore/contract/1"
    rc, o, e = nb("execute", str(c1), "--input", str(f), "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "legacy unsigned" in e      # no tokens at all -> refused
    rc, o, e = nb("execute", str(c1), "--input", str(f), "--transcript", "none", "--no-anchors", "--allow-unregistered", cwd=str(tmp_path)); assert rc == 0 and "legacy unsigned" in e
    rc, o, e = nb("execute", str(c1), "--input", str(f), "--transcript", "none", "--no-anchors", "--allow-unregistered", "--require-log", cwd=str(tmp_path)); assert rc == 0   # --require-log is the default since 0.10.0; still accepted
    # a legacy contract WITH both tokens (what 0.6.0–0.7.x produced): 0.10.0 fails closed — refused by default, DEGRADED with the flag (then gated on the round)
    c0 = tmp_path / "c0.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:legacy2", "--sample", "2", "--out", str(c0), "--unsigned", str(f), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("execute", str(c0), "--input", str(f), "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "legacy unsigned" in e and "fails closed" in e, e
    rc, o, e = nb("execute", str(c0), "--input", str(f), "--transcript", "none", "--no-anchors", "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "DEGRADED" in e and "not strictly before" in e, e
    # a SIGNED contract without tokens: the token gate speaks first (no --allow-unregistered)
    rc, o, e = nb("execute", str(c), "--input", str(f), "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "lacks a verifying token" in e, e
    # a SIGNED, timestamped contract that is NOT in the log: refused by default (fail closed); DEGRADED with the flag (then gated on the round)
    c4 = tmp_path / "c4.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:nolog", "--sample", "2", "--out", str(c4), "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("execute", str(c4), "--input", str(f), "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "did not confirm this contract as the authoritative preregistration" in e and "unregistered" in e, e
    rc, o, e = nb("execute", str(c4), "--input", str(f), "--transcript", "none", "--no-anchors", "--allow-unregistered", cwd=str(tmp_path)); assert rc == 1 and "DEGRADED" in e and "not strictly before" in e, e
def test_30_decision_log_receipts_verify_only_against_vendored_trust(tmp_path, monkeypatch):
    """The client trusts nothing the log says until the note verifies under the vendored key and the proof reaches its
    root. Synthetic log with a throwaway key: a good receipt passes; wrong-key note, wrong index, tampered leaf, or a
    different statement all fail. Also the write-once verdicts from check_authoritative on a faked lookup."""
    import base64, notbefore.decisionlog as DL, notbefore.identity as I
    sys.path.insert(0, os.path.join(CLI_DIR, "notbefore", "verifier")); import tlog as T
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    logk = Ed25519PrivateKey.generate(); lpub = logk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    origin = "notbefore.net/decisions"
    monkeypatch.setattr(DL, "identity", lambda: {"origin": origin, "enabled": True, "base_url": "http://127.0.0.1:9", "key_id_hex": T.key_id(origin, lpub).hex(), "public_key_file": "x"})
    monkeypatch.setattr(DL, "pub_raw", lambda: lpub)
    ck = tmp_path / "id.key"; I.generate(str(ck)); priv, pub, kid, pub_b64 = I.load(str(ck))
    def leaf(i, st, sig, k=1): return DL.canon({"spec": DL.LEAF_SPEC, "index": i, "received_utc": "2026-09-12T02:00:00Z", "seq_in_namespace": k, "statement": st, "signature_b64": sig, "tsa_sha256": {}, "contract_disclosed": False})
    sts = [DL.statement("%064x" % (i + 1), "d:%d" % (3 if i == 2 else i), kid, pub_b64, "notbefore/contract/2") for i in range(5)]   # leaves 2 and 3 share namespace d:3
    leaves = [leaf(i, s, DL.sign_statement(priv, s)) for i, s in enumerate(sts)]
    root = T.mth(leaves); note = T.sign_note(T.checkpoint_body(origin, 5, root), origin, logk)
    rc = lambda i: {"index": i, "size": 5, "checkpoint": note, "leaf": leaves[i].decode(), "proof": [base64.b64encode(h).decode() for h in T.inclusion_path(i, leaves)]}
    assert DL.verify_receipt(rc(3), sts[3])[0]
    assert not DL.verify_receipt(rc(3), sts[2])[0]                                          # different statement than submitted
    assert not DL.verify_receipt(dict(rc(3), index=2), sts[3])[0]                           # wrong index for that proof
    other = Ed25519PrivateKey.generate(); bad_note = T.sign_note(T.checkpoint_body(origin, 5, root), origin, other)
    assert not DL.verify_receipt(dict(rc(3), checkpoint=bad_note), sts[3])[0]               # note signed by a key that is not the vendored one
    tl = json.loads(leaves[3]); tl["received_utc"] = "2026-09-12T02:00:01Z"; assert not DL.verify_receipt(dict(rc(3), leaf=DL.canon(tl).decode()), sts[3])[0]   # tampered leaf
    # write-once verdicts: lookup answers are faked; the client still verifies everything it is handed
    def fake_lookup(entries_idx):
        return lambda key_id, decision_id: {"size": 5, "checkpoint": note, "entries": [{"index": i, "seq_in_namespace": n + 1, "contract_sha256": sts[i]["contract_sha256"], "received_utc": "2026-09-12T02:00:00Z"} for n, i in enumerate(entries_idx)],
                                            "authoritative": ({"index": entries_idx[0], "leaf": leaves[entries_idx[0]].decode(), "proof": rc(entries_idx[0])["proof"]} if entries_idx else None)}
    monkeypatch.setattr(DL, "lookup", fake_lookup([3])); r = DL.check_authoritative(sts[3]); assert r["status"] == "authoritative" and r["index"] == 3 and r["verified"], r
    # binding: leaf 2 (decision d:2) is genuinely in the tree, but it is not the namespace we asked about -> untrusted answer, not "superseded"
    def cross(key_id, decision_id): return {"size": 5, "checkpoint": note, "entries": [{"index": 1, "seq_in_namespace": 1, "contract_sha256": sts[1]["contract_sha256"], "received_utc": "2026-09-12T02:00:00Z"}], "authoritative": {"index": 1, "leaf": leaves[1].decode(), "proof": rc(1)["proof"]}}
    monkeypatch.setattr(DL, "lookup", cross); r = DL.check_authoritative(sts[3]); assert r["status"] == "unreachable" and "different namespace" in r["why"], r
    monkeypatch.setattr(DL, "lookup", fake_lookup([2, 3])); r = DL.check_authoritative(sts[3]); assert r["status"] == "superseded", r     # someone registered first under this namespace
    monkeypatch.setattr(DL, "lookup", fake_lookup([])); assert DL.check_authoritative(sts[3])["status"] == "unregistered"
    def boom(*a): raise OSError("down")
    monkeypatch.setattr(DL, "lookup", boom); assert DL.check_authoritative(sts[3])["status"] == "unreachable"
    monkeypatch.setattr(DL, "lookup", fake_lookup([3])); monkeypatch.setattr(DL, "pub_raw", lambda: other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    assert DL.check_authoritative(sts[3])["status"] == "unreachable"                          # a log whose note does not verify under OUR key is not believed, whatever it says
def test_31_live_decision_log_roundtrip(tmp_path, monkeypatch):
    """Against the live log when the vendored identity is enabled (skipped otherwise): plan registers, the receipt verifies,
    a second contract under the same decision_id is an amendment, and execute refuses the superseded one."""
    import notbefore.decisionlog as DL
    if not DL.enabled() or OFF: pytest.skip("decision log not enabled in this release (or offline)")
    if os.environ.get("NOTBEFORE_LIVE_LOG_TEST") != "1": pytest.skip("appends real entries to the public decision log: run with NOTBEFORE_LIVE_LOG_TEST=1 before a release")
    key = tmp_path / "id.key"; monkeypatch.setenv("NOTBEFORE_KEY", str(key)); nb("keygen")
    f = tmp_path / "r.txt"; f.write_text("a\nb\nc\nd\n"); did = "test:live:" + hashlib.sha256(os.urandom(8)).hexdigest()[:12]
    c1 = tmp_path / "c1.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:live1", "--decision-id", did, "--sample", "1", "--out", str(c1), "--no-timestamp", str(f), cwd=str(tmp_path)); assert rc == 0 and "AUTHORITATIVE" in e, e
    r1 = json.load(open(DL.receipt_path(str(c1)))); assert r1["summary"]["seq_in_namespace"] == 1
    c2 = tmp_path / "c2.json"; rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:live2", "--decision-id", did, "--sample", "1", "--out", str(c2), "--no-timestamp", str(f), cwd=str(tmp_path)); assert rc == 0 and "AMENDMENT" in e, e
    rc, o, e = nb("execute", str(c2), "--input", str(f), "--allow-unregistered", "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "not the first registered" in e, e
    rc, o, e = nb("execute", str(c1), "--input", str(f), "--allow-unregistered", "--transcript", "none", "--no-anchors", cwd=str(tmp_path)); assert rc == 1 and "AT/AFTER the round release" in e, e   # registered today, round in the past
    rc, o, e = nb("register", str(c1), cwd=str(tmp_path)); assert rc == 0 and "already present" in e                     # idempotent
def test_32_commit_bound_value_is_unabortable(tmp_path):
    """§4.6 / §7.13 (FALLBACK.md): a signed contract is commit-bound by default. The rule selects the first eligible COMMIT
    (verified, tokens and Rekor anchor before its round); V* = H(D || C || rho || chain || R) is the same whether the
    operator revealed (FULL-ATTESTED) or not (COMMITMENT-FALLBACK, rho fetched from drand and BLS-verified). Shown by
    executing the same contract against the log and against a copy of the log with the reveal removed."""
    import shutil, notbefore.commitbound as CB
    from notbefore.log import LogSource
    f = tmp_path / "r.txt"; f.write_text("\n".join(f"x{i}" for i in range(9)) + "\n"); c = tmp_path / "c.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T13:00:00Z", "--purpose", "test:cb", "--sample", "3", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    j = json.load(open(c)); assert j["spec"] == "notbefore/contract/3" and j["value"]["rule"] == "commit-bound" and j["selection"]["rule"] == CB.RULE
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "full.json"), cwd=str(tmp_path)); assert rc == 0, e
    t = json.load(open(tmp_path / "full.json")); assert t["value_rule"] == "commit-bound" and t["provenance"] == "FULL-ATTESTED" and t["commit_seq"] >= 42 and t["reveal_seq"] == t["commit_seq"] + 1, t
    n = t["commit_seq"]; com = json.load(open(os.path.join(LOG, "chain", f"pulse-{n:04d}.json")))["core"]; rev = json.load(open(os.path.join(LOG, "chain", f"pulse-{n+1:04d}.json")))["core"]
    buf = b"notbefore/commit-bound/v1" + bytes.fromhex(com["derived"]["entropy_commitment"]) + bytes.fromhex(rev["drand"]["randomness"]) + bytes.fromhex(com["chain_hash"]) + int(com["derived"]["target_round"]).to_bytes(8, "big")
    assert len(buf) == 129 and hashlib.sha256(buf).hexdigest() == t["commit_bound_value"] == CB.value(com["derived"]["entropy_commitment"], rev["drand"]["randomness"], com["chain_hash"], com["derived"]["target_round"])
    assert t["publication_evidence"]["present"] and t["publication_evidence"]["before_release_s"] > 0 and t["drand"]["signature"] == rev["drand"]["signature"]
    # the same contract against a log in which the operator never revealed: identical V*, seed and output
    log = tmp_path / "log"; (log / "chain").mkdir(parents=True); (log / "anchors").mkdir(); (log / "ci").mkdir()
    for fn in os.listdir(os.path.join(LOG, "chain")):
        m = re.match(r"pulse-(\d{4})\.json", fn)
        if m and int(m.group(1)) <= n: shutil.copy2(os.path.join(LOG, "chain", fn), log / "chain" / fn)      # incl. .tsr / .tsa.json sidecars (prefix match)
    shutil.copy2(os.path.join(LOG, "ci", "KNOWN_NONCOMPLIANT.json"), log / "ci" / "KNOWN_NONCOMPLIANT.json")
    src = LogSource(log_dir=LOG); rec, stmt = src.anchor(n); src.close(); assert rec, "anchor record for the selected commit must be reachable"
    json.dump(rec, open(log / "anchors" / f"pulse-{n:04d}.anchor.json", "w")); open(log / "anchors" / f"pulse-{n:04d}.stmt.json", "wb").write(stmt)
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "fb.json"), cwd=str(tmp_path), log=str(log)); assert rc == 0, e
    t2 = json.load(open(tmp_path / "fb.json")); assert t2["provenance"] == "COMMITMENT-FALLBACK" and t2["reveal_seq"] is None and t2["commit_seq"] == n, t2
    assert t2["commit_bound_value"] == t["commit_bound_value"] and t2["derived_seed"] == t["derived_seed"] and t2["output_sha256"] == t["output_sha256"], "a withheld reveal must not change the value"
    assert "COMMITMENT-FALLBACK" in e and "BLS-verified" in e
    # a commit without pre-round publication evidence is passed over by rule (remove the anchor record)
    os.remove(log / "anchors" / f"pulse-{n:04d}.anchor.json"); os.remove(log / "anchors" / f"pulse-{n:04d}.stmt.json")
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--transcript", "none", cwd=str(tmp_path), log=str(log)); assert rc == 1 and "passed over by rule" in e and ("no Rekor anchor" in e or "no publication anchor" in e), e   # either the eligibility check or the anchor check names the missing anchor
    # a legacy contract/2 (reveal-based) still executes with the reveal rule
    c2 = _as_contract2(c)
    rc, o, e = nb("execute", str(c2), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "v2.json"), cwd=str(tmp_path)); assert rc == 0, e
    assert json.load(open(tmp_path / "v2.json"))["value_rule"] == "reveal" and "reveal 0043" in e
