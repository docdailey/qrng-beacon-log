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
    j = json.load(open(t)); assert j["log_git_sha"] and j["seq"] == 23 and j["commit_seq"] == 22 and j["derived_seed"] == out.strip() and j["spec"] == "notbefore/spec/0.3"
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
    rc, out, err = nb("--version"); assert "notbefore/spec/0.3" in out and "0.3.0" in out
