"""WORKFLOW.md artifacts: receipt, bundle, check-bundle. Runs against the repository checkout (or NOTBEFORE_LOG_DIR) with a
throwaway identity; stays off the public decision log (--no-log) and off the TSAs (--no-timestamp) except where noted."""
import os, sys, json, subprocess, zipfile, hashlib, pytest
CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.environ.get("NOTBEFORE_LOG_DIR") or os.path.dirname(CLI_DIR)

@pytest.fixture(autouse=True, scope="module")
def _identity(tmp_path_factory):
    import notbefore.identity as I
    p = tmp_path_factory.mktemp("id") / "identity.key"; I.generate(str(p)); os.environ["NOTBEFORE_KEY"] = str(p); yield str(p)

def nb(*args, cwd=None):
    r = subprocess.run([sys.executable, "-m", "notbefore.cli", "--log-dir", LOG, *args], capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout, r.stderr

def _planned_and_executed(tmp_path):
    f = tmp_path / "eligible.txt"; f.write_text("\n".join(f"p{i:03d}" for i in range(20)) + "\n"); c = tmp_path / "plan.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:receipt", "--decision-id", "REG-1/protocol-2/sample-1", "--sample", "5", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--no-anchors", "--transcript", str(tmp_path / "t.json"), cwd=str(tmp_path)); assert rc == 0, e
    return f, c, tmp_path / "t.json"

def test_40_receipt_is_regenerated_from_verified_facts(tmp_path):
    f, c, t = _planned_and_executed(tmp_path)
    rc, o, e = nb("receipt", str(c), "--transcript", str(t), "--no-anchors", "--out", str(tmp_path / "r.md"), cwd=str(tmp_path)); assert rc == 0, e
    md = open(tmp_path / "r.md").read()
    for must in ("# NotBefore decision receipt — REG-1/protocol-2/sample-1", "EXECUTED", "Key id `", "Decision id `REG-1/protocol-2/sample-1`", "pulse **23**", "sample of k = 5 from 20 records", "Pair re-verified", "## Verification trail", "derived seed recomputes"):
        assert must in md, must
    assert "WARN" in md and "no decision-log receipt" in md          # honest about what it does not have
    # a commitment-only receipt (not executed yet) says so and exits 0
    c2 = tmp_path / "plan2.json"; rc, o, e = nb("plan", "--after", "2030-01-01T00:00Z", "--purpose", "test:future", "--sample", "2", "--out", str(c2), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0
    rc, o, e = nb("receipt", str(c2), cwd=str(tmp_path)); assert rc == 0 and "COMMITTED, not yet executed" in o and "Not yet" in o, e
    # a transcript for a different contract is refused as a receipt input
    rc, o, e = nb("receipt", str(c2), "--transcript", str(t), cwd=str(tmp_path)); assert rc == 1 and "DIFFERENT contract" in o + e

def test_41_bundle_roundtrip_and_tamper(tmp_path):
    f, c, t = _planned_and_executed(tmp_path)
    z = tmp_path / "b.zip"; rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(z), "--no-anchors", cwd=str(tmp_path)); assert rc == 0, e
    names = set(zipfile.ZipFile(z).namelist())
    for must in ("MANIFEST.json", "README.md", "contract/plan.json", "contract/plan.json.sig.json", "transcript/t.json", "log/chain/pulse-0022.json", "log/chain/pulse-0023.json", "log/chain/pulse-0021.json", "log/checkpoint", "log/inclusion.json", "verifier/keys/decisions.pub", "verifier/keys/tsa/PINS.json", "verifier/VENDORED.json"):
        assert must in names, must
    assert not any(n.startswith("input/") or n.startswith("output/") for n in names)          # sensitive files stay out by default
    man = json.loads(zipfile.ZipFile(z).read("MANIFEST.json")); assert man["bundle"] == "notbefore/bundle/1" and man["seq"] == 23 and man["key_id"] and man["decision_id"] == "REG-1/protocol-2/sample-1"
    rc, o, e = nb("check-bundle", str(z), cwd=str(tmp_path)); assert rc == 0, e
    for must in ("files match the manifest", "decision statement by", "bound to this contract", "pulse_hash == SHA-256(canonical core)", "vendored verify.py offline", "derived seed recomputes", "is included in that checkpoint", "2 RFC 3161 token(s) verify against the pinned roots"):
        assert must in e, must
    # tamper inside the zip: edit the transcript's attested value -> manifest + binding fail
    d = tmp_path / "unz"; zipfile.ZipFile(z).extractall(d)
    tp = d / "transcript" / "t.json"; tj = json.load(open(tp)); tj["attested_value"] = "00" + tj["attested_value"][2:]; json.dump(tj, open(tp, "w"))
    rc, o, e = nb("check-bundle", str(d), cwd=str(tmp_path)); assert rc == 1 and "altered since the bundle was written" in e and "transcript/t.json" in e, e
    # a bundle directory with --include-input carries the committed bytes, and their hash is checked
    dd = tmp_path / "bdir"; rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(dd), "--include-input", "--no-anchors", cwd=str(tmp_path)); assert rc == 0, e
    assert (dd / "input" / "eligible.txt").read_bytes() == f.read_bytes()
    rc, o, e = nb("check-bundle", str(dd), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(dd), cwd=str(tmp_path)); assert rc != 0 and "not empty" in e   # never overwrites a bundle
