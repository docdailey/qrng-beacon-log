"""WORKFLOW.md artifacts: receipt, bundle, check-bundle. Runs against the repository checkout (or NOTBEFORE_LOG_DIR) with a
throwaway identity; stays off the public decision log (--no-log) and off the TSAs (--no-timestamp) except where noted."""
import os, sys, json, subprocess, zipfile, hashlib, pytest
CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.environ.get("NOTBEFORE_LOG_DIR") or os.path.dirname(CLI_DIR)

@pytest.fixture(autouse=True, scope="module")
def _identity(tmp_path_factory):
    import notbefore.identity as I
    p = tmp_path_factory.mktemp("id") / "identity.key"; I.generate(str(p)); os.environ["NOTBEFORE_KEY"] = str(p); yield str(p)

OFF = ["--offline"] if os.environ.get("NOTBEFORE_OFFLINE") == "1" else []
def nb(*args, cwd=None):
    r = subprocess.run([sys.executable, "-m", "notbefore.cli", "--log-dir", LOG, *OFF, *args], capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout, r.stderr

def _planned_and_executed(tmp_path):
    f = tmp_path / "eligible.txt"; f.write_text("\n".join(f"p{i:03d}" for i in range(20)) + "\n"); c = tmp_path / "plan.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T03:00:00Z", "--purpose", "test:receipt", "--decision-id", "REG-1/protocol-2/sample-1", "--sample", "5", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--no-anchors", "--transcript", str(tmp_path / "t.json"), cwd=str(tmp_path)); assert rc == 0, e
    return f, c, tmp_path / "t.json"

def test_40_receipt_is_regenerated_from_verified_facts(tmp_path):
    f, c, t = _planned_and_executed(tmp_path)
    rc, o, e = nb("receipt", str(c), "--transcript", str(t), "--no-anchors", "--out", str(tmp_path / "r.md"), cwd=str(tmp_path)); assert rc == 2 and "receipt verdict: DEGRADED" in e, e   # dry run: tokens + registration missing -> DEGRADED, never VERIFIED (R5)
    md = open(tmp_path / "r.md").read(); assert "verification: DEGRADED" in md and "Treat this as a dry run" in md
    for must in ("# NotBefore decision receipt — REG-1/protocol-2/sample-1", "EXECUTED", "Key id `", "Decision id `REG-1/protocol-2/sample-1`", "commit **42**", "Commit-bound value", "sample of k = 5 from 20 records", "Commit re-verified", "## Verification trail", "derived seed recomputes"):
        assert must in md, must
    assert "[DEGRADED]" in md and ("registration not confirmed" in md or "decision log now" in md)          # honest about what it does not have
    # a commitment-only receipt (not executed yet) says so and exits 0
    c2 = tmp_path / "plan2.json"; rc, o, e = nb("plan", "--after", "2030-01-01T00:00Z", "--purpose", "test:future", "--sample", "2", "--out", str(c2), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0
    rc, o, e = nb("receipt", str(c2), cwd=str(tmp_path)); assert rc == 2 and "COMMITTED, not yet executed" in o and "Not yet" in o, e
    # a transcript for a different contract is refused as a receipt input
    rc, o, e = nb("receipt", str(c2), "--transcript", str(t), cwd=str(tmp_path)); assert rc == 1 and "DIFFERENT contract" in o + e

def test_41_bundle_roundtrip_and_tamper(tmp_path):
    f, c, t = _planned_and_executed(tmp_path)
    z = tmp_path / "b.zip"; rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(z), "--no-anchors", cwd=str(tmp_path)); assert rc == 2 and "DEGRADED" in e, e
    names = set(zipfile.ZipFile(z).namelist())
    tj = json.load(open(t)); n = tj["commit_seq"]
    for must in ("MANIFEST.json", "README.md", "contract/plan.json", "contract/plan.json.sig.json", "transcript/t.json", f"log/chain/pulse-{n-1:04d}.json", f"log/chain/pulse-{n:04d}.json", f"log/chain/pulse-{n+1:04d}.json", "log/checkpoint", "log/inclusion.json", "verifier/keys/decisions.pub", "verifier/keys/tsa/PINS.json", "verifier/VENDORED.json"):
        assert must in names, must
    assert not any(n_.startswith("input/") or n_.startswith("output/") for n_ in names)          # sensitive files stay out by default
    man = json.loads(zipfile.ZipFile(z).read("MANIFEST.json")); assert man["bundle"] == "notbefore/bundle/1" and man["commit_seq"] == n and man["key_id"] and man["decision_id"] == "REG-1/protocol-2/sample-1"
    rc, o, e = nb("check-bundle", str(z), cwd=str(tmp_path)); assert rc == 2 and "BUNDLE DEGRADED" in e, e            # a degraded execution cannot become VERIFIED by bundling it (R5)
    for must in ("files match the manifest", "decision statement by", "bound to this contract", "pulse_hash == SHA-256(canonical core)", "vendored verify.py offline", "derived seed recomputes", "is included in that checkpoint", "2 RFC 3161 token(s) verify against the pinned roots", "commit-bound value V* recomputes", "Rekor's SIGNED entry time", "operation, parameters, purpose and input hash are the signed contract's"):
        assert must in e, must
    # tamper inside the zip: edit the transcript's attested value -> manifest + binding fail
    d = tmp_path / "unz"; zipfile.ZipFile(z).extractall(d)
    tp = d / "transcript" / "t.json"; tj = json.load(open(tp)); tj["attested_value"] = "00" + tj["attested_value"][2:]; json.dump(tj, open(tp, "w"))
    rc, o, e = nb("check-bundle", str(d), cwd=str(tmp_path)); assert rc == 1 and "altered since the bundle was written" in e and "transcript/t.json" in e, e
    # the manifest is not the defence: rebuild it after each forgery and the AUTHENTICATION must still fail (R3, R4)
    def rebuild(dd):
        mp = dd / "MANIFEST.json"; man = json.load(open(mp)); man["files"] = {rel: hashlib.sha256(open(dd / rel, "rb").read()).hexdigest() for rel in man["files"]}; json.dump(man, open(mp, "w"))
    rebuild(d); rc, o, e = nb("check-bundle", str(d), cwd=str(tmp_path)); assert rc == 1 and "does NOT recompute" in e or "do NOT match" in e or "INVALID" in e, e     # attested value edited: V*/seed chain breaks
    d2 = tmp_path / "unz2"; zipfile.ZipFile(z).extractall(d2); n = json.load(open(d2 / "transcript" / "t.json"))["commit_seq"]
    ar = d2 / "log" / "anchors" / f"pulse-{n:04d}.anchor.json"; rec = json.load(open(ar)); rec["rekor"]["integratedTime"] = rec["rekor"]["entry"]["integratedTime"] - 1; rec["signature_b64"] = "AA" + rec["signature_b64"][2:]; json.dump(rec, open(ar, "w")); rebuild(d2)
    rc, o, e = nb("check-bundle", str(d2), cwd=str(tmp_path)); assert rc == 1 and "BUNDLE INVALID" in e, e           # forged anchor record (R3)
    d3 = tmp_path / "unz3"; zipfile.ZipFile(z).extractall(d3); tp3 = d3 / "transcript" / "t.json"; tj = json.load(open(tp3)); tj["k"] = 999; tj["record_count"] = 999; tj["output_sha256"] = "0" * 64; json.dump(tj, open(tp3, "w")); rebuild(d3)
    rc, o, e = nb("check-bundle", str(d3), cwd=str(tmp_path)); assert rc == 1 and "do NOT match the signed contract" in e, e   # mutated result claims (R4)
    # a bundle directory with --include-input carries the committed bytes, and their hash is checked
    dd = tmp_path / "bdir"; rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(dd), "--include-input", "--no-anchors", cwd=str(tmp_path)); assert rc == 2, e   # still a dry run -> DEGRADED
    assert (dd / "input" / "eligible.txt").read_bytes() == f.read_bytes()
    rc, o, e = nb("check-bundle", str(dd), cwd=str(tmp_path)); assert rc == 2 and "re-run on the bundled input reproduces the transcript's output" in e, e   # R4: with the input, the result is re-executed
    (dd / "input" / "eligible.txt").write_text("not the roster\n"); rebuild(dd) if False else None
    mp = dd / "MANIFEST.json"; man = json.load(open(mp)); man["files"] = {rel: hashlib.sha256(open(dd / rel, "rb").read()).hexdigest() for rel in man["files"]}; json.dump(man, open(mp, "w"))
    rc, o, e = nb("check-bundle", str(dd), cwd=str(tmp_path)); assert rc == 1 and "does NOT hash to the contract's input" in e, e
    rc, o, e = nb("bundle", str(c), "--transcript", str(t), "--out", str(tmp_path / "bdir"), cwd=str(tmp_path)); assert rc == 2 and "not empty" in e   # never overwrites a bundle

def test_42_commit_bound_bundle_roundtrip(tmp_path):
    """contract/3 bundles carry the commit, its drand round and the publication evidence; check-bundle recomputes V*."""
    f = tmp_path / "r.txt"; f.write_text("a\nb\nc\nd\ne\nf\n"); c = tmp_path / "plan.json"
    rc, o, e = nb("plan", "--after", "2026-09-12T13:00:00Z", "--purpose", "test:cbbundle", "--sample", "2", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    rc, o, e = nb("execute", str(c), "--input", str(f), "--allow-unregistered", "--transcript", str(tmp_path / "t.json"), cwd=str(tmp_path)); assert rc == 0, e
    t = json.load(open(tmp_path / "t.json")); assert t["value_rule"] == "commit-bound"
    rc, o, e = nb("receipt", str(c), "--transcript", str(tmp_path / "t.json"), "--out", str(tmp_path / "r.md"), cwd=str(tmp_path)); assert rc == 2, e
    md = open(tmp_path / "r.md").read(); assert "Commit-bound value" in md and "Provenance **FULL-ATTESTED**" in md and "Rekor-logged" in md and "V*" in md
    z = tmp_path / "b.zip"; rc, o, e = nb("bundle", str(c), "--transcript", str(tmp_path / "t.json"), "--out", str(z), cwd=str(tmp_path)); assert rc == 2, e
    names = set(zipfile.ZipFile(z).namelist()); n = t["commit_seq"]
    for must in (f"log/chain/pulse-{n:04d}.json", f"log/chain/pulse-{n+1:04d}.json", f"log/anchors/pulse-{n:04d}.anchor.json", "log/inclusion.json"): assert must in names, must
    rc, o, e = nb("check-bundle", str(z), cwd=str(tmp_path)); assert rc == 2 and "BUNDLE DEGRADED" in e, e
    for must in ("BLS-verifies under the pinned quicknet key (offline)", "commit-bound value V* recomputes", "Rekor's SIGNED entry time", "FULL-ATTESTED", f"commit {n:04d}: vendored verify.py offline", f"pulse {n:04d} is included in that checkpoint"): assert must in e, must

def test_43_contract2_receipt_requires_its_signature(tmp_path):
    """R6: a contract/2 without its .sig.json is a broken signed contract, not a legacy unsigned one; `register` accepts contract/2."""
    import notbefore.contract as C, json as _j
    f = tmp_path / "r.txt"; f.write_text("a\nb\nc\n"); c = tmp_path / "plan.json"
    rc, o, e = nb("plan", "--after", "2030-01-01T00:00Z", "--purpose", "test:c2", "--sample", "1", "--out", str(c), "--no-timestamp", "--no-log", str(f), cwd=str(tmp_path)); assert rc == 0, e
    j = _j.load(open(c)); j["spec"] = "notbefore/contract/2"; j.pop("value"); j["selection"]["rule"] = C.RULE; C.write(j, str(c)); os.remove(str(c) + ".sig.json")
    rc, o, e = nb("receipt", str(c), cwd=str(tmp_path)); assert rc == 1 and "no .sig.json" in e, e
    rc, o, e = nb("register", str(c), cwd=str(tmp_path)); assert rc != 0 and "only signed contract/2" not in e, e
