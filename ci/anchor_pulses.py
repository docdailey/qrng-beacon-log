#!/usr/bin/env python3
"""anchor_pulses.py — enter every published pulse into Rekor and OpenTimestamps; write the `anchors` branch.

Runs in GitHub Actions (anchor.yml) after each chain push and hourly, or by an operator locally. Idempotent: pulses
that already have anchors/pulse-NNNN.anchor.json are skipped; pending OpenTimestamps proofs are upgraded in place.
Never touches `chain/` or `main`.

  ANCHOR_KEY   PEM private key (secret)            --anchors DIR  checkout of the `anchors` branch
  RUN_URL      (optional) provenance of this run    --only N      anchor one seq (testing)
Anchoring failure must never block minting: this tool is downstream of publication and reports its own tally.
"""
import sys, os, json, base64, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anchor_lib as L

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser(); ap.add_argument("--anchors", required=True); ap.add_argument("--only", type=int); ap.add_argument("--no-ots", action="store_true")
a = ap.parse_args()
A = a.anchors; os.makedirs(A, exist_ok=True)
pem = os.environ.get("ANCHOR_KEY") or (open(os.environ["ANCHOR_KEY_FILE"]).read() if os.environ.get("ANCHOR_KEY_FILE") else None)
if not pem: sys.exit("ANCHOR_KEY (PEM) or ANCHOR_KEY_FILE required")
priv = L.load_priv(pem.encode()); pub = priv.public_key(); pub_pem = L.pub_pem(pub)
pinned = open(os.path.join(ROOT, "keys", "anchor.pub"), "rb").read()
if L.key_id(L.load_pub(pinned)) != L.key_id(pub): sys.exit("ANCHOR_KEY does not match keys/anchor.pub — refusing to anchor with an unpublished key")
kid = L.key_id(pub)
T = dict(pulses=0, anchored_now=0, already=0, rekor_created=0, rekor_existing=0, ots_stamped=0, ots_upgraded=0, ots_pending=0, ots_complete=0, errors=0)
lines = []
def say(s): print(s, flush=True); lines.append(s)

for pf in L.pulse_files(os.path.join(ROOT, "chain")):
    seq = int(L.PULSE_RE.search(pf).group(1)); T["pulses"] += 1
    if a.only and seq != a.only: continue
    stem = os.path.join(A, f"pulse-{seq:04d}"); rec_path = stem + ".anchor.json"; stmt_path = stem + ".stmt.json"; ots_path = stmt_path + ".ots"
    statement, st = L.statement_for(pf)
    if os.path.exists(rec_path):
        T["already"] += 1
        if open(stmt_path, "rb").read() != statement: say(f"[FAIL] {seq:04d}: published statement differs from the pulse file — the chain file changed after anchoring"); T["errors"] += 1
    else:
        try:
            sig = L.sign(priv, statement)
            uuid, entry, how = L.rekor_upload(statement, sig, pub_pem)
            T["rekor_" + how] += 1
            rec = {"anchor": L.ANCHOR_VERSION, "seq": seq, "type": st["type"], "pulse_hash": st["pulse_hash"],
                   "statement_sha256": L.sha256(statement), "signature_b64": base64.b64encode(sig).decode(),
                   "anchor_key_id": kid, "anchor_key_file": "keys/anchor.pub",
                   "rekor": {"server": L.REKOR, "uuid": uuid, "logIndex": entry["logIndex"], "integratedTime": entry["integratedTime"],
                             "integrated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry["integratedTime"])),
                             "logID": entry["logID"], "entry": entry},
                   "ots": {"file": os.path.basename(ots_path), "status": "not stamped"},
                   "anchored_by": {"run_url": os.environ.get("RUN_URL"), "main_commit": os.environ.get("GITHUB_SHA"), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
            with open(stmt_path, "wb") as f: f.write(statement)
            if not a.no_ots:
                ok, msg = L.ots_stamp(stmt_path)
                rec["ots"]["status"] = "pending" if ok else "stamp failed"; T["ots_stamped"] += ok
                if not ok: say(f"[WARN] {seq:04d}: ots stamp failed: {msg}")
            json.dump(rec, open(rec_path, "w"), indent=1, sort_keys=True)
            T["anchored_now"] += 1
            say(f"[OK]   {seq:04d} {st['type']:<7} rekor {how} logIndex {entry['logIndex']} integratedTime {rec['rekor']['integrated_utc']}  ots {rec['ots']['status']}")
        except Exception as e:
            say(f"[FAIL] {seq:04d}: {type(e).__name__}: {e}"); T["errors"] += 1; continue
    # upgrade pending OTS proofs (calendar -> Bitcoin takes hours)
    if os.path.exists(rec_path) and os.path.exists(ots_path) and not a.no_ots:
        rec = json.load(open(rec_path))
        if rec["ots"].get("status") != "complete":
            before = L.ots_status(ots_path)
            status = L.ots_upgrade(ots_path) if before == "pending" else before
            if status == "complete" and rec["ots"].get("status") != "complete":
                atts, _ = L.ots_attestations(ots_path); h = [x[1] for x in atts if x[0] == "bitcoin"]
                rec["ots"].update({"status": "complete", "bitcoin_block_height": min(h) if h else None, "upgraded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
                json.dump(rec, open(rec_path, "w"), indent=1, sort_keys=True); T["ots_upgraded"] += 1
                say(f"[OK]   {seq:04d} ots upgraded: Bitcoin block {rec['ots']['bitcoin_block_height']}")
        T["ots_complete" if json.load(open(rec_path))["ots"].get("status") == "complete" else "ots_pending"] += 1

# INDEX.tsv — one line per anchored pulse, for humans and for grep
rows = []
for f in sorted(os.listdir(A)):
    if f.endswith(".anchor.json"):
        r = json.load(open(os.path.join(A, f)))
        rows.append("\t".join(str(x) for x in (r["seq"], r["type"], r["pulse_hash"], r["statement_sha256"], r["rekor"]["uuid"], r["rekor"]["logIndex"], r["rekor"]["integratedTime"], r["ots"].get("status"), r["ots"].get("bitcoin_block_height") or "")))
open(os.path.join(A, "INDEX.tsv"), "w").write("seq\ttype\tpulse_hash\tstatement_sha256\trekor_uuid\trekor_logIndex\trekor_integratedTime\tots_status\tbitcoin_block\n" + "\n".join(rows) + "\n")
say("\n=== anchor tally ===")
for k, v in T.items(): say(f"  {k:16s} {v}")
summ = os.environ.get("GITHUB_STEP_SUMMARY")
if summ:
    with open(summ, "a") as f: f.write("## anchor-pulses\n\n| item | count |\n|---|---|\n" + "".join(f"| {k} | {v} |\n" for k, v in T.items()))
sys.exit(1 if T["errors"] else 0)
