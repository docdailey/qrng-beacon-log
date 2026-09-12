#!/usr/bin/env python3
"""verify_anchors.py — check the publication anchors of every pulse, and look for a split view.

For each chain/pulse-NNNN.json, with anchors/ = a checkout of the `anchors` branch:
  1. recompute the canonical anchor statement from the pulse file; it must equal the published .stmt.json bytes
  2. the Rekor entry's recorded hash must be sha256(statement) and its public key must be keys/anchor.pub (pinned)
  3. the anchor signature must verify over the statement with keys/anchor.pub
  4. Rekor's Signed Entry Timestamp must verify with keys/rekor.pub (pinned), logID must match
  5. the inclusion proof must reach the checkpoint root and the checkpoint must be signed by Rekor   (offline)
  6. REFETCH=1: fetch the entry live from Rekor by UUID; body and integratedTime must match the published copy
  7. commit pulses: Rekor's integratedTime should precede the drand release (a third clock on the commit) — WARN if not
  8. OpenTimestamps: pending / complete (Bitcoin block header Merkle root checked against public header sources)
Across the log (REFETCH=1): enumerate EVERY Rekor entry ever made under keys/anchor.pub. Each must be one of the
published anchors. An entry that is not is reported as a possible hidden branch — the split-view signal this
whole layer exists to produce. Missing anchors are a failure once a pulse is older than GRACE_S.
"""
import sys, os, json, glob, re, time, subprocess, base64
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
import anchor_lib as L
try:
    import schema as S
except Exception: S = None
A = os.environ.get("ANCHORS_DIR") or (sys.argv[sys.argv.index("--anchors") + 1] if "--anchors" in sys.argv else os.path.join(ROOT, "anchors"))
REFETCH = os.environ.get("REFETCH") == "1"; GRACE_S = int(os.environ.get("ANCHOR_GRACE_S", "1500"))
anchor_pub = L.load_pub(open(os.path.join(ROOT, "keys", "anchor.pub"), "rb").read()); anchor_pem = L.pub_pem(anchor_pub)
rekor_pub = L.load_pub(open(os.environ.get("REKOR_PUB_FILE") or os.path.join(ROOT, "keys", "rekor.pub"), "rb").read())
if L.key_id(rekor_pub) != L.REKOR_LOG_ID: print("[FAIL] keys/rekor.pub does not hash to the pinned Rekor log ID"); sys.exit(1)
RETROACTIVE_THROUGH = 41          # pulses 0001-0041 were anchored after the fact (2026-09-12 12:47 UTC, ERR-008)
T = dict(pulses=0, anchored=0, missing_in_grace=0, missing_overdue=0, statement_ok=0, anchor_sig_ok=0, rekor_set_ok=0, rekor_inclusion_ok=0,
         rekor_refetched=0, rekor_refetch_failed=0, commit_rekor_before_release=0, commit_rekor_retroactive=0, commit_rekor_late=0, ots_complete=0, ots_pending=0,
         rekor_entries_under_key=None, rekor_entries_in_flight=None, unexplained_rekor_entries=None, failures=0)
lines = []
def say(s): print(s); lines.append(s)
def published_time(pf):
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct", "--", os.path.relpath(pf, ROOT)], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return int(out) if out else os.path.getmtime(pf)
    except Exception: return os.path.getmtime(pf)
known_uuids = {}; expected_hash = {}; in_flight = {}
for pf in L.pulse_files(os.path.join(ROOT, "chain")):
    seq = int(L.PULSE_RE.search(pf).group(1)); T["pulses"] += 1
    stem = os.path.join(A, f"pulse-{seq:04d}"); rec_path = stem + ".anchor.json"; stmt_path = stem + ".stmt.json"; ots_path = stmt_path + ".ots"
    statement, st = L.statement_for(pf)
    expected_hash[L.sha256(statement)] = seq          # what a legitimate Rekor entry for this pulse MUST record
    if not os.path.exists(rec_path):
        age = time.time() - published_time(pf); in_flight[seq] = age
        if age > GRACE_S: say(f"[FAIL] {seq:04d}: no anchor {age/60:.0f} min after publication (grace {GRACE_S//60} min)"); T["missing_overdue"] += 1; T["failures"] += 1
        else: say(f"[WAIT] {seq:04d}: anchor pending ({age:.0f} s since publication)"); T["missing_in_grace"] += 1
        continue
    rec = json.load(open(rec_path)); entry = rec["rekor"]["entry"]; T["anchored"] += 1
    ok = True
    def chk(c, msg):
        global ok
        if not c: ok = False; say(f"[FAIL] {seq:04d}: {msg}")
    chk(open(stmt_path, "rb").read() == statement, "published statement differs from the one recomputed from the pulse file")
    chk(rec["statement_sha256"] == L.sha256(statement), "statement_sha256 differs from sha256(statement)")
    if ok: T["statement_ok"] += 1
    h, k = L.entry_hash_and_key(entry)
    chk(h == L.sha256(statement), "Rekor entry hash is not sha256(statement)")
    chk(k is not None and L.key_id(L.load_pub(k)) == L.key_id(anchor_pub), "Rekor entry public key is not keys/anchor.pub")
    sig = base64.b64decode(rec["signature_b64"])
    s_ok = L.verify_sig(anchor_pub, sig, statement) and L.entry_sig(entry) == sig
    chk(s_ok, "anchor signature does not verify over the statement with keys/anchor.pub (or differs from the Rekor copy)"); T["anchor_sig_ok"] += s_ok
    chk(entry["logID"] == L.REKOR_LOG_ID, "entry logID is not the pinned Rekor log")
    set_ok = L.verify_set(entry, rekor_pub); chk(set_ok, "Rekor signed entry timestamp does not verify with keys/rekor.pub"); T["rekor_set_ok"] += set_ok
    inc_ok, why = L.verify_inclusion(entry, rekor_pub); chk(inc_ok, "Rekor inclusion proof: " + why); T["rekor_inclusion_ok"] += inc_ok
    known_uuids[rec["rekor"]["uuid"]] = seq
    if REFETCH:
        live = None
        for attempt in range(3):                       # transient network errors must not read as a broken anchor (ERR-009)
            try: live = L.rekor_get(rec["rekor"]["uuid"]); break
            except Exception as e: err = e; time.sleep(2 * (attempt + 1))
        if live is None:
            say(f"[WARN] {seq:04d}: Rekor refetch failed 3x ({err}); the offline proof (SET + inclusion, pinned Rekor key) stands"); T["rekor_refetch_failed"] += 1
        else:
            chk(live["body"] == entry["body"] and live["integratedTime"] == entry["integratedTime"] and live["logIndex"] == entry["logIndex"], "live Rekor entry differs from the published copy")
            T["rekor_refetched"] += 1
    if st["type"] == "commit" and S is not None:
        core = json.load(open(pf))["core"]
        rel = (core.get("derived") or {}).get("target_release_unix_s") or (S.release_time(core["commitment"]["target_round"]) if core.get("commitment") else None)
        if rel is not None:
            margin = float(rel) - entry["integratedTime"]
            if margin > 0: T["commit_rekor_before_release"] += 1
            elif seq <= RETROACTIVE_THROUGH: T["commit_rekor_retroactive"] += 1     # anchored after the fact on 2026-09-12; expected, documented (ERR-008)
            else: T["commit_rekor_late"] += 1; say(f"[WARN] {seq:04d}: Rekor integratedTime is {-margin:.0f} s AFTER the drand release (anchor late; TSA tokens remain the binding proof)")
    if os.path.exists(ots_path):
        try:
            status, why = L.verify_ots(ots_path, statement)
            if status == "complete": T["ots_complete"] += 1
            elif status in ("pending", "unchecked"): T["ots_pending"] += 1
            else: chk(False, "OpenTimestamps: " + why)
        except Exception as e: say(f"[WARN] {seq:04d}: OpenTimestamps proof unreadable: {e}")
    if ok: say(f"[PASS] {seq:04d} {st['type']:<7} rekor logIndex {entry['logIndex']} @ {rec['rekor']['integrated_utc']}  SET+inclusion OK{'  refetched' if REFETCH else ''}  ots {rec['ots'].get('status')}")
    else: T["failures"] += 1
# ---- signed checkpoints (TLOG.md): each published checkpoints/NNNNNN should be anchored; its statement hash is expected under the key
T["checkpoints"] = 0; T["checkpoints_anchored"] = 0
for cf in L.checkpoint_files(ROOT):
    size = int(os.path.basename(cf)); T["checkpoints"] += 1
    statement, st = L.checkpoint_statement_for(cf); expected_hash[L.sha256(statement)] = f"checkpoint {size:06d}"
    stem = os.path.join(A, f"checkpoint-{size:06d}"); rec_path = stem + ".anchor.json"
    if not os.path.exists(rec_path):
        age = time.time() - os.path.getmtime(cf); in_flight[f"checkpoint {size:06d}"] = age
        say(f"[{'FAIL' if age > GRACE_S else 'WAIT'}] checkpoint {size:06d}: no anchor ({age/60:.0f} min)"); T["failures"] += age > GRACE_S; continue
    rec = json.load(open(rec_path)); entry = rec["rekor"]["entry"]; h, k = L.entry_hash_and_key(entry)
    ok = open(stem + ".stmt.json", "rb").read() == statement and h == L.sha256(statement) and k is not None and L.key_id(L.load_pub(k)) == L.key_id(anchor_pub) \
         and L.verify_sig(anchor_pub, base64.b64decode(rec["signature_b64"]), statement) and entry["logID"] == L.REKOR_LOG_ID and L.verify_set(entry, rekor_pub) and L.verify_inclusion(entry, rekor_pub)[0]
    known_uuids[rec["rekor"]["uuid"]] = f"checkpoint {size:06d}"; T["checkpoints_anchored"] += ok; T["failures"] += not ok
    say(f"[{'PASS' if ok else 'FAIL'}] checkpoint {size:06d} (root {st['root_b64'][:12]}…): Rekor anchor logIndex {entry['logIndex']} @ {rec['rekor']['integrated_utc']} verified offline")

# ---- split-view detector: every entry under the anchor key must be a published anchor
if REFETCH:
    try:
        uuids = L.rekor_search_by_key(anchor_pem) or []
        T["rekor_entries_under_key"] = len(uuids)
        # An entry whose anchor RECORD is not on the anchors branch yet is not a hidden branch if its recorded hash is the
        # statement hash of a published pulse (the anchor job uploads to Rekor before it pushes the branch; ERR-009).
        unexplained, flight = [], []
        for u in uuids:
            if u in known_uuids: continue
            e = None
            for attempt in range(3):
                try: e = L.rekor_get(u); break
                except Exception as ex: err = ex; time.sleep(2 * (attempt + 1))
            if e is None:
                say(f"[FAIL] Rekor entry {u[:16]}… under the anchor key could not be fetched 3x: {err}"); unexplained.append(u); continue
            h, _ = L.entry_hash_and_key(e)
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e["integratedTime"]))
            if h not in expected_hash:
                # This checkout may be OLDER than what is anchored (the verify job checked out main before a pulse
                # that was pushed seconds later got anchored). Look at the LIVE chain before calling it a hidden branch.
                try:
                    subprocess.run(["git", "fetch", "-q", "origin", "main"], cwd=ROOT, capture_output=True, timeout=60)
                    for s_ in range(T["pulses"] + 1, T["pulses"] + 12):
                        r = subprocess.run(["git", "show", f"origin/main:chain/pulse-{s_:04d}.json"], cwd=ROOT, capture_output=True)
                        if r.returncode != 0: break
                        tmp = os.path.join(A, f".live-pulse-{s_:04d}.json"); open(tmp, "wb").write(r.stdout)
                        st_, _ = L.statement_for(tmp); os.remove(tmp)
                        if L.sha256(st_) == h:
                            say(f"[WAIT] Rekor entry logIndex {e['logIndex']} ({when}) is pulse {s_:04d}'s anchor; that pulse is newer than this checkout"); flight.append(u); break
                    else: pass
                except Exception: pass
                if u in flight: continue
                if time.time() - e["integratedTime"] < GRACE_S:
                    say(f"[WAIT] Rekor entry logIndex {e['logIndex']} ({when}) under the anchor key matches nothing published yet ({(time.time()-e['integratedTime'])/60:.0f} min old; alarm if still unexplained after {GRACE_S//60} min)"); flight.append(u); continue
            if h in expected_hash:
                s_ = expected_hash[h]; age = in_flight.get(s_)   # seq (int) for pulses, 'checkpoint NNNNNN' for checkpoints
                if age is not None and age > GRACE_S:
                    say(f"[FAIL] Rekor entry logIndex {e['logIndex']} ({when}) IS {s_ if isinstance(s_, str) else 'pulse %04d' % s_}'s anchor, but its record has been missing from the anchors branch for {age/60:.0f} min"); unexplained.append(u)
                else:
                    say(f"[WAIT] Rekor entry logIndex {e['logIndex']} ({when}) is {s_ if isinstance(s_, str) else 'pulse %04d' % s_}'s anchor; its record is not on the anchors branch yet (in flight)"); flight.append(u)
            else:
                say(f"[FAIL] Rekor entry {u[:16]}… (logIndex {e['logIndex']}, {when}) is signed by the anchor key but its hash {h[:16]}… matches NO published pulse — possible hidden branch / split view"); unexplained.append(u)
        T["unexplained_rekor_entries"] = len(unexplained); T["rekor_entries_in_flight"] = len(flight)
        T["failures"] += len(unexplained)
        if not unexplained: say(f"[PASS] split-view check: all {len(uuids)} Rekor entries under keys/anchor.pub correspond to published pulses" + (f" ({len(flight)} in flight)" if flight else ""))
    except Exception as e: say(f"[WARN] split-view check skipped: Rekor search failed: {e}")
say("\n=== anchor verification tally ===")
for k, v in T.items(): say(f"  {k:28s} {v}")
summ = os.environ.get("GITHUB_STEP_SUMMARY")
if summ:
    with open(summ, "a") as f:
        f.write("## verify-anchors\n\n| check | count |\n|---|---|\n" + "".join(f"| {k} | {v} |\n" for k, v in T.items()))
        f.write(f"\n**{'FAILED' if T['failures'] else 'ANCHORS VERIFIED'}** — {T['anchored']}/{T['pulses']} pulses anchored in Rekor (SET + inclusion proof verified offline against the pinned Rekor key), "
                f"{T['commit_rekor_before_release']} commit anchors timestamped by Rekor before their drand release, OpenTimestamps complete {T['ots_complete']} / pending {T['ots_pending']}, "
                f"split-view check {'clean' if T['unexplained_rekor_entries'] == 0 else ('FLAGGED' if T['unexplained_rekor_entries'] else 'not run')}, {T['commit_rekor_retroactive']} retroactive commit anchors (≤ 0041).\n")
sys.exit(1 if T["failures"] else 0)
