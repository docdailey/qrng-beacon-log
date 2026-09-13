"""commitbound.py — the commit-bound value V* (PROTOCOL.md §"Commit-bound value"; NOTBEFORE.md §4.6, §7.13; FALLBACK.md).

    V* = SHA256( "notbefore/commit-bound/v1" || C || rho_R || chain_hash || R_be8 )        (25 + 32 + 32 + 32 + 8 = 129 bytes)

  C          the commit pulse's derived.entropy_commitment  (= SHA256(D_commit || E), published BEFORE round R existed)
  rho_R      drand quicknet randomness for round R (= SHA256(BLS signature)), BLS-verified under the pinned group key
  chain_hash the commit's chain_hash (the pinned quicknet chain)
  R_be8      the commit's target_round, 8-byte big-endian

V* is fixed the instant round R exists, by data the operator committed to before rho_R was knowable and data nobody
here controls. Nothing the operator does afterwards — reveal, fail, withhold, go offline — changes it. The reveal of E
keeps its job as PROVENANCE (it proves C committed to genuine QRNG bytes and lets the beacon's own attested value V be
recomputed); it is no longer the thing a decision depends on. Labels:
    FULL-ATTESTED         the reveal verifies: provenance shown, V recomputed
    COMMITMENT-FALLBACK   no verifying reveal by the deadline: V* stands, provenance not demonstrated

Commit ELIGIBILITY for a contract/3 selection rule ("first-eligible-commit-released-at-or-after"): protocol v0.5,
seq >= FIRST_ELIGIBLE_COMMIT, not KNOWN-NONCOMPLIANT, the vendored verifier passes on the commit (host signatures,
chain link), both RFC 3161 tokens verify with the LATEST strictly before the round release, AND third-party evidence
that the commit was PUBLIC before the round: its Rekor anchor's integratedTime < release. That last condition is what
makes eligibility a pre-round, irrevocable fact: an operator who has not anchored a commit before its round cannot
make it eligible afterwards, and one who has cannot make it ineligible — so no choice made with knowledge of rho_R can
steer which commit a contract consumes. Withholding publication BEFORE the round is blind (no bias) and visible."""
import os, sys, json, hashlib, time, base64
from . import FIRST_ELIGIBLE_REVEAL
from .check import VENDOR, KEYS, CheckResult, check_pair, check_commit, known_noncompliant
sys.path.insert(0, VENDOR)

DOMAIN = b"notbefore/commit-bound/v1"
RULE = "first-eligible-commit-released-at-or-after"
FIRST_ELIGIBLE_COMMIT = FIRST_ELIGIBLE_REVEAL - 1          # 0020
REVEAL_DEADLINE_S = 600                                    # CADENCE/PROTOCOL: a reveal must be published within 600 s of the round

def value(C_hex: str, rho_hex: str, chain_hex: str, R: int) -> str:
    buf = DOMAIN + bytes.fromhex(C_hex) + bytes.fromhex(rho_hex) + bytes.fromhex(chain_hex) + int(R).to_bytes(8, "big")
    assert len(buf) == 129
    return hashlib.sha256(buf).hexdigest()

def verify_round(R: int, sig_hex: str, chain_hex: str):
    """BLS-verify a drand signature for round R under the pinned quicknet key (offline). -> (ok, rho_hex or why)."""
    import bls_drand
    ok, why = bls_drand.verify_pinned(int(R), sig_hex, chain_hex)
    return (True, hashlib.sha256(bytes.fromhex(sig_hex)).hexdigest()) if ok else (False, why)

def fetch_round(R: int):
    """Fetch round R from the League of Entropy relays (drand_anchor.ENDPOINTS). -> dict with signature/randomness."""
    import drand_anchor
    return drand_anchor.fetch(int(R))

ANCHOR_GRACE_S = 1500

def rekor_direct(src, seq):
    """Ask Rekor itself (append-only, not operator-controlled) for anchor entries of this commit: the statement is derived
    from the pulse bytes, its hash indexes Rekor, every returned entry is checked under the pinned anchor + Rekor keys (SET,
    inclusion). Returns (status, facts): status in {found, none, error}; facts = earliest valid entry (signed integratedTime)."""
    import anchor_lib as L
    try:
        pf = src.materialize(seq); statement, _ = L.statement_for(pf)
        anchor_pub = L.load_pub(open(os.path.join(KEYS, "anchor.pub"), "rb").read()); rekor_pub = L.load_pub(open(os.path.join(KEYS, "rekor.pub"), "rb").read())
        uuids = L.rekor_search_by_hash(L.sha256(statement)) or []
        best = None
        for u in uuids:
            try:
                e = L.rekor_get(u); h, k = L.entry_hash_and_key(e)
                if h != L.sha256(statement) or k is None or L.key_id(L.load_pub(k)) != L.key_id(anchor_pub): continue
                if e.get("logID") != L.REKOR_LOG_ID or not L.verify_set(e, rekor_pub) or not L.verify_inclusion(e, rekor_pub)[0]: continue
                if best is None or int(e["integratedTime"]) < best["integratedTime"]: best = {"ok": True, "integratedTime": int(e["integratedTime"]), "logIndex": int(e["logIndex"]), "uuid": u, "source": "rekor-live"}
            except Exception: continue
        return ("found", best) if best else ("none", None)
    except Exception as e: return "error", {"why": f"{type(e).__name__}: {str(e)[:100]}"}

def publication_evidence(src, seq, release_unix, Rc, online, now=None):
    """Was the commit PUBLIC before its round, by a clock the operator does not run? Evidence, in order of authority:
      1. Rekor itself (online): entries found by the statement hash, verified under the pinned keys; the earliest signed
         integratedTime decides. None found after the anchor grace period -> proved absent (ineligible); before it -> WAIT.
      2. A local anchor record (anchors branch / bundle) whose signed entry verified in check_commit (R.anchor_facts).
    Absence of a LOCAL record is never proof of anything: the anchors branch is operator-controlled and editable after the
    round (R2). -> (verdict, dict) with verdict in {eligible, ineligible, wait, unavailable}."""
    now = now or time.time(); rel = int(release_unix); facts = None
    if online:
        st, f = rekor_direct(src, seq)
        if st == "found": facts = f
        elif st == "none":
            if now - rel < ANCHOR_GRACE_S: return "wait", {"kind": "rekor", "present": False, "why": f"Rekor has no anchor for this commit yet and its round released {int(now - rel)} s ago (grace {ANCHOR_GRACE_S} s): cannot decide"}
            return "ineligible", {"kind": "rekor", "present": False, "why": "Rekor holds no anchor for this commit (queried directly by statement hash): it was never anchored, so pre-round publication is not established"}
        else:
            lf = (Rc.anchor_facts or {}).get(seq)
            if lf and lf.get("ok"): facts = lf                                    # Rekor unreachable, but a signed record is at hand
            else: return "unavailable", {"kind": "rekor", "present": False, "why": f"Rekor not reachable ({f.get('why')}) and no verified local anchor record: cannot establish publication"}
    else:
        lf = (Rc.anchor_facts or {}).get(seq)
        if not (lf and lf.get("ok")): return "unavailable", {"kind": "rekor", "present": False, "why": "offline and no verified anchor record for this commit in this log source: cannot establish publication (run online, or supply the anchors branch)"}
        facts = lf
    it = int(facts["integratedTime"]); ok = it < rel
    d = {"kind": "rekor", "present": True, "source": facts.get("source"), "logIndex": facts["logIndex"], "uuid": facts.get("uuid"), "integrated_unix": it,
         "integrated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(it)), "before_release_s": rel - it,
         "why": "Rekor logged this commit before its round released (signed entry time)" if ok else "Rekor logged this commit only AFTER its round released (signed entry time): not evidence of pre-round publication"}
    return ("eligible" if ok else "ineligible"), d

def select_commit(src, after_unix_s, refetch, anchors, R_lines, now=None):
    """The contract/3 rule. Walk pulses in seq order; the first COMMIT whose round released at/after `after` AND that is
    eligible (verifies, tokens before the round, Rekor-anchored before the round) is THE commit. Returns a dict or None:
      {seq, release_unix, Rc (CheckResult of the commit), reveal_seq, provenance, rho_hex, sig_hex, drand, attested_value, pub, wait_until}
    provenance in FULL-ATTESTED | COMMITMENT-FALLBACK | WAIT (reveal window still open and no reveal yet: come back later)."""
    now = now or time.time(); knc = known_noncompliant(); seq = FIRST_ELIGIBLE_COMMIT
    while src.has_pulse(seq):
        p = src.pulse(seq); c = p["core"]; typ = c.get("type")
        if typ == "commit" and c.get("v") == "0.5" and seq not in knc:
            rel = int(c["derived"]["target_release_unix_s"])
            if rel >= after_unix_s:
                Rc = check_commit(seq, src, refetch=refetch, anchors=True)
                halt = lambda why: (R_lines.append(f"[FAIL] commit {seq:04d}: {why} — refusing to advance past a candidate whose eligibility cannot be established (R2)"), {"seq": seq, "provenance": "ERROR", "halt": True})[1]
                if not Rc.ok:
                    # Advance only on PROVED ineligibility: the pulse bytes are authenticated by the log's signed checkpoint (tlog ok) and the
                    # pulse itself fails (host signatures / chain link / tokens). Anything else (unauthenticated copy, tree error) halts.
                    why = next((l[7:] for l in Rc.lines if l.startswith("[FAIL] ")), "verification failed")
                    if Rc.tlog == "ok" and not any(w in why for w in ("transparency", "checkpoint", "anchor", "SPLIT", "could not rebuild")):
                        R_lines.append(f"[INFO] commit {seq:04d} is authenticated by the checkpoint but not eligible ({why[:140]}) — passed over by rule"); seq += 1; continue
                    return halt(why[:160])
                if Rc.tsa_latest_unix is None: return halt("its RFC 3161 tokens are missing from this log source (they are part of the log): cannot establish")
                if not (Rc.tsa_latest_unix < rel): R_lines.append(f"[INFO] commit {seq:04d}: RFC 3161 tokens not strictly before its round — passed over by rule"); seq += 1; continue
                verdict, pub = publication_evidence(src, seq, rel, Rc, online=refetch, now=now)
                if verdict == "ineligible": R_lines.append(f"[INFO] commit {seq:04d}: {pub['why']} — passed over by rule"); seq += 1; continue
                if verdict == "wait": R_lines.append(f"[WAIT] commit {seq:04d}: {pub['why']}"); return {"seq": seq, "provenance": "WAIT", "wait_until": rel + ANCHOR_GRACE_S, "halt": False}
                if verdict == "unavailable": return halt(pub["why"])
                R_lines.append(f"[PASS] selected by rule '{RULE}': commit {seq:04d} (round {c['derived']['target_round']} released {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(rel))} >= after; verified; tokens {rel - Rc.tsa_latest_unix} s and Rekor {pub['before_release_s']} s before the round)")
                out = {"seq": seq, "release_unix": rel, "Rc": Rc, "target_round": int(c["derived"]["target_round"]), "C": c["derived"]["entropy_commitment"], "chain_hash": c["chain_hash"], "pub": pub,
                       "reveal_seq": None, "provenance": None, "rho_hex": None, "sig_hex": None, "attested_value": None, "Rr": None, "wait_until": None}
                # provenance: is there a verifying reveal?
                nxt = src.pulse(seq + 1) if src.has_pulse(seq + 1) else None
                if nxt and nxt["core"].get("type") == "reveal" and (nxt["core"].get("derived") or {}).get("commit_seq") == seq:
                    Rr = check_pair(seq + 1, src, refetch=refetch, anchors=anchors)
                    if Rr.ok:
                        da = nxt["core"]["drand"]; out.update(reveal_seq=seq + 1, provenance="FULL-ATTESTED", rho_hex=da["randomness"], sig_hex=da["signature"], attested_value=nxt["core"]["derived"]["attested_value"], Rr=Rr)
                        R_lines.append(f"[PASS] reveal {seq+1:04d} verifies: provenance FULL-ATTESTED (QRNG preimage revealed, V recomputed)")
                        return out
                    R_lines.append(f"[WARN] reveal {seq+1:04d} exists but does NOT verify — treated as no reveal")
                elif nxt: R_lines.append(f"[INFO] pulse {seq+1:04d} is a {nxt['core'].get('type')}: the operator did not reveal for commit {seq:04d}")
                if now < rel + REVEAL_DEADLINE_S and not (nxt and nxt["core"].get("type") in ("failure", "skip")):
                    out.update(provenance="WAIT", wait_until=rel + REVEAL_DEADLINE_S); R_lines.append(f"[WAIT] the reveal window for commit {seq:04d} is open until {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(rel + REVEAL_DEADLINE_S))}; V* is already fixed but the provenance label is not — run again then"); return out
                # COMMITMENT-FALLBACK: rho from drand itself, BLS-verified under the pinned key (never over the network when offline — R10)
                if not refetch:
                    R_lines.append(f"[FAIL] commit {seq:04d}: no verifying reveal and --offline: the drand round {out['target_round']} is needed to compute V* and cannot be fetched offline"); out.update(provenance="ERROR"); return out
                try:
                    rd = fetch_round(out["target_round"]); ok, rho = verify_round(out["target_round"], rd["signature"], out["chain_hash"])
                except Exception as e:
                    R_lines.append(f"[FAIL] commit {seq:04d}: cannot obtain drand round {out['target_round']} for the fallback ({type(e).__name__}: {str(e)[:80]}); offline needs the reveal"); out.update(provenance="ERROR"); return out
                if not ok: R_lines.append(f"[FAIL] drand round {out['target_round']}: BLS verification failed under the pinned quicknet key ({rho})"); out.update(provenance="ERROR"); return out
                out.update(provenance="COMMITMENT-FALLBACK", rho_hex=rho, sig_hex=rd["signature"])
                R_lines.append(f"[PASS] drand round {out['target_round']} fetched and BLS-verified under the pinned quicknet key; provenance COMMITMENT-FALLBACK (operator did not reveal — V* stands, QRNG provenance not demonstrated)")
                return out
        seq += 1
    return None
