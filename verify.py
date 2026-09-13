#!/usr/bin/env python3
"""
verify.py — standalone verifier for attested randomness pulses (legacy, commit, reveal, failure, skip).

    pip install cryptography
    python3 verify.py <pulse.json | URL | -> [--prev <file|URL>] [--pin <keys dir|URL prefix>] [--refetch]

Checks, all offline unless --refetch:
  * pulse_hash == sha256(canonical(core)); every ed25519 signature verifies over the RECOMPUTED digest
  * commit:  target_round is strictly after the round current at commit time, and the GNSS anchor
             precedes the target round's release
  * reveal:  sha256(domain||entropy) == the predecessor commit's entropy_commitment;
             drand round == the committed target; randomness == sha256(signature);
             attested_value == documented mix; commit anchor < round release <= reveal anchor
  * --refetch: re-fetch the drand round from the League of Entropy and compare
  * BLS: if `py_ecc` is installed, verify the drand signature under the PINNED League of Entropy
         group key (keys/drand-quicknet.json) — removes the HTTP relay from the trust base.
         Runs automatically; --no-bls skips; a WARN is printed if py_ecc is absent.
  * --prev:  prev_hash chains, and a reveal's predecessor IS its commit
Exit 0 only if every check passed.
"""
import json, base64, hashlib, sys, os, urllib.request, datetime
try:
    import bls_drand
    BLS = bls_drand.available()
except Exception:
    bls_drand, BLS = None, False
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

COMMIT_DOMAIN = b"grok_antics/commit/v1"
QN_GENESIS, QN_PERIOD = 1692803367, 3
def release_time(rnd):                     # drand: round 1 is AT genesis
    return QN_GENESIS + (int(rnd) - 1) * QN_PERIOD
def published_release_check(label, published, rnd):
    """Use the COMPUTED release time for every ordering check; warn if the pulse's own field disagrees."""
    true = release_time(rnd)
    if published is not None and int(published) != true:
        print(f"[WARN] ERR-004: {label} publishes release {int(published)} but round {rnd} released at {true} "
              f"({int(published)-true:+d} s); ordering checks below use the computed value")
    return true
OK = True
def chk(cond, msg, detail=None):
    global OK
    print(f"[{'PASS' if cond else 'FAIL'}] {msg}")
    if not cond and detail: print("       " + detail)
    OK &= bool(cond)

def canonical(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def load(src):
    if src == "-": return json.load(sys.stdin)
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=20) as r: return json.loads(r.read().decode())
    return json.load(open(src))
_HIST = {}
def key_history(pin):
    if pin in _HIST: return _HIST[pin]
    src = f"{pin.rstrip('/')}/KEYS.json" if pin.startswith(("http://", "https://")) else os.path.join(pin, "KEYS.json")
    try: _HIST[pin] = load(src).get("keys", [])
    except Exception: _HIST[pin] = None
    return _HIST[pin]
def pin_check(pin, role, key_b64, seq):
    """True if the key is pinned for this role at this seq. Prefers KEYS.json (a history with validity
    windows); falls back to the single <role>.pub. Returns (ok, description)."""
    hist = key_history(pin)
    if hist is not None:
        for k in hist:
            if k["role"] == role and k["public_key_b64"] == key_b64:
                lo, hi = k.get("valid_from_seq") or 0, k.get("valid_to_seq")
                if lo <= seq and (hi is None or seq <= hi):
                    return True, f"KEYS.json: {role}@{k.get('host')} {k['key_id']} ({k.get('status')}, seq {lo}-{hi or 'now'})"
                return False, f"KEYS.json lists this {role} key but only for seq {lo}-{hi or 'now'}, not {seq}"
        return False, f"KEYS.json has no {role} entry for this key"
    src = f"{pin.rstrip('/')}/{role}.pub" if pin.startswith(("http://", "https://")) else os.path.join(pin, f"{role}.pub")
    try: return (load(src)["public_key_b64"] == key_b64), f"{role}.pub"
    except Exception: return None, f"no pin for {role}"
def utc(ts): return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()

NO_BLS = False
def verify_drand(da, refetch):
    sig, rnd = bytes.fromhex(da["signature"]), bytes.fromhex(da["randomness"])
    chk(hashlib.sha256(sig).digest() == rnd, f"drand randomness == sha256(signature) [offline] (round {da['round']}, {da.get('beacon_id')})")
    if NO_BLS:
        print("[SKIP] BLS verification disabled by --no-bls")
    elif not BLS:
        print("[WARN] BLS verification skipped: `pip install py_ecc` to verify the drand signature under the pinned group key")
    else:
        try:
            ok, why = bls_drand.verify_pinned(da["round"], da["signature"], da["chain_hash"])
        except Exception as e:
            ok, why = False, f"BLS verification error: {type(e).__name__}: {e}"
        chk(ok, f"drand round {da['round']} {why} [full BLS, offline]")
    if refetch:
        try:
            with urllib.request.urlopen(f"https://api.drand.sh/{da['chain_hash']}/public/{da['round']}", timeout=15) as r:
                live = json.loads(r.read().decode())
            chk(live["randomness"] == da["randomness"] and live["signature"] == da["signature"],
                f"drand round {da['round']} re-fetched live from the League of Entropy and matches")
        except Exception as e:
            print(f"[WARN] could not re-fetch drand round: {type(e).__name__}: {e}")

def legacy_main():
    a = sys.argv[1:]
    if not a: print(__doc__); return 2
    p = load(a[0]); core = p["core"]; typ = core.get("type", "legacy")
    pin = a[a.index("--pin") + 1] if "--pin" in a else None
    prev = load(a[a.index("--prev") + 1]) if "--prev" in a else None
    refetch = "--refetch" in a
    global NO_BLS; NO_BLS = "--no-bls" in a
    print(f"pulse seq {core['seq']}  type {typ}  version {core.get('version')}")

    # ---- integrity + signatures (all types) ----
    recomputed = hashlib.sha256(canonical(core)).hexdigest()
    chk(recomputed == p["pulse_hash"], "pulse_hash == sha256(canonical(core))",
        f"claimed {p['pulse_hash']}\n       recomputed {recomputed}")
    for name, s in p["signatures"].items():
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(s["public_key_b64"])).verify(base64.b64decode(s["sig_b64"]), bytes.fromhex(recomputed)); r = True
        except Exception: r = False
        chk(r, f"{name} signature by {s['signer']} (key {s['key_id']}) over the RECOMPUTED digest")
        if pin:
            ok, desc = pin_check(pin, s["role"], s["public_key_b64"], core["seq"])
            if ok is None: print(f"[WARN] {desc}")
            else: chk(ok, f"{name} key is pinned for seq {core['seq']} — {desc}")

    # ---- type-specific ----
    if typ == "commit":
        c = core["commitment"]; now = core["drand_at_commit"]
        verify_drand(now, refetch)
        chk(c["target_round"] > now["round"], f"target round {c['target_round']} is strictly after the round current at commit ({now['round']})")
        rel = published_release_check("commitment.target_release_unix_s", c.get("target_release_unix_s"), c["target_round"])
        chk(core["time"]["anchor"]["utc_unix_s"] < rel,
            f"GNSS anchor {core['time']['utc']} precedes target release {utc(rel)} (computed) by {rel - core['time']['anchor']['utc_unix_s']:.1f} s")
        chk(len(c["entropy_commitment"]) == 64, "entropy_commitment is a 32-byte digest")
        print(f"\nThis pulse fixes a value (by hash) that will be revealed after drand round {c['target_round']} "
              f"releases at {utc(c['target_release_unix_s'])}. It only means something if it was PUBLISHED before then.")
    elif typ == "reveal":
        rv = core["reveals"]; da = core["external_anchor"]
        E = bytes.fromhex(rv["entropy_hex"])
        chk(hashlib.sha256(E).hexdigest() == rv["entropy_sha256"], "revealed entropy digest matches")
        commit_ok = hashlib.sha256(COMMIT_DOMAIN + E).hexdigest() == rv["entropy_commitment"]
        chk(commit_ok, "sha256(domain||entropy) == the commitment published in the commit pulse")
        if prev is not None:
            chk(prev["pulse_hash"] == rv["commit_pulse_hash"] and prev["core"].get("type") == "commit", "predecessor pulse IS the referenced commit")
            pc = prev["core"]["commitment"]
            chk(pc["entropy_commitment"] == rv["entropy_commitment"], "commitment value matches the commit pulse")
            chk(pc["target_round"] == da["round"], f"drand round {da['round']} == committed target round {pc['target_round']}")
        rel = published_release_check("external_anchor.round_release_unix_s", da.get("round_release_unix_s"), da["round"])
        if prev is not None:
            chk(prev["core"]["time"]["anchor"]["utc_unix_s"] < rel,
                f"commit anchor {prev['core']['time']['utc']} precedes round release {utc(rel)} (computed) by {rel - prev['core']['time']['anchor']['utc_unix_s']:.1f} s")
        chk(core["time"]["anchor"]["utc_unix_s"] >= rel,
            f"reveal anchor is not before the round release (computed), {core['time']['anchor']['utc_unix_s'] - rel:.1f} s after")
        verify_drand(da, refetch)
        m = core["mix"]; buf = m["domain_tag"].encode() + E + bytes.fromhex(da["randomness"]) + bytes.fromhex(da["chain_hash"]) + int(da["round"]).to_bytes(8, "big")
        rec = hashlib.sha256(buf).hexdigest()
        chk(rec == core["attested_value"], f"attested_value == {m['algorithm']}", f"published {core['attested_value']}\n       recomputed {rec}")
        tl = core.get("timeline", {})
        print(f"\nAttested value {core['attested_value']}")
        cb = (rel - prev["core"]["time"]["anchor"]["utc_unix_s"]) if prev is not None else None
        print(f"Unknowable to anyone before {utc(rel)} (drand round {da['round']}, computed release); the entropy was "
              f"committed {cb if cb is not None else '?'} s before that round existed, so it could not have been chosen after. "
              f"Residual assumptions: the commit was PUBLISHED before the round (third-party TSA tokens prove the published "
              f"candidate existed; uniqueness of the public commitment depends on pre-round observation of the log).")
    else:
        da = core.get("external_anchor")
        if da:
            verify_drand(da, refetch)
            m = core.get("mix", {}); buf = m.get("domain_tag", "").encode() + bytes.fromhex(core["entropy"]["hex"]) + bytes.fromhex(da["randomness"]) + bytes.fromhex(da["chain_hash"]) + int(da["round"]).to_bytes(8, "big")
            chk(hashlib.sha256(buf).hexdigest() == core.get("attested_value"), "attested_value == documented mix")
            rel = published_release_check("external_anchor.round_release_unix_s", da.get("round_release_unix_s"), da["round"])
            print(f"\nLegacy single-phase pulse: not computable before {utc(rel)} (computed), but selection after that moment is NOT excluded.")
        else:
            print("\n[INFO] legacy pulse without external anchor: integrity + attestation only.")

    if prev is not None:
        chk(core["prev_hash"] == prev["pulse_hash"], f"chains to previous pulse (seq {prev['core']['seq']} -> {core['seq']})")
    elif core["prev_hash"] == "0" * 64:
        print("[INFO] genesis pulse")
    print("\n" + ("ALL CHECKS PASSED" if OK else "VERIFICATION FAILED"))
    return 0 if OK else 1

# =====================================================================================
# PROTOCOL v0.5 — strict path. Schema first (fail closed), then host statements, bindings, derived
# values, drand BLS, aggregator signature. Pulses <= v0.4 go to legacy_main() unchanged.
# =====================================================================================
import decimal, re, glob as _glob
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts"))
try:
    import attest_lib as A, schema as S
    V05 = True
except Exception as _e:
    V05 = False

def _D(x): return decimal.Decimal(str(x))
def _hex(s, n): return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)

def strict_main():
    a = sys.argv[1:]; src = a[0]
    p = load(src); core = p["core"]; typ = core.get("type")
    pin = a[a.index("--pin") + 1] if "--pin" in a else None
    prev = load(a[a.index("--prev") + 1]) if "--prev" in a else None
    refetch = "--refetch" in a; global NO_BLS; NO_BLS = "--no-bls" in a
    print(f"pulse seq {core.get('seq')}  type {typ}  v0.5 (strict)")

    # ---- 1. schema: everything below assumes these hold, so they fail closed first ----
    chk(typ in S.TYPES, f"type is one of {S.TYPES}")
    chk(isinstance(core.get("seq"), int) and core["seq"] >= 1, "seq is a positive integer")
    m = re.search(r"pulse-(\d{4})\.json$", src)
    if m: chk(int(m.group(1)) == core["seq"], "filename sequence matches core.seq")
    chk(_hex(core.get("prev_hash"), 64), "prev_hash is 64 hex")
    chk(core.get("chain_hash") == S.CHAIN_HASH, "chain_hash is the pinned quicknet chain")
    sts = core.get("statements", {})
    req = S.REQUIRED.get(typ, ())
    chk(all(k in sts for k in req), f"required statements present: {req}")
    chk(all(k in S.STATEMENTS for k in sts), "no unknown statements")
    chk(set(p.get("signatures", {}).keys()) == {"aggregator"}, "exactly one outer signature: aggregator")
    try:
        A.canon(core); chk(True, "core is in canonical form (no floats, no integers beyond 2^53)")
    except Exception as e:
        chk(False, "core is in canonical form", str(e))
    if not OK:
        print("\nVERIFICATION FAILED (schema)"); return 1

    d = core.get("derived", {})
    # ---- 2. each host statement: its OWN signature over its OWN canonical bytes, bound to this pulse ----
    def stmt_ok(name, expect_seq, expect_phase, expect_binding):
        role, host = S.STATEMENTS[name]; signed = sts[name]; st, sig = signed["statement"], signed["signature"]
        good = (st.get("v") == S.VERSION and st.get("role") == role and st.get("host") == host and st.get("chain_hash") == S.CHAIN_HASH)
        chk(good, f"{name}: statement is v0.5 {role}@{host} on the pinned chain")
        chk(st.get("seq") == expect_seq and st.get("phase") == expect_phase and st.get("binding") == expect_binding,
            f"{name}: bound to seq {expect_seq} / phase {expect_phase} / binding {str(expect_binding)[:16]}…",
            f"got seq {st.get('seq')} phase {st.get('phase')} binding {str(st.get('binding'))[:16]}")
        kid_ok = sig.get("alg") == "ed25519" and hashlib.sha256(base64.b64decode(sig["public_key_b64"])).hexdigest()[:16] == sig.get("key_id")
        chk(kid_ok, f"{name}: key_id == SHA256(public_key)[:16], alg ed25519")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key_b64"])).verify(base64.b64decode(sig["sig_b64"]), A.canon(st)); r = True
        except Exception: r = False
        chk(r, f"{name}: {host}'s signature verifies over canon(statement) — the host attested this itself")
        if core["seq"] >= S.ENFORCE_EXECUTION_FROM_SEQ:
            ok_e, why_e = S.execution_ok(st.get("execution"), host, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts", "EXPECTED.json"))
            chk(ok_e, f"{name}: execution self-report — {why_e}")
        elif st.get("execution"):
            print(f"[INFO] {name}: execution self-report present (enforced from seq {S.ENFORCE_EXECUTION_FROM_SEQ})")
        if pin:
            ok, desc = pin_check(pin, role, sig["public_key_b64"], core["seq"])
            if ok is None: print(f"[WARN] {desc}")
            else: chk(ok, f"{name}: key pinned for seq {core['seq']} — {desc}")
        return st

    def clock_health(st, name):
        """A REQUIRED clock statement must itself report a healthy clock. Signature alone is not enough (ERR-007)."""
        g = (st.get("measurement") or {}).get("epoch_guard") or {}
        sel = g.get("chrony_selects_refclock", g.get("chrony_selects_iphc"))
        chk(g.get("epoch_ok") is True and sel is True and not g.get("ALERT"),
            f"{name}: {st.get('host')} reports a healthy clock in its own statement (epoch_ok, hardware refclock selected, no alert)",
            f"epoch_ok={g.get('epoch_ok')} selects_refclock={sel} alert={g.get('ALERT')}")

    if typ == "commit":
        C, R = d.get("entropy_commitment"), d.get("target_round")
        chk(_hex(C, 64) and isinstance(R, int), "derived.entropy_commitment is 64 hex and target_round is an int")
        e = stmt_ok("entropy", core["seq"], "commit", C)
        chk(e.get("entropy_commitment") == C and e.get("target_round") == R, "entropy host's own commitment and target round match derived")
        chk("entropy_hex" not in e, "commit statement discloses no entropy")
        g = stmt_ok("gnss", core["seq"], "commit", C); tm = stmt_ok("time", core["seq"], "commit", C); wt = stmt_ok("witness", core["seq"], "commit", C)
        clock_health(tm, "time"); clock_health(wt, "witness")
        now = core["drand_at_commit"]; verify_drand(now, refetch)
        chk(R > now["round"], f"target round {R} is strictly after the round current at commit ({now['round']})")
        rel = S.release_time(R); chk(d.get("target_release_unix_s") == rel, f"derived.target_release_unix_s == genesis+(R-1)*period == {rel}")
        anchor = _D(g["measurement"]["anchor"]["utc_unix_s"])
        chk(anchor < rel, f"GNSS anchor (from f9t's signed statement) precedes target release by {rel - anchor} s")
        chk(_D(d.get("anchor_utc_unix_s", "nan")) == anchor, "derived.anchor_utc_unix_s equals the GNSS host's signed anchor")
        eg = sts["time"]["statement"]["measurement"].get("epoch_guard", {})
        # (p550 guard is covered by clock_health above)
        # ---- cadence trigger (2026-09-13): who said the hour started, and does the target follow from that instant? ----
        cad = core.get("cadence") or {}
        selfw = cad.get("self_trigger") or {}
        if selfw:
            print(f"[INFO] cadence: aggregator {selfw.get('host')} woke {int((selfw.get('wake') or {}).get('late_ns') or 0) / 1000:.1f} us after "
                  f"{utc(selfw['scheduled_unix_s']) if isinstance(selfw.get('scheduled_unix_s'), int) else '?'} on its own clock (covered by the aggregator signature only)")
            if cad.get("trigger"):
                chk((cad["trigger"].get("statement") or {}).get("scheduled_unix_s") == selfw.get("scheduled_unix_s"),
                    "cadence: the time host's trigger and the aggregator's wake record name the same instant")
        if cad.get("trigger"):
            ts_, tsig = cad["trigger"]["statement"], cad["trigger"]["signature"]
            chk(ts_.get("v") == S.VERSION and ts_.get("role") == "time_attester" and ts_.get("host") == "p550" and ts_.get("kind") == "cadence-trigger"
                and ts_.get("chain_hash") == S.CHAIN_HASH, "cadence: trigger is a v0.5 time_attester@p550 cadence-trigger on the pinned chain")
            kid_ok = tsig.get("alg") == "ed25519" and hashlib.sha256(base64.b64decode(tsig["public_key_b64"])).hexdigest()[:16] == tsig.get("key_id")
            try: Ed25519PublicKey.from_public_bytes(base64.b64decode(tsig["public_key_b64"])).verify(base64.b64decode(tsig["sig_b64"]), A.canon(ts_)); r = True
            except Exception: r = False
            chk(kid_ok and r, "cadence: p550's signature verifies over the trigger — the instant that started the hour was attested by the i210-disciplined host, not by the aggregator")
            if pin:
                ok, desc = pin_check(pin, "time_attester", tsig["public_key_b64"], core["seq"])
                if ok is not None: chk(ok, f"cadence: trigger key pinned for seq {core['seq']} — {desc}")
            t0 = ts_.get("scheduled_unix_s")
            chk(isinstance(t0, int) and (t0 - S.GENESIS) % S.PERIOD == 0, "cadence: scheduled instant is a drand round boundary")
            if cad.get("targeting") == "scheduled-instant+lead":
                chk(isinstance(t0, int) and rel == t0 + int(d.get("lead_rounds") or 0) * S.PERIOD,
                    f"cadence: target release == scheduled instant + {d.get('lead_rounds')} rounds ({utc(rel) if isinstance(t0, int) else '?'})")
        elif selfw and cad.get("targeting") == "scheduled-instant+lead":
            t0 = selfw.get("scheduled_unix_s")
            chk(isinstance(t0, int) and (t0 - S.GENESIS) % S.PERIOD == 0 and rel == t0 + int(d.get("lead_rounds") or 0) * S.PERIOD,
                f"cadence: target release == the aggregator's scheduled instant + {d.get('lead_rounds')} rounds ({utc(rel) if isinstance(t0, int) else '?'})")
            w, ph = selfw.get("wake") or {}, selfw.get("phc") or {}                # no time-host trigger bound: only the aggregator's own record
            print(f"[INFO] cadence: {cad.get('source')}; no time-host trigger in this pulse; aggregator woke {int(w.get('late_ns') or 0) / 1000:.1f} us after "
                  f"{utc(t0) if isinstance(t0, int) else t0} ({selfw.get('start_source')}); PHC-REALTIME at wake {ph.get('phc_minus_realtime_ns')} ns; targeting {cad.get('targeting')}")
        elif cad:
            print(f"[INFO] cadence: {cad.get('source')} ({cad.get('targeting')})" + (f"; trigger rejected: {cad['trigger_rejected']}" if cad.get("trigger_rejected") else ""))
        if prev is not None:
            chk(prev["core"].get("type", "legacy") in ("legacy", "reveal", "failure", "skip") or "type" not in prev["core"], "state machine: commit follows a reveal, failure, skip or legacy pulse")
    elif typ in ("reveal", "failure"):
        cs, cph, C = d.get("commit_seq"), d.get("commit_pulse_hash"), d.get("entropy_commitment")
        chk(isinstance(cs, int) and _hex(cph, 64) and _hex(C, 64), "derived commit_seq / commit_pulse_hash / entropy_commitment well-formed")
        if typ == "reveal":
            e = stmt_ok("entropy", cs, "reveal", cph)
            E = bytes.fromhex(e.get("entropy_hex", "")); chk(len(E) == 32, "revealed entropy is 32 bytes")
            chk(hashlib.sha256(S.COMMIT_DOMAIN + E).hexdigest() == C, "SHA256(domain||E) == the commitment (entropy host's E matches what it committed)")
            g = stmt_ok("gnss", core["seq"], "reveal", cph); tm = stmt_ok("time", core["seq"], "reveal", cph); wt = stmt_ok("witness", core["seq"], "reveal", cph)
            clock_health(tm, "time"); clock_health(wt, "witness")
            dr = core["drand"]; verify_drand(dr, refetch)
            R = dr["round"]; rel = S.release_time(R); chk(d.get("round_release_unix_s") == rel, f"derived.round_release_unix_s == computed {rel}")
            anchor = _D(g["measurement"]["anchor"]["utc_unix_s"]); chk(anchor >= rel, f"reveal GNSS anchor is {anchor - rel} s after the round release")
            buf = S.MIX_DOMAIN + E + bytes.fromhex(dr["randomness"]) + bytes.fromhex(dr["chain_hash"]) + int(R).to_bytes(8, "big")
            chk(hashlib.sha256(buf).hexdigest() == d.get("attested_value"), "attested_value == SHA256(domain||E||randomness||chain||round_be8)")
            if prev is not None:
                pc = prev["core"]
                chk(pc.get("type") == "commit" and prev["pulse_hash"] == cph and pc["seq"] == cs, "state machine: predecessor IS the referenced commit")
                chk(pc.get("derived", {}).get("entropy_commitment") == C, "commitment equals the commit pulse's")
                chk(pc.get("derived", {}).get("target_round") == R, f"drand round {R} == committed target round")
                cprev = _D(pc["derived"]["anchor_utc_unix_s"]); chk(cprev < rel, f"commit anchor precedes round release by {rel - cprev} s")
        else:
            e = stmt_ok("entropy", cs, "failure", cph)                  # PROTOCOL v0.5: failure binds to the COMMIT PULSE HASH
            chk(e.get("entropy_commitment") == C and e.get("commit_pulse_hash") == cph, "entropy host's failure names the same commitment and commit pulse")
            chk(e.get("reason") == d.get("reason"), "host-signed failure reason equals the aggregator's published reason")
            chk("entropy_hex" not in e, "failure statement discloses no entropy (E abandoned unrevealed)")
            for n in ("gnss", "time", "witness"):
                if n in sts: stmt_ok(n, core["seq"], "failure", cph)
            if prev is not None:
                chk(prev["core"].get("type") == "commit" and prev["pulse_hash"] == cph and prev["core"]["seq"] == cs, "state machine: predecessor IS the failed commit")
    elif typ == "skip":
        # v0.5.1: an aggregator-only record that a commit was REFUSED. It carries no host statements because the
        # refusing dependency is usually the one that cannot be asked. It proves when the operator recorded the
        # refusal (aggregator signature; RFC 3161 tokens when a TSA was reachable) and what it claimed - not that the
        # claim is true. Nothing was selected or withheld: no commitment existed.
        chk(sts == {}, "skip carries no host statements")
        chk(isinstance(d.get("reason"), str) and d["reason"].strip() != "", "derived.reason is a non-empty string")
        chk(d.get("refused_by") in S.SKIP_REFUSED_BY, f"derived.refused_by is one of {S.SKIP_REFUSED_BY}")
        chk(isinstance(d.get("attempted_unix_s"), int), "derived.attempted_unix_s is an int")
        toks = _glob.glob(src + ".*.tsr") if not src.startswith(("http://", "https://")) else []
        print(f"[INFO] skip: {len(toks)} RFC 3161 token(s) beside the pulse (best-effort for skips; verify with tsa.py)")
        if prev is not None:
            chk(prev["core"].get("type", "legacy") in ("legacy", "reveal", "failure", "skip"), "state machine: a skip follows a reveal, failure, skip or legacy pulse - never an unresolved commit")
    # ---- 3. tooling drift (informational) ----
    here = os.path.dirname(os.path.abspath(__file__))
    for name, tools in (core.get("tooling") or {}).items():
        for t in tools or []:
            loc = os.path.join(here, "hosts", t["name"]) if os.path.exists(os.path.join(here, "hosts", t["name"])) else os.path.join(here, t["name"])
            if os.path.exists(loc) and hashlib.sha256(open(loc, "rb").read()).hexdigest() != t["sha256"]:
                print(f"[WARN] tooling drift: {name}/{t['name']} in this pulse differs from the published copy")
    # ---- 4. hash + aggregator signature + chain ----
    recomputed = hashlib.sha256(A.canon(core)).hexdigest()
    chk(recomputed == p["pulse_hash"], "pulse_hash == sha256(canon(core))", f"claimed {p['pulse_hash']}\n       recomputed {recomputed}")
    ag = p["signatures"]["aggregator"]
    try: Ed25519PublicKey.from_public_bytes(base64.b64decode(ag["public_key_b64"])).verify(base64.b64decode(ag["sig_b64"]), bytes.fromhex(recomputed)); r = True
    except Exception: r = False
    chk(r and hashlib.sha256(base64.b64decode(ag["public_key_b64"])).hexdigest()[:16] == ag.get("key_id"), "aggregator signature over the RECOMPUTED digest (attests assembly only)")
    if pin:
        ok, desc = pin_check(pin, "aggregator", ag["public_key_b64"], core["seq"])
        if ok is not None: chk(ok, f"aggregator key pinned for seq {core['seq']} — {desc}")
    if prev is not None:
        chk(core["prev_hash"] == prev["pulse_hash"] and core["seq"] == prev["core"]["seq"] + 1, f"chains to previous pulse (seq {prev['core']['seq']} -> {core['seq']})")
    if typ == "reveal" and OK:
        rel = S.release_time(core["drand"]["round"])
        print(f"\nAttested value {d['attested_value']}\nUnknowable to anyone before {utc(rel)} (drand round {core['drand']['round']}). "
              f"E was generated, held and revealed by the entropy host itself; every measurement is signed by the host that made it. "
              f"Residual: pre-round uniqueness of the published commitment rests on third-party observation (TSA existence + watcher receipts).")
    print("\n" + ("ALL CHECKS PASSED" if OK else "VERIFICATION FAILED")); return 0 if OK else 1

def main():
    a = sys.argv[1:]
    if not a: print(__doc__); return 2
    p = load(a[0]); v = p["core"].get("v") or p["core"].get("version") or "legacy"
    if v == "0.5":
        if not V05: print("[FAIL] v0.5 pulse but hosts/attest_lib.py + schema.py are not beside verify.py"); return 1
        return strict_main()
    if v in ("legacy", "0", "0.2", "0.3", "0.4"): return legacy_main()
    print(f"[FAIL] unsupported protocol version {v!r}"); return 1

if __name__ == "__main__":
    sys.exit(main())
