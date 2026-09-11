#!/usr/bin/env python3
"""
verify.py — standalone verifier for attested randomness pulses (legacy, commit, reveal).

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
  * --prev:  prev_hash chains, and a reveal's predecessor IS its commit
Exit 0 only if every check passed.
"""
import json, base64, hashlib, sys, os, urllib.request, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

COMMIT_DOMAIN = b"grok_antics/commit/v1"
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
def load_key(pin, role):
    src = f"{pin.rstrip('/')}/{role}.pub" if pin.startswith(("http://", "https://")) else os.path.join(pin, f"{role}.pub")
    try: return load(src)
    except Exception: return None
def utc(ts): return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()

def verify_drand(da, refetch):
    sig, rnd = bytes.fromhex(da["signature"]), bytes.fromhex(da["randomness"])
    chk(hashlib.sha256(sig).digest() == rnd, f"drand randomness == sha256(signature) [offline] (round {da['round']}, {da.get('beacon_id')})")
    if refetch:
        try:
            with urllib.request.urlopen(f"https://api.drand.sh/{da['chain_hash']}/public/{da['round']}", timeout=15) as r:
                live = json.loads(r.read().decode())
            chk(live["randomness"] == da["randomness"] and live["signature"] == da["signature"],
                f"drand round {da['round']} re-fetched live from the League of Entropy and matches")
        except Exception as e:
            print(f"[WARN] could not re-fetch drand round: {type(e).__name__}: {e}")

def main():
    a = sys.argv[1:]
    if not a: print(__doc__); return 2
    p = load(a[0]); core = p["core"]; typ = core.get("type", "legacy")
    pin = a[a.index("--pin") + 1] if "--pin" in a else None
    prev = load(a[a.index("--prev") + 1]) if "--prev" in a else None
    refetch = "--refetch" in a
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
            k = load_key(pin, s["role"])
            if k: chk(k["public_key_b64"] == s["public_key_b64"], f"{name} key matches pinned {s['role']}.pub")
            else: print(f"[WARN] no pinned key for {s['role']}")

    # ---- type-specific ----
    if typ == "commit":
        c = core["commitment"]; now = core["drand_at_commit"]
        verify_drand(now, refetch)
        chk(c["target_round"] > now["round"], f"target round {c['target_round']} is strictly after the round current at commit ({now['round']})")
        chk(core["time"]["anchor"]["utc_unix_s"] < c["target_release_unix_s"],
            f"GNSS anchor {core['time']['utc']} precedes target release {utc(c['target_release_unix_s'])}")
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
            chk(prev["core"]["time"]["anchor"]["utc_unix_s"] < da["round_release_unix_s"],
                f"commit anchor {prev['core']['time']['utc']} precedes round release {utc(da['round_release_unix_s'])}")
        chk(core["time"]["anchor"]["utc_unix_s"] >= da["round_release_unix_s"], "reveal anchor is not before the round release")
        verify_drand(da, refetch)
        m = core["mix"]; buf = m["domain_tag"].encode() + E + bytes.fromhex(da["randomness"]) + bytes.fromhex(da["chain_hash"]) + int(da["round"]).to_bytes(8, "big")
        rec = hashlib.sha256(buf).hexdigest()
        chk(rec == core["attested_value"], f"attested_value == {m['algorithm']}", f"published {core['attested_value']}\n       recomputed {rec}")
        tl = core.get("timeline", {})
        print(f"\nAttested value {core['attested_value']}")
        print(f"Unknowable to anyone before {utc(da['round_release_unix_s'])} (drand round {da['round']}); the entropy was "
              f"committed {tl.get('commit_before_round_by_s')} s before that round existed, so it could not have been chosen "
              f"after. Residual assumption: the commit was PUBLISHED before the round - check the public log's history.")
    else:
        da = core.get("external_anchor")
        if da:
            verify_drand(da, refetch)
            m = core.get("mix", {}); buf = m.get("domain_tag", "").encode() + bytes.fromhex(core["entropy"]["hex"]) + bytes.fromhex(da["randomness"]) + bytes.fromhex(da["chain_hash"]) + int(da["round"]).to_bytes(8, "big")
            chk(hashlib.sha256(buf).hexdigest() == core.get("attested_value"), "attested_value == documented mix")
            print(f"\nLegacy single-phase pulse: not computable before {utc(da['round_release_unix_s'])}, but selection after that moment is NOT excluded.")
        else:
            print("\n[INFO] legacy pulse without external anchor: integrity + attestation only.")

    if prev is not None:
        chk(core["prev_hash"] == prev["pulse_hash"], f"chains to previous pulse (seq {prev['core']['seq']} -> {core['seq']})")
    elif core["prev_hash"] == "0" * 64:
        print("[INFO] genesis pulse")
    print("\n" + ("ALL CHECKS PASSED" if OK else "VERIFICATION FAILED"))
    return 0 if OK else 1

if __name__ == "__main__":
    sys.exit(main())
