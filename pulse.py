#!/usr/bin/env python3
"""
pulse.py — v0.5 AGGREGATOR. Assembles statements that each role host produced AND SIGNED ITSELF;
the aggregator can neither invent a host's facts nor alter them without breaking that host's signature.

  pulse.py commit [--lead N]   entropy host generates+holds E and signs {commitment, target_round};
                               gnss/time/witness hosts sign their own measurements bound to the commitment;
                               drand round at commit is BLS-verified here; >=2 RFC 3161 tokens or NOTHING is written.
  pulse.py reveal              refuses until drand released the target round (BLS-verified); entropy host releases E
                               and signs; other hosts sign fresh measurements bound to the commit pulse hash.
  pulse.py fail <reason>       signed FAILURE pulse for the pending commit (entropy host abandons E, signs that).
  pulse.py status

State machine (enforced): head ∈ {legacy, reveal, failure} -> commit -> (reveal | failure) -> commit ...
At most one pending commit. The chain is append-only. Only a checkout equal to the published head may mint.
Canonical form: hosts/attest_lib.canon — no floats, no integers beyond 2^53; violations abort.
"""
import json, base64, hashlib, subprocess, sys, time, os, glob, re, decimal
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts"))
import attest_lib as A, drand_anchor, tsa, bls_drand, schema as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE   = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.isdir(os.path.join(HERE, "chain"))
CHAIN  = os.path.join(HERE, "chain") if PUBLIC else os.path.join(HERE, "..", "chain")
KEYS   = os.path.join(HERE, "keys", "KEYS.json")
SSH = {"protectli": "willy@192.168.70.1", "p550": "willy@192.168.68.44", "k3": "root@192.168.68.24", "f9t": "willy@192.168.68.46"}
PROBE = {"time": "sudo -n python3 ~/beacon/stamp_probe.py /dev/ptp0", "witness": "python3 ~/beacon/stamp_probe.py /dev/ptp1",
         "gnss": "python3 ~/beacon/gnss_probe.py"}
DEFAULT_LEAD, MIN_LEAD = 100, 60
_PULSE_RE = re.compile(r"^pulse-\d{4}\.json$")

def die(m): sys.stderr.write("REFUSING TO MINT: %s\n" % m); sys.exit(2)
def ssh(host, cmd, timeout=150):
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", SSH[host], cmd], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0: raise RuntimeError(f"{host}: {r.stderr.strip()[:200]}")
    return r.stdout.strip()
def git(*a):
    r = subprocess.run(["git", "-C", HERE, *a], capture_output=True, text=True); return r.returncode, r.stdout.strip(), r.stderr.strip()
def pulse_files(): return sorted(f for f in glob.glob(os.path.join(CHAIN, "pulse-*.json")) if _PULSE_RE.match(os.path.basename(f)))
def head():
    fs = pulse_files()
    if not fs: return 0, "0" * 64, None
    p = json.load(open(fs[-1])); return p["core"]["seq"], p["pulse_hash"], p
def ptype(p): return (p or {}).get("core", {}).get("type", "legacy")
def D(x): return decimal.Decimal(str(x))

def require_synced():
    if git("rev-parse", "--is-inside-work-tree")[0] != 0: return
    rc, _, err = git("fetch", "-q", "origin", "main")
    if rc != 0: die("cannot fetch origin - " + err[:120])
    if git("rev-parse", "HEAD")[1] != git("rev-parse", "origin/main")[1]: die("checkout is not the published head; pull first, never mint on a fork")
    dirty = [l for l in git("status", "--porcelain")[1].splitlines() if "chain/" in l and "chain/pending/" not in l]
    if dirty: die("chain has unpublished changes: " + "; ".join(dirty[:3]))

# ---------------------------------------------------------------- statements
def key_allowed(role, pk_b64, seq):
    for k in json.load(open(KEYS))["keys"]:
        if k["role"] == role and k["public_key_b64"] == pk_b64:
            lo, hi = k.get("valid_from_seq") or 0, k.get("valid_to_seq")
            return lo <= seq and (hi is None or seq <= hi)
    return False

def check_statement(name, signed, seq, phase, binding):
    """Aggregator-side defence in depth: a host statement must be self-consistent before we build on it."""
    role, host = S.STATEMENTS[name]; st, sig = signed["statement"], signed["signature"]
    if st.get("v") != S.VERSION or st.get("role") != role or st.get("host") != host: die(f"{name}: wrong v/role/host")
    if st.get("seq") != seq or st.get("phase") != phase or st.get("binding") != binding or st.get("chain_hash") != S.CHAIN_HASH:
        die(f"{name}: statement not bound to this pulse (seq/phase/binding/chain)")
    if sig.get("alg") != "ed25519" or hashlib.sha256(base64.b64decode(sig["public_key_b64"])).hexdigest()[:16] != sig["key_id"]: die(f"{name}: bad key_id")
    if not key_allowed(role, sig["public_key_b64"], seq): die(f"{name}: signing key not in KEYS.json for role {role} at seq {seq}")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key_b64"])).verify(base64.b64decode(sig["sig_b64"]), A.canon(st))
    return signed

def collect(seq, phase, binding, names):
    out = {}
    for n in names:
        if n == "entropy": continue
        role, host = S.STATEMENTS[n]
        raw = ssh(host, f"python3 ~/beacon/attest_host.py {role} {host} {seq} {phase} {binding} {S.CHAIN_HASH} -- {PROBE[n]}")
        out[n] = check_statement(n, json.loads(raw), seq, phase, binding)
    return out

def drand_verified(rnd=None):
    d = drand_anchor.fetch(rnd)
    if not d["randomness_equals_sha256_signature"]: die("drand randomness != sha256(signature)")
    ok, why = bls_drand.verify_pinned(d["round"], d["signature"], d["chain_hash"])
    if not ok: die("drand BLS verification failed: " + why)
    d["round_release_unix_s"] = S.release_time(d["round"]); d["bls_verified_by_aggregator"] = True
    return d

def tooling(statements):
    t = {"aggregator": A.tool_binding(os.path.join(HERE, "pulse.py"), os.path.join(HERE, "hosts", "attest_lib.py"),
                                       os.path.join(HERE, "schema.py"), os.path.join(HERE, "verify.py"))}
    for n, s in statements.items(): t[n] = s["statement"].get("tools")
    return t

def seal(core):
    """pulse_hash over canon(core); aggregator signs the digest. Writes to a temp path, TSA-stamps, requires
    >= MIN_TSA_TOKENS, then atomically renames into the chain. Returns final path."""
    core = A.normalize(core); ph = hashlib.sha256(A.canon(core)).hexdigest()
    priv = A.load_private("aggregator"); raw, b64, kid = A.pub_of(priv)
    if not key_allowed("aggregator", b64, core["seq"]): die("aggregator key not in KEYS.json for this seq")
    pulse = {"core": core, "pulse_hash": ph,
             "signatures": {"aggregator": {"alg": "ed25519", "key_id": kid, "public_key_b64": b64, "signer": "think", "role": "aggregator",
                                           "sig_b64": base64.b64encode(priv.sign(bytes.fromhex(ph))).decode(), "over": "pulse_hash bytes",
                                           "attests": "assembly only; each host's facts are attested by that host's own signature inside core.statements"}},
             "disclosure": {"protocol": "PROTOCOL.md v0.5", "not_certified": "Not NIST/FIPS/CC validated. Not an accredited service. See CLAIMS.md."}}
    final = os.path.join(CHAIN, f"pulse-{core['seq']:04d}.json"); tmp = os.path.join(CHAIN, f".pulse-{core['seq']:04d}.json.tmp")
    if os.path.exists(final): die(f"{final} exists - append-only")
    json.dump(pulse, open(tmp, "w"), indent=2)
    if core["type"] == "commit":
        st = tsa.stamp(tmp, "at-commit")
        if len(st["tokens"]) < S.MIN_TSA_TOKENS:
            for f in glob.glob(tmp + "*"): os.remove(f)
            return None, ph, st
        for t in st["tokens"]:
            os.replace(os.path.join(CHAIN, t["file"]), final + "." + t["tsa"] + ".tsr")
        meta = json.load(open(tmp + ".tsa.json")); meta["pulse"] = os.path.basename(final)
        json.dump(meta, open(final + ".tsa.json", "w"), indent=2); os.remove(tmp + ".tsa.json")
    os.replace(tmp, final)
    return final, ph, None

# ---------------------------------------------------------------- commands
def cmd_commit(lead):
    if lead < MIN_LEAD: die(f"lead {lead} < MIN_LEAD {MIN_LEAD}")
    require_synced()
    seq, prev_hash, hp = head()
    if ptype(hp) == "commit": die(f"pulse {seq} is an unresolved commit; reveal it or record a failure first")
    seq += 1
    now = drand_verified()
    target = now["round"] + lead; release = S.release_time(target)
    if release - time.time() < S.PUBLISH_MARGIN_S + 60: die("target round is not far enough away to honour the publication margin")
    raw = ssh("protectli", f"python3 ~/beacon/entropy_host.py commit {seq} {target} {S.CHAIN_HASH}")
    ent_signed = json.loads(raw); commitment = ent_signed["statement"]["entropy_commitment"]
    ent = check_statement("entropy", ent_signed, seq, "commit", commitment)
    if ent["statement"]["target_round"] != target: die("entropy host bound a different target round")
    sts = {"entropy": ent, **collect(seq, "commit", commitment, S.REQUIRED["commit"])}
    anchor_s = D(sts["gnss"]["statement"]["measurement"]["anchor"]["utc_unix_s"])
    if anchor_s >= release: die("GNSS anchor is not before the target release")
    core = {"v": S.VERSION, "type": "commit", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH,
            "statements": sts, "drand_at_commit": now,
            "derived": {"entropy_commitment": commitment, "target_round": target, "target_release_unix_s": release,
                        "target_release_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(release)),
                        "anchor_utc_unix_s": str(anchor_s), "anchor_before_release_s": str(D(release) - anchor_s), "lead_rounds": lead},
            "tooling": tooling(sts), "aggregator_host": "think"}
    path, ph, st = seal(core)
    if path is None:
        ssh("protectli", f"python3 ~/beacon/entropy_host.py abandon {seq} tsa-tokens-insufficient")
        die(f"only {len(st['tokens'])} TSA token(s); nothing was written; E abandoned on the entropy host")
    print(json.dumps({"minted": path, "type": "commit", "seq": seq, "pulse_hash": ph, "target_round": target,
                      "target_release_utc": core["derived"]["target_release_utc"], "tsa_tokens": [(t["tsa"], t["time"]) for t in json.load(open(path + ".tsa.json"))["tokens"]],
                      "reveal_after_s": round(release - time.time(), 1)}, indent=2))

def cmd_reveal():
    require_synced()
    seq, prev_hash, hp = head()
    if ptype(hp) != "commit": die("head is not a commit; nothing to reveal")
    cseq, cph = seq, prev_hash; target = hp["core"]["derived"]["target_round"]; seq += 1
    latest = drand_verified()
    if latest["round"] < target: die(f"drand at round {latest['round']}; target {target} releases {hp['core']['derived']['target_release_utc']}")
    dr = drand_verified(target)
    ent = check_statement("entropy", json.loads(ssh("protectli", f"python3 ~/beacon/entropy_host.py reveal {cseq} {cph}")), cseq, "reveal", cph)
    E = bytes.fromhex(ent["statement"]["entropy_hex"])
    if hashlib.sha256(S.COMMIT_DOMAIN + E).hexdigest() != hp["core"]["derived"]["entropy_commitment"]: die("revealed E does not match the published commitment")
    sts = {"entropy": ent, **collect(seq, "reveal", cph, S.REQUIRED["reveal"])}
    anchor_s = D(sts["gnss"]["statement"]["measurement"]["anchor"]["utc_unix_s"])
    if anchor_s < dr["round_release_unix_s"]: die("reveal anchored before the round released")
    buf = S.MIX_DOMAIN + E + bytes.fromhex(dr["randomness"]) + bytes.fromhex(dr["chain_hash"]) + int(target).to_bytes(8, "big")
    core = {"v": S.VERSION, "type": "reveal", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH,
            "statements": sts, "drand": dr,
            "derived": {"commit_seq": cseq, "commit_pulse_hash": cph, "entropy_commitment": hp["core"]["derived"]["entropy_commitment"],
                        "attested_value": hashlib.sha256(buf).hexdigest(),
                        "mix": {"algorithm": "SHA256(domain || E || drand_randomness || chain_hash || round_be8)", "domain_tag": S.MIX_DOMAIN.decode()},
                        "round_release_unix_s": dr["round_release_unix_s"], "anchor_utc_unix_s": str(anchor_s),
                        "anchor_after_release_s": str(anchor_s - D(dr["round_release_unix_s"])),
                        "commit_anchor_before_release_s": str(D(dr["round_release_unix_s"]) - D(hp["core"]["derived"]["anchor_utc_unix_s"]))},
            "tooling": tooling(sts), "aggregator_host": "think"}
    path, ph, _ = seal(core)
    print(json.dumps({"minted": path, "type": "reveal", "seq": seq, "reveals_commit": cseq, "attested_value": core["derived"]["attested_value"],
                      "drand_round": target, "commit_before_round_by_s": core["derived"]["commit_anchor_before_release_s"],
                      "reveal_after_round_by_s": core["derived"]["anchor_after_release_s"]}, indent=2))

def cmd_fail(reason):
    require_synced()
    seq, prev_hash, hp = head()
    if ptype(hp) != "commit": die("head is not a commit; nothing to fail")
    cseq, cph = seq, prev_hash; seq += 1
    ent = check_statement("entropy", json.loads(ssh("protectli", f"python3 ~/beacon/entropy_host.py abandon {cseq} {reason}")), cseq, "failure",
                          hp["core"]["derived"]["entropy_commitment"])
    sts = {"entropy": ent}
    for n in ("gnss", "time", "witness"):
        try: sts.update(collect(seq, "failure", cph, (n,)))
        except Exception as e: sys.stderr.write(f"failure pulse: {n} statement unavailable ({str(e)[:80]}); continuing\n")
    core = {"v": S.VERSION, "type": "failure", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH, "statements": sts,
            "derived": {"commit_seq": cseq, "commit_pulse_hash": cph, "reason": reason, "target_round": hp["core"]["derived"]["target_round"],
                        "entropy_commitment": hp["core"]["derived"]["entropy_commitment"],
                        "meaning": "The referenced commit did not complete its contract. Consumers must treat it as failed; its E was abandoned unrevealed."},
            "tooling": tooling(sts), "aggregator_host": "think"}
    path, ph, _ = seal(core)
    print(json.dumps({"minted": path, "type": "failure", "seq": seq, "fails_commit": cseq, "reason": reason}, indent=2))

def cmd_status():
    seq, h, p = head(); print(f"head: seq {seq}  type {ptype(p)}  hash {h[:16]}")
    try: print("entropy host pending:", ssh("protectli", "python3 ~/beacon/entropy_host.py pending"))
    except Exception as e: print("entropy host unreachable:", str(e)[:80])

if __name__ == "__main__":
    a = sys.argv[1:]; cmd = a[0] if a else "status"
    if cmd == "commit": cmd_commit(int(a[a.index("--lead") + 1]) if "--lead" in a else DEFAULT_LEAD)
    elif cmd == "reveal": cmd_reveal()
    elif cmd == "fail": cmd_fail(" ".join(a[1:]) or "unspecified")
    else: cmd_status()
