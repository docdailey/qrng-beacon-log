#!/usr/bin/env python3
"""
pulse.py — v0.5 AGGREGATOR. Assembles statements that each role host produced AND SIGNED ITSELF;
the aggregator can neither invent a host's facts nor alter them without breaking that host's signature.

  pulse.py commit [--lead N] [--self-trigger FILE] [--trigger FILE | --trigger-dir DIR]
                               entropy host generates+holds E and signs {commitment, target_round};
                               --self-trigger: the aggregator's own wake record for the scheduled instant (beacon-cycle --at);
                               --trigger/--trigger-dir: the time host's signed cadence trigger, given or arriving by UDP;
                               target = round released at the instant + lead; both records are embedded in core.cadence;
                               gnss/time/witness hosts sign their own measurements bound to the commitment;
                               drand round at commit is BLS-verified here; >=2 RFC 3161 tokens or NOTHING is written.
  pulse.py reveal [--drand FILE]   refuses until drand released the target round (BLS-verified; FILE = the round document the
                               cycle driver already fetched from the relays, verified here); entropy host releases E
                               and signs; other hosts sign fresh measurements bound to the commit pulse hash.
  pulse.py fail <reason>       signed FAILURE pulse for the pending commit (entropy host abandons E, signs that).
  pulse.py status

State machine (enforced): head ∈ {legacy, reveal, failure} -> commit -> (reveal | failure) -> commit ...
At most one pending commit. The chain is append-only. Only a checkout equal to the published head may mint.
Canonical form: hosts/attest_lib.canon — no floats, no integers beyond 2^53; violations abort.
"""
import json, base64, hashlib, subprocess, sys, time, os, glob, re, decimal
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts"))
import attest_lib as A, drand_anchor, tsa, bls_drand, schema as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE   = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.isdir(os.path.join(HERE, "chain"))
CHAIN  = os.path.join(HERE, "chain") if PUBLIC else os.path.join(HERE, "..", "chain")
KEYS   = os.path.join(HERE, "keys", "KEYS.json")
# Isolation model (hosts/ISOLATION.md): the aggregator logs in ONLY as the confined `beacon` user, whose forced command
# (beacon-cmd) accepts a fixed set of operations. Role, host name and probe are fixed ON THE HOST, never sent from here.
SSH = {"protectli": "beacon@192.168.70.1", "p550": "beacon@192.168.68.44", "k3": "beacon@192.168.68.24", "f9t": "beacon@192.168.68.46"}
DEFAULT_LEAD, MIN_LEAD = 20, 10       # 2026-09-13: 100/60 -> 20/10 rounds; the gate below still requires margin + 30 s of room
START_NS = time.time_ns()                      # aggregator clock at process start: latency bookkeeping only
AGG_HOST = os.environ.get("BEACON_AGGREGATOR_HOST") or os.uname().nodename.split(".")[0]   # think (until 2026-09-13) / k3
_PULSE_RE = re.compile(r"^pulse-\d{4}\.json$")

def die(m): sys.stderr.write("REFUSING TO MINT: %s\n" % m); sys.exit(2)
RPC = os.environ.get("BEACON_RPC", "ssh")           # "agentd": signed requests over TCP to hosts/agentd.py; "ssh": the forced command
def ssh(host, cmd, timeout=150):
    """Ask a role host for one operation. Named for its history; with BEACON_RPC=agentd this is a signed TCP request
    (hosts/rpc.py) and no SSH is involved. Returns what the host script printed, as before."""
    if RPC == "agentd":
        import shlex, rpc
        return rpc.call(host, *shlex.split(cmd), timeout=timeout)
    return _ssh(host, cmd, timeout)
def _ssh(host, cmd, timeout=150):
    # stdin=DEVNULL: an inherited stdin let inner ssh sessions swallow the caller's script stream (2026-09-12 cut-over incident)
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", SSH[host], cmd], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
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

def require_synced(allow_offline=False, assume=False):
    """Returns True when the published head could NOT be confirmed but allow_offline let us proceed (skip pulses).
    assume=True (beacon-cycle --at fetched origin/main seconds before the tick and found HEAD == origin/main): skip
    the network fetch here - the local origin/main ref is at most a few seconds old - but keep every other check."""
    if git("rev-parse", "--is-inside-work-tree")[0] != 0: return False
    if assume and git("rev-parse", "HEAD")[1].strip() == git("rev-parse", "origin/main")[1].strip():
        rc = 0
    else:
        rc, _, err = git("fetch", "-q", "origin", "main")
    if rc != 0:
        if allow_offline: sys.stderr.write("warning: cannot fetch origin; proceeding on the local head\n"); return True
        die("cannot fetch origin - " + err[:120])
    dirty = [l for l in git("status", "--porcelain")[1].splitlines() if "chain/" in l and "chain/pending/" not in l]
    if dirty: die("chain has unpublished changes: " + "; ".join(dirty[:3]))
    if git("rev-parse", "HEAD")[1] != git("rev-parse", "origin/main")[1]:
        # Behind the published head with nothing local (someone pushed docs/site while a cycle ran): fast-forward and
        # continue — that is not a fork. Diverged (local commits origin does not have) IS refused. ERR-010.
        if git("merge-base", "--is-ancestor", "HEAD", "origin/main")[0] == 0:
            rc, _, err = git("merge", "--ff-only", "origin/main")
            if rc != 0: die("cannot fast-forward to the published head - " + err[:120])
            sys.stderr.write("note: checkout was behind origin/main; fast-forwarded\n")
        else: die("checkout has commits the published head does not (diverged); never mint on a fork - reconcile first")
    return False

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
    if seq >= S.ENFORCE_EXECUTION_FROM_SEQ:
        ok, why = S.execution_ok(st.get("execution"), host, os.path.join(HERE, "hosts", "EXPECTED.json"))
        if not ok: die(f"{name}: execution self-report rejected: {why}")
    return signed

def check_trigger(signed, seq):
    """A cadence trigger is a statement by the TIME host (p550) that its i210-disciplined clock reached the scheduled
    instant (hosts/beacon-cadence.py). Embedded in the commit, it makes the instant that started the hour attested by
    the clock that measured it. Verified like a host statement; a bad one is RECORDED and ignored, never fatal."""
    try:
        st, sig = signed["statement"], signed["signature"]
        if (st.get("v") != S.VERSION or st.get("role") != "time_attester" or st.get("host") != "p550"
                or st.get("kind") != "cadence-trigger" or st.get("chain_hash") != S.CHAIN_HASH): return False, "wrong v/role/host/kind/chain"
        if sig.get("alg") != "ed25519" or hashlib.sha256(base64.b64decode(sig["public_key_b64"])).hexdigest()[:16] != sig["key_id"]: return False, "bad key_id"
        if not key_allowed("time_attester", sig["public_key_b64"], seq): return False, f"key not valid for time_attester at seq {seq}"
        Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key_b64"])).verify(base64.b64decode(sig["sig_b64"]), A.canon(st))
        t0 = st.get("scheduled_unix_s")
        if not isinstance(t0, int) or (t0 - S.GENESIS) % S.PERIOD != 0: return False, "scheduled instant is not a drand round boundary"
        if not (0 <= time.time() - t0 <= 900): return False, "scheduled instant is not within the last 15 minutes"
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def collect(seq, phase, binding, names):
    """Gather the attest hosts' statements CONCURRENTLY (2026-09-13: they used to be queried one after another, which put the
    sum of the probe windows on the critical path). Each host still runs its own forced command and signs its own facts;
    the aggregator only assembles. Any failure aborts the phase exactly as before."""
    wanted = [n for n in names if n != "entropy"]
    def one(n):
        role, host = S.STATEMENTS[n]
        raw = ssh(host, f"attest {phase} {seq} {binding} {S.CHAIN_HASH}")          # forced command; host decides role+probe
        return n, host, json.loads(raw)
    out = {}
    with ThreadPoolExecutor(max_workers=max(1, len(wanted))) as ex:
        results = list(ex.map(one, wanted))                                          # exceptions propagate here, in order
    for n, host, j in results:
        out[n] = check_statement(n, j, seq, phase, binding)
        if n in ("time", "witness"):                      # a REQUIRED clock statement must report a healthy clock
            g = out[n]["statement"]["measurement"].get("epoch_guard", {})
            if g.get("epoch_ok") is not True or g.get("chrony_selects_refclock") is not True or g.get("ALERT"):
                die(f"{n} ({host}) reports an unhealthy clock: epoch_ok={g.get('epoch_ok')} selects_refclock={g.get('chrony_selects_refclock')} {g.get('ALERT') or ''}")
    return out

def drand_verified(rnd=None, doc_file=None):
    """BLS-verified drand round: `latest`, a specific round, or (doc_file) a document the cycle driver already fetched."""
    d = None
    if doc_file:
        j = json.load(open(doc_file))
        if rnd is None or int(j["doc"].get("round", -1)) == int(rnd):
            d = drand_anchor.fetch(rnd, doc=j["doc"], base=j.get("base"), fetched_at=j.get("fetched_unix_s"))
        else: sys.stderr.write(f"note: handed-over drand document is round {j['doc'].get('round')}, need {rnd}; fetching the round itself\n")
    if d is None: d = drand_anchor.fetch(rnd)
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
             "signatures": {"aggregator": {"alg": "ed25519", "key_id": kid, "public_key_b64": b64, "signer": AGG_HOST, "role": "aggregator",
                                           "sig_b64": base64.b64encode(priv.sign(bytes.fromhex(ph))).decode(), "over": "pulse_hash bytes",
                                           "attests": "assembly only; each host's facts are attested by that host's own signature inside core.statements"}},
             "disclosure": {"protocol": "PROTOCOL.md v0.5", "not_certified": "Not NIST/FIPS/CC validated. Not an accredited service. See CLAIMS.md."}}
    final = os.path.join(CHAIN, f"pulse-{core['seq']:04d}.json"); tmp = os.path.join(CHAIN, f".pulse-{core['seq']:04d}.json.tmp")
    if os.path.exists(final): die(f"{final} exists - append-only")
    json.dump(pulse, open(tmp, "w"), indent=2)
    if core["type"] in ("commit", "skip"):
        st = tsa.stamp(tmp, "at-commit" if core["type"] == "commit" else "at-skip")
        if core["type"] == "commit" and len(st["tokens"]) < S.MIN_TSA_TOKENS:
            for f in glob.glob(tmp + "*"): os.remove(f)
            return None, ph, st
        for t in st["tokens"]:
            os.replace(os.path.join(CHAIN, t["file"]), final + "." + t["tsa"] + ".tsr")
        meta = json.load(open(tmp + ".tsa.json")); meta["pulse"] = os.path.basename(final)
        json.dump(meta, open(final + ".tsa.json", "w"), indent=2); os.remove(tmp + ".tsa.json")
    os.replace(tmp, final)
    return final, ph, None

# ---------------------------------------------------------------- commands
def _load_trigger(path, seq):
    """(signed, received_unix_ns, ok, why) for a delivered trigger file, or None if absent."""
    try: tj = json.load(open(path))
    except Exception: return None
    signed = tj.get("trigger") or {}; ok, why = check_trigger(signed, seq)
    return signed, tj.get("received_unix_ns"), ok, why, tj.get("kernel_rx_unix_ns")

def cmd_commit(lead, trigger_path=None, self_trigger_path=None, trigger_dir=None, assume_synced=False):
    """--self-trigger: the aggregator's own wake record for the scheduled instant (beacon-cycle.py --at); --trigger /
    --trigger-dir: the time host's signed cadence trigger, delivered up front or arriving by UDP while this runs;
    --assume-synced: the cycle driver fetched origin seconds ago (see require_synced)."""
    if lead < MIN_LEAD: die(f"lead {lead} < MIN_LEAD {MIN_LEAD}")
    require_synced(assume=assume_synced)
    seq, prev_hash, hp = head()
    if ptype(hp) == "commit": die(f"pulse {seq} is an unresolved commit; reveal it or record a failure first")
    seq += 1
    # Cadence (2026-09-13): the cycle starts ON the scheduled instant (the aggregator's own PHC-disciplined clock, and/or
    # the time host's signed trigger). Then the target is the round released AT that instant + lead, so the release lands
    # on a fixed grid (:05:00), and drand's latest round is fetched and BLS-verified IN PARALLEL with the entropy host and
    # the statements instead of ahead of them. Without any instant the target is drand-latest + lead as before.
    cadence = {"schedule": "hourly; the cycle starts at :00:00 UTC on the aggregator's PHC-disciplined clock; the time host (p550) attests the same "
                           "instant with a signed trigger sent by UDP; target round = the round released at that instant + lead (CADENCE.md)",
               "source": f"{AGG_HOST}-timer", "targeting": "drand-latest+lead", "aggregator_start_unix_ns": str(START_NS)}
    t0 = None
    if self_trigger_path:
        try:
            st_ = json.load(open(self_trigger_path))
            if isinstance(st_.get("scheduled_unix_s"), int) and (st_["scheduled_unix_s"] - S.GENESIS) % S.PERIOD == 0 and 0 <= time.time() - st_["scheduled_unix_s"] <= 900:
                t0 = st_["scheduled_unix_s"]; cadence["self_trigger"] = st_; cadence["source"] = f"{AGG_HOST} clock"
            else: cadence["self_trigger_rejected"] = "not a fresh drand round boundary"
        except Exception as e: cadence["self_trigger_rejected"] = f"{type(e).__name__}: {e}"
    tr = _load_trigger(trigger_path, seq) if trigger_path else None
    if tr:
        signed, rx, ok, why, krx = tr
        if ok and (t0 is None or signed["statement"]["scheduled_unix_s"] == t0):
            t0 = signed["statement"]["scheduled_unix_s"]; cadence.update({"trigger": signed, "received_unix_ns": str(rx), "datagram_kernel_rx_unix_ns": krx})
            cadence["source"] = f"{AGG_HOST} clock + p550/i210 trigger" if "self_trigger" in cadence else "p550/i210 cadence trigger"
        else: cadence["trigger_rejected"] = why if not ok else "trigger instant differs from the aggregator's scheduled instant"
    ex = ThreadPoolExecutor(max_workers=1); fut = ex.submit(drand_verified)          # fetch + BLS in the background
    if t0 is not None:
        r0 = (t0 - S.GENESIS) // S.PERIOD + 1                                          # the round released AT t0
        target = r0 + lead; cadence["targeting"] = "scheduled-instant+lead"
    else:
        now = fut.result(); target = now["round"] + lead
    release = S.release_time(target)
    if release - time.time() < S.PUBLISH_MARGIN_S + 30: die("target round is not far enough away to honour the publication margin")   # 30 s: the chain mints in 1-3 s; MIN_LEAD (60 rounds = 180 s) must pass this gate at the tick
    # The SSH outcome itself is uncertain (timeout after the host created its secret, malformed reply): treat the
    # entropy host as POSSIBLY holding a secret from the moment we ask, and roll back on any exception from here on.
    def rollback(why):
        """Idempotent. Harmless if the host never created a secret for this seq."""
        try:
            if f"{seq:04d}.secret" in json.loads(ssh("protectli", "pending")) or f"{seq:04d}.abandoning" in json.loads(ssh("protectli", "pending")):
                ssh("protectli", f"abandon-prepare {seq} {'0'*64} unpublished:{why}")
                ssh("protectli", f"finalize {seq} {'0'*64}")
        except Exception as e:
            sys.stderr.write(f"rollback of unpublished seq {seq} incomplete ({e}); `pulse.py recover` will retry\n")
    try:
        raw = ssh("protectli", f"commit {seq} {target} {S.CHAIN_HASH}")
        ent_signed = json.loads(raw); commitment = ent_signed["statement"]["entropy_commitment"]
        ent = check_statement("entropy", ent_signed, seq, "commit", commitment)
        if ent["statement"]["target_round"] != target: raise RuntimeError("entropy host bound a different target round")
        sts = {"entropy": ent, **collect(seq, "commit", commitment, S.REQUIRED["commit"])}
        anchor_s = D(sts["gnss"]["statement"]["measurement"]["anchor"]["utc_unix_s"])
        if anchor_s >= release: raise RuntimeError("GNSS anchor is not before the target release")
        # the time host's trigger normally lands by UDP a few ms after the instant; pick it up now if it was not given up front
        if "trigger" not in cadence and trigger_dir and os.path.exists(os.path.join(trigger_dir, "pending.json")):
            tr = _load_trigger(os.path.join(trigger_dir, "pending.json"), seq); os.replace(os.path.join(trigger_dir, "pending.json"), os.path.join(trigger_dir, "last.json"))
            if tr:
                signed, rx, ok, why, krx = tr
                if ok and (t0 is None or signed["statement"]["scheduled_unix_s"] == t0):
                    cadence.update({"trigger": signed, "received_unix_ns": str(rx), "datagram_kernel_rx_unix_ns": krx, "source": f"{AGG_HOST} clock + p550/i210 trigger" if "self_trigger" in cadence else "p550/i210 cadence trigger"})
                else: cadence["trigger_rejected"] = why if not ok else "trigger instant differs from the aggregator's scheduled instant"
        now = fut.result(); ex.shutdown(wait=False)                                     # drand latest, BLS-verified (ran in parallel)
        if now["round"] >= target: raise RuntimeError(f"drand is already at round {now['round']} >= target {target}")
        if t0 is not None and target - now["round"] < MIN_LEAD: raise RuntimeError(f"scheduled target {target} is only {target - now['round']} rounds ahead of drand {now['round']} (< MIN_LEAD {MIN_LEAD})")
    except SystemExit:
        rollback("aggregator-refused"); raise
    except Exception as e:
        rollback(type(e).__name__); die(f"commit aborted before anything was written: {e}")
    core = {"v": S.VERSION, "type": "commit", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH,
            "statements": sts, "drand_at_commit": now,
            "derived": {"entropy_commitment": commitment, "target_round": target, "target_release_unix_s": release,
                        "target_release_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(release)),
                        "anchor_utc_unix_s": str(anchor_s), "anchor_before_release_s": str(D(release) - anchor_s), "lead_rounds": lead},
            "tooling": tooling(sts), "aggregator_host": AGG_HOST, "cadence": cadence}
    try:
        path, ph, st = seal(core)
    except SystemExit:
        rollback("seal-refused"); raise
    except Exception as e:
        rollback("seal-error"); die(f"seal failed, nothing written: {e}")
    if path is None:
        rollback("tsa-tokens-insufficient")
        die(f"only {len(st['tokens'])} TSA token(s); nothing was written; E abandoned and erased on the entropy host")
    print(json.dumps({"minted": path, "type": "commit", "seq": seq, "pulse_hash": ph, "target_round": target,
                      "target_release_utc": core["derived"]["target_release_utc"], "tsa_tokens": [(t["tsa"], t["time"]) for t in json.load(open(path + ".tsa.json"))["tokens"]],
                      "reveal_after_s": round(release - time.time(), 1)}, indent=2))

def cmd_reveal(drand_file=None):
    from concurrent.futures import ThreadPoolExecutor      # also at module level; repeated here so an extracted function still runs (review probe)
    require_synced()
    seq, prev_hash, hp = head()
    if ptype(hp) != "commit": die("head is not a commit; nothing to reveal")
    cseq, cph = seq, prev_hash; target = hp["core"]["derived"]["target_round"]; seq += 1
    if time.time() > S.release_time(target) + S.REVEAL_DEADLINE_S:
        die(f"reveal deadline passed ({time.time() - S.release_time(target):.0f} s past the round on the aggregator's clock); record a failure instead")
    if drand_file:
        dr = drand_verified(target, doc_file=drand_file)                               # the round the cycle driver already fetched; BLS-verified here
    else:
        with ThreadPoolExecutor(max_workers=2) as ex:                                    # latest + target: two fetches, two BLS checks, at once
            f_latest, f_target = ex.submit(drand_verified), ex.submit(drand_verified, target)
            latest = f_latest.result()
            if latest["round"] < target: die(f"drand at round {latest['round']}; target {target} releases {hp['core']['derived']['target_release_utc']}")
            if latest["round_release_unix_s"] > S.release_time(target) + S.REVEAL_DEADLINE_S:
                die(f"reveal deadline passed (drand time is {latest['round_release_unix_s'] - S.release_time(target):.0f} s past the round); record a failure instead")
            dr = f_target.result()
    with ThreadPoolExecutor(max_workers=1) as ex:                                        # the entropy host reveals while the clock hosts attest
        f_ent = ex.submit(lambda: json.loads(ssh("protectli", f"reveal-prepare {cseq} {cph}")))
        rest = collect(seq, "reveal", cph, S.REQUIRED["reveal"])
        ent = check_statement("entropy", f_ent.result(), cseq, "reveal", cph)
    E = bytes.fromhex(ent["statement"]["entropy_hex"])
    if hashlib.sha256(S.COMMIT_DOMAIN + E).hexdigest() != hp["core"]["derived"]["entropy_commitment"]: die("revealed E does not match the published commitment")
    sts = {"entropy": ent, **rest}
    anchor_s = D(sts["gnss"]["statement"]["measurement"]["anchor"]["utc_unix_s"])
    # The GNSS host's anchor is a whole second and can lag the release; its serial stream can also stall for seconds (ERR-019:
    # three 0.7 s retries were not enough at 12:01Z 2026-09-14). Ask again every second for up to 60 s, never past the window.
    t_retry = time.time(); attempt = 0
    while anchor_s < dr["round_release_unix_s"]:
        attempt += 1
        if time.time() - t_retry > 60 or time.time() > S.release_time(target) + S.REVEAL_DEADLINE_S - 90: break
        sys.stderr.write(f"note: GNSS anchor {anchor_s} precedes the release {dr['round_release_unix_s']}; asking f9t again ({attempt}, {time.time() - t_retry:.0f} s)\n")
        time.sleep(1.0); sts.update(collect(seq, "reveal", cph, ("gnss",))); anchor_s = D(sts["gnss"]["statement"]["measurement"]["anchor"]["utc_unix_s"])
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
            "tooling": tooling(sts), "aggregator_host": AGG_HOST,
            "cadence": {"aggregator_start_unix_ns": str(START_NS), "started_after_release_s": str(D(START_NS) / D(10**9) - D(dr["round_release_unix_s"])),
                        "meaning": "when the aggregator began the reveal, on its own (NTP) clock; the attested ordering is the GNSS anchor, not this"}}
    path, ph, _ = seal(core)
    print(json.dumps({"minted": path, "type": "reveal", "seq": seq, "reveals_commit": cseq, "attested_value": core["derived"]["attested_value"],
                      "drand_round": target, "commit_before_round_by_s": core["derived"]["commit_anchor_before_release_s"],
                      "reveal_after_round_by_s": core["derived"]["anchor_after_release_s"]}, indent=2))

HOST_REASON_CHARS = re.compile(r"[^A-Za-z0-9 ._:{}\",=-]")     # what beacon-cmd / beacon-agentd keep of a failure reason
def cmd_fail(reason):
    """The entropy host signs the reason it RECEIVED, after its sanitizer; send exactly what it will sign (ERR-017: a
    traceback in the reason made the host's string differ and the failure pulse could not mint)."""
    reason = HOST_REASON_CHARS.sub("", " ".join(str(reason).split()))[:200].strip() or "unspecified"
    require_synced()
    seq, prev_hash, hp = head()
    if ptype(hp) != "commit": die("head is not a commit; nothing to fail")
    cseq, cph = seq, prev_hash; seq += 1
    # ERR-019 (2026-09-14): the reason went through shlex.split on its way to the daemon, which stripped the quotes json.dumps
    # had put in (host signed one string, we compared another) and raised on an unbalanced quote (the 12:01Z crash). Send the
    # reason as ONE argument; the daemon joins its trailing arguments with single spaces, so it signs exactly this string.
    if RPC == "agentd":
        import rpc
        raw = rpc.call("protectli", "abandon-prepare", str(cseq), cph, reason)
    else: raw = ssh("protectli", f"abandon-prepare {cseq} {cph} {reason}")
    ent = check_statement("entropy", json.loads(raw), cseq, "failure", cph)
    host_reason = ent["statement"].get("reason")
    if not host_reason: die("entropy host signed an empty failure reason")
    if host_reason != reason:
        sys.stderr.write(f"note: entropy host signed the reason as {host_reason!r}; the pulse carries the host's signed wording\n"); reason = host_reason
    sts = {"entropy": ent}
    for n in ("gnss", "time", "witness"):
        try: sts.update(collect(seq, "failure", cph, (n,)))
        except Exception as e: sys.stderr.write(f"failure pulse: {n} statement unavailable ({str(e)[:80]}); continuing\n")
    core = {"v": S.VERSION, "type": "failure", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH, "statements": sts,
            "derived": {"commit_seq": cseq, "commit_pulse_hash": cph, "reason": reason, "target_round": hp["core"]["derived"]["target_round"],
                        "entropy_commitment": hp["core"]["derived"]["entropy_commitment"],
                        "meaning": "The referenced commit did not complete its contract. Consumers must treat it as failed; its E was abandoned unrevealed."},
            "tooling": tooling(sts), "aggregator_host": AGG_HOST}
    path, ph, _ = seal(core)
    print(json.dumps({"minted": path, "type": "failure", "seq": seq, "fails_commit": cseq, "reason": reason}, indent=2))

def cmd_finalize():
    """After the resolving pulse (reveal/failure) is written AND pushed, tell the entropy host to retire its secret."""
    seq, ph, hp = head()
    if ptype(hp) not in ("reveal", "failure"): die("head is not a reveal or failure; nothing to finalize")
    cseq = hp["core"]["derived"]["commit_seq"]
    if git("rev-parse", "--is-inside-work-tree")[0] == 0:
        git("fetch", "-q", "origin", "main")
        if git("rev-parse", "HEAD")[1] != git("rev-parse", "origin/main")[1] or git("status", "--porcelain", "chain")[1]:
            die("resolving pulse is not yet published; refusing to finalize (E stays recoverable)")
    print(ssh("protectli", f"finalize {cseq} {ph}"))

def cmd_recover():
    """Derive the right action from the PUBLISHED chain and the entropy host's held state, before any new commit.
    Idempotent; safe to run every cycle. Prints what it did; exits 3 if the head commit must be resolved by the caller."""
    require_synced()
    seq, ph, hp = head(); pend = json.loads(ssh("protectli", "pending")); actions = []
    for f in pend:
        s_, st = int(f.split(".")[0]), f.split(".")[1]
        if s_ > seq or (s_ == seq and ptype(hp) != "commit"):
            ssh("protectli", f"abandon-prepare {s_} {'0'*64} unpublished:recover"); ssh("protectli", f"finalize {s_} {'0'*64}")
            actions.append(f"aborted unpublished {f}"); continue
        if st in ("revealing", "abandoning") and s_ < seq:
            # its resolving pulse should be s_+1 in the published chain; finalize against that hash
            fs = [x for x in pulse_files() if os.path.basename(x) == f"pulse-{s_+1:04d}.json"]
            if fs:
                rp = json.load(open(fs[0]))
                if rp["core"].get("type") in ("reveal", "failure") and rp["core"]["derived"]["commit_seq"] == s_:
                    ssh("protectli", f"finalize {s_} {rp['pulse_hash']}"); actions.append(f"finalized {f} against {rp['pulse_hash'][:12]}"); continue
            actions.append(f"UNRESOLVED leftover {f} (no published resolver) - needs operator attention")
    print(json.dumps({"head_seq": seq, "head_type": ptype(hp), "pending_before": pend, "actions": actions,
                      "head_commit_unresolved": ptype(hp) == "commit"}))
    if ptype(hp) == "commit": sys.exit(3)          # caller must resume: reveal (if in window) or fail

def cmd_abort_unpublished():
    """Idempotent: retire any secret the entropy host holds for a seq that never entered the published chain.
    A secret whose seq equals the chain head commit is a live pending commit and is left alone."""
    require_synced()
    seq, _, hp = head()
    pend = json.loads(ssh("protectli", "pending"))
    done = []
    for f in pend:
        s_ = int(f.split(".")[0]); st = f.split(".")[1]
        if s_ > seq or (s_ == seq and ptype(hp) != "commit"):
            ssh("protectli", f"abandon-prepare {s_} {'0'*64} unpublished:abort-unpublished")
            ssh("protectli", f"finalize {s_} {'0'*64}"); done.append(f)
    print(json.dumps({"head_seq": seq, "head_type": ptype(hp), "entropy_host_pending_before": pend, "aborted": done}))

def cmd_skip(reason):
    """A REFUSED commit becomes a public, signed, third-party-timestamped chain event instead of a silent gap
    (PROTOCOL v0.5.1). Aggregator-only, by necessity: the dependency that refused is usually the one that cannot be
    asked. It proves WHEN the operator recorded a refusal and WHAT it claimed — not that the claim is true. A skip may
    follow a reveal, a failure, a legacy pulse or another skip; never an unresolved commit (that must be failed)."""
    offline = require_synced(allow_offline=True)
    seq, prev_hash, hp = head()
    if ptype(hp) == "commit": die("head is an unresolved commit; a skip cannot follow a commit - resolve it (reveal or fail) first")
    seq += 1
    seen = None
    try: seen = int(drand_anchor.fetch()["round"])            # informational: which round the world was at
    except Exception: pass
    now = int(time.time())
    core = {"v": S.VERSION, "type": "skip", "seq": seq, "prev_hash": prev_hash, "chain_hash": S.CHAIN_HASH, "statements": {},
            "derived": {"reason": str(reason)[:400], "refused_by": S.classify_refusal(reason), "attempted_unix_s": now,
                        "attempted_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), "drand_round_seen": seen,
                        "published_head_confirmed": not offline, "head_type_before": ptype(hp),
                        "meaning": "No commit was minted this cycle. Nothing was selected and nothing was withheld: no commitment "
                                   "existed. This pulse only makes the gap, and the operator's stated cause, public at a timestamped moment."},
            "tooling": {}, "aggregator_host": AGG_HOST}
    path, ph, _ = seal(core)
    toks = json.load(open(path + ".tsa.json"))["tokens"] if os.path.exists(path + ".tsa.json") else []
    print(json.dumps({"minted": path, "type": "skip", "seq": seq, "refused_by": core["derived"]["refused_by"],
                      "tsa_tokens": [(t["tsa"], t["time"]) for t in toks], "published_head_confirmed": not offline}, indent=2))

def cmd_preflight():
    """Readiness check before (re)enabling the cadence, e.g. after the timing bench was down. MINTS NOTHING.
    Answers: would a commit be accepted right now, and if not, which dependency is the reason? Side effects are the same
    as a refused commit attempt: each measurement host signs one statement at the NEXT seq bound to the all-zero
    binding; the entropy host is only asked `pending`; two throw-away TSA tokens are requested on a scratch file."""
    import tempfile, shutil
    rows = []
    def row(name, ok, detail):
        rows.append(ok); print(f"[{'OK  ' if ok else ('FAIL' if ok is False else 'WARN')}] {name:<13} {detail}", flush=True)
    # 1. checkout == published head, no unresolved commit
    rc, _, _ = git("fetch", "-q", "origin", "main")
    head_, om = git("rev-parse", "HEAD")[1], git("rev-parse", "origin/main")[1]
    behind = rc == 0 and head_ != om and git("merge-base", "--is-ancestor", "HEAD", "origin/main")[0] == 0
    synced = rc == 0 and (head_ == om or behind)          # merely behind is fine: the cycle fast-forwards (ERR-010); diverged is not
    row("git", synced, "checkout equals origin/main" if head_ == om else ("behind origin/main by docs/site commits; the cycle will fast-forward" if behind else ("cannot fetch origin (no GitHub?)" if rc else "checkout has commits origin lacks (DIVERGED) — reconcile before minting")))
    seq, ph, hp = head(); nxt = seq + 1
    row("chain head", ptype(hp) != "commit", f"seq {seq} type {ptype(hp)}" + ("" if ptype(hp) != "commit" else " — UNRESOLVED COMMIT: let the cycle (recover) resolve it before anything else"))
    # 2. drand reachable and BLS-verifying
    try: d = drand_verified(); row("drand", True, f"round {d['round']} BLS-verified under the pinned group key")
    except SystemExit: row("drand", False, "unreachable or failed verification (see REFUSING line above)")
    except Exception as e: row("drand", False, str(e)[:120])
    # 3. entropy host
    try: pend = json.loads(ssh("protectli", "pending")); row("entropy", not pend, "protectli reachable; pending " + json.dumps(pend))
    except Exception as e: row("entropy", False, str(e)[:140])
    # 4. measurement hosts: the exact statement a commit would collect, at the next seq, dummy binding
    for n in ("gnss", "time", "witness"):
        role, host = S.STATEMENTS[n]
        try:
            st = check_statement(n, json.loads(ssh(host, f"attest commit {nxt} {'0'*64} {S.CHAIN_HASH}")), nxt, "commit", "0" * 64)
            m = st["statement"]["measurement"]
            if n == "gnss":
                age = time.time() - float(m["anchor"]["utc_unix_s"])
                row(n, age < 120, f"{host}: anchor epoch {age:.0f} s old (qErr {m['anchor'].get('sawtooth_qerr_ns_this_epoch')} ns); needs f9t logger + timehat DB fresh")
            else:
                g = m.get("epoch_guard", {}); ok = g.get("epoch_ok") is True and g.get("chrony_selects_refclock") is True and not g.get("ALERT")
                row(n, ok, f"{host}: epoch_ok={g.get('epoch_ok')} chrony_selects_{g.get('expected_refid','refclock')}={g.get('chrony_selects_refclock')}" + (f" ALERT: {g['ALERT'][:80]}" if g.get("ALERT") else ""))
        except SystemExit: row(n, False, f"{host}: statement rejected by check_statement (see REFUSING line above: key, binding or execution self-report)")
        except Exception as e: row(n, False, f"{host}: {str(e)[:140]}")
    # 5. TSA: at least MIN_TSA_TOKENS of the configured TSAs must answer, or a commit writes nothing
    d_ = tempfile.mkdtemp(prefix="preflight-"); f = os.path.join(d_, "preflight.bin"); open(f, "wb").write(b"qrng-beacon-log preflight " + str(int(time.time())).encode())
    try:
        st = tsa.stamp(f, "preflight"); got = [t["tsa"] for t in st["tokens"]]
        row("tsa", len(got) >= S.MIN_TSA_TOKENS, f"{len(got)}/{len(tsa.TSAS)} tokens ({', '.join(got) or 'none'}); a commit needs {S.MIN_TSA_TOKENS}")
    except Exception as e: row("tsa", False, str(e)[:120])
    finally: shutil.rmtree(d_, ignore_errors=True)
    ready = all(r is True for r in rows)
    print("\nPREFLIGHT " + ("READY — a commit would be accepted now; the timer may be enabled" if ready else "NOT READY — fix every FAIL above before enabling the timer (a cycle would refuse and mint nothing)"))
    sys.exit(0 if ready else 1)

def cmd_status():
    seq, h, p = head(); print(f"head: seq {seq}  type {ptype(p)}  hash {h[:16]}")
    try: print("entropy host pending:", ssh("protectli", "pending"))
    except Exception as e: print("entropy host unreachable:", str(e)[:80])

if __name__ == "__main__":
    a = sys.argv[1:]; cmd = a[0] if a else "status"
    if cmd == "commit":
        opt = lambda k: a[a.index(k) + 1] if k in a else None
        cmd_commit(int(opt("--lead") or DEFAULT_LEAD), opt("--trigger"), opt("--self-trigger"), opt("--trigger-dir"), "--assume-synced" in a)
    elif cmd == "reveal": cmd_reveal(a[a.index("--drand") + 1] if "--drand" in a else None)
    elif cmd == "fail": cmd_fail(" ".join(a[1:]) or "unspecified")
    elif cmd == "finalize": cmd_finalize()
    elif cmd == "abort-unpublished": cmd_abort_unpublished()
    elif cmd == "recover": cmd_recover()
    elif cmd == "preflight": cmd_preflight()
    elif cmd == "skip": cmd_skip(" ".join(a[1:]) or "unspecified")
    else: cmd_status()
