#!/usr/bin/env python3
"""
pulse.py — attested randomness chain with COMMIT-THEN-REVEAL (v0.4).

  pulse.py commit [--lead N]   mint a COMMIT pulse: publishes sha256(entropy) bound to a FUTURE
                               drand round R = now + N (default 20 rounds = 60 s). The entropy
                               itself is held back in chain/pending/ (mode 600) until reveal.
  pulse.py reveal              mint the REVEAL pulse for the oldest pending commit. Fails closed
                               unless drand has actually released round R.
  pulse.py status              show chain head and pending commits.

Why two phases: mixing drand alone proves a value was not computable BEFORE round R, but a
single publisher could still mint many candidates AFTER R and publish a favourite. Committing
sha256(entropy) BEFORE R exists removes that freedom: once R releases, the entropy is already
fixed, and R itself was unknowable when the commitment was made. Nobody - including us - can
know the attested value before R releases, and we cannot select the entropy after.

The commitment only proves what it claims if it is PUBLISHED before R. Signing is not
publishing. See ../PUBLICATION.md.
"""
import json, base64, hashlib, subprocess, sys, time, os, glob
from concurrent.futures import ThreadPoolExecutor
import drand_anchor

HERE      = os.path.dirname(os.path.abspath(__file__))
CHAIN     = os.path.join(HERE, "..", "chain")
PENDING   = os.path.join(CHAIN, "pending")
LEGACY    = os.path.join(HERE, "..", "samples")

PROTECTLI = "willy@192.168.70.1"      # entropy: ID Quantique Quantis USB
P550      = "willy@192.168.68.44"      # time: Intel i210 PHC (authoritative)
K3        = "root@192.168.68.24"       # time witness: Milk-V, monitored peer
F9T       = "willy@192.168.68.46"      # GNSS telemetry from timehat DB

COMMIT_DOMAIN = b"grok_antics/commit/v1"
MIX_DOMAIN    = b"grok_antics/pulse-mix/v1"
DEFAULT_LEAD  = 20        # rounds; x3 s = 60 s
MIN_LEAD      = 5         # never commit to a round fewer than 15 s away

# ---------------------------------------------------------------- helpers
def ssh(host, cmd, timeout=120):
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", host, cmd],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"ssh {host} failed: {r.stderr.strip()[:200]}")
    return r.stdout.strip()

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def iso(ns):
    s, rem = divmod(int(ns), 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + f".{rem:09d}Z"

def die(msg):
    sys.stderr.write("REFUSING TO MINT: %s\n" % msg); sys.exit(2)

def get_entropy(n=32):
    d = json.loads(ssh(PROTECTLI,
        f"curl -s -m 20 'http://127.0.0.1:8080/api/v1/random/bytes?count={n}&format=base64&correction=none'"))
    if not d.get("success"):
        raise RuntimeError(f"QRNG API error: {d}")
    b = base64.b64decode(d["data"]["bytes"])
    if len(b) != n:
        raise RuntimeError(f"expected {n} bytes, got {len(b)}")
    return b

def get_stamp(host, phc, sudo):
    pre = time.time_ns()
    out = json.loads(ssh(host, f"{'sudo -n ' if sudo else ''}python3 ~/beacon/stamp_probe.py {phc}"))
    post = time.time_ns()
    return out, {"local_pre_ns": pre, "local_post_ns": post, "acquisition_window_ns": post - pre}

def get_time_block():
    """Hardware-anchored time (p550 i210 primary, k3 witness, GNSS epoch from timehat). Fails closed."""
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_pri = ex.submit(get_stamp, P550, "/dev/ptp0", True)
        f_wit = ex.submit(get_stamp, K3,   "/dev/ptp1", False)
        f_gns = ex.submit(lambda: json.loads(ssh(F9T, "python3 ~/beacon/gnss_probe.py")))
        pri, pri_acq = f_pri.result(); wit, wit_acq = f_wit.result(); gnss = f_gns.result()
    g = pri.get("epoch_guard", {})
    if g.get("epoch_ok") is False:
        die("i210 PHC epoch guard FAILED (%s) - %s" % (g.get("phc_minus_realtime_minus_tai_s"), g.get("ALERT")))
    if g.get("chrony_selects_iphc") is False:
        die("chrony no longer selects IPHC - %s" % g.get("chrony_iphc_line"))
    a = gnss["anchor"]; aq = gnss["anchor_quality"]
    # public record: hostnames, never LAN addresses
    gnss["database"]["host"] = "nas1"
    return {
        "utc": iso(int(a["utc_unix_s"] * 1e9)), "tai": iso(int(a["tai_unix_s"] * 1e9)),
        "tai_minus_utc_s": a["tai_minus_utc_s"],
        "tai_source": "GNSS broadcast leapS + 19; cross-checked against p550 kernel adjtimex = %s" % pri["tai_minus_utc_s"],
        "anchor": a, "anchor_quality": aq, "timehat_db": gnss["database"],
        "clock_chain": {
            "stamper": "Intel i210 (PCI 01:00.0) PHC /dev/ptp0 on p550; TP1 captured on SDP0 via ts2phc EXTTS",
            "reference": "u-blox ZED-F9T TP1 PPS, falling edge, 100 ms",
            "i210_discipline": pri["discipline"], "bmc_crosscheck": pri.get("mesh_crosscheck"),
            "epoch_guard": g, "chrony_primary": pri["chrony"], "chrony_witness": wit["chrony"],
            "witness_discipline": wit["discipline"],
        },
        "orchestration": {
            "note": "Software latency of assembling this record. A FRESHNESS limit, never added to the anchor.",
            "primary_observation": {"host": "p550", "observed_utc": iso(pri["stamp"]["utc_ns"]),
                                    "read_cost_ns": pri["stamp"]["chosen_read_cost_ns"], "acquisition": pri_acq},
            "witness_observation": {"host": "k3", "observed_utc": iso(wit["stamp"]["utc_ns"]),
                                    "read_cost_ns": wit["stamp"]["chosen_read_cost_ns"], "acquisition": wit_acq},
            "observation_minus_anchor_s": round(pri["stamp"]["utc_ns"] / 1e9 - a["utc_unix_s"], 3),
        },
        "precision": {
            "model": "anchored",
            "anchor_uncertainty": {
                "receiver_sawtooth_sd_ns": aq["sawtooth_sd_ns"],
                "sawtooth_this_epoch_ns": a["sawtooth_qerr_ns_this_epoch"],
                "sawtooth_applied_in_servo": False,
                "phc_sawtooth_residual_note": ("This epoch's TP1 edge fell %s ns from ideal (sign: corrected = raw + qErr, "
                                               "notebook 212). The servo does not correct it; it is reported so a consumer can." % a["sawtooth_qerr_ns_this_epoch"]),
                "i210_servo_residual_ns_rms": pri["discipline"].get("offset_ns_rms") or pri["discipline"].get("last_offset_ns"),
                "dominant_term": "ts2phc servo residual plus uncalibrated path delays",
                "not_dominant": "userspace clock read cost - it does not enter the anchor",
            },
            "calibrated_terms": ["GNSS antenna cable delay 69 ns, MEASURED (notebook 213/215)",
                                 "BMC EXTI+PHC-read latency trimmed via ptptgt 900 (notebook 214)"],
            "uncalibrated_terms": ["PPS coax length F9T TP1 -> i210 SDP0", "i210 SDP0 input latency",
                                   "i210-monitor path asymmetry, bounded +/-445 ns", "6T-vs-F9T receiver difference"],
            "absolute_utc_limit": "F9T is L1-ONLY today (0 signals on L2): absolute UTC carries an uncorrected ionospheric term. L1/L2 (TW3972) is roadmap.",
            "absolute_accuracy_claimed": False,
        },
    }

def sign_all(pulse_hash):
    sigs = {}
    for name, host, role, signer in (("entropy", PROTECTLI, "entropy_signer", "protectli"),
                                     ("time", P550, "time_attester", "p550"),
                                     ("time_witness", K3, "time_witness", "k3")):
        sig = ssh(host, f"python3 ~/beacon/sign.py {role} {pulse_hash}")
        pub = json.loads(ssh(host, f"cat ~/beacon/{role}.pub"))
        sigs[name] = {"signer": signer, "role": role, "alg": "ed25519", "key_id": pub["key_id"],
                      "public_key_b64": pub["public_key_b64"], "sig_b64": sig}
        os.makedirs(os.path.join(HERE, "keys"), exist_ok=True)
        open(os.path.join(HERE, "keys", f"{role}.pub"), "w").write(json.dumps(pub, indent=2))
    return sigs

def head():
    files = sorted(glob.glob(os.path.join(CHAIN, "pulse-*.json")))
    if files:
        p = json.load(open(files[-1])); return p["core"]["seq"], p["pulse_hash"], p
    leg = sorted(glob.glob(os.path.join(LEGACY, "pulse-*.json")))
    if leg:
        p = json.load(open(leg[-1])); return p["core"]["seq"], p["pulse_hash"], p
    return 0, "0" * 64, None

def write_pulse(seq, pulse):
    path = os.path.join(CHAIN, f"pulse-{seq:04d}.json")
    if os.path.exists(path):
        die(f"{path} already exists - the chain is append-only")
    tmp = path + ".tmp"; json.dump(pulse, open(tmp, "w"), indent=2); os.replace(tmp, path)
    return path

def mix(entropy, drand):
    buf = MIX_DOMAIN + entropy + bytes.fromhex(drand["randomness"]) + bytes.fromhex(drand["chain_hash"]) + int(drand["round"]).to_bytes(8, "big")
    return {"algorithm": "SHA256(domain || entropy || drand_randomness || chain_hash || round_be8)",
            "domain_tag": MIX_DOMAIN.decode(), "preimage_len_bytes": len(buf),
            "attested_value": hashlib.sha256(buf).hexdigest()}

DISCLOSURE = {
    "signed_payload": "sha256 of canonical(core); all signatures cover the same digest",
    "time_precision_vs_accuracy": "We claim precision and a traceable discipline chain, NOT calibrated absolute accuracy versus UTC(k).",
    "not_certified": "Not NIST/FIPS/CC validated. Not an accredited service. See CLAIMS.md.",
}

# ---------------------------------------------------------------- commit
def cmd_commit(lead):
    if lead < MIN_LEAD: die(f"lead {lead} < MIN_LEAD {MIN_LEAD}")
    try: now = drand_anchor.fetch()
    except Exception as e: die(f"drand unreachable - {e}")
    if not now["randomness_equals_sha256_signature"]: die("drand randomness != sha256(signature)")
    target = now["round"] + lead
    target_release = drand_anchor.round_time(target)
    if target_release <= time.time() + MIN_LEAD * drand_anchor.PERIOD:
        die("target round would not be safely in the future")

    seq, prev_hash, _ = head(); seq += 1
    ent = get_entropy(32)
    commitment = hashlib.sha256(COMMIT_DOMAIN + ent).hexdigest()
    tblock = get_time_block()
    if tblock["anchor"]["utc_unix_s"] >= target_release:
        die("GNSS anchor is not before the target round release - commit would be meaningless")

    core = {
        "version": "0.4", "type": "commit", "seq": seq, "prev_hash": prev_hash,
        "commitment": {
            "scheme": "SHA256(domain || entropy32)", "domain_tag": COMMIT_DOMAIN.decode(),
            "entropy_commitment": commitment, "entropy_len_bytes": 32,
            "entropy_source": {"device": "ID Quantique Quantis USB", "serial": "246578A410", "host": "protectli", "correction": "none"},
            "target_round": target, "target_release_unix_s": target_release,
            "target_release_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(target_release)),
            "lead_rounds": lead,
            "rule": ("The reveal pulse MUST disclose entropy E with SHA256(domain||E) == entropy_commitment, "
                     "and MUST mix drand round == target_round. Because E is fixed here, before target_round "
                     "exists, the attested value is unknowable to anyone - including the publisher - until "
                     "target_round releases, and the publisher cannot select E after seeing it."),
            "publication_requirement": ("This commitment proves what it claims only if it is PUBLISHED before "
                                        "target_release. Signing is not publishing. See PUBLICATION.md."),
        },
        "drand_at_commit": {**now, "meaning": "Latest round at commit time: proves this commit was made no earlier than its release."},
        "time": tblock,
    }
    if core["drand_at_commit"]["round"] >= target: die("internal: target not in the future")
    pulse_hash = hashlib.sha256(canonical(core)).hexdigest()
    pulse = {"core": core, "pulse_hash": pulse_hash, "signatures": sign_all(pulse_hash),
             "disclosure": {**DISCLOSURE,
                            "what_this_proves": "A specific 32-byte value was fixed (by hash) before drand round %d existed." % target,
                            "what_this_does_NOT_prove_yet": "Nothing about the value itself until the matching reveal pulse."}}
    # hold the secret back, mode 600, until reveal
    os.makedirs(PENDING, exist_ok=True)
    sp = os.path.join(PENDING, f"pulse-{seq:04d}.secret")
    fd = os.open(sp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps({"seq": seq, "entropy_hex": ent.hex(), "commitment": commitment,
                             "target_round": target, "pulse_hash": pulse_hash}).encode()); os.close(fd)
    path = write_pulse(seq, pulse)
    print(json.dumps({"minted": path, "type": "commit", "seq": seq, "pulse_hash": pulse_hash,
                      "target_round": target, "target_release_utc": core["commitment"]["target_release_utc"],
                      "reveal_after_s": round(target_release - time.time(), 1)}, indent=2))

# ---------------------------------------------------------------- reveal
def cmd_reveal():
    pend = sorted(glob.glob(os.path.join(PENDING, "pulse-*.secret")))
    if not pend: die("no pending commit to reveal")
    sec = json.load(open(pend[0]))
    cseq, target = sec["seq"], sec["target_round"]
    cpath = os.path.join(CHAIN, f"pulse-{cseq:04d}.json")
    commit = json.load(open(cpath))
    if commit["pulse_hash"] != sec["pulse_hash"]: die("pending secret does not match its commit pulse")
    ent = bytes.fromhex(sec["entropy_hex"])
    if hashlib.sha256(COMMIT_DOMAIN + ent).hexdigest() != commit["core"]["commitment"]["entropy_commitment"]:
        die("held entropy does not hash to the published commitment")

    # EXTERNAL "now": drand's latest round, not our clock. Fail closed if R is not out yet.
    try: latest = drand_anchor.fetch()
    except Exception as e: die(f"drand unreachable - {e}")
    if latest["round"] < target:
        die(f"drand has only reached round {latest['round']}; target {target} releases at "
            f"{commit['core']['commitment']['target_release_utc']} - wait")
    try: dr = drand_anchor.fetch(target)
    except Exception as e: die(f"could not fetch target round {target} - {e}")
    if dr["round"] != target or not dr["randomness_equals_sha256_signature"]:
        die("target round fetch inconsistent")

    seq, prev_hash, hp = head()
    if hp["pulse_hash"] != commit["pulse_hash"]:
        die("reveal must directly follow its commit in the chain (head is %s)" % hp["core"]["seq"])
    seq += 1
    mixed = mix(ent, dr)
    tblock = get_time_block()
    if tblock["anchor"]["utc_unix_s"] < dr["round_release_unix_s"]:
        die("reveal anchored before the target round released - impossible unless a clock is wrong")

    core = {
        "version": "0.4", "type": "reveal", "seq": seq, "prev_hash": prev_hash,
        "reveals": {"commit_seq": cseq, "commit_pulse_hash": commit["pulse_hash"],
                    "entropy_hex": ent.hex(), "entropy_sha256": hashlib.sha256(ent).hexdigest(),
                    "entropy_commitment": commit["core"]["commitment"]["entropy_commitment"],
                    "commit_anchor_utc": commit["core"]["time"]["utc"],
                    "commit_anchor_unix_s": commit["core"]["time"]["anchor"]["utc_unix_s"]},
        "external_anchor": {**dr, "is_committed_target": True},
        "attested_value": mixed["attested_value"], "mix": mixed,
        "time": tblock,
        "timeline": {
            "commit_anchor_unix_s": commit["core"]["time"]["anchor"]["utc_unix_s"],
            "target_round_release_unix_s": dr["round_release_unix_s"],
            "reveal_anchor_unix_s": tblock["anchor"]["utc_unix_s"],
            "commit_before_round_by_s": round(dr["round_release_unix_s"] - commit["core"]["time"]["anchor"]["utc_unix_s"], 3),
            "reveal_after_round_by_s": round(tblock["anchor"]["utc_unix_s"] - dr["round_release_unix_s"], 3),
            "reading": ("commit_before_round_by_s > 0 means the entropy was fixed before the round existed; "
                        "exact timing is what makes both edges of this window checkable rather than asserted."),
        },
    }
    pulse_hash = hashlib.sha256(canonical(core)).hexdigest()
    pulse = {"core": core, "pulse_hash": pulse_hash, "signatures": sign_all(pulse_hash),
             "disclosure": {**DISCLOSURE,
                            "attested_value_is_the_output": "Use core.attested_value.",
                            "what_this_proves": ("The attested value was unknowable to ANYONE - the publisher included - before "
                                                 "drand round %d released, and the publisher could not have chosen the entropy "
                                                 "after seeing that round, because sha256(entropy) was committed in pulse %d "
                                                 "beforehand." % (target, cseq)),
                            "residual_assumptions": ["the commit pulse was PUBLISHED (not merely signed) before the round - see PUBLICATION.md",
                                                     "drand's threshold network is honest (League of Entropy, >= threshold of independent operators)",
                                                     "SHA-256 is preimage resistant"]}}
    path = write_pulse(seq, pulse)
    os.replace(pend[0], os.path.join(PENDING, f"pulse-{cseq:04d}.revealed"))  # keep the record, never re-use
    print(json.dumps({"minted": path, "type": "reveal", "seq": seq, "reveals_commit": cseq,
                      "attested_value": mixed["attested_value"], "drand_round": target,
                      "commit_before_round_by_s": core["timeline"]["commit_before_round_by_s"],
                      "reveal_after_round_by_s": core["timeline"]["reveal_after_round_by_s"]}, indent=2))

def cmd_status():
    seq, h, p = head()
    print("head: seq %s  type %s  hash %s" % (seq, (p or {}).get("core", {}).get("type", "legacy"), h[:16]))
    for f in sorted(glob.glob(os.path.join(PENDING, "pulse-*.secret"))):
        s = json.load(open(f)); rel = drand_anchor.round_time(s["target_round"]) - time.time()
        print("pending commit seq %s -> round %s (%s)" % (s["seq"], s["target_round"],
              "revealable now" if rel <= 0 else "revealable in %.0f s" % rel))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "commit":
        lead = int(sys.argv[sys.argv.index("--lead") + 1]) if "--lead" in sys.argv else DEFAULT_LEAD
        cmd_commit(lead)
    elif cmd == "reveal": cmd_reveal()
    else: cmd_status()
