#!/usr/bin/env python3
"""
watcher.py — independent non-reveal auditor for the qrng-beacon-log. Anyone can run this.

It needs NO access to the operator's systems: it reads the public log via the GitHub API, reads
drand via the League of Entropy, and publishes signed findings under ITS OWN key to a repo the
operator does not control. That is what turns a skipped reveal from "visible" into "attested".

    pip install cryptography
    WATCH_REPO=docdailey/qrng-beacon-log OUT_DIR=~/beacon-watch python3 watcher.py

For every commit pulse whose target_release + REVEAL_DEADLINE_S has passed (judged by drand's own
round clock, not this machine's) with no matching reveal, it writes
  OUT_DIR/non-reveal/pulse-NNNN.json   signed with OUT_DIR/watcher.key (ed25519, created on first run)
and, if OUT_DIR is a git checkout, commits and pushes. It also records every reveal it did observe,
so the watcher's own history shows it was actually watching.
"""
import os, sys, json, time, base64, hashlib, urllib.request, subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REPO   = os.environ.get("WATCH_REPO", "docdailey/qrng-beacon-log")
OUT    = os.path.expanduser(os.environ.get("OUT_DIR", "~/beacon-watch"))
DEADLINE = int(os.environ.get("REVEAL_DEADLINE_S", "600"))
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
GENESIS, PERIOD = 1692803367, 3
UA = {"User-Agent": "qrng-beacon-watcher/1"}

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
        return json.loads(r.read().decode())

def key():
    os.makedirs(OUT, exist_ok=True)
    kp = os.path.join(OUT, "watcher.key")
    if os.path.exists(kp):
        return serialization.load_pem_private_key(open(kp, "rb").read(), None)
    k = Ed25519PrivateKey.generate()
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); os.close(fd)
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    json.dump({"alg": "ed25519", "key_id": hashlib.sha256(pub).hexdigest()[:16], "public_key_b64": base64.b64encode(pub).decode(),
               "role": "non-reveal watcher", "watching": REPO}, open(os.path.join(OUT, "watcher.pub"), "w"), indent=2)
    return k

def signed(k, doc):
    body = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"record": doc, "record_sha256": hashlib.sha256(body).hexdigest(),
            "signature": {"alg": "ed25519", "key_id": hashlib.sha256(pub).hexdigest()[:16],
                          "public_key_b64": base64.b64encode(pub).decode(),
                          "sig_b64": base64.b64encode(k.sign(body)).decode()}}

def main():
    k = key()
    drand_round = get(f"https://api.drand.sh/{CHAIN_HASH}/public/latest")["round"]
    drand_now = GENESIS + (drand_round - 1) * PERIOD    # external clock; round 1 is AT genesis (ERR-004)
    listing = get(f"https://api.github.com/repos/{REPO}/contents/chain")
    pulses = {}
    for f in listing:
        if f["name"].startswith("pulse-") and f["name"].endswith(".json") and ".FAILED" not in f["name"] and ".tsa" not in f["name"]:
            pulses[f["name"]] = get(f["download_url"])
    commits = {p["core"]["seq"]: p for p in pulses.values() if p["core"].get("type") == "commit"}
    reveals = {p["core"]["reveals"]["commit_seq"]: p for p in pulses.values() if p["core"].get("type") == "reveal"}
    failed  = {int(f["name"].split("-")[1][:4]) for f in listing if ".FAILED" in f["name"]}
    os.makedirs(os.path.join(OUT, "non-reveal"), exist_ok=True); os.makedirs(os.path.join(OUT, "observed"), exist_ok=True)
    new = []
    for seq, c in sorted(commits.items()):
        cm = c["core"]["commitment"]; target_release = cm["target_release_unix_s"]
        if seq in reveals:
            r = reveals[seq]; op = os.path.join(OUT, "observed", f"pulse-{seq:04d}.json")
            if not os.path.exists(op):
                doc = {"kind": "REVEAL-OBSERVED", "commit_seq": seq, "reveal_seq": r["core"]["seq"], "commit_pulse_hash": c["pulse_hash"],
                       "reveal_pulse_hash": r["pulse_hash"], "drand_round": r["core"]["external_anchor"]["round"],
                       "commitment_ok": hashlib.sha256(b"grok_antics/commit/v1" + bytes.fromhex(r["core"]["reveals"]["entropy_hex"])).hexdigest() == cm["entropy_commitment"],
                       "watched_repo": REPO, "observed_unix": int(time.time()), "drand_round_at_observation": drand_round}
                json.dump(signed(k, doc), open(op, "w"), indent=2); new.append(op)
            continue
        if drand_now < target_release + DEADLINE:
            continue                                     # still inside the reveal window
        np_ = os.path.join(OUT, "non-reveal", f"pulse-{seq:04d}.json")
        if os.path.exists(np_): continue
        doc = {"kind": "NON-REVEAL", "commit_seq": seq, "commit_pulse_hash": c["pulse_hash"], "entropy_commitment": cm["entropy_commitment"],
               "target_round": cm["target_round"], "target_release_unix_s": target_release, "reveal_deadline_s": DEADLINE,
               "operator_marked_failed": seq in failed, "watched_repo": REPO,
               "drand_round_at_observation": drand_round, "drand_time_at_observation_unix_s": drand_now, "observed_unix": int(time.time()),
               "statement": ("The operator published a commitment to drand round %d and did not publish a matching reveal within %d s of "
                             "that round's release, as judged by drand's own round clock. This pulse must be treated as failed." % (cm["target_round"], DEADLINE))}
        json.dump(signed(k, doc), open(np_, "w"), indent=2); new.append(np_)
        print("NON-REVEAL:", np_)
    if new and os.path.isdir(os.path.join(OUT, ".git")):
        subprocess.run(["git", "-C", OUT, "add", "-A"]); subprocess.run(["git", "-C", OUT, "commit", "-q", "-m", f"watcher: {len(new)} record(s) at drand round {drand_round}"])
        subprocess.run(["git", "-C", OUT, "push", "-q"])
    print(json.dumps({"commits": len(commits), "reveals": len(reveals), "failed_markers": len(failed), "new_records": len(new), "drand_round": drand_round}))

if __name__ == "__main__":
    main()
