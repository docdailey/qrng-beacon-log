"""schema.py — PROTOCOL v0.5 constants shared by the aggregator (pulse.py) and the verifier (verify.py)."""
VERSION = "0.5"
TYPES = ("commit", "reveal", "failure")
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
GENESIS, PERIOD = 1692803367, 3
def release_time(rnd): return GENESIS + (int(rnd) - 1) * PERIOD          # round 1 is AT genesis (ERR-004)
COMMIT_DOMAIN = b"grok_antics/commit/v1"
MIX_DOMAIN    = b"grok_antics/pulse-mix/v1"
# statement name -> (role, host)
STATEMENTS = {"entropy": ("entropy_signer", "protectli"), "gnss": ("gnss_attester", "f9t"),
              "time": ("time_attester", "p550"), "witness": ("time_witness", "k3")}
REQUIRED = {"commit": ("entropy", "gnss", "time", "witness"),
            "reveal": ("entropy", "gnss", "time", "witness"),
            "failure": ("entropy",)}
AGGREGATOR = ("aggregator", "think")
PUBLISH_MARGIN_S, REVEAL_DEADLINE_S, MIN_TSA_TOKENS = 120, 600, 2
HEX64 = 64

# Execution self-report enforcement (review #4): from this seq onward every host statement must carry an `execution`
# block showing it ran as the confined user via the forced command with the published beacon-cmd and host config.
ENFORCE_EXECUTION_FROM_SEQ = 26
def execution_ok(ex, host, expected_path):
    import json
    if not isinstance(ex, dict): return False, "missing execution block"
    try: exp = json.load(open(expected_path))
    except Exception as e: return False, f"cannot read expected hashes: {e}"
    h = exp.get("hosts", {}).get(host)
    if not h: return False, f"no expected configuration published for host {host}"
    if ex.get("user") != "beacon": return False, f"user is {ex.get('user')!r}, expected 'beacon'"
    if ex.get("via_forced_command") is not True: return False, "not executed via the forced command"
    if ex.get("beacon_cmd_sha256") not in exp.get("beacon_cmd_sha256", []): return False, "beacon-cmd hash not among published values"
    if ex.get("host_config_sha256") != h.get("host_config_sha256"): return False, "host config hash differs from published value"
    return True, "user=beacon, forced command, beacon-cmd and host config match published hashes"
