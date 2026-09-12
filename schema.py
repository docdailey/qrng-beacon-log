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
