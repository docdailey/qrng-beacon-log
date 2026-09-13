"""Test partition (review R9): the DEFAULT suite is deterministic and offline-capable; anything that needs a live service is
marked `network` and skipped under NOTBEFORE_OFFLINE=1. Under that switch the CLI is invoked with --offline (no drand or
Rekor refetch, no site cross-check); publication evidence for commit-bound contracts then comes from the local anchors
branch (origin/anchors in a full clone, or an anchors/ directory).

  network   RFC 3161 timestamping (freetsa, DigiCert), Rekor-direct lookups, drand fetches, the live decision log
            (the live log additionally needs NOTBEFORE_LIVE_LOG_TEST=1 because it appends real entries)

  NOTBEFORE_OFFLINE=1 python -m pytest -q cli/tests -m "not network"     # default in CI, every supported Python
  python -m pytest -q cli/tests -m network                               # the live-service job"""
import os, pytest

def pytest_configure(config):
    config.addinivalue_line("markers", "network: needs a live external service (TSA, Rekor, drand relays, the decision log)")

def pytest_collection_modifyitems(config, items):
    if os.environ.get("NOTBEFORE_OFFLINE") == "1":
        skip = pytest.mark.skip(reason="NOTBEFORE_OFFLINE=1: needs a live external service")
        for it in items:
            if "network" in it.keywords: it.add_marker(skip)
