"""NotBefore — the consumer side of the qrng-beacon-log: verify one hourly commit-then-reveal pair with a
pinned, vendored verifier, and derive labeled seeds / shuffles / splits from its attested value.

Spec: NOTBEFORE.md in https://github.com/docdailey/qrng-beacon-log (version in SPEC below). Not a certification of anything.
"""
__version__ = "0.6.0"
SPEC = "notbefore/spec/0.5"
D_DERIVE = b"notbefore/derive/v1"
D_SHUFFLE = b"notbefore/shuffle/v1"
DEFAULT_REPO = "https://github.com/docdailey/qrng-beacon-log.git"
FIRST_ELIGIBLE_REVEAL = 21          # 0020/0021; 18/19 are KNOWN-NONCOMPLIANT (ERR-007)
ANCHOR_GRACE_S = 1500               # a pulse older than this with no anchor is non-compliant
