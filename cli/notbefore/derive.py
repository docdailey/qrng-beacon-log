"""The derive layer (NOTBEFORE.md §7): labeled seed, shuffle, split, transcript. Pure functions; no I/O."""
import hashlib, re, unicodedata, json, time
from . import D_DERIVE, D_SHUFFLE, SPEC, __version__

PURPOSE_RE = re.compile(r"^[A-Za-z0-9._:/=@+-]+$")

class PurposeError(ValueError): pass

def normalize_purpose(purpose: str) -> bytes:
    """UTF-8 NFC, 1–256 bytes, CLI-safe charset, no newline. Returns the exact bytes that enter the hash."""
    if not isinstance(purpose, str) or purpose == "": raise PurposeError("purpose must be a non-empty string")
    if "\n" in purpose or "\r" in purpose: raise PurposeError("purpose must not contain a newline")
    p = unicodedata.normalize("NFC", purpose).encode("utf-8")
    if len(p) > 256: raise PurposeError("purpose must be at most 256 bytes of UTF-8")
    if not PURPOSE_RE.match(p.decode("utf-8")): raise PurposeError("purpose must match ^[A-Za-z0-9._:/=@+-]+$ (no spaces; use - or _)")
    return p

def seed(attested_value_hex: str, purpose: str) -> bytes:
    """S = SHA256( 'notbefore/derive/v1' || V || purpose ). V is the 32 raw bytes of the attested value."""
    V = bytes.fromhex(attested_value_hex)
    if len(V) != 32: raise ValueError("attested_value must be 32 bytes")
    return hashlib.sha256(D_DERIVE + V + normalize_purpose(purpose)).digest()

def rank(key: bytes, i: int, record: str) -> bytes:
    return hashlib.sha256(D_SHUFFLE + key + i.to_bytes(8, "big") + record.encode("utf-8")).digest()

def shuffle(records, key: bytes):
    """Stable sort by rank ascending; tie-break on the hex of the record bytes. Input order is part of the transcript."""
    if len(key) != 32: raise ValueError("key must be the 32-byte derived seed")
    ranked = [(rank(key, i, x), x.encode("utf-8").hex(), x) for i, x in enumerate(records)]
    ranked.sort(key=lambda t: (t[0], t[1]))
    return [t[2] for t in ranked]

def split(records, key: bytes, frac):
    """A = the first floor(frac · n) of the shuffle. frac is taken as an EXACT decimal (Fraction(str(frac))), never a
    binary float, so 0.8 × 20 is exactly 16 in every implementation."""
    from fractions import Fraction
    fr = Fraction(str(frac))
    if not (0 < fr < 1): raise ValueError("frac must be in (0, 1)")
    s = shuffle(records, key); k = int(fr * len(s))            # floor; do not re-draw
    return s[:k], s[k:]

# ---- one more deterministic step on S (spec 0.4). Every function is a pure function of (S, inputs); nothing is secret.
D_ID, D_RANGE, D_BYTES = b"notbefore/id/v1", b"notbefore/range/v1", b"notbefore/bytes/v1"

def sample(records, key: bytes, k: int):
    """shuffle, take the first k. `exactly 12` — split with an odd frac is the wrong tool."""
    if not (0 <= k <= len(records)): raise ValueError(f"k must be between 0 and {len(records)}")
    return shuffle(records, key)[:k]

def assign(records, key: bytes, arms: int):
    """shuffle; shuffled position i -> arm i mod arms (0-based). Balanced arms without a size cut. Returns [(record, arm)] in shuffled order."""
    if arms < 1: raise ValueError("arms must be >= 1")
    return [(x, i % arms) for i, x in enumerate(shuffle(records, key))]

def pseudonym(record: str, key: bytes, hexlen: int = 16) -> str:
    """SHA256(notbefore/id/v1 || S || record) truncated to hexlen hex chars. A PSEUDONYM, not a secret: anyone holding the
    name list and the public S can recompute it. It blinds readers who lack the names; it does not encrypt them."""
    if not (8 <= hexlen <= 64): raise ValueError("hexlen must be 8..64")
    return hashlib.sha256(D_ID + key + record.encode("utf-8")).hexdigest()[:hexlen]

def stream(key: bytes, domain: bytes, n: int) -> bytes:
    """Counter-mode SHA-256: SHA256(domain || S || counter_be8) for counter = 0, 1, ... concatenated; first n bytes."""
    out, c = b"", 0
    while len(out) < n: out += hashlib.sha256(domain + key + c.to_bytes(8, "big")).digest(); c += 1
    return out[:n]

def rand_bytes(key: bytes, n: int) -> bytes:
    if not (1 <= n <= 1 << 20): raise ValueError("n must be 1..1048576")
    return stream(key, D_BYTES, n)

def rand_range(key: bytes, lo: int, hi: int) -> int:
    """Uniform integer in [lo, hi] by rejection sampling over 64-bit chunks of counter-mode SHA-256 (domain notbefore/range/v1).
    chunk = SHA256(D_RANGE || S || counter_be8)[:8] as uint64 BE; accept if chunk < floor(2^64 / span) * span."""
    if lo > hi: raise ValueError("lo must be <= hi")
    span = hi - lo + 1
    if span > (1 << 64): raise ValueError("range span must be <= 2^64 (notbefore/range/v1 samples 64-bit chunks; a wider span would never accept)")
    if span == 1: return lo
    limit = ((1 << 64) // span) * span; c = 0
    while True:
        r = int.from_bytes(hashlib.sha256(D_RANGE + key + c.to_bytes(8, "big")).digest()[:8], "big"); c += 1
        if r < limit: return lo + (r % span)

def sha256_hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()

def transcript(check, purpose: str, derived: bytes, extra=None):
    """The engineering artifact (§7.5). `check` is a CheckResult from notbefore.check."""
    t = {"spec": SPEC, "derive_domain": D_DERIVE.decode(), "seq": check.seq, "commit_seq": check.commit_seq,
         "pulse_hash_reveal": check.pulse_hash_reveal, "pulse_hash_commit": check.pulse_hash_commit,
         "attested_value": check.attested_value, "drand_round": check.drand_round,
         "purpose": normalize_purpose(purpose).decode("utf-8"), "derived_seed": derived.hex(),
         "verifier_git_sha": check.verifier_git_sha, "log_git_sha": check.log_git_sha, "log_ref": check.log_ref,
         "cli_version": __version__, "verified_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "checks": check.summary()}
    if extra: t.update(extra)
    return t
