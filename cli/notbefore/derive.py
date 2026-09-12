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

def split(records, key: bytes, frac: float):
    if not (0.0 < frac < 1.0): raise ValueError("frac must be in (0, 1)")
    s = shuffle(records, key); k = int(frac * len(s))          # floor(f * k); do not re-draw
    return s[:k], s[k:]

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
