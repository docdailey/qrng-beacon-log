"""Consumer identity (NOTBEFORE.md §7.12): one Ed25519 key per consumer, generated locally, never uploaded.

  notbefore keygen          -> ~/.config/notbefore/identity.key (PKCS8 PEM, mode 0600) + identity.pub
  key_id = SHA256(raw 32-byte public key)[:16] hex — the same convention the log's own host keys use (PROTOCOL.md §5).

The key signs DECISION STATEMENTS (decisionlog.py): "this key commits to contract <sha256> under decision_id <d>".
It is an identity for the write-once namespace (key_id, decision_id), not a secret shared with anyone. Losing it means
starting a new namespace; there is no recovery and no escrow by design."""
import os, base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class IdentityError(Exception): pass

def default_path():
    return os.environ.get("NOTBEFORE_KEY") or os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "notbefore", "identity.key")

def key_id_of(pub_raw: bytes) -> str: return hashlib.sha256(pub_raw).hexdigest()[:16]

def generate(path=None, force=False):
    """Write a new identity. Refuses to overwrite unless force. Returns (path, key_id, pub_b64)."""
    path = path or default_path()
    if os.path.exists(path) and not force: raise IdentityError(f"{path} exists; pass --force to replace it (the old key_id's namespace is then abandoned)")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, pem); os.close(fd); os.chmod(path, 0o600)
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    open(path + ".pub" if not path.endswith(".key") else path[:-4] + ".pub", "w").write(f"{key_id_of(pub_raw)} ed25519 {base64.b64encode(pub_raw).decode()}\n")
    return path, key_id_of(pub_raw), base64.b64encode(pub_raw).decode()

def load(path=None):
    """-> (priv, pub_raw, key_id, pub_b64). IdentityError with the fix if the key is missing or unreadable."""
    path = path or default_path()
    if not os.path.exists(path): raise IdentityError(f"no identity at {path}: run `notbefore keygen` (or set NOTBEFORE_KEY / --key)")
    try: priv = serialization.load_pem_private_key(open(path, "rb").read(), None)
    except Exception as e: raise IdentityError(f"cannot read {path}: {e}")
    if not isinstance(priv, Ed25519PrivateKey): raise IdentityError(f"{path} is not an Ed25519 key")
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub_raw, key_id_of(pub_raw), base64.b64encode(pub_raw).decode()

def sign(priv, data: bytes) -> str: return base64.b64encode(priv.sign(data)).decode()

def verify(pub_raw: bytes, sig_b64: str, data: bytes) -> bool:
    try: Ed25519PublicKey.from_public_bytes(pub_raw).verify(base64.b64decode(sig_b64), data); return True
    except (InvalidSignature, ValueError): return False
