"""Shared crypto for Track B. Ed25519 + HMAC pseudonyms + hash-chained receipts.
agency: secrets-credential-engineer | ECC: security-review, backend-patterns service layer.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

EXPIRY_SEC = 300
CLOCK_SKEW_SEC = 30


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def gen_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return (priv.private_bytes_raw().hex(), pub.public_bytes_raw().hex())


def sign_cred(payload_without_s: dict, priv_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return b64u_encode(priv.sign(canonical(payload_without_s)))


def verify_sig(payload_without_s: dict, sig_b64u: str, pub_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(b64u_decode(sig_b64u), canonical(payload_without_s))
        return True
    except Exception:
        return False


def pseudonym(master_secret_hex: str, verifier_id: str) -> str:
    """Pairwise ID: same user maps to different IDs per shop. Stops linkability."""
    return hmac.new(
        bytes.fromhex(master_secret_hex), verifier_id.encode(), hashlib.sha256
    ).hexdigest()[:16]


def gen_nonce() -> str:
    return secrets.token_hex(16)


def otp6(secret_hex: str, verifier_id: str, t_step: int | None = None) -> str:
    """Feature-phone fallback: 6-digit, 30s step, single-use enforced by verifier."""
    if t_step is None:
        t_step = int(time.time() // 30)
    msg = f"{verifier_id}|{t_step}".encode()
    d = hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).hexdigest()
    return str(int(d, 16) % 1_000_000).zfill(6)


def receipt_hash(prev_hash: str, ts: int, verifier_id: str, q: str,
                 result: str, nonce_hash: str, sig_hash: str) -> str:
    raw = f"{prev_hash}|{ts}|{verifier_id}|{q}|{result}|{nonce_hash}|{sig_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]
