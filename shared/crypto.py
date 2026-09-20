"""Cryptography: Ed25519 (issuer + receipts), HMAC pseudonyms, P-256 holder
proofs (P1363 raw r||s from WebCrypto, converted to DER for verification).
Base64url everywhere, no padding. Pure functions, no I/O.
"""
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256


def b64u_encode(raw: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Base64url without padding. Raises on garbage (callers map to 400)."""
    if not isinstance(text, str):
        raise TypeError("b64u input must be str")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_fingerprint(pub_hex: str) -> str:
    """Operator-facing key fingerprint: first 8 bytes, grouped."""
    raw = pub_hex[:16]
    return " ".join(raw[i:i + 4] for i in range(0, 16, 4))


def ed25519_keypair() -> tuple[str, str]:
    """Fresh (priv_hex, pub_hex) pair, raw 32-byte keys as hex."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw().hex(), pub.public_bytes_raw().hex()


def ed25519_sign(priv_hex: str, data: bytes) -> str:
    """Sign bytes; return base64url signature."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return b64u_encode(priv.sign(data))


def ed25519_verify(pub_hex: str, sig_b64u: str, data: bytes) -> bool:
    """Verify an Ed25519 signature. Never raises on bad input."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(b64u_decode(sig_b64u), data)
        return True
    except Exception:
        return False


def pseudonym(master_secret_hex: str, verifier_id: str) -> str:
    """Pairwise pseudonym: first 16 BYTES of HMAC-SHA256, hex (32 chars).
    Different per shop, so shops cannot join records."""
    digest = hmac.new(bytes.fromhex(master_secret_hex),
                      verifier_id.encode(), hashlib.sha256).digest()
    return digest[:16].hex()


def otp_code(secret_hex: str, verifier_id: str, step: int) -> str:
    """6-digit code = HMAC-SHA256(secret, verifier_id|step) mod 10^6."""
    digest = hmac.new(bytes.fromhex(secret_hex),
                      f"{verifier_id}|{step}".encode(), hashlib.sha256).hexdigest()
    return str(int(digest, 16) % 1_000_000).zfill(6)


def p256_pubkey_from_b64u(raw_b64u: str):
    """Parse a base64url uncompressed P-256 point (65 bytes, 0x04 prefix).
    Raises on any malformation (callers map to 400/BAD_PUBKEY)."""
    raw = b64u_decode(raw_b64u)
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("P-256 public key must be 65-byte uncompressed point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def p1363_to_der(raw_sig_b64u: str) -> bytes:
    """Convert a WebCrypto raw r||s (IEEE P1363, 64 bytes) signature to DER.
    Raises on any malformation."""
    raw = b64u_decode(raw_sig_b64u)
    if len(raw) != 64:
        raise ValueError("P-256 signature must be 64-byte raw r||s")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    return encode_dss_signature(r, s)


def p256_verify(pub_b64u: str, raw_sig_b64u: str, msg: bytes) -> bool:
    """Verify a WebCrypto P-256/SHA-256 signature. Never raises on bad input."""
    try:
        pub = p256_pubkey_from_b64u(pub_b64u)
        pub.verify(p1363_to_der(raw_sig_b64u), msg, ec.ECDSA(SHA256()))
        return True
    except Exception:
        return False
