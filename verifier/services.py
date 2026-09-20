"""Verifier service: decision logic with explicit inputs. No Flask, no globals.

The decision order implements docs/protocol.md exactly; every failure maps to
a stable reason code. Nonce consumption is delegated to the repository's
atomic DELETE so concurrent claimants cannot double-spend a challenge.
"""
import hashlib
import hmac
import logging
import secrets
from typing import Any

from shared import config
from shared.canonical import canonical
from shared.crypto import ed25519_keypair, ed25519_verify, otp_code, p256_verify, sha256_hex
from shared.errors import REASONS
from shared.schemas import (
    CRED_MAX_BYTES, bundle_sig_body, signed_body,
    validate_bundle_shape, validate_credential, validate_proof,
)
from verifier import repo as _repo

log = logging.getLogger("verifier.service")


def pairing_ok(presented: Any, required: str) -> bool:
    """Constant-time pairing-token comparison. Non-string never matches."""
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented, required)


def mint_challenge(*, verifier_id: str, now: float, ttl_sec: int) -> dict:
    """Fresh shop challenge for the challenge-QR: {n, vid, exp}."""
    issued = int(now)
    return {"n": secrets.token_hex(16), "vid": verifier_id, "exp": issued + ttl_sec}


def proof_message(*, cred_canonical_sha: str, nonce: str, vid: str, ts: int) -> bytes:
    """Exact bytes the holder signs: canonical list per docs/protocol.md."""
    return canonical(["yn-proof-v1", cred_canonical_sha, nonce, vid, ts])


def decide(cred: dict, proof: dict | None, raw_len: int, *, trust: dict | None,
           verifier_id: str, now: float,
           consume_nonce,
           ttl_sec: int = config.NONCE_TTL_SEC,
           skew_sec: int = config.CLOCK_SKEW_SEC,
           proof_window_sec: int = config.PROOF_TS_WINDOW_SEC,
           max_bytes: int = CRED_MAX_BYTES) -> tuple[str, str]:
    """Full decision order (docs/protocol.md). ``consume_nonce(nonce,
    min_issued, now)`` must atomically take a fresh nonce or return None.

    Returns (YES/NO, reason). Proof is mandatory: there is no code path that
    accepts a credential without a fresh holder proof.
    """
    if trust is None:
        return "NO", "NO_TRUSTBUNDLE"
    shape_err = validate_credential(cred)
    if shape_err:
        return "NO", shape_err
    if raw_len > max_bytes:
        return "NO", "TOO_LARGE"
    if cred.get("vid") != verifier_id:
        return "NO", "WRONG_VERIFIER"
    if cred.get("iss") != trust.get("iss"):
        return "NO", "ISSUER_MISMATCH"
    if cred["exp"] + skew_sec < now:
        return "NO", "EXPIRED"
    try:
        body = signed_body(cred)
    except Exception:
        return "NO", "MALFORMED"
    if not ed25519_verify(trust["pub"], cred["s"], canonical(body)):
        return "NO", "BADSIG"
    if proof is None:
        return "NO", "BAD_PROOF"
    proof_err = validate_proof(proof)
    if proof_err:
        return "NO", proof_err
    claimed = consume_nonce(proof["n"], now - ttl_sec, now)
    if claimed is None:
        return "NO", "UNKNOWN_CHALLENGE"
    if abs(now - proof["ts"]) > proof_window_sec:
        return "NO", "BAD_PROOF"
    # vid binding lives in the signed message (recomputed with OUR vid), so a
    # proof minted for another shop cannot verify here.
    msg = proof_message(cred_canonical_sha=sha256_hex(canonical(body)),
                        nonce=proof["n"], vid=verifier_id, ts=proof["ts"])
    if not p256_verify(cred["cnf"], proof["sig"], msg):
        return "NO", "BAD_PROOF"
    if cred["sub"] in (trust.get("revoked") or []):
        return "NO", "REVOKED"
    if cred["sub"] in (trust.get("minors") or []):
        return "NO", "NOT_ADULT"
    if cred.get("a") != "over_18" or cred.get("r") != 1:
        return "NO", "NOT_ADULT"
    return "YES", "OK"


def check_bundle(bundle: dict, *, pinned: dict | None, now: float) -> tuple[bool, str | None]:
    """Validate a posted bundle against pinning. Returns (accepted, reason).

    First sync is TOFU (pins, caller logs fingerprint). Later syncs need a
    signature from the pinned key OR the chained next_pub, a monotonic version,
    matching vid/iss and a future exp.
    """
    shape_err = validate_bundle_shape(bundle)
    if shape_err:
        return False, shape_err
    if bundle["exp"] <= now:
        return False, "EXPIRED"
    if pinned is None or not pinned.get("pub"):
        return True, None  # TOFU: caller pins + shows fingerprint
    if bundle.get("iss") != pinned.get("iss") or bundle.get("vid") != pinned.get("vid"):
        return False, "ISSUER_MISMATCH"
    if bundle["v"] < pinned.get("v", 0):
        return False, "ROLLBACK"
    body = bundle_sig_body(bundle)
    if ed25519_verify(pinned["pub"], bundle["s"], canonical(body)):
        return True, None
    chained = pinned.get("next_pub")
    if chained and ed25519_verify(chained, bundle["s"], canonical(body)):
        return True, None
    return False, "BADSIG"


def match_otp_code(secrets: dict, code: str, verifier_id: str, step: int,
                   grace_steps: int = config.OTP_GRACE_STEPS) -> str | None:
    """Find the holder sub whose secret yields this code (current + grace
    steps), else None. The match identifies WHO, so bundle status lists can be
    enforced — a bare valid code is never enough."""
    for sub, secret in secrets.items():
        for back in range(grace_steps + 1):
            if code == otp_code(secret, verifier_id, step - back):
                return sub
    return None


def otp_status(sub: str, trust: dict) -> tuple[str, str]:
    """Enforce holder status for an OTP-identified pseudonym."""
    if sub in (trust.get("revoked") or []):
        return "NO", "REVOKED"
    if sub in (trust.get("minors") or []):
        return "NO", "NOT_ADULT"
    return "YES", "OK_OTP"

def load_receipt_key(db_path: str) -> str:
    """Verifier Ed25519 receipt-signing key, generated once, kept in kv."""
    stored = _repo.kv_get(db_path, "receipt_priv")
    if stored:
        return stored
    priv, _pub = ed25519_keypair()
    _repo.kv_set(db_path, "receipt_priv", priv)
    return priv


def receipt_pub(db_path: str) -> str:
    """Public half of the receipt-signing key (published in exports)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = load_receipt_key(db_path)
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(priv)).public_key().public_bytes_raw().hex()


def chain_entry(prev_hash: str, ts: int, verifier_id: str, q: str, result: str,
                reason: str, key: str) -> str:
    """One HMAC chain link. No raw nonce/credential/code material is stored or
    hashed into receipts — identical checks in the same second hash alike, and
    the chain position (prev link) is what makes each entry unique."""
    raw = f"{prev_hash}|{ts}|{verifier_id}|{q}|{result}|{reason}"
    return hmac.new(key.encode(), raw.encode(), hashlib.sha256).hexdigest()


def sign_head(key_priv_hex: str, head_hash: str, ts: int) -> str:
    """Sign the chain head (periodic + on export) for auditor verification."""
    from shared.crypto import ed25519_sign

    return ed25519_sign(key_priv_hex, canonical({"head": head_hash, "ts": ts}))


def check_reason(reason: str) -> bool:
    """The response reason must stay inside the stable contract set."""
    return reason in REASONS