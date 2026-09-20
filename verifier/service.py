"""Verifier service: decision logic with explicit inputs. No Flask, no globals.

``decide_decision`` takes the trust bundle, a mutable nonce registry and the
current time as arguments, so nonce TTL/consumption is unit-testable without
HTTP. ``verifier/app.py`` passes its live globals through thin wrappers.
"""
import hashlib
import hmac
import json
import logging
import os
from typing import Any

from shared import config
from shared.crypto import CLOCK_SKEW_SEC, otp6, verify_sig
from shared.schemas import (
    CRED_MAX_BYTES, REASONS, TRUSTBUNDLE_REQUIRED_FIELDS, malformed, unsigned_body,
)

log = logging.getLogger("verifier.service")


def pairing_ok(presented: Any, required: str) -> bool:
    """Constant-time pairing-token comparison. Non-string input never matches."""
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented, required)


def prune_nonces(nonces: dict[str, float], now: float, ttl: int) -> None:
    """Drop challenges older than the TTL (mutates the passed registry)."""
    for nonce, issued in list(nonces.items()):
        if now - issued > ttl:
            del nonces[nonce]


def decide_decision(cred: dict, nonce: str, *, trust: dict | None,
                    nonces: dict[str, float], now: float, ttl: int,
                    skew: int = CLOCK_SKEW_SEC,
                    max_bytes: int = CRED_MAX_BYTES) -> tuple[str, str]:
    """Order: trust -> shape -> size -> expiry -> challenge -> sig ->
    issuer-match -> revocation -> attribute.

    Challenges are single-use: a registered nonce is consumed on ANY use
    (success or failure), so an intercepted live credential cannot be replayed
    inside the window. Returns (YES/NO, reason)."""
    if trust is None:
        return "NO", "NO_TRUSTBUNDLE"
    if malformed(cred):
        return "NO", "MALFORMED"
    if len(json.dumps(cred)) > max_bytes:
        return "NO", "TOO_LARGE"
    if cred["exp"] + skew < now:
        return "NO", "EXPIRED"
    # Live-challenge binding: the nonce must be one THIS verifier issued and
    # still fresh, and the credential must echo it under issuer signature.
    if nonce:
        prune_nonces(nonces, now, ttl)
        issued = nonces.get(nonce)
        if issued is None or now - issued > ttl:
            return "NO", "UNKNOWN_CHALLENGE"
        del nonces[nonce]  # consume: one challenge, one attempt
        if cred.get("n") != nonce:
            return "NO", "REPLAY"
    body = unsigned_body(cred)
    if not verify_sig(body, cred["s"], trust["pubkey_hex"]):
        return "NO", "BADSIG"
    if cred.get("iss") != trust.get("iss"):
        return "NO", "BADSIG"
    # Status lists from the signed bundle (per-verifier pseudonyms — no PII).
    # Revocation/minor status applies immediately after a sync, independent of
    # the signed r-flag inside older credentials.
    if cred["uid_p"] in (trust.get("revoked") or []):
        return "NO", "REVOKED"
    if cred["uid_p"] in (trust.get("minors") or []):
        return "NO", "NOT_ADULT"
    if cred.get("a") == "over_18" and cred.get("r") == 1:
        return "YES", "OK"
    return "NO", "NOT_ADULT"


def match_otp_code(secrets: dict, code: str, verifier_id: str, step: int,
                   grace_steps: int = config.OTP_GRACE_STEPS) -> str | None:
    """Find the holder pseudonym whose secret yields this code (current step
    plus grace window), else None. The match identifies WHO, so bundle status
    lists can be enforced — a bare valid code is never enough."""
    for uid_p, secret in secrets.items():
        if any(code == otp6(secret, verifier_id, step - back)
               for back in range(grace_steps + 1)):
            return uid_p
    return None


def otp_status(uid_p: str, trust: dict) -> tuple[str, str]:
    """Enforce holder status for an OTP-identified pseudonym."""
    if uid_p in (trust.get("revoked") or []):
        return "NO", "REVOKED"
    if uid_p in (trust.get("minors") or []):
        return "NO", "NOT_ADULT"
    return "YES", "OK_OTP"


def validate_bundle(bundle: dict) -> str | None:
    """Shape-check a posted trust bundle. None if OK, else an error reason."""
    if not isinstance(bundle, dict):
        return "MALFORMED"
    if not TRUSTBUNDLE_REQUIRED_FIELDS.issubset(bundle.keys()):
        return "MALFORMED"
    if not isinstance(bundle["pubkey_hex"], str) or len(bundle["pubkey_hex"]) != 64:
        return "MALFORMED"
    if not isinstance(bundle["v"], int):
        return "MALFORMED"
    for lst in ("revoked", "minors"):
        if lst in bundle and not isinstance(bundle[lst], list):
            return "MALFORMED"
    return None


def bundle_sig_body(bundle: dict) -> dict:
    """The exact dict the issuer signs: operator-supplied extras (pairing
    token, locally provisioned OTP secrets) are excluded so they can ride
    along without breaking the issuer signature."""
    return {k: v for k, v in bundle.items()
            if k not in ("s", "pairing_token", "otp_secrets")}


def verify_bundle_sig(body: dict, sig: str, pubkey_hex: str) -> bool:
    """Check a trust-bundle signature (rollback/swap protection)."""
    if not isinstance(sig, str):
        return False
    return verify_sig(body, sig, pubkey_hex)


def check_reason(reason: str) -> bool:
    """The response reason must stay inside the stable contract set."""
    return reason in REASONS


def load_receipt_key(keys_dir: str) -> str:
    """HMAC key for the receipt chain, persisted so restarts stay verifiable.

    Anyone with DB *and* key access can still rewrite history — the chain
    proves tampering to key-less auditors, nothing more (see README limits)."""
    if config.ON_VERCEL:
        return os.environ.get(config.RECEIPT_HMAC_KEY_ENV, "vercel-demo-key")
    import secrets as _rand

    os.makedirs(keys_dir, exist_ok=True)
    key_file = os.path.join(keys_dir, "receipt_hmac.key")
    if os.path.exists(key_file):
        with open(key_file) as f:
            return f.read().strip()
    key = _rand.token_hex(32)
    with open(key_file, "w") as f:
        f.write(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


def chain_entry(prev_hash: str, ts: int, verifier_id: str, q: str, result: str,
                nonce_hash: str, sig_hash: str, key: str) -> str:
    """One HMAC chain link over the stored (already peppered) fields."""
    raw = f"{prev_hash}|{ts}|{verifier_id}|{q}|{result}|{nonce_hash}|{sig_hash}"
    return hmac.new(key.encode(), raw.encode(), hashlib.sha256).hexdigest()


def peppered(value: str, key: str) -> str:
    """One-way hash for receipt fields. A bare 6-digit OTP (or nonce) must not
    be brute-forceable by readers of the public /receipts endpoint."""
    return hashlib.sha256((key + value).encode()).hexdigest()
