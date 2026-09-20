"""Issuer service: business logic with explicit inputs. No Flask, no globals.

All functions take what they need as arguments so they are unit-testable in
isolation; ``issuer/app.py`` wires them to HTTP + module configuration.
"""
import hmac
import logging
import os
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared import config
from shared.crypto import EXPIRY_SEC, gen_keypair, otp6, pseudonym, sign_cred
from shared.schemas import CRED_REQUIRED_FIELDS, unsigned_body

log = logging.getLogger("issuer.service")


class UnknownUserError(LookupError):
    """No such user enrolled."""


class RevokedError(PermissionError):
    """User is revoked: must not be issued to."""


class ContractDriftError(RuntimeError):
    """Built credential disagrees with shared.schemas (server bug, not input)."""


class EnvManagedKeyError(RuntimeError):
    """Rotation requested while the key comes from the environment."""


def is_adult(dob_str: str, today: date | None = None) -> bool:
    """Calendar-correct 18+ check (leap-day safe). Day counts drift on leap years."""
    year, month, day = map(int, dob_str.split("-"))
    today = today or date.today()
    try:
        milestone = date(year + 18, month, day)
    except ValueError:  # Feb 29 -> Feb 28 on non-leap years
        milestone = date(year + 18, month, 28)
    return milestone <= today


def admin_ok(presented: Any, required: str) -> bool:
    """Constant-time operator-token comparison. Non-string input never matches."""
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented, required)


def load_keys(keydir: str) -> tuple[str, str]:
    """Load (priv, pub) hex pair: env-managed key wins, else files, else generate."""
    priv_hex = os.environ.get(config.ISSUER_PRIV_HEX_ENV)
    os.makedirs(keydir, exist_ok=True)
    priv_file = os.path.join(keydir, "issuer_priv.hex")
    pub_file = os.path.join(keydir, "issuer_pub.hex")
    if priv_hex and len(priv_hex) == 64:
        pub = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(priv_hex)).public_key().public_bytes_raw().hex()
        return priv_hex, pub
    if os.path.exists(priv_file):
        with open(priv_file) as f:
            priv_hex = f.read().strip()
        with open(pub_file) as f:
            return priv_hex, f.read().strip()
    priv_hex, pub_hex = gen_keypair()
    with open(priv_file, "w") as f:
        f.write(priv_hex)
    with open(pub_file, "w") as f:
        f.write(pub_hex)
    log.info("generated new Ed25519 issuer keypair")
    return priv_hex, pub_hex


def issue_credential(*, user: dict | None, verifier_id: str, nonce: str,
                     issuer_id: str, priv_hex: str, now: float) -> dict:
    """Build + sign a credential. Raises UnknownUserError / RevokedError /
    ContractDriftError (routes map these to 404 / 403 / 500)."""
    if user is None:
        raise UnknownUserError("unknown user")
    if user["revoked"]:
        raise RevokedError("revoked")
    payload: dict[str, Any] = {
        "v": 1, "iss": issuer_id,
        "uid_p": pseudonym(user["master_secret"], verifier_id),
        "a": "over_18", "r": 1 if is_adult(user["dob"]) else 0,
        "exp": int(now) + EXPIRY_SEC,
    }
    # Live-challenge binding: a holder-presented verifier nonce is embedded and
    # signed. Static QRs (no n) fail a fresh challenge -> anti-replay.
    if nonce:
        payload["n"] = nonce
    want = set(CRED_REQUIRED_FIELDS) - {"s"}
    if nonce:
        want |= {"n"}
    if set(unsigned_body(payload)) != want:
        raise ContractDriftError(f"keys={sorted(payload)}")
    payload["s"] = sign_cred(unsigned_body(payload), priv_hex)
    return payload


def current_revlist(*, rev_version: int, at_ts: int, revoked_ids: list[str],
                    priv_hex: str) -> dict:
    """Raw revocation log (user IDs — issuer-internal transparency, not the channel)."""
    body = {"v": rev_version, "at": at_ts, "revoked": revoked_ids}
    body["s"] = sign_cred(dict(body), priv_hex)
    return body


def build_bundle(*, verifier_id: str, users: list[dict], rev_version: int,
                 issuer_id: str, priv_hex: str, pub_hex: str) -> dict:
    """Signed trust bundle for one verifier: per-verifier pseudonyms of revoked
    users and minors, so the verifier enforces status without ever seeing
    names or DOBs. v is monotonic — verifiers reject rollbacks."""
    revoked, minors = [], []
    for user in users:
        pseudo = pseudonym(user["master_secret"], verifier_id)
        if user["revoked"]:
            revoked.append(pseudo)
        elif not is_adult(user["dob"]):
            minors.append(pseudo)
    body = {"iss": issuer_id, "pubkey_hex": pub_hex, "v": rev_version,
            "verifier": verifier_id, "revoked": sorted(revoked),
            "minors": sorted(minors)}
    body["s"] = sign_cred(body, priv_hex)
    return body


def fetch_otp_code(*, user: dict | None, verifier_id: str, now: float) -> tuple[str, int]:
    """Current 6-digit fallback code for a user at a verifier (feature phones)."""
    if user is None:
        raise UnknownUserError("unknown user")
    step = int(now // config.OTP_STEP_SEC)
    return otp6(user["master_secret"], verifier_id, step), config.OTP_STEP_SEC


def rotate_keys(keydir: str) -> tuple[str, str]:
    """Generate + persist a replacement keypair. Refuses when env-managed."""
    if os.environ.get(config.ISSUER_PRIV_HEX_ENV):
        # Refuse rather than lie: rotation would advertise a key that never signs.
        raise EnvManagedKeyError("key is env-managed; rotate ISSUER_PRIV_HEX instead")
    priv_hex, pub_hex = gen_keypair()
    os.makedirs(keydir, exist_ok=True)
    with open(os.path.join(keydir, "issuer_priv.hex"), "w") as f:
        f.write(priv_hex)
    with open(os.path.join(keydir, "issuer_pub.hex"), "w") as f:
        f.write(pub_hex)
    return priv_hex, pub_hex
