"""Issuer service: enrollment, issuance, bundles, rotation. Pure logic.

Key custody: the active Ed25519 key comes from ISSUER_PRIV_HEX env or a 0600
file (imported into the keys table once); rotated keys live in the keys table
(DB file itself must be protected — see deploy notes). All functions take
explicit arguments; no Flask, no module globals.
"""
import hashlib
import hmac as _hm
import logging
import os
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import issuer.repo as repo
from shared.canonical import canonical
from shared.crypto import (
    ed25519_keypair, ed25519_sign, p256_pubkey_from_b64u, pseudonym,
)
from shared.schemas import CRED_REQUIRED_FIELDS, bundle_sig_body, signed_body

log = logging.getLogger("issuer.service")


class UnknownUserError(LookupError):
    """No such user enrolled."""


class RevokedError(PermissionError):
    """User is revoked: must not be issued to."""


class ContractDriftError(RuntimeError):
    """Built credential disagrees with shared.schemas (server bug, not input)."""


def is_adult(dob_str: str, today: date | None = None) -> bool:
    """Calendar-correct 18+ check (leap-day safe). Day counts drift on leaps."""
    year, month, day = map(int, dob_str.split("-"))
    today = today or date.today()
    try:
        milestone = date(year + 18, month, day)
    except ValueError:  # Feb 29 -> Feb 28 on non-leap years
        milestone = date(year + 18, month, 28)
    return milestone <= today


def ensure_active_key(db_path: str, keydir: str) -> dict:
    """Bootstrap key custody: env key or 0600 file wins, else generate.

    Returns the active key row. Env/file material is imported into the keys
    table once so rotation has a uniform store afterwards.
    """
    env_priv = os.environ.get("ISSUER_PRIV_HEX", "")
    if env_priv and len(env_priv) == 64:
        pub = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(env_priv)).public_key().public_bytes_raw().hex()
        existing = repo.active_key(db_path)
        if existing and existing["pub"] == pub:
            return existing
        repo.deactivate_all_keys(db_path)
        repo.store_key(db_path, env_priv, pub, active=True)
        created = repo.active_key(db_path)
        assert created is not None
        return created
    # DB is the source of truth once bootstrapped: an active row here means a
    # previous boot (or an operator rotation) already decided. Re-importing the
    # key FILE on top would silently revert rotations, so the file is only
    # honored for a fresh database. Explicit ISSUER_PRIV_HEX above still wins.
    existing = repo.active_key(db_path)
    if existing:
        return existing
    os.makedirs(keydir, exist_ok=True)
    priv_file = os.path.join(keydir, "issuer_priv.hex")
    if os.path.exists(priv_file):
        with open(priv_file) as f:
            file_priv = f.read().strip()
        pub = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(file_priv)).public_key().public_bytes_raw().hex()
        repo.store_key(db_path, file_priv, pub, active=True)
        created = repo.active_key(db_path)
        assert created is not None
        return created
    priv_hex, pub_hex = ed25519_keypair()
    fd = os.open(priv_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, priv_hex.encode())
    finally:
        os.close(fd)
    repo.deactivate_all_keys(db_path)
    repo.store_key(db_path, priv_hex, pub_hex, active=True)
    created = repo.active_key(db_path)
    assert created is not None
    log.info("generated new Ed25519 issuer keypair")
    return created


def issue_credential(*, user: dict | None, verifier_id: str,
                     holder_pub_b64u: str, issuer_id: str, priv_hex: str,
                     now: float, ttl_sec: int) -> dict:
    """Build + sign an enrollment credential. Raises UnknownUserError /
    RevokedError / ValueError (bad holder key) / ContractDriftError."""
    if user is None:
        raise UnknownUserError("unknown user")
    if user["revoked"]:
        raise RevokedError("revoked")
    try:
        p256_pubkey_from_b64u(holder_pub_b64u)  # validates point, keeps raw form
    except Exception as exc:
        raise ValueError(f"bad holder key: {exc}") from exc
    iat = int(now)
    payload: dict[str, Any] = {
        "v": 1, "iss": issuer_id,
        "sub": pseudonym(user["master_secret"], verifier_id),
        "vid": verifier_id, "a": "over_18",
        "r": 1 if is_adult(user["dob"]) else 0,
        "iat": iat, "exp": iat + ttl_sec, "cnf": holder_pub_b64u,
    }
    want = set(CRED_REQUIRED_FIELDS) - {"s"}
    if set(signed_body(payload)) != want:
        raise ContractDriftError(f"keys={sorted(payload)}")
    payload["s"] = ed25519_sign(priv_hex, canonical(signed_body(payload)))
    return payload


def build_bundle(*, verifier_id: str, users: list[dict], rev_version: int,
                 issued_at: int, ttl_sec: int, issuer_id: str,
                 priv_hex: str, pub_hex: str, next_pub: str | None) -> dict:
    """Signed per-verifier trust bundle (pseudonyms only, no PII)."""
    revoked, minors = [], []
    for user in users:
        pseudo = pseudonym(user["master_secret"], verifier_id)
        if user["revoked"]:
            revoked.append(pseudo)
        elif not is_adult(user["dob"]):
            minors.append(pseudo)
    body = {"v": rev_version, "iss": issuer_id, "vid": verifier_id,
            "pub": pub_hex, "next_pub": next_pub,
            "revoked": sorted(revoked), "minors": sorted(minors),
            "iat": issued_at, "exp": issued_at + ttl_sec}
    body["s"] = ed25519_sign(priv_hex, canonical(bundle_sig_body(body)))
    return body


def otp_secret_for(user_master_secret: str, verifier_id: str) -> str:
    """Deterministic per-user-per-shop OTP secret (hex). Stateless for issuer."""
    return _hm.new(user_master_secret.encode(), f"otp|{verifier_id}".encode(),
                   hashlib.sha256).hexdigest()


def fingerprint(pub_hex: str) -> str:
    """Operator-facing key fingerprint (shared helper, kept here for compat)."""
    from shared.crypto import key_fingerprint

    return key_fingerprint(pub_hex)



