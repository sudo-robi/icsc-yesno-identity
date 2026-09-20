"""Issuer unit tests: age boundaries, enrollment codes, key custody."""
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.repo as repo
from issuer import services


@pytest.fixture()
def db(tmp_path):
    path = os.path.join(str(tmp_path), "issuer.db")
    repo.init_db(path)
    repo.seed_users(path)
    return path


def test_age_boundaries():
    assert services.is_adult("2000-05-12", date(2026, 9, 20)) is True
    assert services.is_adult("2008-09-20", date(2026, 9, 20)) is True  # exactly 18y0d
    assert services.is_adult("2008-09-21", date(2026, 9, 20)) is False  # 17y364d
    assert services.is_adult("2008-09-24", date(2026, 9, 20)) is False  # 4 days short
    assert services.is_adult("2008-02-29", date(2026, 2, 28)) is True  # leap baby
    assert services.is_adult("2008-02-29", date(2026, 2, 27)) is False


def test_enrollment_code_single_use(db):
    code = repo.create_enrollment_code(db, "U001", 3600)
    first = repo.consume_enrollment_code(db, code)
    assert first == {"ok": True, "user_id": "U001"}
    assert repo.consume_enrollment_code(db, code)["reason"] == "CODE_USED"
    assert repo.consume_enrollment_code(db, "bogus")["reason"] == "UNKNOWN_CODE"


def test_enrollment_code_expiry(db):
    code = repo.create_enrollment_code(db, "U001", -1)
    assert repo.consume_enrollment_code(db, code)["reason"] == "CODE_EXPIRED"


def test_code_hash_never_stores_raw(db):
    code = repo.create_enrollment_code(db, "U001", 3600)
    conn = repo.connect(db)
    stored = conn.execute("SELECT code_hash FROM enrollment_codes").fetchone()["code_hash"]
    conn.close()
    assert code not in stored and len(stored) == 64


def test_key_custody_env_wins(db, tmp_path, monkeypatch):
    from shared.crypto import ed25519_keypair
    priv, pub = ed25519_keypair()
    monkeypatch.setenv("ISSUER_PRIV_HEX", priv)
    key = services.ensure_active_key(db, str(tmp_path))
    assert key["pub"] == pub
    # second call reuses the stored row instead of duplicating
    assert services.ensure_active_key(db, str(tmp_path))["pub"] == pub


def test_keygen_file_0600(db, tmp_path, monkeypatch):
    monkeypatch.delenv("ISSUER_PRIV_HEX", raising=False)
    keydir = os.path.join(str(tmp_path), "keys")
    key = services.ensure_active_key(db, keydir)
    assert len(key["priv"]) == 64
    assert oct(os.stat(os.path.join(keydir, "issuer_priv.hex")).st_mode & 0o777) == "0o600"


def test_fingerprint_format():
    fp = services.fingerprint("ab" * 32)
    assert fp == "abab abab abab abab"


def test_otp_secret_deterministic_per_shop():
    a = services.otp_secret_for("secret", "SHOP-A")
    assert a == services.otp_secret_for("secret", "SHOP-A")
    assert a != services.otp_secret_for("secret", "SHOP-B")
    assert len(a) == 64
