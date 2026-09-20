"""Gap tests: error branches, env-key paths, boundary dates. Keeps gate at 90%+."""
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import issuer.app as I
import verifier.app as V


def _idb(tmp):
    I.DB = os.path.join(tmp, "i.db")
    I.init_db()


def _vdb(tmp):
    V.DB = os.path.join(tmp, "v.db")
    V.TRUST = os.path.join(tmp, "t.json")
    V.SECRETS_PATH = os.path.join(tmp, "s.json")
    V.init_db()


def test_is_adult_boundaries():
    assert I.is_adult("2000-05-12", date(2026, 9, 20)) is True
    assert I.is_adult("2010-03-01", date(2026, 9, 20)) is False
    assert I.is_adult("2008-09-20", date(2026, 9, 20)) is True  # exactly 18
    assert I.is_adult("2008-09-21", date(2026, 9, 20)) is False  # 1 day short
    assert I.is_adult("2008-09-24", date(2026, 9, 20)) is False  # 4 days short (leap bug)
    assert I.is_adult("2008-02-29", date(2026, 2, 28)) is True  # Feb29 fallback


def test_load_keys_env_and_generated(tmp_path, monkeypatch):
    from shared.crypto import gen_keypair
    priv, pub = gen_keypair()
    monkeypatch.setenv("ISSUER_PRIV_HEX", priv)
    assert I.load_keys() == (priv, pub)
    monkeypatch.delenv("ISSUER_PRIV_HEX")
    monkeypatch.setattr(I, "KEYDIR", os.path.join(str(tmp_path), "keys"))
    p2, q2 = I.load_keys()
    assert len(p2) == 64 and len(q2) == 64
    assert I.load_keys() == (p2, q2)  # persisted, not regenerated


def test_bundle_verifier_id_too_long(tmp_path):
    _idb(str(tmp_path))
    ic = I.app.test_client()
    assert ic.get("/bundle?verifier_id=" + "X" * 33).status_code == 400


def test_otp_errors_and_ok(tmp_path):
    _idb(str(tmp_path))
    ic = I.app.test_client()
    assert ic.get("/otp").status_code == 400
    assert ic.get("/otp?user_id=NOPE").status_code == 404
    r = ic.get("/otp?user_id=U001&verifier_id=SHOP-A").get_json()
    assert len(r["code"]) == 6 and r["step_sec"] == 30


def test_revoke_bad_body(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "a")
    _idb(str(tmp_path))
    ic = I.app.test_client()
    assert ic.post("/revoke", json={},
                   headers={"X-Admin-Token": "a"}).status_code == 400


def test_rotate_refused_for_env_key(tmp_path, monkeypatch):
    from shared.crypto import gen_keypair
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "a")
    monkeypatch.setenv("ISSUER_PRIV_HEX", gen_keypair()[0])
    _idb(str(tmp_path))
    ic = I.app.test_client()
    r = ic.post("/rotate", headers={"X-Admin-Token": "a"})
    assert r.status_code == 409


def test_issue_contract_drift_is_500_not_crash(tmp_path, monkeypatch):
    _idb(str(tmp_path))
    # Logic moved to issuer.service in the Phase-1 layer split; patch it there.
    monkeypatch.setattr("issuer.service.unsigned_body", lambda p: {"wrong": 1})
    ic = I.app.test_client()
    assert ic.post("/issue", json={"user_id": "U001"}).status_code == 500


def test_log_receipt_rejects_bad_result(tmp_path):
    _vdb(str(tmp_path))
    with pytest.raises(ValueError):
        V.log_receipt("over_18", "MAYBE", "n", "s")


def test_log_receipt_rolls_back(tmp_path, monkeypatch):
    _vdb(str(tmp_path))
    def boom(*a):
        raise RuntimeError("disk gone")
    # Chain hashing moved to verifier.service in the Phase-1 layer split.
    monkeypatch.setattr("verifier.service.chain_entry", boom)
    with pytest.raises(RuntimeError):
        V.log_receipt("over_18", "YES", "n", "s")
    assert V.db().execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"] == 0


def test_verify_cred_wrong_type(tmp_path):
    _vdb(str(tmp_path))
    vc = V.app.test_client()
    assert vc.post("/verify", json={"cred": ["not", "a", "dict"]}).status_code == 400
    assert vc.post("/verify_code", json=["not", "a", "dict"]).status_code == 400


def test_sync_shape_errors(tmp_path):
    _vdb(str(tmp_path))
    vc = V.app.test_client()
    assert vc.post("/sync", json=["list"]).status_code == 400
    assert vc.post("/sync", json={"pubkey_hex": "00" * 32, "v": 1}).status_code == 400
    base = {"iss": "T", "pubkey_hex": "00" * 32, "v": 1}
    assert vc.post("/sync", json={**base, "v": "seven"}).status_code == 400
    assert vc.post("/sync", json={**base, "revoked": "U001"}).status_code == 400
    assert vc.post("/sync", json={**base, "pubkey_hex": 123}).status_code == 400


def test_token_compare_rejects_non_strings():
    from issuer.service import admin_ok
    from verifier.service import pairing_ok
    assert admin_ok("shop-secret", "shop-secret") is True
    assert pairing_ok("shop-secret", "shop-secret") is True
    for bad in (None, 123, ["shop-secret"], {"t": 1}, "SHOP-SECRET"):
        assert admin_ok(bad, "shop-secret") is False
        assert pairing_ok(bad, "shop-secret") is False


def test_holder_page(tmp_path):
    _vdb(str(tmp_path))
    assert V.app.test_client().get("/holder/").status_code == 200


def test_receipt_key_generation_and_chmod_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "KEYS_DIR", str(tmp_path))
    k1 = V._receipt_key()
    assert len(k1) == 64 and V._receipt_key() == k1  # persisted
    def boom(*a, **k):
        raise OSError("ro fs")
    monkeypatch.setattr(os, "chmod", boom)
    monkeypatch.setattr(V, "KEYS_DIR", os.path.join(str(tmp_path), "k2"))
    assert len(V._receipt_key()) == 64
