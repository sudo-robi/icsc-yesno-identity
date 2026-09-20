"""Issuer HTTP tests: enroll, bundle, admin auth, rotate chain staging."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as appmod
import issuer.repo as repo


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    appmod.DB = os.path.join(str(tmp_path), "issuer.db")
    appmod.KEYDIR = os.path.join(str(tmp_path), "keys")
    repo.init_db(appmod.DB)
    repo.seed_users(appmod.DB)
    return appmod.app.test_client()


def test_healthz_pubkey_bundle(client):
    assert client.get("/healthz").get_json()["ok"] is True
    pub = client.get("/pubkey").get_json()
    assert len(pub["pubkey_hex"]) == 64 and "fingerprint" in pub
    bundle = client.get("/bundle?vid=SHOP-A").get_json()
    assert bundle["vid"] == "SHOP-A" and bundle["v"] >= 1
    assert isinstance(bundle["revoked"], list) and "s" in bundle
    assert client.get("/bundle?vid=" + "X" * 33).status_code == 400


def _p256_raw():
    from shared.crypto import b64u_encode
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers().public_numbers
    raw = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return b64u_encode(raw)


def _enroll(client, uid="U001", vid="SHOP-A"):
    code = client.post(f"/admin/users/{uid}/enrollment-code",
                       headers={"Authorization": "Bearer admin-secret"}).get_json()["code"]
    return client.post("/enroll", json={"code": code, "verifier_id": vid,
                                        "holder_pub": _p256_raw()})


def test_enroll_happy_path(client):
    r = _enroll(client)
    assert r.status_code == 200, r.data
    body = r.get_json()
    cred = body["credential"]
    assert cred["vid"] == "SHOP-A" and cred["r"] == 1 and "s" in cred
    assert set(cred) == {"v", "iss", "sub", "vid", "a", "r", "iat", "exp", "cnf", "s"}


def test_enroll_rejects(client):
    assert client.post("/enroll", json={}).status_code == 400
    assert client.post("/enroll", json=["x"]).status_code == 400
    r = client.post("/enroll", json={"code": "nope", "verifier_id": "S",
                                     "holder_pub": "e30"})
    assert r.get_json()["error"] == "UNKNOWN_CODE"
    # bad holder key
    code = client.post("/admin/users/U001/enrollment-code",
                       headers={"Authorization": "Bearer admin-secret"}).get_json()["code"]
    r = client.post("/enroll", json={"code": code, "verifier_id": "S",
                                     "holder_pub": "e30"})
    assert r.get_json()["error"] == "BAD_PUBKEY"
    # revoked user cannot enroll
    code = client.post("/admin/users/U003/enrollment-code",
                       headers={"Authorization": "Bearer admin-secret"}).get_json()["code"]
    from shared.crypto import b64u_encode
    raw = b"\x04" + b"\x11" * 64
    r = client.post("/enroll", json={"code": code, "verifier_id": "S",
                                     "holder_pub": b64u_encode(raw)})
    assert r.status_code == 403 and r.get_json()["error"] == "REVOKED_USER"


def test_enroll_code_single_use(client):
    code = client.post("/admin/users/U001/enrollment-code",
                       headers={"Authorization": "Bearer admin-secret"}).get_json()["code"]
    body = {"code": code, "verifier_id": "S", "holder_pub": _p256_raw()}
    assert client.post("/enroll", json=body).status_code == 200
    # second redemption of the same code always fails as used
    r = client.post("/enroll", json=body)
    assert r.get_json()["error"] == "CODE_USED"


def test_admin_auth_required(client):
    assert client.post("/admin/revoke", json={"user_id": "U001"}).status_code == 401
    r = client.post("/admin/revoke", json={"user_id": "U001"},
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403
    assert client.post("/admin/rotate", json={}).status_code == 401


def test_revoke_and_rotate_chain(client):
    hdr = {"Authorization": "Bearer admin-secret"}
    assert client.post("/admin/revoke", json={"user_id": "U002"},
                       headers=hdr).get_json()["ok"] is True
    assert client.post("/admin/revoke", json={}, headers=hdr).status_code == 400
    assert client.post("/admin/revoke", json={"user_id": "NOPE"},
                       headers=hdr).status_code == 404
    staged = client.post("/admin/rotate", json={}, headers=hdr).get_json()
    assert len(staged["staged_pub"]) == 64
    bundle = client.get("/bundle?vid=SHOP-A").get_json()
    assert bundle["next_pub"] == staged["staged_pub"]
    activated = client.post("/admin/rotate", json={"activate": True},
                            headers=hdr).get_json()
    assert activated["pub"] == staged["staged_pub"]
    assert client.post("/admin/rotate", json={"activate": True},
                       headers=hdr).status_code == 400


def test_otp_secret_only_when_enabled(client):
    r = _enroll(client)
    assert "otp_secret" in r.get_json()  # OTP_ENABLED defaults on in test env


def test_dashboard_no_dobs(client):
    html = client.get("/").data.decode()
    assert "2000-05-12" not in html and "1999-01-01" not in html
    assert "U001" in html
