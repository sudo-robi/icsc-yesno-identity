"""Integration: OTP fallback (flagged) end to end."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo
from shared import config
from shared.crypto import b64u_encode, otp_code


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    base = str(tmp_path)
    issuer_app.DB = os.path.join(base, "i.db")
    issuer_app.KEYDIR = os.path.join(base, "keys")
    verifier_app.DB = os.path.join(base, "v.db")
    verifier_app.SECRETS_PATH = os.path.join(base, "secrets.json")
    issuer_repo.init_db(issuer_app.DB)
    issuer_repo.seed_users(issuer_app.DB)
    verifier_repo.init_db(verifier_app.DB)
    hdr = {"Authorization": "Bearer admin-secret"}
    return issuer_app.app.test_client(), verifier_app.app.test_client(), hdr


def _p256_raw():
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers().public_numbers
    return b64u_encode(b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))


def _sub_for(ic, hdr, uid, vid="SHOP-A"):
    code = ic.post(f"/admin/users/{uid}/enrollment-code",
                   headers=hdr).get_json()["code"]
    cred = ic.post("/enroll", json={"code": code, "verifier_id": vid,
                                    "holder_pub": _p256_raw()}).get_json()["credential"]
    return cred["sub"]


def _provision(ic, vc, hdr, vid="SHOP-A"):
    secrets = ic.get(f"/admin/otp-secrets?vid={vid}", headers=hdr).get_json()["secrets"]
    r = vc.post("/admin/otp-secrets", json={"secrets": secrets}, headers=hdr)
    assert r.status_code == 200, r.data
    return secrets


def _pair(ic, vc, hdr=None, vid="SHOP-A"):
    hdr = hdr or {"Authorization": "Bearer admin-secret"}
    bundle = ic.get(f"/bundle?vid={vid}").get_json()
    assert vc.post("/sync", json=bundle, headers=hdr).status_code == 200


def _code(secrets, sub, vid="SHOP-A", step=None):
    step = int(time.time() // config.OTP_STEP_SEC) if step is None else step
    return otp_code(secrets[sub], vid, step)


def test_otp_happy_path_and_reuse(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    _pair(ic, vc)
    secrets = _provision(ic, vc, hdr)
    sub = _sub_for(ic, hdr, "U001")
    assert vc.post("/verify_code", json={"code": _code(secrets, sub)}).get_json()["result"] == "YES"
    res = vc.post("/verify_code", json={"code": _code(secrets, sub)}).get_json()
    assert res["reason"] == "UNKNOWN_CHALLENGE"  # same step reuse is spent


def test_otp_minor_and_revoked(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    _pair(ic, vc)
    secrets = _provision(ic, vc, hdr)
    sub_u001 = _sub_for(ic, hdr, "U001")
    sub_u002 = _sub_for(ic, hdr, "U002")
    # minors are never provisioned: no valid code can exist for them
    assert sub_u002 not in secrets
    assert vc.post("/verify_code", json={"code": "000000"}).get_json()["reason"] == "BAD_OTP"
    # revoke the adult, re-sync, then prove the grace-step code is refused by status
    assert ic.post("/admin/revoke", json={"user_id": "U001"}, headers=hdr).status_code == 200
    _pair(ic, vc)
    step = int(time.time() // config.OTP_STEP_SEC)
    prev_code = otp_code(secrets[sub_u001], "SHOP-A", step - 1)
    assert vc.post("/verify_code", json={"code": prev_code}).get_json()["reason"] == "REVOKED"


def test_otp_secrets_only_adults(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    secrets = ic.get("/admin/otp-secrets?vid=SHOP-A", headers=hdr).get_json()["secrets"]
    bundle = ic.get("/bundle?vid=SHOP-A").get_json()
    # provisioned subs are exactly the non-revoked non-minors (U001 + U004 leap adult)
    forbidden = set(bundle["revoked"]) | set(bundle["minors"])
    assert not (set(secrets) & forbidden)
    assert len(secrets) == 2


def test_otp_disabled_flag(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    _pair(ic, vc)
    monkeypatch.setattr(config, "OTP_ENABLED", False)
    assert vc.post("/verify_code", json={"code": "000000"}).status_code == 404
    assert ic.get("/admin/otp-secrets?vid=SHOP-A", headers=hdr).status_code == 404
    # enrollment works but carries no OTP secret
    code = ic.post("/admin/users/U001/enrollment-code",
                   headers=hdr).get_json()["code"]
    from tests.helpers import p256_pub_b64u, p256_key
    body = ic.post("/enroll", json={"code": code, "verifier_id": "SHOP-A",
                                    "holder_pub": p256_pub_b64u(p256_key())}).get_json()
    assert "otp_secret" not in body
