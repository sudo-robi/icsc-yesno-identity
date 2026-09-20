"""Integration: receipts export, status, OTP provisioning, malformed bodies."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo
from shared.canonical import canonical
from shared.crypto import ed25519_verify
from tests.helpers import enroll_holder, fresh_challenge, make_proof, pair_shop


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")
    base = str(tmp_path)
    issuer_app.DB = os.path.join(base, "i.db")
    issuer_app.KEYDIR = os.path.join(base, "keys")
    verifier_app.DB = os.path.join(base, "v.db")
    verifier_app.TRUST = os.path.join(base, "trust.json")
    verifier_app.SECRETS_PATH = os.path.join(base, "secrets.json")
    issuer_repo.init_db(issuer_app.DB)
    issuer_repo.seed_users(issuer_app.DB)
    verifier_repo.init_db(verifier_app.DB)
    hdr = {"Authorization": "Bearer admin-secret"}
    return issuer_app.app.test_client(), verifier_app.app.test_client(), hdr


def test_status_unpaired_then_paired(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    assert vc.get("/status").get_json() == {"paired": False}
    pair_shop(ic, vc, hdr)
    status = vc.get("/status").get_json()
    assert status["paired"] is True and status["iss"] == "NIMC-TEST-01"
    assert len(status["fingerprint"].split(" ")) == 4
    assert status["bundle_exp"] > 0


def test_receipts_signed_head_and_csv(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    empty = vc.get("/receipts", headers=hdr).get_json()
    assert empty["rows"] == [] and empty["head"] is None
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])})
    data = vc.get("/receipts", headers=hdr).get_json()
    assert len(data["rows"]) == 1
    head = data["head"]
    assert ed25519_verify(data["receipt_pub"], head["sig"],
                          canonical({"head": head["head"], "ts": head["ts"]}))
    row = data["rows"][0]
    assert set(row) == {"id", "ts", "verifier_id", "q", "result", "reason",
                        "prev_hash", "entry_hash"}
    csv = vc.get("/receipts.csv", headers=hdr).data.decode().splitlines()
    assert csv[0].startswith("id,ts,verifier_id")
    assert any(line.startswith("head,") for line in csv)
    assert any(line.startswith("receipt_pub,") for line in csv)


def test_provision_otp_secrets(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    r = vc.post("/admin/otp-secrets", json={"secrets": {"ab": "cd"}}, headers=hdr)
    assert r.get_json() == {"ok": True, "count": 1}
    assert vc.post("/admin/otp-secrets", json={}, headers=hdr).status_code == 400
    assert vc.post("/admin/otp-secrets", json={"secrets": []},
                   headers=hdr).status_code == 400


def test_malformed_json_bodies_never_500(tmp_path, monkeypatch):
    ic, vc, hdr = _setup(monkeypatch, tmp_path)
    pair_shop(ic, vc, hdr)
    bad = {"Content-Type": "application/json", **hdr}
    for method, url in [("POST", "/verify"), ("POST", "/verify_code"),
                        ("POST", "/sync"), ("POST", "/admin/otp-secrets")]:
        r = vc.open(url, method=method, data="{oops", headers=bad)
        assert r.status_code == 400, (url, r.status_code)
    for method, url in [("POST", "/enroll"), ("POST", "/admin/revoke")]:
        r = ic.open(url, method=method, data="{oops",
                    headers={"Content-Type": "application/json", **hdr})
        assert r.status_code == 400, (url, r.status_code)
