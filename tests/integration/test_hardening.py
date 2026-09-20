"""Hardening gaps: headers/CORS, rotation flow, offline proof, injection safety,
enumeration resistance, prune logic, latency budget, log hygiene, repo hygiene.
"""
import logging
import os
import socket
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo
from tests.helpers import enroll_holder, fresh_challenge, make_proof, pair_shop


@pytest.fixture()
def env(tmp_path, monkeypatch):
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


def test_security_headers_both_apps(env):
    ic, vc, _hdr = env
    for client, path in ((ic, "/healthz"), (ic, "/"), (vc, "/healthz"),
                         (vc, "/"), (vc, "/holder/")):
        headers = client.get(path).headers
        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp, path
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp, path
        assert headers.get("X-Content-Type-Options") == "nosniff", path
        assert headers.get("Referrer-Policy") == "no-referrer", path
        assert "camera=(self)" in headers.get("Permissions-Policy", ""), path


def test_cors_allowlist(env, monkeypatch):
    _ic, vc, _hdr = env
    assert "Access-Control-Allow-Origin" not in vc.get("/healthz").headers
    monkeypatch.setattr("shared.config.CORS_ALLOW_ORIGINS",
                        ["https://shop.example"])
    r = vc.get("/healthz", headers={"Origin": "https://shop.example"})
    assert r.headers.get("Access-Control-Allow-Origin") == "https://shop.example"
    r = vc.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_rotation_full_flow_old_bad_new_yes(env):
    ic, vc, hdr = env
    pair_shop(ic, vc, hdr)
    old_cred, old_key, _ = enroll_holder(ic, hdr)
    staged = ic.post("/admin/rotate", json={}, headers=hdr).get_json()
    assert "staged_pub" in staged
    pair_shop(ic, vc, hdr)  # v2 signed by K1, advertises K2 as next_pub: learned
    activated = ic.post("/admin/rotate", json={"activate": True}, headers=hdr).get_json()
    assert activated["pub"] == staged["staged_pub"]
    pair_shop(ic, vc, hdr)  # re-pair: v3 bundle signed by K2, chained via learned next_pub
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": old_cred,
                                   "p": make_proof(old_key, old_cred, ch["n"])}).get_json()
    assert res["reason"] == "BADSIG"  # K1-signed credential under pinned K2
    new_cred, new_key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": new_cred,
                                   "p": make_proof(new_key, new_cred, ch["n"])}).get_json()
    assert (res["result"], res["reason"]) == ("YES", "OK")


def test_verifier_makes_zero_outbound_calls(env, monkeypatch):
    """Offline proof: with every socket blocked, a paired verify still works."""
    ic, vc, hdr = env
    pair_shop(ic, vc, hdr)
    cred, key, _ = enroll_holder(ic, hdr)

    class DeadSocket(socket.socket):
        def connect(self, *a, **k):
            raise OSError("network down")

    monkeypatch.setattr(socket, "socket", DeadSocket)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["result"] == "YES"


def test_csv_cells_not_formulas(env):
    ic, vc, hdr = env
    pair_shop(ic, vc, hdr)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])})
    for line in vc.get("/receipts.csv", headers=hdr).data.decode().splitlines()[1:]:
        if not line or line.startswith("head,") or line.startswith("receipt_pub,"):
            continue
        for cell in line.split(","):
            assert cell[:1] not in ("=", "+", "-", "@"), cell


def test_sqli_strings_are_data_not_code(env):
    ic, vc, hdr = env
    evil = "' OR '1'='1'; DROP TABLE users;--"
    r = ic.post("/enroll", json={"code": evil, "verifier_id": "S", "holder_pub": "e30"})
    assert r.status_code == 400
    conn = issuer_repo.connect(issuer_app.DB)
    count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    assert count == 4  # table intact, all seed users present
    assert ic.post("/admin/revoke", json={"user_id": evil}, headers=hdr).status_code in (400, 404)


def test_no_user_enumeration_without_token(env):
    ic, _vc, _hdr = env
    known = ic.post("/admin/users/U001/enrollment-code").status_code
    unknown = ic.post("/admin/users/NOPE/enrollment-code").status_code
    assert known == unknown == 401  # indistinguishable without a token


def test_prune_logic(env):
    now = int(time.time())
    verifier_repo.add_nonce(verifier_app.DB, "old", "SHOP-A", now - 9999, now - 9000)
    verifier_repo.add_nonce(verifier_app.DB, "fresh", "SHOP-A", now, now + 300)
    verifier_repo.prune_nonces(verifier_app.DB, now - 300)
    assert verifier_repo.consume_nonce(verifier_app.DB, "old", 0, now) is None
    assert verifier_repo.consume_nonce(verifier_app.DB, "fresh", 0, now) is not None
    verifier_repo.mark_code_used(verifier_app.DB, "sub", 100, now)
    verifier_repo.prune_codes(verifier_app.DB, 101)
    assert verifier_repo.is_code_used(verifier_app.DB, "sub", 100) is False


def test_verify_latency_budget(env, capsys):
    ic, vc, hdr = env
    pair_shop(ic, vc, hdr)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    body = {"c": cred, "p": make_proof(key, cred, ch["n"])}
    start = time.perf_counter()
    assert vc.post("/verify", json=body).get_json()["result"] == "YES"
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"\n/verify latency: {elapsed_ms:.1f}ms")
    assert elapsed_ms < 500


def test_logs_hold_no_pii_or_secrets(env, caplog):
    ic, vc, hdr = env
    pair_shop(ic, vc, hdr)
    with caplog.at_level(logging.INFO):
        cred, key, _ = enroll_holder(ic, hdr)
        ch = fresh_challenge(vc)
        vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])})
    blob = "\n".join(r.getMessage() for r in caplog.records)
    conn = issuer_repo.connect(issuer_app.DB)
    secrets = [r["master_secret"] for r in
               conn.execute("SELECT master_secret FROM users").fetchall()]
    dobs = [r["dob"] for r in conn.execute("SELECT dob FROM users").fetchall()]
    conn.close()
    for forbidden in secrets + dobs + ["admin-secret", cred["s"], cred["cnf"]]:
        assert forbidden not in blob, forbidden[:12]


def test_repo_hygiene_no_secrets_tracked():
    import subprocess

    tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                             cwd=os.path.join(os.path.dirname(__file__), "..", ".."))
    assert tracked.returncode == 0
    files = tracked.stdout.split()
    assert files, "expected a git repo with tracked files"
    banned = [f for f in files
              if f.endswith(".db") or f.endswith(".db-journal")
              or f.endswith(".key") or f.endswith(".hex")
              or f.endswith(".env") or "/keys/" in f]
    assert banned == [], banned
    gitignore = open(os.path.join(os.path.dirname(__file__), "..", "..",
                                  ".gitignore")).read()
    for pattern in ("*.db", "keys/", "*.key"):
        assert pattern in gitignore
