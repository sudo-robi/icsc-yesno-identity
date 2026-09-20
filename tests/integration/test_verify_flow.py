"""Integration: full HTTP flows through issuer + verifier (new protocol)."""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import issuer.app as issuer_app
import issuer.repo as issuer_repo
import verifier.app as verifier_app
import verifier.repo as verifier_repo
from shared.canonical import canonical
from shared.crypto import ed25519_sign
from shared.schemas import bundle_sig_body
from tests.helpers import (
    enroll_holder, fresh_challenge, make_proof, p256_key, pair_shop,
)


@pytest.fixture()
def pair(tmp_path, monkeypatch):
    """Live issuer + verifier pair (isolated DBs/keys), returns (ic, vc, hdr)."""
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
    return (issuer_app.app.test_client(), verifier_app.app.test_client(), hdr)


def test_enroll_challenge_proof_yes(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc, hdr)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["result"] == "YES" and res["reason"] == "OK"


def test_minor_no(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr, uid="U002")
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert (res["result"], res["reason"]) == ("NO", "NOT_ADULT")


def test_wrong_verifier(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc, vid="SHOP-A")
    cred, key, _ = enroll_holder(ic, hdr, vid="SHOP-B")
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "WRONG_VERIFIER"


def test_expired_credential(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    cred = dict(cred, exp=10)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "EXPIRED"


def test_tampered_issuer_sig(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    cred = dict(cred, r=0)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "BADSIG"


def test_missing_proof(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, _key, _ = enroll_holder(ic, hdr)
    assert vc.post("/verify", json={"c": cred}).status_code == 400
    res = vc.post("/verify", json={"c": cred, "p": None}).get_json()
    assert res["reason"] in ("MALFORMED", "BAD_PROOF")


def test_proof_wrong_holder_key(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, _key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(p256_key(), cred, ch["n"])}).get_json()
    assert res["reason"] == "BAD_PROOF"


def test_reused_nonce_fails(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    body = {"c": cred, "p": make_proof(key, cred, ch["n"])}
    assert vc.post("/verify", json=body).get_json()["result"] == "YES"
    assert vc.post("/verify", json=body).get_json()["reason"] == "UNKNOWN_CHALLENGE"


def test_expired_nonce(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    verifier_repo.prune_nonces(verifier_app.DB, int(time.time()) + 99999)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "UNKNOWN_CHALLENGE"


def test_concurrent_nonce_race(pair):
    """20 threads, one challenge: exactly one YES, nineteen UNKNOWN_CHALLENGE."""
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    barrier = threading.Barrier(20)
    outcomes = []

    def attempt():
        client = verifier_app.app.test_client()
        barrier.wait(timeout=10)
        res = client.post("/verify",
                          json={"c": cred, "p": make_proof(key, cred, ch["n"])})
        outcomes.append(res.get_json()["reason"])

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(outcomes) == 20
    assert outcomes.count("OK") == 1
    assert outcomes.count("UNKNOWN_CHALLENGE") == 19


def test_concurrent_receipts_unforked(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)

    def attempt():
        client = verifier_app.app.test_client()
        ch = client.get("/challenge").get_json()
        client.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])})

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    rows = verifier_repo.all_receipts(verifier_app.DB)
    assert len(rows) == 10
    # single unforked chain: every prev_hash links to the previous entry
    prev = "GENESIS"
    seen = set()
    for row in rows:
        assert row["prev_hash"] == prev
        assert row["entry_hash"] not in seen
        seen.add(row["entry_hash"])
        prev = row["entry_hash"]


def test_revoke_sync_revoked(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    ch = fresh_challenge(vc)
    assert vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()["result"] == "YES"
    assert ic.post("/admin/revoke", json={"user_id": "U001"}, headers=hdr).status_code == 200
    # delay window: old bundle still passes
    ch = fresh_challenge(vc)
    assert vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()["result"] == "YES"
    pair_shop(ic, vc)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "REVOKED"


def test_stale_and_forged_bundles_rejected(pair):
    ic, vc, hdr = pair
    b1 = pair_shop(ic, vc)
    ic.post("/admin/revoke", json={"user_id": "U002"}, headers=hdr)
    b2 = pair_shop(ic, vc)
    assert b2["v"] > b1["v"]
    assert vc.post("/sync", json=b1, headers=hdr).get_json()["error"] == "ROLLBACK"
    forged = dict(b2, revoked=[])
    assert vc.post("/sync", json=forged, headers=hdr).get_json()["error"] == "BADSIG"


def test_rotation_chain(pair):
    ic, vc, hdr = pair
    b1 = pair_shop(ic, vc)
    staged = ic.post("/admin/rotate", json={}, headers=hdr).get_json()
    assert staged["v"] > b1["v"]  # staging bumps the bundle version
    b2 = pair_shop(ic, vc)  # signed by K1, announces K2
    assert b2["next_pub"] == staged["staged_pub"]
    activated = ic.post("/admin/rotate", json={"activate": True}, headers=hdr).get_json()
    assert activated["pub"] == staged["staged_pub"]
    b3 = pair_shop(ic, vc)  # signed by K2, chained via learned next_pub
    assert b3["v"] > b2["v"]
    # rogue key with no chain linkage is rejected
    from shared.crypto import ed25519_keypair
    rogue_priv, rogue_pub = ed25519_keypair()
    rogue = dict(b3, pub=rogue_pub, v=b3["v"] + 1)
    rogue["s"] = ed25519_sign(rogue_priv, canonical(bundle_sig_body(
        {k: rogue[k] for k in rogue if k != "s"})))
    assert vc.post("/sync", json=rogue, headers=hdr).get_json()["error"] == "BADSIG"


def test_unauthenticated_admin(pair):
    ic, vc, _hdr = pair
    assert vc.post("/sync", json={}).status_code == 401
    assert vc.get("/receipts").status_code == 401
    assert vc.get("/receipts.csv").status_code == 401
    assert ic.post("/admin/revoke", json={"user_id": "U001"}).status_code == 401
    assert ic.post("/admin/rotate", json={}).status_code == 401
    assert ic.get("/admin/otp-secrets?vid=SHOP-A").status_code == 401
    assert vc.post("/admin/otp-secrets", json={}).status_code == 401
    bad = {"Authorization": "Bearer wrong"}
    assert vc.post("/sync", json={}, headers=bad).status_code == 403


def test_forged_issuer_needs_token(pair):
    ic, vc, _hdr = pair
    from shared.crypto import ed25519_keypair
    _, rogue_pub = ed25519_keypair()
    forged = {"v": 1, "iss": "EVIL", "vid": "SHOP-A", "pub": rogue_pub,
              "next_pub": None, "revoked": [], "minors": [],
              "iat": 1, "exp": 9999999999, "s": "x"}
    assert vc.post("/sync", json=forged).status_code == 401  # no token first


def test_oversized_payload(pair):
    ic, vc, hdr = pair
    pair_shop(ic, vc)
    cred, key, _ = enroll_holder(ic, hdr)
    cred = dict(cred, cnf="x" * 3000)
    ch = fresh_challenge(vc)
    res = vc.post("/verify", json={"c": cred, "p": make_proof(key, cred, ch["n"])}).get_json()
    assert res["reason"] == "TOO_LARGE"


def test_garbage_sweep_4xx(pair):
    ic, vc, hdr = pair
    for body in ([], "str", {}, {"c": []}, {"c": {}, "p": []}):
        assert vc.post("/verify", json=body).status_code == 400
    for body in ([], "str"):
        assert vc.post("/verify_code", json=body).status_code == 400
        assert vc.post("/sync", json=body, headers=hdr).status_code == 400
    assert vc.post("/sync", json={"bundle": []}, headers=hdr).status_code == 400
    # empty-but-valid shapes reach reason codes, never 500s
    assert vc.post("/verify_code", json={}).get_json()["reason"] == "BAD_OTP"
    assert vc.post("/verify_code", json={"code": 1}).get_json()["reason"] == "BAD_OTP"
    assert ic.post("/enroll", json=[]).status_code == 400
    assert ic.post("/admin/revoke", json=[], headers=hdr).status_code == 400
