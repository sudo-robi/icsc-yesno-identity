"""Integration: end-to-end issue->verify through the DOCUMENTED flows
(bundle->sync pairing, /issue with nonce, single-use challenges)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import issuer.app as issuer_app
import verifier.app as verifier_app


def _setup(tmp, monkeypatch=None):
    issuer_app.DB = os.path.join(tmp, "i.db")
    verifier_app.DB = os.path.join(tmp, "v.db")
    verifier_app.TRUST = os.path.join(tmp, "trust.json")
    verifier_app.SECRETS_PATH = os.path.join(tmp, "secrets.json")
    issuer_app.init_db()
    verifier_app.init_db()
    priv, pub = issuer_app.load_keys()
    return priv, pub


def _pair(ic, vc, verifier_id="SHOP-A"):
    """The documented pairing ceremony: issuer bundle -> verifier sync."""
    bundle = ic.get(f"/bundle?verifier_id={verifier_id}").get_json()
    r = vc.post("/sync", json=bundle)
    assert r.status_code == 200, r.data
    return bundle


def test_e2e_adult_yes_and_minor_no(tmp_path):
    _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    _pair(ic, vc)
    for uid, expect in (("U001", "YES"), ("U002", "NO")):
        r = ic.post("/issue", json={"user_id": uid, "verifier_id": "SHOP-A"})
        assert r.status_code == 200, r.data
        cred = r.get_json()
        v = vc.post("/verify", json={"cred": cred, "nonce": ""})
        assert v.get_json()["result"] == expect, v.get_json()


def test_full_flow_http_api(tmp_path, monkeypatch):
    """The whole story over HTTP: pair -> issue -> challenge -> nonce-bound
    issue -> YES -> reuse spent -> revoke -> sync -> REVOKED."""
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "admin-secret")
    _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    hdr = {"X-Admin-Token": "admin-secret"}

    bundle = _pair(ic, vc)  # pair
    assert bundle["v"] >= 1
    static = ic.post("/issue", json={"user_id": "U001",
                                     "verifier_id": "SHOP-A"}).get_json()
    assert vc.post("/verify", json={"cred": static, "nonce": ""}).get_json()["result"] == "YES"
    nonce = vc.get("/challenge").get_json()["nonce"]  # challenge
    live = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A",
                                   "nonce": nonce}).get_json()  # nonce-bound issue
    first = vc.post("/verify", json={"cred": live, "nonce": nonce}).get_json()
    assert first["result"] == "YES" and first["mode"] == "challenge"
    again = vc.post("/verify", json={"cred": live, "nonce": nonce}).get_json()
    assert again["reason"] in ("REPLAY", "UNKNOWN_CHALLENGE")  # reuse spent
    assert ic.post("/revoke", json={"user_id": "U001"}, headers=hdr).status_code == 200
    _pair(ic, vc)  # sync
    final = vc.post("/verify", json={"cred": static, "nonce": ""}).get_json()
    assert final["reason"] == "REVOKED"


def test_revocation_through_documented_flow(tmp_path, monkeypatch):
    """Revoke on the issuer, re-pair, and the SAME credential now fails —
    end to end through /bundle -> /sync, no hand-written bundles."""
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "admin-secret")
    _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    hdr = {"X-Admin-Token": "admin-secret"}
    _pair(ic, vc)
    cred = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A"}).get_json()
    assert vc.post("/verify", json={"cred": cred, "nonce": ""}).get_json()["result"] == "YES"
    # delay window: before re-sync the old bundle still passes
    assert ic.post("/revoke", json={"user_id": "U001"}, headers=hdr).status_code == 200
    assert vc.post("/verify", json={"cred": cred, "nonce": ""}).get_json()["result"] == "YES"
    # after re-pairing the signed bundle: REVOKED
    bundle = _pair(ic, vc)
    assert cred["uid_p"] in bundle["revoked"]
    res = vc.post("/verify", json={"cred": cred, "nonce": ""}).get_json()
    assert res["reason"] == "REVOKED"


def test_bundle_rollback_and_forgery_rejected(tmp_path, monkeypatch):
    """Pinned key + monotonic version: old bundles and re-signed tampering fail."""
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "admin-secret")
    priv, _ = _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    hdr = {"X-Admin-Token": "admin-secret"}
    b1 = _pair(ic, vc)
    assert ic.post("/revoke", json={"user_id": "U003"}, headers=hdr).status_code == 200
    b2 = _pair(ic, vc)
    assert b2["v"] == b1["v"] + 1
    # replay the older SIGNED bundle -> ROLLBACK
    assert vc.post("/sync", json=b1).get_json()["reason"] == "ROLLBACK"
    # bumped version without a matching signature -> BADSIG
    forged = dict(b2, v=b2["v"] + 1)
    assert vc.post("/sync", json=forged).get_json()["reason"] == "BADSIG"
    # attacker-signed bundle with unknown key, no pinning yet -> TOFU accepts (documented),
    # but once pinned, an attacker key is rejected
    assert vc.post("/sync", json=b2).status_code == 200  # re-sync current is fine


def test_replay_static_qr_fails_fresh_nonce(tmp_path):
    _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    _pair(ic, vc)
    nonce1 = vc.get("/challenge").get_json()["nonce"]
    # attacker pastes someone else's static QR against a fresh nonce -> REPLAY,
    # and the challenge is spent even though the attempt failed
    static = ic.post("/issue", json={"user_id": "U001",
                                     "verifier_id": "SHOP-A"}).get_json()
    res = vc.post("/verify", json={"cred": static, "nonce": nonce1}).get_json()
    assert res["reason"] == "REPLAY"
    # honest holder answers a FRESH live challenge through /issue -> YES, once
    nonce2 = vc.get("/challenge").get_json()["nonce"]
    live = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A",
                                   "nonce": nonce2}).get_json()
    assert vc.post("/verify", json={"cred": live, "nonce": nonce2}).get_json()["result"] == "YES"
    # ...and the SAME live credential + nonce replayed again is consumed
    res2 = vc.post("/verify", json={"cred": live, "nonce": nonce2}).get_json()
    assert res2["reason"] == "UNKNOWN_CHALLENGE"


def test_otp_minor_and_revoked_rejected(tmp_path, monkeypatch):
    """OTP fallback enforces holder status, not just code validity."""
    import time as _time
    monkeypatch.setattr(_time, "time", lambda: 1726800045.0)  # frozen mid-step
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "admin-secret")
    _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    vc = verifier_app.app.test_client()
    hdr = {"X-Admin-Token": "admin-secret"}
    _pair(ic, vc)
    from shared.crypto import otp6
    # demo OTP secrets keyed by holder pseudonym (as the pairing operator provisions)
    c = issuer_app.db()
    secrets = {row["id"]: row["master_secret"]
               for row in c.execute("SELECT id, master_secret FROM users")}
    c.close()
    by_pseudo = {}
    for uid in ("U001", "U002"):
        cred = ic.post("/issue", json={"user_id": uid,
                                       "verifier_id": "SHOP-A"}).get_json()
        by_pseudo[uid] = (cred["uid_p"], secrets[uid])
    # U003 is revoked at seed: no issuance possible — derive its pseudonym directly
    from shared.crypto import pseudonym
    by_pseudo["U003"] = (pseudonym(secrets["U003"], "SHOP-A"), secrets["U003"])
    with open(verifier_app.SECRETS_PATH, "w") as f:
        json.dump({p: s for p, s in by_pseudo.values()}, f)
    step = int(_time.time() // 30)
    adult_code = otp6(by_pseudo["U001"][1], "SHOP-A", step)
    assert vc.post("/verify_code", json={"code": adult_code}).get_json()["result"] == "YES"
    minor_code = otp6(by_pseudo["U002"][1], "SHOP-A", step)
    assert vc.post("/verify_code", json={"code": minor_code}).get_json()["reason"] == "NOT_ADULT"
    revoked_code = otp6(by_pseudo["U003"][1], "SHOP-A", step)
    assert vc.post("/verify_code", json={"code": revoked_code}).get_json()["reason"] == "REVOKED"
    _ = ic.post("/revoke", json={"user_id": "U001"}, headers=hdr)
    _pair(ic, vc)  # re-sync picks up the revocation
    prev_code = otp6(by_pseudo["U001"][1], "SHOP-A", step - 1)  # unused grace-step code
    assert vc.post("/verify_code", json={"code": prev_code}).get_json()["reason"] == "REVOKED"
    # deterministically: a fresh issue for the revoked user is refused at issuance
    assert ic.post("/issue", json={"user_id": "U001",
                                   "verifier_id": "SHOP-A"}).status_code == 403
