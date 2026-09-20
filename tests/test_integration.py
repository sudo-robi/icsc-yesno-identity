"""Integration: end-to-end issue->verify incl. revocation-delay + replay demos."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import issuer.app as issuer_app
import verifier.app as verifier_app
from shared.crypto import sign_cred


def _setup(tmp):
    issuer_app.DB = os.path.join(tmp, "i.db")
    verifier_app.DB = os.path.join(tmp, "v.db")
    verifier_app.TRUST = os.path.join(tmp, "trust.json")
    issuer_app.init_db()
    verifier_app.init_db()
    priv, pub = issuer_app.load_keys()
    return priv, pub


def test_e2e_adult_yes_and_minor_no(tmp_path):
    priv, pub = _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    with open(verifier_app.TRUST, "w") as f:
        json.dump({"iss": "NIMC-TEST-01", "pubkey_hex": pub, "v": 1,
                   "revoked_uids": [], "otp_secrets": {}}, f)
    vc = verifier_app.app.test_client()
    for uid, expect in (("U001", "YES"), ("U002", "NO")):
        r = ic.post("/issue", json={"user_id": uid, "verifier_id": "SHOP-A"})
        assert r.status_code == 200, r.data
        cred = r.get_json()
        v = vc.post("/verify", json={"cred": cred, "nonce": ""})
        assert v.get_json()["result"] == expect, v.get_json()


def test_revocation_delay_window(tmp_path):
    """Old revlist passes, new revlist blocks — honest delay, bounded by 5-min expiry."""
    priv, pub = _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    cred = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A"}).get_json()
    uid_p = cred["uid_p"]
    # old bundle: not revoked -> YES
    with open(verifier_app.TRUST, "w") as f:
        json.dump({"iss": "NIMC-TEST-01", "pubkey_hex": pub, "v": 4,
                   "revoked_uids": [], "otp_secrets": {}}, f)
    vc = verifier_app.app.test_client()
    assert vc.post("/verify", json={"cred": cred, "nonce": ""}).get_json()["result"] == "YES"
    # after sync v5: REVOKED
    with open(verifier_app.TRUST, "w") as f:
        json.dump({"iss": "NIMC-TEST-01", "pubkey_hex": pub, "v": 5,
                   "revoked_uids": [uid_p], "otp_secrets": {}}, f)
    assert vc.post("/verify", json={"cred": cred, "nonce": ""}).get_json()["reason"] == "REVOKED"


def test_replay_static_qr_fails_fresh_nonce(tmp_path):
    priv, pub = _setup(str(tmp_path))
    ic = issuer_app.app.test_client()
    cred = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A"}).get_json()
    with open(verifier_app.TRUST, "w") as f:
        json.dump({"iss": "NIMC-TEST-01", "pubkey_hex": pub, "v": 1,
                   "revoked_uids": [], "otp_secrets": {}}, f)
    vc = verifier_app.app.test_client()
    nonce = vc.get("/challenge").get_json()["nonce"]
    # attacker pastes static QR (n=None) against fresh nonce -> REPLAY
    res = vc.post("/verify", json={"cred": cred, "nonce": nonce}).get_json()
    assert res["reason"] == "REPLAY"
    # honest holder signs nonce live -> YES
    body = {k: cred[k] for k in cred if k != "s"}
    body["n"] = nonce
    cred2 = dict(body)
    cred2["s"] = sign_cred(body, priv)
    res2 = vc.post("/verify", json={"cred": cred2, "nonce": nonce}).get_json()
    assert res2["result"] == "YES"
