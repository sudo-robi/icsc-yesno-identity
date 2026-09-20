import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import issuer.app as I
import verifier.app as V

def _s(tmp):
    I.DB = os.path.join(tmp, "i.db")
    V.DB = os.path.join(tmp, "v.db")
    V.TRUST = os.path.join(tmp, "t.json")
    V.SECRETS_PATH = os.path.join(tmp, "secrets.json")
    I.init_db()
    V.init_db()
    return I.load_keys()[1]

def test_endpoints(tmp_path):
    pub = _s(str(tmp_path))
    ic = I.app.test_client()
    assert ic.get("/healthz").get_json()["ok"]
    assert ic.get("/pubkey").get_json()["pubkey_hex"] == pub
    assert "revoked" in ic.get("/revlist").get_json()
    assert ic.post("/issue", json={}).status_code == 400
    assert ic.post("/issue", json={"user_id": "NOPE"}).status_code == 404
    assert ic.post("/issue", json={"user_id": "U003"}).status_code == 403
    r = ic.post("/revoke", json={"user_id": "U002"})
    assert r.status_code == 200
    rot = ic.post("/rotate").get_json()
    assert len(rot["pubkey_hex"]) == 64
    assert ic.get("/").status_code == 200
    with open(V.TRUST, "w") as f:
        json.dump({"iss": "x", "pubkey_hex": rot["pubkey_hex"], "v": 9,
                   "revoked_uids": []}, f)
    with open(V.SECRETS_PATH, "w") as f:
        json.dump({"a": "11" * 16}, f)
    vc = V.app.test_client()
    assert vc.get("/healthz").get_json()["ok"]
    assert vc.get("/challenge").get_json()["nonce"]
    from shared.crypto import otp6
    import time
    code = otp6("11" * 16, V.VERIFIER_ID, int(time.time() // 30))
    assert vc.post("/verify_code", json={"code": code}).get_json()["result"] == "YES"
    assert vc.post("/verify_code", json={"code": code}).get_json()["reason"] == "REPLAY"
    assert vc.get("/receipts").status_code == 200
    assert "entry_hash" in vc.get("/receipts.csv").data.decode()
    assert vc.post("/sync", json={"pubkey_hex": "00" * 32, "v": 1}).get_json()["ok"]
    # /sync splits bundled demo secrets OUT of the trustbundle into the secrets store
    assert vc.post("/sync", json={"pubkey_hex": "00" * 32, "v": 2,
                                  "otp_secrets": {"b": "22" * 16}}).get_json()["ok"]
    with open(V.TRUST) as f:
        assert "otp_secrets" not in json.load(f)
    with open(V.SECRETS_PATH) as f:
        assert json.load(f) == {"b": "22" * 16}
    assert vc.get("/").status_code == 200
    assert vc.post("/verify", json={}).status_code == 400
