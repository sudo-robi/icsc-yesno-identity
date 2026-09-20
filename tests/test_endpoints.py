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

def test_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSUER_ADMIN_TOKEN", "admin-secret")
    pub = _s(str(tmp_path))
    ic = I.app.test_client()
    assert ic.get("/healthz").get_json()["ok"]
    assert ic.get("/pubkey").get_json()["pubkey_hex"] == pub
    assert "revoked" in ic.get("/revlist").get_json()
    assert ic.post("/issue", json={}).status_code == 400
    assert ic.post("/issue", json={"user_id": "NOPE"}).status_code == 404
    assert ic.post("/issue", json={"user_id": "U003"}).status_code == 403
    # nonce-bound issuance through the documented endpoint (was HTTP 500)
    r = ic.post("/issue", json={"user_id": "U001", "verifier_id": "SHOP-A",
                                "nonce": "n123"})
    assert r.status_code == 200 and r.get_json()["n"] == "n123"
    assert ic.post("/revoke", json={"user_id": "U002"}).status_code == 403
    hdr = {"X-Admin-Token": "admin-secret"}
    r = ic.post("/revoke", json={"user_id": "U002"}, headers=hdr)
    assert r.status_code == 200
    rot = ic.post("/rotate", headers=hdr).get_json()
    assert len(rot["pubkey_hex"]) == 64
    assert ic.post("/rotate", json={"admin_token": "wrong"}).status_code == 403
    assert ic.get("/").status_code == 200
    with open(V.TRUST, "w") as f:
        json.dump({"iss": "x", "pubkey_hex": rot["pubkey_hex"], "v": 9,
                   "revoked_uids": []}, f)
    with open(V.SECRETS_PATH, "w") as f:
        json.dump({"a": "11" * 16}, f)
    vc = V.app.test_client()
    assert vc.get("/healthz").get_json()["ok"]
    assert vc.get("/challenge").get_json()["nonce"]
    from shared.crypto import otp6, sign_cred
    import time
    code = otp6("11" * 16, V.VERIFIER_ID, int(time.time() // 30))
    assert vc.post("/verify_code", json={"code": code}).get_json()["result"] == "YES"
    assert vc.post("/verify_code", json={"code": code}).get_json()["reason"] == "REPLAY"
    assert vc.get("/receipts").status_code == 200
    assert "entry_hash" in vc.get("/receipts.csv").data.decode()
    # pinned-key sync: must be signed by the pinned (rotated) issuer key
    priv_now, _ = I.load_keys()
    tb = {"iss": "x", "pubkey_hex": rot["pubkey_hex"], "v": 9}
    tb["s"] = sign_cred(dict(tb), priv_now)
    assert vc.post("/sync", json=tb).get_json()["ok"] is True
    # /sync splits bundled demo secrets OUT of the trustbundle into the secrets store
    tb2 = {"iss": "x", "pubkey_hex": rot["pubkey_hex"], "v": 10,
           "otp_secrets": {"b": "22" * 16}}
    # signature covers issuer material only — operator-attached secrets excluded
    tb2["s"] = sign_cred({k: v for k, v in tb2.items()
                          if k not in ("s", "otp_secrets")}, priv_now)
    assert vc.post("/sync", json=tb2).get_json()["ok"] is True
    with open(V.TRUST) as f:
        assert "otp_secrets" not in json.load(f)
    with open(V.SECRETS_PATH) as f:
        assert json.load(f) == {"b": "22" * 16}
    assert vc.get("/").status_code == 200
    assert vc.post("/verify", json={}).status_code == 400


def test_holder_lib_and_versioned_healthz(tmp_path):
    _s(str(tmp_path))
    vc = V.app.test_client()
    lib = vc.get("/holder/qrcode-lib.js")
    assert lib.status_code == 200 and b"qrcode" in lib.data
    h = vc.get("/healthz").get_json()
    assert h["trust"] is False and h["v"] is None
    with open(V.TRUST, "w") as f:
        json.dump({"iss": "T", "pubkey_hex": "00" * 32, "v": 4}, f)
    h = vc.get("/healthz").get_json()
    assert h["trust"] is True and h["v"] == 4


def test_sync_pairing_token(tmp_path, monkeypatch):
    from shared.crypto import gen_keypair, sign_cred
    _s(str(tmp_path))
    vc = V.app.test_client()
    priv, pub = gen_keypair()

    def signed_bundle(v, **kw):
        body = {"iss": "T", "pubkey_hex": pub, "v": v}
        body.update(kw)
        body["s"] = sign_cred({k: body[k] for k in body}, priv)
        return body

    monkeypatch.setenv("PAIRING_TOKEN", "shop-secret")
    unsigned = {"iss": "T", "pubkey_hex": pub, "v": 7}
    # wrong/missing token -> 403, nothing pinned
    r = vc.post("/sync", json=unsigned)
    assert r.status_code == 403
    assert r.get_json()["reason"] == "BAD_PAIRING_TOKEN"
    assert not os.path.exists(V.TRUST)
    # TOFU first sync (unsigned) with token -> ok, key pinned
    r = vc.post("/sync", json={**unsigned, "pairing_token": "shop-secret"})
    assert r.get_json()["ok"] is True
    with open(V.TRUST) as f:
        assert "pairing_token" not in json.load(f)  # token never persisted
    # pinned: same bundle WITHOUT a signature is now rejected
    r = vc.post("/sync", json={**unsigned, "pairing_token": "shop-secret"})
    assert r.get_json()["reason"] == "BADSIG"
    # pinned: header auth + valid signature, same version -> ok
    r = vc.post("/sync", json=signed_bundle(7),
                headers={"X-Pairing-Token": "shop-secret"})
    assert r.get_json()["ok"] is True
    # pinned: valid-signed older version -> ROLLBACK (token still required)
    tok = {"X-Pairing-Token": "shop-secret"}
    assert vc.post("/sync", json=signed_bundle(6),
                   headers=tok).get_json()["reason"] == "ROLLBACK"
    monkeypatch.delenv("PAIRING_TOKEN")
    # open demo mode still works when no token is configured
    assert vc.post("/sync", json=signed_bundle(7)).get_json()["ok"] is True
