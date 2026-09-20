"""OTP + receipts-chain integrity tests (integration)."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import verifier.app as V
from shared.crypto import otp6


def _setup(tmp, secret="22" * 16):
    V.DB = os.path.join(tmp, "v.db")
    V.TRUST = os.path.join(tmp, "t.json")
    V.SECRETS_PATH = os.path.join(tmp, "secrets.json")
    V.init_db()
    with open(V.TRUST, "w") as f:
        json.dump({"iss": "T", "pubkey_hex": "00" * 32, "v": 1,
                   "revoked_uids": []}, f)
    with open(V.SECRETS_PATH, "w") as f:
        json.dump({"u": secret}, f)
    return V.app.test_client(), secret


def test_embedded_trustbundle_secrets_ignored(tmp_path):
    """Regression: secrets accidentally left inside the trustbundle must NOT work."""
    vc, secret = _setup(str(tmp_path))
    with open(V.TRUST, "w") as f:
        json.dump({"iss": "T", "pubkey_hex": "00" * 32, "v": 1,
                   "revoked_uids": [], "otp_secrets": {"u": secret}}, f)
    os.remove(V.SECRETS_PATH)
    code = otp6(secret, V.VERIFIER_ID, int(time.time() // 30))
    assert vc.post("/verify_code", json={"code": code}).get_json()["reason"] == "BAD_OTP"


def test_otp_valid_then_reuse_replay(tmp_path):
    vc, secret = _setup(str(tmp_path))
    step = int(time.time() // 30)
    code = otp6(secret, V.VERIFIER_ID, step)
    assert vc.post("/verify_code", json={"code": code}).get_json()["result"] == "YES"
    assert vc.post("/verify_code", json={"code": code}).get_json()["reason"] == "REPLAY"


def test_otp_bad_code(tmp_path):
    vc, _ = _setup(str(tmp_path))
    assert vc.post("/verify_code", json={"code": "000000"}).get_json()["reason"] == "BAD_OTP"


def test_receipt_chain_links(tmp_path):
    vc, _ = _setup(str(tmp_path))
    vc.post("/verify_code", json={"code": "000000"})
    vc.post("/verify_code", json={"code": "111111"})
    rows = vc.get("/receipts").get_json()
    assert len(rows) == 2
    # Recompute each link from the STORED fields: any edit breaks the chain.
    # (Stored nh/sh are peppered one-way hashes — deliberately not invertible.)
    prev = "GENESIS"
    for r in reversed(rows):  # oldest first
        assert r["prev_hash"] == prev
        assert r["entry_hash"] == V._chain_hash(
            r["prev_hash"], r["ts"], r["verifier_id"], r["q"],
            r["result"], r["nonce_hash"], r["sig_hash"])
        prev = r["entry_hash"]
    csv = vc.get("/receipts.csv").data.decode().splitlines()
    assert csv[0].startswith("id,ts,verifier")
    assert len(csv) == 3  # header + 2 rows


def test_sync_rejects_bad_pubkey(tmp_path):
    _setup(str(tmp_path))
    vc = V.app.test_client()
    r = vc.post("/sync", json={"pubkey_hex": "short", "v": 1})
    assert r.status_code == 400  # schema validation, not an assert-crash 500
