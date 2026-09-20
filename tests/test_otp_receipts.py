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


def test_invalid_code_never_marked(tmp_path):
    """A wrong code must stay BAD_OTP on retry — only validated codes are stored."""
    vc, _ = _setup(str(tmp_path))
    assert vc.post("/verify_code", json={"code": "000000"}).get_json()["reason"] == "BAD_OTP"
    assert vc.post("/verify_code", json={"code": "000000"}).get_json()["reason"] == "BAD_OTP"


def test_otp_receipt_hides_code(tmp_path):
    """Receipts must not contain any derivative of the raw code: two receipts
    for the same code value must be unlinkable."""
    vc, _ = _setup(str(tmp_path))
    vc.post("/verify_code", json={"code": "000000"})
    vc.post("/verify_code", json={"code": "000000"})
    rows = vc.get("/receipts").get_json()
    assert len(rows) == 2
    assert rows[0]["nonce_hash"] != rows[1]["nonce_hash"]


def test_used_codes_keyed_by_step_and_pruned(tmp_path):
    """Same code value in a new step is fresh; entries outside the grace window go."""
    from verifier import repo
    _setup(str(tmp_path))
    db = V.DB
    repo.mark_code_used(db, "123456", 100, 1)
    assert repo.is_code_used(db, "123456", 100) is True
    assert repo.is_code_used(db, "123456", 101) is False
    repo.mark_code_used(db, "123456", 101, 2)
    repo.prune_codes(db, 101)  # keep current + previous step only
    assert repo.is_code_used(db, "123456", 100) is False
    assert repo.is_code_used(db, "123456", 101) is True


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
