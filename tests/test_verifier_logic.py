"""Direct decide() policy tests. agency: api-tester | ECC: verification-loop."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import verifier.app as V
from shared.crypto import gen_keypair, sign_cred

PRIV, PUB = gen_keypair()


def _trust(tmp, **kw):
    tb = {"iss": "NIMC-TEST-01", "pubkey_hex": PUB, "v": 1,
          "revoked_uids": []}
    tb.update(kw)
    p = os.path.join(tmp, "trust.json")
    with open(p, "w") as f:
        json.dump(tb, f)
    V.TRUST = p
    V._nonces.clear()
    return tb


def _cred(priv=PRIV, **kw):
    body = {"v": 1, "iss": "NIMC-TEST-01", "uid_p": "abcd1234efgh5678",
            "a": "over_18", "r": 1, "exp": int(time.time()) + 300}
    body.update(kw)
    c = dict(body)
    c["s"] = sign_cred(body, priv)
    return c


def test_ok_and_not_adult(tmp_path):
    _trust(str(tmp_path))
    assert V.decide(_cred(), "") == ("YES", "OK")
    assert V.decide(_cred(r=0), "") == ("NO", "NOT_ADULT")


def test_expired_and_skew(tmp_path):
    _trust(str(tmp_path))
    assert V.decide(_cred(exp=int(time.time()) - 3600), "")[1] == "EXPIRED"
    # inside 30s skew still verifies (not expired)
    assert V.decide(_cred(exp=int(time.time()) - 10), "") == ("YES", "OK")


def test_badsig_tampered_and_wrong_key(tmp_path):
    _trust(str(tmp_path))
    c = _cred()
    c["uid_p"] = "ffff"  # tamper after signing
    assert V.decide(c, "")[1] == "BADSIG"
    other_priv, _ = gen_keypair()
    assert V.decide(_cred(priv=other_priv), "")[1] == "BADSIG"


def test_revoked(tmp_path):
    _trust(str(tmp_path), revoked=["abcd1234efgh5678"])
    assert V.decide(_cred(), "") == ("NO", "REVOKED")


def test_minors_list(tmp_path):
    _trust(str(tmp_path), minors=["abcd1234efgh5678"])
    assert V.decide(_cred(), "") == ("NO", "NOT_ADULT")


def test_exp_wrong_type(tmp_path):
    _trust(str(tmp_path))
    assert V.decide(_cred(exp="tomorrow"), "")[1] == "MALFORMED"


def test_replay_and_live_nonce(tmp_path):
    _trust(str(tmp_path))
    V._nonces["n1"] = time.time()
    # static QR against a live challenge: REPLAY (and the nonce is spent)
    assert V.decide(_cred(), "n1")[1] == "REPLAY"
    # same challenge reused, even with a properly bound credential: spent
    assert V.decide(_cred(n="n1"), "n1")[1] == "UNKNOWN_CHALLENGE"
    # fresh challenge + bound credential: YES, then spent
    V._nonces["n2"] = time.time()
    assert V.decide(_cred(n="n2"), "n2") == ("YES", "OK")
    assert V.decide(_cred(n="n2"), "n2")[1] == "UNKNOWN_CHALLENGE"


def test_consume_on_any_use(tmp_path):
    """A challenge is single-use even when the first attempt fails: static QR
    burns the nonce, so a live credential on the SAME nonce must fail."""
    _trust(str(tmp_path))
    V._nonces["n1"] = time.time()
    assert V.decide(_cred(), "n1")[1] == "REPLAY"  # binding fails, nonce spent
    assert V.decide(_cred(n="n1"), "n1")[1] == "UNKNOWN_CHALLENGE"


def test_iss_mismatch(tmp_path):
    """A credential signed for another issuer id must not verify."""
    _trust(str(tmp_path))
    assert V.decide(_cred(iss="EVIL-ISSUER"), "")[1] == "BADSIG"


def test_strict_field_types(tmp_path):
    _trust(str(tmp_path))
    assert V.decide(_cred(r=2), "")[1] == "MALFORMED"
    assert V.decide(_cred(exp=1710000300.5), "")[1] == "MALFORMED"
    assert V.decide(_cred(exp=True), "")[1] == "MALFORMED"
    assert V.decide(_cred(uid_p=12345), "")[1] == "MALFORMED"
    assert V.decide(_cred(a=7), "")[1] == "MALFORMED"
    assert V.decide(_cred(n=123), "")[1] == "MALFORMED"


def test_unknown_and_expired_challenge(tmp_path):
    _trust(str(tmp_path))
    assert V.decide(_cred(), "never-issued")[1] == "UNKNOWN_CHALLENGE"
    V._nonces["stale"] = time.time() - V.NONCE_TTL_SEC - 10
    assert V.decide(_cred(n="stale"), "stale")[1] == "UNKNOWN_CHALLENGE"
    assert "stale" not in V._nonces  # pruned on read path


def test_challenge_prunes_stale(tmp_path):
    _trust(str(tmp_path))
    V.DB = os.path.join(str(tmp_path), "v.db")
    V.init_db()
    V._nonces["old"] = time.time() - V.NONCE_TTL_SEC - 1
    vc = V.app.test_client()
    vc.get("/challenge")
    assert "old" not in V._nonces


def test_malformed_and_too_large(tmp_path):
    _trust(str(tmp_path))
    assert V.decide({"a": 1}, "")[1] == "MALFORMED"
    big = _cred()
    big["pad"] = "x" * 5000
    assert V.decide(big, "")[1] == "TOO_LARGE"


def test_no_trustbundle(tmp_path):
    V.TRUST = os.path.join(str(tmp_path), "missing.json")
    assert V.decide(_cred(), "") == ("NO", "NO_TRUSTBUNDLE")
