"""Verifier unit tests: decision order, nonces, OTP window, receipts, bundles."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import verifier.repo as repo
from shared.canonical import canonical
from shared.crypto import (
    b64u_encode, ed25519_keypair, ed25519_sign, ed25519_verify, otp_code, sha256_hex,
)
from shared.schemas import signed_body
from verifier import services


def _trust(pub, **kw):
    tb = {"v": 1, "iss": "T", "vid": "SHOP-A", "pub": pub, "next_pub": None,
          "revoked": [], "minors": [], "iat": 100, "exp": 9999999999}
    tb.update(kw)
    return tb


def _cred(priv, holder_pub, **kw):
    body = {"v": 1, "iss": "T", "sub": "ab" * 16, "vid": "SHOP-A",
            "a": "over_18", "r": 1, "iat": 100, "exp": 9999999999,
            "cnf": holder_pub}
    body.update(kw)
    body["s"] = ed25519_sign(priv, canonical(signed_body(body)))
    return body


def _holder():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


def _holder_pub(key):
    nums = key.private_numbers().public_numbers
    raw = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return b64u_encode(raw)


def _proof(key, cred, nonce, vid="SHOP-A", ts=1000):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    msg = services.proof_message(
        cred_canonical_sha=sha256_hex(canonical(signed_body(cred))),
        nonce=nonce, vid=vid, ts=ts)
    der = key.sign(msg, _ec.ECDSA(SHA256()))
    r, s = decode_dss_signature(der)
    return {"n": nonce, "ts": ts,
            "sig": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def _decide(cred, proof, trust, nonces, now=1000.0, raw_len=100):
    consumed = []

    def consume(nonce, min_issued, now_ts):
        if nonce in nonces and nonces[nonce] >= min_issued:
            del nonces[nonce]
            consumed.append(nonce)
            return {"nonce": nonce}
        return None

    return services.decide(cred, proof, raw_len, trust=trust,
                           verifier_id="SHOP-A", now=now, consume_nonce=consume)


def test_decide_happy_path():
    priv, pub = ed25519_keypair()
    key = _holder()
    cred = _cred(priv, _holder_pub(key))
    proof = _proof(key, cred, "n1")
    assert _decide(cred, proof, _trust(pub), {"n1": 999.0}) == ("YES", "OK")


def test_expiry_skew_edges():
    priv, pub = ed25519_keypair()
    key = _holder()
    now = 100000.0
    # Within-skew cred still needs its mandatory holder proof to reach OK;
    # proof="" can never yield OK (validate_proof -> MALFORMED).
    cred_ok = _cred(priv, _holder_pub(key), exp=int(now) - 29)
    proof_ok = _proof(key, cred_ok, "n1", ts=int(now))
    assert _decide(cred_ok, proof_ok,
                   _trust(pub), {"n1": now}, now=now)[1] == "OK"
    assert _decide(_cred(priv, _holder_pub(key), exp=int(now) - 31), "",
                   _trust(pub), {}, now=now)[1] == "EXPIRED"


def test_check_precedence_earliest_wins():
    priv, pub = ed25519_keypair()
    key = _holder()
    # malformed shape beats an expired timestamp
    assert _decide({"v": 1}, "", _trust(pub), {}, now=100000.0)[1] == "MALFORMED"
    # expired beats a bad signature (can't even get to crypto)
    bad = _cred(priv, _holder_pub(key), exp=10)
    bad["s"] = "bogus"
    assert _decide(bad, "", _trust(pub), {}, now=100000.0)[1] == "EXPIRED"
    # wrong verifier beats issuer mismatch
    other = _cred(priv, _holder_pub(key), vid="SHOP-B", iss="EVIL")
    assert _decide(other, "", _trust(pub), {}, now=1000.0)[1] == "WRONG_VERIFIER"


def test_decide_order():
    priv, pub = ed25519_keypair()
    key = _holder()
    base = _cred(priv, _holder_pub(key))
    proof = _proof(key, base, "n1")
    nonces = {"n1": 999.0}
    assert _decide({}, proof, _trust(pub), dict(nonces))[1] == "MALFORMED"
    assert _decide(base, proof, _trust(pub), dict(nonces), raw_len=99999)[1] == "TOO_LARGE"
    assert _decide(base, proof, _trust(pub), dict(nonces))[1] == "OK"  # sanity
    wrong_vid = _cred(priv, _holder_pub(key), vid="SHOP-B")
    assert _decide(wrong_vid, proof, _trust(pub), dict(nonces))[1] == "WRONG_VERIFIER"
    wrong_iss = _cred(priv, _holder_pub(key), iss="EVIL")
    assert _decide(wrong_iss, proof, _trust(pub), dict(nonces))[1] == "ISSUER_MISMATCH"
    expired = _cred(priv, _holder_pub(key), exp=10)
    assert _decide(expired, proof, _trust(pub), dict(nonces), now=1000.0)[1] == "EXPIRED"
    tampered = dict(base, r=0)
    assert _decide(tampered, proof, _trust(pub), dict(nonces))[1] == "BADSIG"
    assert _decide(base, proof, None, dict(nonces))[1] == "NO_TRUSTBUNDLE"


def test_decide_proof_checks():
    priv, pub = ed25519_keypair()
    key = _holder()
    other = _holder()
    cred = _cred(priv, _holder_pub(key))
    assert _decide(cred, None, _trust(pub), {"n1": 999.0})[1] == "BAD_PROOF"
    # partial proof (missing ts/sig) is a schema failure, not a crypto failure
    assert _decide(cred, {"n": "n1"}, _trust(pub), {"n1": 999.0})[1] == "MALFORMED"
    assert _decide(cred, _proof(key, cred, "ghost"), _trust(pub),
                   {"n1": 999.0})[1] == "UNKNOWN_CHALLENGE"
    stale = _proof(key, cred, "n1", ts=1)
    assert _decide(cred, stale, _trust(pub), {"n1": 999.0}, now=1000.0)[1] == "BAD_PROOF"
    wrong_key = _proof(other, cred, "n1")
    assert _decide(cred, wrong_key, _trust(pub), {"n1": 999.0})[1] == "BAD_PROOF"


def test_decide_status_lists():
    priv, pub = ed25519_keypair()
    key = _holder()
    cred = _cred(priv, _holder_pub(key))
    proof = _proof(key, cred, "n1")
    assert _decide(cred, proof, _trust(pub, revoked=["ab" * 16]),
                   {"n1": 999.0}) == ("NO", "REVOKED")
    assert _decide(cred, proof, _trust(pub, minors=["ab" * 16]),
                   {"n1": 999.0}) == ("NO", "NOT_ADULT")
    minor_cred = _cred(priv, _holder_pub(key), r=0)
    minor_proof = _proof(key, minor_cred, "n1")
    assert _decide(minor_cred, minor_proof, _trust(pub),
                   {"n1": 999.0}) == ("NO", "NOT_ADULT")


def test_consume_on_any_use():
    priv, pub = ed25519_keypair()
    key = _holder()
    static = _cred(priv, _holder_pub(key))
    # a failed proof against a REGISTERED nonce still consumes it
    reg = {"n9": 999.0}
    bad_proof = {"n": "n9", "ts": 1000, "sig": "bogus"}
    assert _decide(static, bad_proof, _trust(pub), reg)[1] == "BAD_PROOF"
    assert "n9" not in reg  # consumed despite the failure


def test_nonce_repo_atomic_shape(tmp_path):
    path = os.path.join(str(tmp_path), "v.db")
    repo.init_db(path)
    repo.add_nonce(path, "n1", "SHOP-A", 999, 9999)
    assert repo.consume_nonce(path, "n1", 0, 1000) is not None
    assert repo.consume_nonce(path, "n1", 0, 1000) is None  # second loses
    repo.add_nonce(path, "old", "SHOP-A", 1, 2)
    assert repo.consume_nonce(path, "old", 0, 1000) is None  # expired
    repo.prune_nonces(path, 999)
    assert repo.consume_nonce(path, "old", 0, 1000) is None


def test_bundle_checks():
    priv, pub = ed25519_keypair()
    k2priv, k2pub = ed25519_keypair()
    from shared.canonical import canonical as _c
    from shared.crypto import ed25519_sign as _sign
    from shared.schemas import bundle_sig_body

    def bundle(v, key, iss="T", vid="SHOP-A", nxt=None, exp=9999):
        body = {"v": v, "iss": iss, "vid": vid, "pub": pub, "next_pub": nxt,
                "revoked": [], "minors": [], "iat": 1, "exp": exp}
        body["s"] = _sign(key, _c(bundle_sig_body(body)))
        return body

    pinned = {"pub": pub, "v": 1, "iss": "T", "vid": "SHOP-A", "next_pub": None}
    ok, _ = services.check_bundle(bundle(2, priv), pinned=pinned, now=5)
    assert ok is True
    assert services.check_bundle(bundle(0, priv), pinned=pinned, now=5) == (False, "ROLLBACK")
    assert services.check_bundle(bundle(2, priv, vid="SHOP-X"),
                                 pinned=pinned, now=5)[1] == "ISSUER_MISMATCH"
    assert services.check_bundle(bundle(2, priv, exp=1),
                                 pinned=pinned, now=5) == (False, "EXPIRED")
    tampered = bundle(2, priv)
    tampered["revoked"] = ["zz"]
    assert services.check_bundle(tampered, pinned=pinned, now=5) == (False, "BADSIG")
    # rotation chain: K2 announced via next_pub, then K2-signed bundles verify
    nxt = bundle(2, priv, nxt=k2pub)
    ok, _ = services.check_bundle(nxt, pinned={**pinned, "next_pub": k2pub}, now=5)
    assert ok is True
    k2bundle = dict(bundle(3, priv), pub=k2pub)
    k2bundle["s"] = _sign(k2priv, _c(bundle_sig_body(
        {k: k2bundle[k] for k in k2bundle if k != "s"})))
    assert services.check_bundle(k2bundle, pinned={**pinned, "pub": k2pub},
                                 now=5) == (True, None)
    # rogue key with no chain linkage is rejected
    rogue_priv, rogue_pub = ed25519_keypair()
    rogue = dict(bundle(9, priv), pub=rogue_pub)
    rogue["s"] = _sign(rogue_priv, _c(bundle_sig_body(
        {k: rogue[k] for k in rogue if k != "s"})))
    assert services.check_bundle(rogue, pinned=pinned, now=5) == (False, "BADSIG")


def test_receipt_chain_head_and_tamper(tmp_path):
    path = os.path.join(str(tmp_path), "v.db")
    repo.init_db(path)
    key = services.load_receipt_key(path)
    assert key == services.load_receipt_key(path)  # persisted
    ts = 1000
    h1 = repo.append_receipt(path, ts=ts, verifier_id="S", q="over_18:proof",
                             result="YES", reason="OK",
                             entry_hash_of=lambda prev: services.chain_entry(
                                 prev, ts, "S", "over_18:proof", "YES", "OK", key))
    rows = repo.all_receipts(path)
    assert len(rows) == 1 and rows[0]["entry_hash"] == h1
    bad = dict(rows[0], result="NO", reason="BADSIG")
    assert bad["entry_hash"] != services.chain_entry(
        bad["prev_hash"], bad["ts"], "S", "over_18:proof", "NO", "BADSIG", key)
    sig = services.sign_head(key, h1, ts)
    assert ed25519_verify(services.receipt_pub(path), sig,
                          canonical({"head": h1, "ts": ts})) is True


def test_receipts_hold_no_code_material(tmp_path):
    """Phase 2.8: receipt rows contain exactly the documented columns — no raw
    nonce/credential/code and no derivatives of them."""
    path = os.path.join(str(tmp_path), "v.db")
    repo.init_db(path)
    key = services.load_receipt_key(path)
    repo.append_receipt(path, ts=1, verifier_id="S", q="over_18:otp",
                        result="YES", reason="OK_OTP",
                        entry_hash_of=lambda prev: services.chain_entry(
                            prev, 1, "S", "over_18:otp", "YES", "OK_OTP", key))
    row = repo.all_receipts(path)[0]
    assert set(row) == {"id", "ts", "verifier_id", "q", "result", "reason",
                        "prev_hash", "entry_hash"}


def test_otp_window_and_status():
    secrets_map = {"sub1": "aa" * 16}
    step = 1000
    code = otp_code("aa" * 16, "SHOP-A", step)
    assert services.match_otp_code(secrets_map, code, "SHOP-A", step) == "sub1"
    assert services.match_otp_code(secrets_map, code, "SHOP-A", step + 1) == "sub1"
    assert services.match_otp_code(secrets_map, code, "SHOP-A", step + 2) is None
    assert services.match_otp_code(secrets_map, "000000", "SHOP-A", step) is None
    assert services.otp_status("sub1", {}) == ("YES", "OK_OTP")
    assert services.otp_status("sub1", {"revoked": ["sub1"]}) == ("NO", "REVOKED")
    assert services.otp_status("sub1", {"minors": ["sub1"]}) == ("NO", "NOT_ADULT")


def test_fingerprint_and_reasons():
    from shared.crypto import key_fingerprint

    assert key_fingerprint("ab" * 32) == "abab abab abab abab"
    assert services.check_reason("WRONG_VERIFIER") is True
    assert services.check_reason("BAD_PROOF") is True
    assert services.check_reason("NOPE") is False


def test_proof_message_vector():
    msg = services.proof_message(cred_canonical_sha="ab", nonce="n",
                                 vid="SHOP-A", ts=5)
    assert msg == b'["yn-proof-v1","ab","n","SHOP-A",5]'
