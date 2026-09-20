"""Unit: contract schemas (shared/schemas.py) + error shape."""
import pytest

from shared import schemas
from shared.errors import REASONS, SchemaError, err


def _cred(**kw):
    body = {"v": 1, "iss": "T", "sub": "ab" * 16, "vid": "SHOP-A",
            "a": "over_18", "r": 1, "iat": 100, "exp": 200, "cnf": "k",
            "did": "device1"}
    body.update(kw)
    body["s"] = "sig"
    return body


def test_signed_body_exact_and_rejects_unknown():
    body = schemas.signed_body(_cred())
    assert set(body) == schemas.CRED_SIGNED_FIELDS
    assert "s" not in body
    with pytest.raises(SchemaError):
        schemas.signed_body(_cred(extra=1))


def test_validate_credential_types():
    assert schemas.validate_credential(_cred()) is None
    assert schemas.validate_credential("str") == "MALFORMED"
    assert schemas.validate_credential(["list"]) == "MALFORMED"
    assert schemas.validate_credential({}) == "MALFORMED"
    assert schemas.validate_credential(_cred(exp="tomorrow")) == "MALFORMED"
    assert schemas.validate_credential(_cred(exp=1.5)) == "MALFORMED"
    assert schemas.validate_credential(_cred(exp=True)) == "MALFORMED"
    assert schemas.validate_credential(_cred(r=2)) == "MALFORMED"
    assert schemas.validate_credential(_cred(r=True)) == "MALFORMED"
    assert schemas.validate_credential(_cred(sub=7)) == "MALFORMED"
    assert schemas.validate_credential(_cred(a=7)) == "MALFORMED"
    assert schemas.validate_credential(_cred(iss=None)) == "MALFORMED"
    assert schemas.validate_credential(_cred(n=5)) == "MALFORMED"
    # "n" lives in the proof, never in the credential — even a str is rejected
    assert schemas.validate_credential(_cred(n="abc")) == "MALFORMED"


def test_validate_proof_and_challenge():
    assert schemas.validate_proof({"n": "a", "ts": 1, "sig": "b"}) is None
    assert schemas.validate_proof({"n": "a", "ts": 1}) == "MALFORMED"
    assert schemas.validate_proof({"n": "a", "ts": "x", "sig": "b"}) == "MALFORMED"
    assert schemas.validate_proof(["x"]) == "MALFORMED"
    assert schemas.validate_challenge({"n": "a", "vid": "S", "exp": 9}) is None
    assert schemas.validate_challenge({"n": "a", "vid": "S"}) == "MALFORMED"
    assert schemas.validate_challenge({"n": "a", "vid": "S", "exp": 9, "z": 1}) == "MALFORMED"


def test_validate_bundle_shape():
    good = {"v": 1, "iss": "T", "vid": "S", "pub": "ab" * 32, "next_pub": None,
            "revoked": [], "minors": [], "iat": 1, "exp": 2, "s": "sig"}
    assert schemas.validate_bundle_shape(good) is None
    assert schemas.validate_bundle_shape(dict(good, next_pub="zz")) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, minors="x")) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, iat=1.5)) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, iss=7)) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, extra=1)) == "MALFORMED"
    bad_pub = dict(good, pub="short")
    assert schemas.validate_bundle_shape(bad_pub) == "MALFORMED"
    assert schemas.validate_bundle_shape({"v": 1}) == "MALFORMED"
    assert schemas.validate_bundle_shape([1]) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, revoked="x")) == "MALFORMED"
    assert schemas.validate_bundle_shape(dict(good, v="1")) == "MALFORMED"


def test_validate_challenge_extra_field():
    good = {"n": "a", "vid": "S", "exp": 9}
    assert schemas.validate_challenge(good) is None
    # challenge shape is exact: unknown fields rejected
    assert schemas.validate_challenge(dict(good, z=1)) == "MALFORMED"
    assert schemas.validate_challenge(dict(good, n=5)) == "MALFORMED"
    assert schemas.validate_challenge("str") == "MALFORMED"


def test_error_shape_contract():
    assert err("BADSIG") == {"error": "BADSIG"}
    assert err("BADSIG", "why") == {"error": "BADSIG", "detail": "why"}
    with pytest.raises(ValueError):
        err("NOPE")
    assert "WRONG_VERIFIER" in REASONS and "BAD_PROOF" in REASONS
    assert "ISSUER_MISMATCH" in REASONS and "REPLAY" not in REASONS
