"""Unit: crypto primitives (shared/crypto.py)."""
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

from shared import crypto
from shared.canonical import canonical


def test_b64u_no_padding_roundtrip():
    for raw in (b"", b"f", b"fo", b"foo", b"foob", bytes(range(256))):
        enc = crypto.b64u_encode(raw)
        assert "=" not in enc
        assert crypto.b64u_decode(enc) == raw
    with pytest.raises(Exception):
        crypto.b64u_decode("!!!not-base64!!!")


def test_ed25519_sign_verify_and_tamper():
    priv, pub = crypto.ed25519_keypair()
    assert len(priv) == 64 and len(pub) == 64
    msg = canonical({"v": 1})
    sig = crypto.ed25519_sign(priv, msg)
    assert crypto.ed25519_verify(pub, sig, msg) is True
    assert crypto.ed25519_verify(pub, sig, msg + b"x") is False
    assert crypto.ed25519_verify(pub, "AAAA", msg) is False
    assert crypto.ed25519_verify("zz", sig, msg) is False


def test_pseudonym_per_shop_and_length():
    a = crypto.pseudonym("00" * 16, "SHOP-A")
    b = crypto.pseudonym("00" * 16, "SHOP-B")
    assert a != b
    assert len(a) == 32  # first 16 BYTES of HMAC-SHA256, hex
    assert crypto.pseudonym("00" * 16, "SHOP-A") == a  # deterministic


def _webcrypto_style_fixture():
    """Simulate a WebCrypto P-256 signature: raw r||s over the message.

    WebCrypto returns IEEE P1363 (64-byte r||s); the backend must convert to
    DER before verifying. Built here with `cryptography` so the fixture is a
    faithful stand-in for a browser-produced signature.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    pub_raw = b"\x04" + numbers.public_numbers.x.to_bytes(32, "big") + \
        numbers.public_numbers.y.to_bytes(32, "big")
    msg = canonical(["yn-proof-v1", "ab12", "nonce", "SHOP-A", 99])
    der = key.sign(msg, ec.ECDSA(SHA256()))
    # DER -> raw r||s, exactly as WebCrypto would hand it over
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return crypto.b64u_encode(pub_raw), crypto.b64u_encode(raw), msg


def test_p256_webcrypto_fixture_verifies():
    pub, raw_sig, msg = _webcrypto_style_fixture()
    assert crypto.p256_verify(pub, raw_sig, msg) is True


def test_p256_tamper_and_malformed():
    pub, raw_sig, msg = _webcrypto_style_fixture()
    assert crypto.p256_verify(pub, raw_sig, msg + b"x") is False
    # wrong key
    other_pub, _, _ = _webcrypto_style_fixture()
    assert crypto.p256_verify(other_pub, raw_sig, msg) is False
    # malformed inputs never raise, just fail
    assert crypto.p256_verify("nope", raw_sig, msg) is False
    assert crypto.p256_verify(pub, "nope", msg) is False
    assert crypto.p256_verify(pub, crypto.b64u_encode(b"short"), msg) is False
    # non-uncompressed point rejected at parse
    with pytest.raises(ValueError):
        crypto.p256_pubkey_from_b64u(crypto.b64u_encode(b"\x05" + b"\x00" * 64))
    with pytest.raises(ValueError):
        crypto.p1363_to_der(crypto.b64u_encode(b"short"))


def test_sha256_hex():
    assert crypto.sha256_hex(b"abc") == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
