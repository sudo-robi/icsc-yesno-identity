"""Shared attack/demo helpers: holder-side P-256 crypto + HTTP ceremonies.

Mirrors exactly what the holder PWA does (WebCrypto ECDSA P-256, raw r||s):
generate a device key, enroll it, sign challenge proofs.
"""
import time

from shared.canonical import canonical
from shared.crypto import b64u_encode, sha256_hex
from shared.schemas import signed_body
from verifier import services as verifier_services


def p256_key():
    """Fresh holder device key (like WebCrypto generateKey, per shop)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


def p256_pub_raw(key):
    """Uncompressed point bytes (what WebCrypto exportKey('raw') yields)."""
    nums = key.private_numbers().public_numbers
    return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def p256_pub_b64u(key):
    """Holder public key as exchanged in enrollment (cnf)."""
    return b64u_encode(p256_pub_raw(key))


def enroll_holder(ic, hdr, uid="U001", vid="SHOP-A"):
    """Enroll a fresh device key; return (credential, key, otp_secret)."""
    code = ic.post(f"/admin/users/{uid}/enrollment-code",
                   headers=hdr).get_json()["code"]
    key = p256_key()
    r = ic.post("/enroll", json={"code": code, "verifier_id": vid,
                                 "holder_pub": p256_pub_b64u(key)})
    assert r.status_code == 200, r.data
    body = r.get_json()
    return body["credential"], key, body.get("otp_secret")


def make_proof(key, cred, nonce, vid="SHOP-A", ts=None):
    """Build a holder proof exactly per docs/protocol.md."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    ts = int(time.time()) if ts is None else ts
    msg = verifier_services.proof_message(
        cred_canonical_sha=sha256_hex(canonical(signed_body(cred))),
        nonce=nonce, vid=vid, ts=ts, did=cred.get("did", ""))
    der = key.sign(msg, _ec.ECDSA(SHA256()))
    r, s = decode_dss_signature(der)
    return {"n": nonce, "ts": ts,
            "sig": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def pair_shop(ic, vc, hdr=None, vid="SHOP-A"):
    """Documented pairing ceremony over HTTP. Returns the bundle."""
    hdr = hdr or {"Authorization": "Bearer admin-secret"}
    bundle = ic.get(f"/bundle?vid={vid}").get_json()
    r = vc.post("/sync", json=bundle, headers=hdr)
    assert r.status_code == 200, r.data
    return bundle


def fresh_challenge(vc):
    return vc.get("/challenge").get_json()
