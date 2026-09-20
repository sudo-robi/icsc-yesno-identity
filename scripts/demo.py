#!/usr/bin/env python3
"""End-to-end smoke: exercises the full protocol over HTTP and prints a checklist.

Expects issuer :5001 + verifier :5002 running (see run.sh) with a shared
ADMIN_TOKEN. Exit code 0 only if EVERY check passes.

Usage: ADMIN_TOKEN=... [ISSUER_URL=...] [VERIFIER_URL=...] python scripts/demo.py
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from shared.canonical import canonical
from shared.crypto import b64u_encode, sha256_hex
from shared.schemas import signed_body

ISSUER = os.environ.get("ISSUER_URL", "http://localhost:5001").rstrip("/")
VERIFIER = os.environ.get("VERIFIER_URL", "http://localhost:5002").rstrip("/")
ADMIN = os.environ.get("ADMIN_TOKEN", "")
HDRS = {"Content-Type": "application/json", "Authorization": f"Bearer {ADMIN}"}
CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    CHECKS.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name)


def call(base: str, method: str, path: str, body=None, headers=None):
    req = urllib.request.Request(
        base + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def p256():
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers().public_numbers
    pub = b64u_encode(b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"))
    return key, pub


def proof_for(key, cred, nonce, vid="SHOP-A"):
    import time

    ts = int(time.time())
    msg = canonical(["yn-proof-v1", sha256_hex(canonical(signed_body(cred))),
                     nonce, vid, ts])
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(SHA256())))
    return {"n": nonce, "ts": ts,
            "sig": b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def main() -> int:
    # pair
    _, bundle = call(ISSUER, "GET", "/bundle?vid=SHOP-A")
    status, synced = call(VERIFIER, "POST", "/sync", bundle, HDRS)
    check("pair shop (TOFU + fingerprint)", status == 200 and synced.get("ok") is True)
    if status != 200:
        print("fingerprint would print here; aborting:", synced)
        return 1

    # enroll adult + minor on separate device keys
    adult_key, adult_pub = p256()
    minor_key, minor_pub = p256()

    def enroll(uid, pub):
        _, data = call(ISSUER, "POST", "/admin/users/" + uid + "/enrollment-code",
                       {}, HDRS)
        status, body = call(ISSUER, "POST", "/enroll",
                            {"code": data["code"], "verifier_id": "SHOP-A",
                             "holder_pub": pub})
        return status, body.get("credential", {})

    _, adult = enroll("U001", adult_pub)
    _, minor = enroll("U002", minor_pub)

    def attempt(cred, key):
        _, ch = call(VERIFIER, "GET", "/challenge")
        _, res = call(VERIFIER, "POST", "/verify",
                      {"c": cred, "p": proof_for(key, cred, ch["n"])})
        return res

    check("adult YES", attempt(adult, adult_key).get("result") == "YES")
    check("minor NO", attempt(minor, minor_key).get("reason") == "NOT_ADULT")

    # tampered issuer signature
    bad = dict(adult, r=0)
    _, ch = call(VERIFIER, "GET", "/challenge")
    res = call(VERIFIER, "POST", "/verify",
               {"c": bad, "p": proof_for(adult_key, bad, ch["n"])})[1]
    check("BADSIG on tampered credential", res.get("reason") == "BADSIG")

    # screenshot replay of a live presentation
    _, ch = call(VERIFIER, "GET", "/challenge")
    live = {"c": adult, "p": proof_for(adult_key, adult, ch["n"])}
    first = call(VERIFIER, "POST", "/verify", live)[1]
    second = call(VERIFIER, "POST", "/verify", live)[1]
    check("live presentation YES once", first.get("result") == "YES")
    check("replay blocked", second.get("reason") == "UNKNOWN_CHALLENGE")

    # forged bundle (self-signed rogue key) rejected even with admin token
    from shared.crypto import ed25519_keypair, ed25519_sign
    from shared.schemas import bundle_sig_body
    rogue_priv, rogue_pub = ed25519_keypair()
    rogue = {"v": 99, "iss": "EVIL", "vid": "SHOP-A", "pub": rogue_pub,
             "next_pub": None, "revoked": [], "minors": [], "iat": 1, "exp": 9999999999}
    rogue["s"] = ed25519_sign(rogue_priv, canonical(bundle_sig_body(rogue)))
    status, body = call(VERIFIER, "POST", "/sync", rogue, HDRS)
    check("forged bundle rejected", status == 409 and body.get("error") == "BADSIG")

    # revoke -> sync -> REVOKED
    call(ISSUER, "POST", "/admin/revoke", {"user_id": "U001"}, HDRS)
    _, bundle2 = call(ISSUER, "GET", "/bundle?vid=SHOP-A")
    call(VERIFIER, "POST", "/sync", bundle2, HDRS)
    _, ch = call(VERIFIER, "GET", "/challenge")
    res = call(VERIFIER, "POST", "/verify",
               {"c": adult, "p": proof_for(adult_key, adult, ch["n"])})[1]
    check("revoked after sync", res.get("reason") == "REVOKED")

    failed = [name for name, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
