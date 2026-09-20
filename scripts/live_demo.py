"""Live smoke: pairing + YES + NO + forgery + replay.
Run: ISSUER_URL=http://localhost:5001 VERIFIER_URL=http://localhost:5002 \
     .venv/bin/python scripts/live_demo.py
"""
import json
import os
import urllib.request

ISSUER = os.environ.get("ISSUER_URL", "http://localhost:5001").rstrip("/")
VERIFIER = os.environ.get("VERIFIER_URL", "http://localhost:5002").rstrip("/")
IPFX = os.environ.get("ISSUER_PREFIX", "")
VPFX = os.environ.get("VERIFIER_PREFIX", "")


def call(base, prefix, method, path, body=None):
    req = urllib.request.Request(
        base + prefix + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def issuer_call(method, path, body=None):
    return call(ISSUER, IPFX, method, path, body)


def verifier_call(method, path, body=None):
    return call(VERIFIER, VPFX, method, path, body)


print("--- pairing")
pub = issuer_call("GET", "/healthz") and issuer_call("GET", "/pubkey")
print("pubkey:", pub["pubkey_hex"][:16], "...")
print(verifier_call("POST", "/sync", {"pubkey_hex": pub["pubkey_hex"],
      "v": pub["v"], "revoked_uids": [], "otp_secrets": {}}))

print("--- adult YES")
cred = issuer_call("POST", "/issue", {"user_id": "U001", "verifier_id": "SHOP-A"})
print(verifier_call("POST", "/verify", {"cred": cred, "nonce": ""}))

print("--- minor NO")
cred2 = issuer_call("POST", "/issue", {"user_id": "U002", "verifier_id": "SHOP-A"})
print(verifier_call("POST", "/verify", {"cred": cred2, "nonce": ""}))

print("--- forgery BADSIG")
fake = {"v": 1, "iss": "X", "uid_p": "x", "a": "over_18",
        "r": 1, "exp": 9999999999, "s": "fake"}
print(verifier_call("POST", "/verify", {"cred": fake, "nonce": ""}))

print("--- replay vs fresh nonce")
nonce = verifier_call("GET", "/challenge")["nonce"]
print("static QR + fresh nonce:", verifier_call("POST", "/verify",
      {"cred": cred, "nonce": nonce}))
print("ALL LIVE CHECKS DONE")
