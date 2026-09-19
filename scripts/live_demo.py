"""Live production smoke: pairing + YES + NO + forgery + replay. Run: .venv/bin/python scripts/live_demo.py"""
import json
import urllib.request

BASE = "https://icsc-yesno-identity-rho.vercel.app"


def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


print("--- pairing")
pub = call("GET", "/issuer/healthz") and call("GET", "/issuer/pubkey")
print("pubkey:", pub["pubkey_hex"][:16], "...")
print(call("POST", "/verifier/sync", {"pubkey_hex": pub["pubkey_hex"],
      "v": pub["v"], "revoked_uids": [], "otp_secrets": {}}))

print("--- adult YES")
cred = call("POST", "/issuer/issue", {"user_id": "U001", "verifier_id": "SHOP-A"})
print(call("POST", "/verifier/verify", {"cred": cred, "nonce": ""}))

print("--- minor NO")
cred2 = call("POST", "/issuer/issue", {"user_id": "U002", "verifier_id": "SHOP-A"})
print(call("POST", "/verifier/verify", {"cred": cred2, "nonce": ""}))

print("--- forgery BADSIG")
fake = {"v": 1, "iss": "X", "uid_p": "x", "a": "over_18",
        "r": 1, "exp": 9999999999, "s": "fake"}
print(call("POST", "/verifier/verify", {"cred": fake, "nonce": ""}))

print("--- replay vs fresh nonce")
nonce = call("GET", "/verifier/challenge")["nonce"]
print("static QR + fresh nonce:", call("POST", "/verifier/verify",
      {"cred": cred, "nonce": nonce}))
print("ALL LIVE CHECKS DONE")
