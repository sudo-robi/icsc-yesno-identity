"""Vercel serverless entrypoint: mounts Issuer (/issuer) + Verifier (/verifier) + Holder (/).
Single Python function — ephemeral /tmp storage (demo; receipts don't persist across
cold starts — stated honestly in README limits).
"""
import json
import os

# Ephemeral storage on Vercel (read-only FS except /tmp)
if os.environ.get("VERCEL") == "1":
    os.environ.setdefault("ISSUER_DB", "/tmp/issuer.db")
    os.environ.setdefault("VERIFIER_DB", "/tmp/receipts.db")
    os.environ.setdefault("TRUSTBUNDLE_PATH", "/tmp/trustbundle.json")
    os.environ.setdefault("ISSUER_KEYDIR", "/tmp/keys")

from flask import Flask, send_from_directory
from werkzeug.middleware.dispatcher import DispatcherMiddleware

import issuer.app as issuer_mod
import verifier.app as verifier_mod

issuer_mod.init_db()
verifier_mod.init_db()
_, _pub = issuer_mod.load_keys()

# Cold-start pairing: cache issuer pubkey into verifier trustbundle (mirrors run.sh)
try:
    with open(verifier_mod.TRUST) as f:
        json.load(f)
except Exception:
    with open(verifier_mod.TRUST, "w") as f:
        json.dump({"iss": issuer_mod.ISSUER_ID, "pubkey_hex": _pub, "v": 1,
                   "revoked_uids": [], "otp_secrets": {}}, f, indent=2)

root = Flask(__name__)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOLDER_DIR = os.path.join(BASE, "holder")


@root.get("/")
def home():
    return {"ok": True, "service": "icsc-yesno-trackB",
            "issuer": "/issuer/healthz", "verifier": "/verifier/healthz",
            "holder": "/holder/"}


@root.get("/holder/")
def holder():
    return send_from_directory(HOLDER_DIR, "index.html")


app = DispatcherMiddleware(root, {
    "/issuer": issuer_mod.app,
    "/verifier": verifier_mod.app,
})
