"""Issuer service — agency: backend-architect | ECC: backend-patterns service/repo layers.
Production: Flask + Flask-Limiter, env config, structured logs, parameterized SQL.
"""
import json
import logging
import os
import secrets as _rand
import sqlite3
import time
from datetime import date

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

from shared.crypto import (
    EXPIRY_SEC, gen_keypair, otp6, pseudonym, sign_cred,
)
from shared.schemas import CRED_REQUIRED_FIELDS, unsigned_body

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("issuer")

BASE = os.path.dirname(os.path.abspath(__file__))
_ON_VERCEL = os.environ.get("VERCEL") == "1"
DB = os.environ.get("ISSUER_DB",
     "/tmp/issuer.db" if _ON_VERCEL else os.path.join(BASE, "issuer.db"))
KEYDIR = os.environ.get("ISSUER_KEYDIR",
         "/tmp/keys" if _ON_VERCEL else os.path.join(os.path.dirname(BASE), "keys"))
ISSUER_ID = os.environ.get("ISSUER_ID", "NIMC-TEST-01")

ADMIN_TOKEN = os.environ.get("ISSUER_ADMIN_TOKEN")
if not ADMIN_TOKEN:
    ADMIN_TOKEN = _rand.token_hex(16)
    log.warning(json.dumps({"event": "admin_token_generated",
                            "note": "set ISSUER_ADMIN_TOKEN to pin it",
                            "token": ADMIN_TOKEN}))


def require_admin():
    """Operator auth for /revoke + /rotate. Returns None if OK, else (body, 403).
    Env ISSUER_ADMIN_TOKEN overrides the generated default at request time
    (so tests and redeploys can pin it without reimporting)."""
    required = os.environ.get("ISSUER_ADMIN_TOKEN", ADMIN_TOKEN)
    presented = request.headers.get("X-Admin-Token") or \
        ((request.get_json(silent=True) or {}) if request.is_json else {}).get("admin_token")
    if presented != required:
        log.warning(json.dumps({"event": "admin_rejected",
                                "path": request.path}))
        return {"error": "bad admin token"}, 403
    return None


def is_adult(dob_str: str, today: date | None = None) -> bool:
    """Calendar-correct 18+ check (leap-day safe). `18*365` day counts are off by days."""
    y, m, d = map(int, dob_str.split("-"))
    today = today or date.today()
    try:
        milestone = date(y + 18, m, d)
    except ValueError:  # Feb 29 -> Feb 28 on non-leap years
        milestone = date(y + 18, m, 28)
    return milestone <= today

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/hour"])


class IssueSchema(Schema):
    user_id = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 32)
    verifier_id = fields.Str(load_default="SHOP-A", validate=lambda s: len(s) <= 32)
    nonce = fields.Str(load_default="", validate=lambda s: len(s) <= 64)


class RevokeSchema(Schema):
    user_id = fields.Str(required=True)


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY, full_name TEXT, dob TEXT,
                  revoked INT DEFAULT 0, master_secret TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS revlist
                 (v INT PRIMARY KEY, atTs INT, revoked_json TEXT, sig TEXT)""")
    if c.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        import secrets as pysec
        seed = [("U001", "Ada Test (adult)", "2000-05-12", 0),
                ("U002", "Bola Test (minor)", "2010-03-01", 0),
                ("U003", "Revoked Test", "1999-01-01", 1)]
        for uid, nm, dob, rev in seed:
            c.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                      (uid, nm, dob, rev, pysec.token_hex(16)))
        log.info("seeded synthetic users (no real PII)")
    if c.execute("SELECT COUNT(*) c FROM revlist").fetchone()["c"] == 0:
        c.execute("INSERT INTO revlist VALUES (1,?, '[]','')", (int(time.time()),))
    c.commit()
    c.close()


def load_keys():
    priv_hex = os.environ.get("ISSUER_PRIV_HEX")
    os.makedirs(KEYDIR, exist_ok=True)
    pf = os.path.join(KEYDIR, "issuer_priv.hex")
    qf = os.path.join(KEYDIR, "issuer_pub.hex")
    if priv_hex and len(priv_hex) == 64:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(priv_hex)).public_key().public_bytes_raw().hex()
        return priv_hex, pub
    if os.path.exists(pf):
        with open(pf) as f:
            priv_hex = f.read().strip()
        with open(qf) as f:
            return priv_hex, f.read().strip()
    priv_hex, pub_hex = gen_keypair()
    with open(pf, "w") as f:
        f.write(priv_hex)
    with open(qf, "w") as f:
        f.write(pub_hex)
    log.info("generated new Ed25519 issuer keypair")
    return priv_hex, pub_hex


def current_revlist(priv_hex):
    c = db()
    row = c.execute("SELECT * FROM revlist ORDER BY v DESC LIMIT 1").fetchone()
    revoked = [r["id"] for r in c.execute(
        "SELECT id FROM users WHERE revoked=1").fetchall()]
    body = {"v": row["v"], "at": row["atTs"], "revoked": revoked}
    body["s"] = sign_cred({k: body[k] for k in ("v", "at", "revoked")}, priv_hex)
    c.close()
    return body


def build_bundle(verifier_id: str, priv_hex: str, pub_hex: str) -> dict:
    """Signed trust bundle for one verifier: per-verifier pseudonyms of revoked
    users and minors, so the verifier can enforce status without ever seeing
    names or DOBs. v is monotonic — verifiers reject rollbacks."""
    c = db()
    row = c.execute("SELECT * FROM revlist ORDER BY v DESC LIMIT 1").fetchone()
    users = c.execute("SELECT id, dob, revoked, master_secret FROM users").fetchall()
    c.close()
    revoked, minors = [], []
    for u in users:
        pseudo = pseudonym(u["master_secret"], verifier_id)
        if u["revoked"]:
            revoked.append(pseudo)
        elif not is_adult(u["dob"]):
            minors.append(pseudo)
    body = {"iss": ISSUER_ID, "pubkey_hex": pub_hex, "v": row["v"],
            "verifier": verifier_id, "revoked": sorted(revoked),
            "minors": sorted(minors)}
    body["s"] = sign_cred(body, priv_hex)
    return body


@app.get("/healthz")
def healthz():
    return {"ok": True, "iss": ISSUER_ID}


@app.get("/pubkey")
def pubkey():
    _, pub = load_keys()
    c = db()
    v = c.execute("SELECT v FROM revlist ORDER BY v DESC LIMIT 1").fetchone()["v"]
    c.close()
    return {"iss": ISSUER_ID, "pubkey_hex": pub, "v": v}


@app.get("/bundle")
def bundle():
    """Signed per-verifier trust bundle (the documented revocation channel)."""
    verifier_id = request.args.get("verifier_id", "SHOP-A")
    if len(verifier_id) > 32:
        return {"error": "verifier_id too long"}, 400
    priv, pub = load_keys()
    return jsonify(build_bundle(verifier_id, priv, pub))


@app.get("/revlist")
def revlist():
    """Raw revocation log (user IDs — issuer-internal transparency, not the channel)."""
    priv, _ = load_keys()
    return jsonify(current_revlist(priv))


@app.post("/issue")
@limiter.limit("30/minute")
def issue():
    try:
        args = IssueSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"error": e.messages}, 400
    c = db()
    u = c.execute("SELECT * FROM users WHERE id=?", (args["user_id"],)).fetchone()
    c.close()
    if not u:
        return {"error": "unknown user"}, 404
    if u["revoked"]:
        return {"error": "revoked"}, 403
    # over-18 from DOB (calendar-correct; day counts drift on leap years)
    adult = is_adult(u["dob"])
    priv, _ = load_keys()
    payload = {"v": 1, "iss": ISSUER_ID,
               "uid_p": pseudonym(u["master_secret"], args["verifier_id"]),
               "a": "over_18", "r": 1 if adult else 0,
               "exp": int(time.time()) + EXPIRY_SEC}
    # Live-challenge binding: if holder presents verifier nonce at issue time,
    # issuer embeds + signs it. Static QRs (no n) fail a fresh challenge -> anti-replay.
    if args.get("nonce"):
        payload["n"] = args["nonce"]
    # Contract check (explicit 500, never bare assert): the unsigned body must be
    # exactly the required fields minus "s", with optional "n".
    want = set(CRED_REQUIRED_FIELDS) - {"s"}
    if args.get("nonce"):
        want |= {"n"}
    if set(unsigned_body(payload)) != want:
        log.error(json.dumps({"event": "contract_drift",
                              "keys": sorted(payload)}))
        return {"error": "issuer contract drift"}, 500
    payload["s"] = sign_cred(unsigned_body(payload), priv)
    log.info(json.dumps({"event": "issue", "uid_p": payload["uid_p"],
                         "r": payload["r"]}))
    return jsonify(payload)


@app.get("/otp")
@limiter.limit("30/minute")
def otp():
    """Holder fallback-code source (feature phones): current 6-digit code for a
    user at a verifier. Open like /issue — enrollment identity proofing is an
    explicit prototype boundary (see README limits)."""
    user_id = request.args.get("user_id", "")
    verifier_id = request.args.get("verifier_id", "SHOP-A")
    if not (1 <= len(user_id) <= 32 and len(verifier_id) <= 32):
        return {"error": "bad user_id/verifier_id"}, 400
    c = db()
    u = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    c.close()
    if not u:
        return {"error": "unknown user"}, 404
    return {"code": otp6(u["master_secret"], verifier_id), "verifier": verifier_id,
            "step_sec": 30}


@app.post("/revoke")
def revoke():
    denied = require_admin()
    if denied:
        return denied
    try:
        args = RevokeSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"error": e.messages}, 400
    priv, _ = load_keys()
    c = db()
    c.execute("UPDATE users SET revoked=1 WHERE id=?", (args["user_id"],))
    v = c.execute("SELECT MAX(v) m FROM revlist").fetchone()["m"] + 1
    c.execute("INSERT INTO revlist VALUES (?,?, '[]','')",
              (v, int(time.time())))
    c.commit()
    c.close()
    log.info(json.dumps({"event": "revoke", "v": v}))
    return jsonify(current_revlist(priv))


@app.post("/rotate")
def rotate():
    """Issuer-compromise recovery: fast key rotation, bumps trustbundle version."""
    denied = require_admin()
    if denied:
        return denied
    if os.environ.get("ISSUER_PRIV_HEX"):
        # Refuse rather than lie: rotation would advertise a key that never signs.
        return {"error": "key is env-managed; rotate ISSUER_PRIV_HEX instead"}, 409
    priv_new, pub_new = gen_keypair()
    os.makedirs(KEYDIR, exist_ok=True)
    with open(os.path.join(KEYDIR, "issuer_priv.hex"), "w") as f:
        f.write(priv_new)
    with open(os.path.join(KEYDIR, "issuer_pub.hex"), "w") as f:
        f.write(pub_new)
    c = db()
    v = c.execute("SELECT MAX(v) m FROM revlist").fetchone()["m"] + 1
    c.execute("INSERT INTO revlist VALUES (?,?, '[]','')",
              (v, int(time.time())))
    c.commit()
    c.close()
    log.warning(json.dumps({"event": "key_rotation", "new_v": v}))
    return {"iss": ISSUER_ID, "pubkey_hex": pub_new, "v": v,
            "note": "redistribute trustbundle to verifiers"}


@app.get("/")
def index():
    c = db()
    users = c.execute("SELECT id, dob, revoked FROM users").fetchall()
    c.close()
    priv, pub = load_keys()
    rl = current_revlist(priv)
    return render_template("issuer.html", users=users, pub=pub,
                           iss=ISSUER_ID, rev=rl)


init_db()  # import-safe (CREATE TABLE IF NOT EXISTS): needed for gunicorn/Vercel


# Dual hosting: serve at root AND under /issuer (Vercel services subpath).
# Assigned here (not after the __main__ guard) so `python -m issuer.app` matches deploys.
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/issuer"])
if os.environ.get("BEHIND_PROXY") == "1":  # Render/Vercel terminate TLS at the edge
    from werkzeug.middleware.proxy_fix import ProxyFix as _PF  # noqa: E402
    app.wsgi_app = _PF(app.wsgi_app, x_for=1, x_proto=1)


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    init_db()
    load_keys()
    app.run(port=int(os.environ.get("PORT", 5001)), debug=False)
