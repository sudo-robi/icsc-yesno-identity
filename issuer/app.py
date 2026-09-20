"""Issuer service — agency: backend-architect | ECC: backend-patterns service/repo layers.
Production: Flask + Flask-Limiter, env config, structured logs, parameterized SQL.
"""
import json
import logging
import os
import sqlite3
import time

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

from shared.crypto import (
    EXPIRY_SEC, gen_keypair, pseudonym, sign_cred,
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


@app.get("/revlist")
def revlist():
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
    # over-18 from DOB
    from datetime import date
    y, m, d = map(int, u["dob"].split("-"))
    adult = (date.today() - date(y, m, d)).days >= 18 * 365
    priv, _ = load_keys()
    payload = {"v": 1, "iss": ISSUER_ID,
               "uid_p": pseudonym(u["master_secret"], args["verifier_id"]),
               "a": "over_18", "r": 1 if adult else 0,
               "exp": int(time.time()) + EXPIRY_SEC}
    # Live-challenge binding: if holder presents verifier nonce at issue time,
    # issuer embeds + signs it. Static QRs (no n) fail a fresh challenge -> anti-replay.
    if args.get("nonce"):
        payload["n"] = args["nonce"]
    # Contract check: the unsigned body must be exactly the required fields minus "s".
    # This is what the verifier re-derives via shared.schemas.unsigned_body().
    assert set(unsigned_body(payload)) == set(CRED_REQUIRED_FIELDS) - {"s"}, \
        f"contract drift: {sorted(payload)}"
    payload["s"] = sign_cred(unsigned_body(payload), priv)
    log.info(json.dumps({"event": "issue", "uid_p": payload["uid_p"],
                         "r": payload["r"]}))
    return jsonify(payload)


@app.post("/revoke")
def revoke():
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


if __name__ == "__main__":
    init_db()
    load_keys()
    app.run(port=int(os.environ.get("PORT", 5001)), debug=False)


# Dual hosting: serve at root AND under /issuer (Vercel services subpath).
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/issuer"])
