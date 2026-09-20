"""Verifier service — agency: backend-architect + database-optimizer.
Offline-first: caches trustbundle.json, zero issuer calls at check time.
ECC: service layer, rate limits, hash-chained PII-free receipts.
"""
import json
import logging
import os
import sqlite3
import time

from flask import Flask, jsonify, render_template, request, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

from shared.crypto import (
    CLOCK_SKEW_SEC, otp6, receipt_hash, sha256_hex, verify_sig,
)
from shared.schemas import CRED_MAX_BYTES, malformed, unsigned_body

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("verifier")

BASE = os.path.dirname(os.path.abspath(__file__))
_ON_VERCEL = os.environ.get("VERCEL") == "1"
DB = os.environ.get("VERIFIER_DB",
     "/tmp/receipts.db" if _ON_VERCEL else os.path.join(BASE, "receipts.db"))
TRUST = os.environ.get("TRUSTBUNDLE_PATH",
        "/tmp/trustbundle.json" if _ON_VERCEL else os.path.join(BASE, "trustbundle.json"))
VERIFIER_ID = os.environ.get("VERIFIER_ID", "SHOP-A")

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/hour"])
_nonces: dict[str, float] = {}
NONCE_TTL_SEC = 300

SECRETS_PATH = os.environ.get("OTP_SECRETS_PATH",
               "/tmp/otp_secrets.json" if _ON_VERCEL else os.path.join(BASE, "otp_secrets.json"))


class VerifySchema(Schema):
    cred = fields.Dict(required=True)
    nonce = fields.Str(validate=lambda s: len(s) <= 64, load_default="")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS receipts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INT, verifier_id TEXT,
                  q TEXT, result TEXT, nonce_hash TEXT, sig_hash TEXT,
                  prev_hash TEXT, entry_hash TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS used_codes (code TEXT PRIMARY KEY, ts INT)""")
    c.close()


def trust():
    if not os.path.exists(TRUST):
        return None
    with open(TRUST) as f:
        return json.load(f)


def log_receipt(q, result, nonce, sig):
    c = db()
    prev = c.execute("SELECT entry_hash FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
    prev_h = prev["entry_hash"] if prev else "GENESIS"
    ts = int(time.time())
    nh = sha256_hex(nonce or "-")
    sh = sha256_hex(json.dumps(sig, sort_keys=True) if isinstance(sig, dict) else str(sig))
    eh = receipt_hash(prev_h, ts, VERIFIER_ID, q, result, nh, sh)
    c.execute("INSERT INTO receipts (ts,verifier_id,q,result,nonce_hash,sig_hash,prev_hash,entry_hash)"
              " VALUES (?,?,?,?,?,?,?,?)",
              (ts, VERIFIER_ID, q, result, nh, sh, prev_h, eh))
    c.commit()
    c.close()
    return eh


def _prune_nonces(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for n, issued in list(_nonces.items()):
        if now - issued > NONCE_TTL_SEC:
            del _nonces[n]


def _load_secrets() -> dict:
    """Demo-only OTP shared secrets. Stored SEPARATE from the trustbundle:
    the bundle is public material (pubkeys, versions); secrets never belong in it."""
    if not os.path.exists(SECRETS_PATH):
        return {}
    with open(SECRETS_PATH) as f:
        return json.load(f)


def decide(cred: dict, nonce: str) -> tuple[str, str]:
    """Order: trust -> shape -> size -> expiry -> challenge -> sig ->
    revocation -> attribute. Returns (YES/NO, reason)."""
    t = trust()
    if not t:
        return "NO", "NO_TRUSTBUNDLE"
    if malformed(cred):
        return "NO", "MALFORMED"
    if len(json.dumps(cred)) > CRED_MAX_BYTES:
        return "NO", "TOO_LARGE"
    if cred["exp"] + CLOCK_SKEW_SEC < time.time():
        return "NO", "EXPIRED"
    # live-challenge binding: nonce must be one THIS verifier issued (and fresh),
    # and the credential must echo it under issuer signature.
    if nonce:
        _prune_nonces()
        issued = _nonces.get(nonce)
        if issued is None or time.time() - issued > NONCE_TTL_SEC:
            return "NO", "UNKNOWN_CHALLENGE"
        if cred.get("n") != nonce:
            return "NO", "REPLAY"
    body = unsigned_body(cred)
    if not verify_sig(body, cred["s"], t["pubkey_hex"]):
        return "NO", "BADSIG"
    # revocation: cached list version
    rev = t.get("revoked_uids", [])
    # uid_p is a pseudonym so revocation maps via issuer-side list of uid_p per verifier;
    # for demo: issuer also publishes revoked pseudonyms for this verifier in trustbundle.
    if cred["uid_p"] in rev:
        return "NO", "REVOKED"
    if cred.get("a") == "over_18" and cred.get("r") == 1:
        return "YES", "OK"
    return "NO", "NOT_ADULT"


@app.get("/healthz")
def healthz():
    return {"ok": True, "verifier": VERIFIER_ID, "trust": bool(trust())}


@app.get("/challenge")
def challenge():
    from shared.crypto import gen_nonce
    _prune_nonces()
    n = gen_nonce()
    _nonces[n] = time.time()
    return {"nonce": n, "verifier": VERIFIER_ID}


@app.post("/verify")
@limiter.limit("60/minute")
def verify():
    try:
        args = VerifySchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"result": "NO", "reason": "MALFORMED", "detail": str(e)}, 400
    cred, nonce = args["cred"], args.get("nonce", "")
    # replay: static QR reused with a *different* fresh nonce fails unless holder re-signed
    result, reason = decide(cred, nonce)
    eh = log_receipt("over_18", result, nonce or str(cred.get("n")),
                     cred.get("s"))
    log.info(json.dumps({"event": "verify", "result": result,
                         "reason": reason, "receipt": eh}))
    return jsonify({"result": result, "reason": reason, "receipt": eh})


@app.post("/verify_code")
@limiter.limit("60/minute")
def verify_code():
    """Feature-phone path: 6-digit single-use code. Demo OTP secrets live in the
    SEPARATE secrets store (never in the trustbundle). Codes expire per 30s step."""
    data = request.get_json(force=True)
    code = str(data.get("code", ""))
    # demo check: code must match one of the known secrets for current/prev step
    import time as _t
    step = int(_t.time() // 30)
    ok = False
    for sec in _load_secrets().values():
        if code in (otp6(sec, VERIFIER_ID, step), otp6(sec, VERIFIER_ID, step - 1)):
            ok = True
            break
    c = db()
    if c.execute("SELECT 1 FROM used_codes WHERE code=?", (code,)).fetchone():
        c.close()
        log_receipt("over_18", "NO", code, "otp-reuse")
        return {"result": "NO", "reason": "REPLAY"}
    c.execute("INSERT OR IGNORE INTO used_codes VALUES (?,?)", (code, int(_t.time())))
    c.commit()
    c.close()
    result = "YES" if ok else "NO"
    eh = log_receipt("over_18", result, code, "otp")
    return {"result": result, "reason": "OK_OTP" if ok else "BAD_OTP", "receipt": eh}


@app.get("/receipts")
def receipts():
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM receipts ORDER BY id DESC LIMIT 100")]
    c.close()
    return jsonify(rows)


@app.get("/receipts.csv")
def receipts_csv():
    c = db()
    rows = c.execute("SELECT * FROM receipts ORDER BY id").fetchall()
    c.close()
    out = ["id,ts,verifier,q,result,nonce_hash,sig_hash,prev_hash,entry_hash"]
    out += [",".join(map(str, [r["id"], r["ts"], r["verifier_id"], r["q"],
                               r["result"], r["nonce_hash"], r["sig_hash"],
                               r["prev_hash"], r["entry_hash"]])) for r in rows]
    return Response("\n".join(out), mimetype="text/csv")


@app.post("/sync")
def sync():
    """One-time pairing (USB/QR): cache issuer pubkey + revocation pseudonyms.
    Public material goes to the trustbundle; any bundled demo OTP secrets are
    split out into the separate secrets store.
    Auth: if PAIRING_TOKEN env is set, the caller must present it (body field
    `pairing_token` or `X-Pairing-Token` header), else 403 — otherwise anyone
    reaching the verifier could swap its trusted keys. Unset = open pairing
    for local demos (logged as a warning)."""
    data = request.get_json(force=True)
    required = os.environ.get("PAIRING_TOKEN")
    if required:
        presented = data.get("pairing_token") or request.headers.get("X-Pairing-Token")
        if presented != required:
            log.warning(json.dumps({"event": "sync_rejected"}))
            return {"result": "NO", "reason": "BAD_PAIRING_TOKEN"}, 403
    else:
        log.warning(json.dumps({"event": "sync_open_mode",
                                "note": "set PAIRING_TOKEN to lock pairing"}))
    tb = dict(data)
    assert "pubkey_hex" in tb and len(tb["pubkey_hex"]) == 64
    secrets = tb.pop("otp_secrets", None)
    tb.pop("pairing_token", None)
    with open(TRUST, "w") as f:
        json.dump(tb, f, indent=2)
    if secrets is not None:
        with open(SECRETS_PATH, "w") as f:
            json.dump(secrets, f, indent=2)
    return {"ok": True, "verifier": VERIFIER_ID}


@app.get("/")
def index():
    return render_template("verifier.html", verifier=VERIFIER_ID,
                           has_trust=bool(trust()))


init_db()  # import-safe (CREATE TABLE IF NOT EXISTS): needed for gunicorn/Vercel


@app.get("/holder/")
def holder_page():
    from flask import send_from_directory
    holder_dir = os.path.join(os.path.dirname(BASE), "holder")
    return send_from_directory(holder_dir, "index.html")


if __name__ == "__main__":
    init_db()
    app.run(port=int(os.environ.get("PORT", 5002)), debug=False)


# Dual hosting: serve at root AND under /verifier (Vercel services subpath).
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/verifier"])
