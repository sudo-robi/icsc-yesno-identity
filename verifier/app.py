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
    CLOCK_SKEW_SEC, otp6, sha256_hex, verify_sig,
)
from shared.schemas import (
    CRED_MAX_BYTES, REASONS, TRUSTBUNDLE_REQUIRED_FIELDS, malformed, unsigned_body,
)

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

KEYS_DIR = os.environ.get("RECEIPT_KEY_DIR",
             os.path.join(os.path.dirname(BASE), "keys"))


def _receipt_key() -> str:
    """HMAC key for the receipt chain, persisted so restarts stay verifiable.
    Anyone with DB *and* key access can still rewrite history — the chain
    proves tampering to key-less auditors, nothing more (see README limits)."""
    if _ON_VERCEL:
        return os.environ.get("RECEIPT_HMAC_KEY", "vercel-demo-key")
    import secrets as _s
    os.makedirs(KEYS_DIR, exist_ok=True)
    kf = os.path.join(KEYS_DIR, "receipt_hmac.key")
    if os.path.exists(kf):
        with open(kf) as f:
            return f.read().strip()
    key = _s.token_hex(32)
    with open(kf, "w") as f:
        f.write(key)
    try:
        os.chmod(kf, 0o600)
    except OSError:
        pass
    return key


def _chain_hash(prev_hash: str, ts: int, verifier_id: str, q: str,
                result: str, nonce_hash: str, sig_hash: str) -> str:
    import hmac as _hm
    import hashlib as _hl
    raw = f"{prev_hash}|{ts}|{verifier_id}|{q}|{result}|{nonce_hash}|{sig_hash}"
    return _hm.new(_receipt_key().encode(), raw.encode(), _hl.sha256).hexdigest()


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
    if result not in ("YES", "NO"):
        raise ValueError(f"unknown result: {result!r}")
    c = db()
    # IMMEDIATE: serialize read-then-insert so concurrent requests can't fork the chain.
    c.isolation_level = None
    c.execute("BEGIN IMMEDIATE")
    try:
        prev = c.execute("SELECT entry_hash FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
        prev_h = prev["entry_hash"] if prev else "GENESIS"
        ts = int(time.time())
        # Peppered hashes: a bare 6-digit OTP (or nonce) must not be brute-forceable
        # by readers of the public /receipts endpoint.
        pepper = _receipt_key()
        nh = sha256_hex(pepper + (nonce or "-"))
        sh = sha256_hex(pepper + (json.dumps(sig, sort_keys=True)
                                  if isinstance(sig, dict) else str(sig)))
        eh = _chain_hash(prev_h, ts, VERIFIER_ID, q, result, nh, sh)
        c.execute("INSERT INTO receipts (ts,verifier_id,q,result,nonce_hash,sig_hash,prev_hash,entry_hash)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (ts, VERIFIER_ID, q, result, nh, sh, prev_h, eh))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    finally:
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
    revocation -> attribute. Single-use challenges: a registered nonce is
    consumed once its binding passes, so an intercepted live credential
    cannot be replayed inside the window. Returns (YES/NO, reason)."""
    t = trust()
    if not t:
        return "NO", "NO_TRUSTBUNDLE"
    if malformed(cred):
        return "NO", "MALFORMED"
    if len(json.dumps(cred)) > CRED_MAX_BYTES:
        return "NO", "TOO_LARGE"
    if not isinstance(cred["exp"], (int, float)):
        return "NO", "MALFORMED"
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
        del _nonces[nonce]  # consume: one challenge, one attempt
    body = unsigned_body(cred)
    if not verify_sig(body, cred["s"], t["pubkey_hex"]):
        return "NO", "BADSIG"
    # Status lists from the signed bundle (per-verifier pseudonyms — no PII).
    # Revocation/minor status applies immediately after a sync, independent of
    # the signed r-flag inside older credentials.
    if cred["uid_p"] in (t.get("revoked") or []):
        return "NO", "REVOKED"
    if cred["uid_p"] in (t.get("minors") or []):
        return "NO", "NOT_ADULT"
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
    if not isinstance(cred, dict):
        return {"result": "NO", "reason": "MALFORMED"}, 400
    # replay: static QR reused with a *different* fresh nonce fails unless holder re-signed
    result, reason = decide(cred, nonce)
    if reason not in REASONS:  # internal contract drift, never caller input
        log.error(json.dumps({"event": "reason_drift", "reason": reason}))
        return {"result": "NO", "reason": "MALFORMED"}, 500
    mode = "challenge" if nonce else "static"
    eh = log_receipt(f"over_18:{mode}", result, nonce or str(cred.get("n")),
                     cred.get("s"))
    log.info(json.dumps({"event": "verify", "result": result,
                         "reason": reason, "receipt": eh}))
    return jsonify({"result": result, "reason": reason, "mode": mode, "receipt": eh})


@app.post("/verify_code")
@limiter.limit("60/minute")
def verify_code():
    """Feature-phone path: 6-digit single-use code. Demo OTP secrets live in the
    SEPARATE secrets store (never in the trustbundle). Codes expire per 30s step."""
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return {"result": "NO", "reason": "MALFORMED"}, 400
    code = str(data.get("code", ""))
    # demo check: code must match one of the known secrets for current/prev step.
    # The match also identifies the holder pseudonym, so status (revoked/minor)
    # from the signed bundle is enforced — a bare valid code is never enough.
    import time as _t
    step = int(_t.time() // 30)
    matched_uid = None
    for uid_p, sec in _load_secrets().items():
        if code in (otp6(sec, VERIFIER_ID, step), otp6(sec, VERIFIER_ID, step - 1)):
            matched_uid = uid_p
            break
    c = db()
    if c.execute("SELECT 1 FROM used_codes WHERE code=?", (code,)).fetchone():
        c.close()
        log_receipt("over_18:otp", "NO", code, "otp-reuse")
        return {"result": "NO", "reason": "REPLAY"}
    c.execute("INSERT OR IGNORE INTO used_codes VALUES (?,?)", (code, int(_t.time())))
    c.commit()
    c.close()
    if matched_uid is None:
        result, reason = "NO", "BAD_OTP"
    else:
        t = trust() or {}
        if matched_uid in (t.get("revoked") or []):
            result, reason = "NO", "REVOKED"
        elif matched_uid in (t.get("minors") or []):
            result, reason = "NO", "NOT_ADULT"
        else:
            result, reason = "YES", "OK_OTP"
    eh = log_receipt("over_18:otp", result, code, "otp")
    return {"result": result, "reason": reason, "receipt": eh}


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
    """One-time pairing (USB/QR): cache the issuer's SIGNED trust bundle.
    Public material goes to the trustbundle; any bundled demo OTP secrets are
    split out into the separate secrets store.
    Auth: if PAIRING_TOKEN env is set, the caller must present it (body field
    `pairing_token` or `X-Pairing-Token` header), else 403 — otherwise anyone
    reaching the verifier could swap its trusted keys. Unset = open pairing
    for local demos (logged as a warning).
    Trust: first sync is TOFU (pins the key, logged). Later syncs must carry a
    signature from the pinned key AND a version >= the pinned one, else 409 —
    this kills rollback/swap attacks."""
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return {"result": "NO", "reason": "MALFORMED"}, 400
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
    if not TRUSTBUNDLE_REQUIRED_FIELDS.issubset(tb.keys()):
        return {"result": "NO", "reason": "MALFORMED",
                "detail": f"needs {sorted(TRUSTBUNDLE_REQUIRED_FIELDS)}"}, 400
    if not isinstance(tb["pubkey_hex"], str) or len(tb["pubkey_hex"]) != 64:
        return {"result": "NO", "reason": "MALFORMED"}, 400
    if not isinstance(tb["v"], int):
        return {"result": "NO", "reason": "MALFORMED"}, 400
    for lst in ("revoked", "minors"):
        if lst in tb and not isinstance(tb[lst], list):
            return {"result": "NO", "reason": "MALFORMED"}, 400
    pinned = trust()
    sig = tb.pop("s", None)
    # The signature covers issuer material only — operator-supplied extras
    # (pairing token, locally provisioned OTP secrets) are excluded so they
    # can ride along without breaking the issuer signature.
    sig_body = {k: v for k, v in tb.items()
                if k not in ("pairing_token", "otp_secrets")}
    if pinned and pinned.get("pubkey_hex"):
        if not sig or not verify_sig(sig_body, sig, pinned["pubkey_hex"]):
            log.warning(json.dumps({"event": "sync_bad_signature"}))
            return {"result": "NO", "reason": "BADSIG"}, 409
        if tb["v"] < pinned.get("v", 0):
            log.warning(json.dumps({"event": "sync_rollback",
                                    "got": tb["v"], "pinned": pinned.get("v")}))
            return {"result": "NO", "reason": "ROLLBACK"}, 409
    else:
        log.warning(json.dumps({"event": "sync_tofu", "iss": tb.get("iss")}))
    if sig is not None:
        tb["s"] = sig
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


# Dual hosting: serve at root AND under /verifier (Vercel services subpath).
# Assigned here (not after the __main__ guard) so local runs match deploys.
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/verifier"])
if os.environ.get("BEHIND_PROXY") == "1":  # Render/Vercel terminate TLS at the edge
    from werkzeug.middleware.proxy_fix import ProxyFix as _PF  # noqa: E402
    app.wsgi_app = _PF(app.wsgi_app, x_for=1, x_proto=1)


@app.get("/holder/")
def holder_page():
    from flask import send_from_directory
    holder_dir = os.path.join(os.path.dirname(BASE), "holder")
    return send_from_directory(holder_dir, "index.html")


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    init_db()
    app.run(port=int(os.environ.get("PORT", 5002)), debug=False)
