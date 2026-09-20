"""Issuer service routes (thin Flask layer over issuer.service / issuer.repo).

Module globals (DB, KEYDIR, ISSUER_ID, ADMIN_TOKEN) are the documented override
points used by tests, run.sh and live_demo.py — the service functions below
take explicit arguments and read these globals at call time.
"""
import json
import logging
import os
import time

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

from issuer import repo, service
from shared import config
from shared.schemas import unsigned_body  # noqa: F401  (re-exported: test hook)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("issuer")

BASE = os.path.dirname(os.path.abspath(__file__))
DB = config.file_path(config.ISSUER_DB_ENV, "issuer.db", BASE)
KEYDIR = config.dir_path(config.ISSUER_KEYDIR_ENV, "keys", os.path.dirname(BASE))
ISSUER_ID = os.environ.get(config.ISSUER_ID_ENV, config.ISSUER_ID_DEFAULT)

ADMIN_TOKEN = os.environ.get(config.ISSUER_ADMIN_TOKEN_ENV)
if not ADMIN_TOKEN:
    import secrets as _rand

    ADMIN_TOKEN = _rand.token_hex(16)
    log.warning(json.dumps({"event": "admin_token_generated",
                            "note": "set ISSUER_ADMIN_TOKEN to pin it",
                            "token": ADMIN_TOKEN}))

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app,
                  default_limits=config.DEFAULT_LIMITS,
                  storage_uri=os.environ.get(config.RATELIMIT_STORAGE_ENV,
                                             config.RATELIMIT_STORAGE_DEFAULT))


class IssueSchema(Schema):
    """POST /issue body."""
    user_id = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 32)
    verifier_id = fields.Str(load_default="SHOP-A", validate=lambda s: len(s) <= 32)
    nonce = fields.Str(load_default="", validate=lambda s: len(s) <= 64)


class RevokeSchema(Schema):
    """POST /revoke body."""
    user_id = fields.Str(required=True)


# --- compat wrappers (used by tests, run.sh, live_demo.py) ---
def db():
    """Open the issuer database."""
    return repo.connect(DB)


def init_db():
    """Create + seed the issuer database (idempotent)."""
    repo.init_db(DB)


def load_keys() -> tuple[str, str]:
    """Load (priv, pub) hex pair via KEYDIR (overridable for tests)."""
    return service.load_keys(KEYDIR)


def is_adult(dob_str: str, today=None) -> bool:
    """Calendar-correct 18+ check (re-exported from issuer.service)."""
    return service.is_adult(dob_str, today)


def current_revlist(priv_hex: str) -> dict:
    """Raw revocation log for this issuer."""
    return service.current_revlist(
        rev_version=repo.revlist_version(DB), at_ts=int(time.time()),
        revoked_ids=repo.revoked_user_ids(DB), priv_hex=priv_hex)


def build_bundle(verifier_id: str, priv_hex: str, pub_hex: str) -> dict:
    """Signed per-verifier trust bundle (pseudonyms only, no PII)."""
    return service.build_bundle(
        verifier_id=verifier_id, users=repo.all_user_status(DB),
        rev_version=repo.revlist_version(DB),
        issuer_id=ISSUER_ID, priv_hex=priv_hex, pub_hex=pub_hex)


def require_admin():
    """Operator auth for /revoke + /rotate. None if OK, else (body, 403)."""
    required = os.environ.get(config.ISSUER_ADMIN_TOKEN_ENV, ADMIN_TOKEN)
    presented = request.headers.get("X-Admin-Token")
    if presented is None and request.is_json:
        presented = (request.get_json(silent=True) or {}).get("admin_token")
    if not service.admin_ok(presented, required):
        log.warning(json.dumps({"event": "admin_rejected", "path": request.path}))
        return {"error": "bad admin token"}, 403
    return None


@app.get("/healthz")
def healthz():
    """Liveness probe."""
    return {"ok": True, "iss": ISSUER_ID}


@app.get("/pubkey")
def pubkey():
    """Current public key + revlist version (bootstrap for pairing)."""
    _, pub = load_keys()
    return {"iss": ISSUER_ID, "pubkey_hex": pub, "v": repo.revlist_version(DB)}


@app.get("/bundle")
@app.get("/trustbundle")  # alias: matches the documented pairing name
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
@limiter.limit(config.LIMIT_ISSUE)
def issue():
    """Sign a credential for an enrolled user (open enrollment: prototype boundary)."""
    try:
        args = IssueSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"error": e.messages}, 400
    try:
        payload = service.issue_credential(
            user=repo.get_user(DB, args["user_id"]),
            verifier_id=args["verifier_id"], nonce=args.get("nonce", ""),
            issuer_id=ISSUER_ID, priv_hex=load_keys()[0], now=time.time())
    except service.UnknownUserError:
        return {"error": "unknown user"}, 404
    except service.RevokedError:
        return {"error": "revoked"}, 403
    except service.ContractDriftError as e:
        log.error(json.dumps({"event": "contract_drift", "detail": str(e)}))
        return {"error": "issuer contract drift"}, 500
    log.info(json.dumps({"event": "issue", "uid_p": payload["uid_p"],
                         "r": payload["r"]}))
    return jsonify(payload)


@app.get("/otp")
@limiter.limit(config.LIMIT_ISSUE)
def otp():
    """Holder fallback-code source (feature phones): current 6-digit code.
    Open like /issue — enrollment identity proofing is a prototype boundary."""
    user_id = request.args.get("user_id", "")
    verifier_id = request.args.get("verifier_id", "SHOP-A")
    if not (1 <= len(user_id) <= 32 and len(verifier_id) <= 32):
        return {"error": "bad user_id/verifier_id"}, 400
    try:
        code, step_sec = service.fetch_otp_code(
            user=repo.get_user(DB, user_id), verifier_id=verifier_id,
            now=time.time())
    except service.UnknownUserError:
        return {"error": "unknown user"}, 404
    return {"code": code, "verifier": verifier_id, "step_sec": step_sec}


@app.post("/revoke")
def revoke():
    """Revoke a user (operator only) and bump the revlist version."""
    denied = require_admin()
    if denied:
        return denied
    try:
        args = RevokeSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"error": e.messages}, 400
    repo.set_revoked(DB, args["user_id"])
    version = repo.bump_revlist(DB)
    log.info(json.dumps({"event": "revoke", "v": version}))
    return jsonify(current_revlist(load_keys()[0]))


@app.post("/rotate")
def rotate():
    """Issuer-compromise recovery: fast key rotation, bumps revlist version."""
    denied = require_admin()
    if denied:
        return denied
    try:
        priv_new, pub_new = service.rotate_keys(KEYDIR)
    except service.EnvManagedKeyError as e:
        return {"error": str(e)}, 409
    version = repo.bump_revlist(DB)
    log.warning(json.dumps({"event": "key_rotation", "new_v": version}))
    return {"iss": ISSUER_ID, "pubkey_hex": pub_new, "v": version,
            "note": "redistribute trustbundle to verifiers"}


@app.get("/")
def index():
    """Operator dashboard (synthetic seed data — no real PII, no DOBs shown)."""
    users = [{"id": u["id"], "revoked": bool(u["revoked"]),
              "adult": service.is_adult(u["dob"])} for u in repo.list_users(DB)]
    priv, pub = load_keys()
    return render_template("issuer.html", users=users, pub=pub,
                           iss=ISSUER_ID, rev=current_revlist(priv))


init_db()  # import-safe (idempotent): needed for gunicorn/Vercel


# Dual hosting: serve at root AND under /issuer (Vercel services subpath).
# Assigned here (not after the __main__ guard) so `python -m issuer.app` matches deploys.
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/issuer"])
if config.BEHIND_PROXY:  # Render/Vercel terminate TLS at the edge
    from werkzeug.middleware.proxy_fix import ProxyFix as _PF  # noqa: E402
    app.wsgi_app = _PF(app.wsgi_app, x_for=1, x_proto=1)


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    init_db()
    load_keys()
    app.run(port=int(os.environ.get("PORT", 5001)), debug=False)
