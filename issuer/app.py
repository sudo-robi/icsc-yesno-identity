"""Issuer service routes (thin Flask layer over issuer.services / issuer.repo).

Env: ISSUER_DB, ISSUER_KEYDIR, ISSUER_ID, ISSUER_PRIV_HEX, ADMIN_TOKEN (required
outside debug), CRED_TTL_SEC, OTP_ENABLED, ENROLL_CODE_TTL_SEC, BUNDLE_TTL_SEC.
"""
import os
import time

from flask import jsonify, render_template, request, send_from_directory
from marshmallow import Schema, fields, ValidationError

import issuer.repo as repo
from issuer import services
from shared import config
from shared.errors import err
from shared.web import (
    admin_required, base_logger, log_event, make_app, require_admin_configured,
)

log = base_logger("issuer")

require_admin_configured()

BASE = os.path.dirname(os.path.abspath(__file__))
DB = config.ISSUER_DB
KEYDIR = config.ISSUER_KEYDIR
ISSUER_ID = config.ISSUER_ID

app, limiter = make_app("issuer", config.RATELIMIT_DEFAULT)


class EnrollSchema(Schema):
    """POST /issuer/enroll body."""
    code = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 128)
    verifier_id = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 32)
    holder_pub = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 128)


class RevokeSchema(Schema):
    """POST /issuer/admin/revoke body."""
    user_id = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 32)


class RotateSchema(Schema):
    """POST /issuer/admin/rotate body."""
    activate = fields.Bool(load_default=False)


def _active_key() -> dict:
    key = services.ensure_active_key(DB, KEYDIR)
    return key


@app.get("/healthz")
def healthz():
    """Liveness probe."""
    return {"ok": True, "iss": ISSUER_ID}


@app.get("/pubkey")
def pubkey():
    """Current public key + bundle version (bootstrap for pairing)."""
    key = _active_key()
    return {"iss": ISSUER_ID, "pubkey_hex": key["pub"],
            "fingerprint": services.fingerprint(key["pub"]),
            "v": repo.bundle_version(DB)}


@app.get("/bundle")
def bundle():
    """Signed per-verifier trust bundle (?vid=SHOP-A). Public, signed."""
    verifier_id = request.args.get("vid", request.args.get("verifier_id", "SHOP-A"))
    if len(verifier_id) > 32:
        return err("MALFORMED", "vid too long"), 400
    key = _active_key()
    staged = _staged_key()
    return jsonify(services.build_bundle(
        verifier_id=verifier_id, users=repo.all_user_status(DB),
        rev_version=repo.bundle_version(DB), issued_at=int(time.time()),
        ttl_sec=config.BUNDLE_TTL_SEC, issuer_id=ISSUER_ID,
        priv_hex=key["priv"], pub_hex=key["pub"],
        next_pub=staged["pub"] if staged else None))


def _staged_key() -> dict | None:
    return repo.staged_key(DB)


@app.post("/enroll")
@limiter.limit(config.RATELIMIT_SENSITIVE)
def enroll():
    """Redeem a single-use enrollment code for a holder key. Returns the
    signed credential (+ OTP secret when the flag is on)."""
    try:
        args = EnrollSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return err("MALFORMED", str(e.messages)), 400
    except Exception:
        return err("MALFORMED"), 400
    redeemed = repo.consume_enrollment_code(DB, args["code"])
    if not redeemed["ok"]:
        return err(redeemed["reason"]), 400
    try:
        payload = services.issue_credential(
            user=repo.get_user(DB, redeemed["user_id"]),
            verifier_id=args["verifier_id"], holder_pub_b64u=args["holder_pub"],
            issuer_id=ISSUER_ID, priv_hex=_active_key()["priv"],
            now=time.time(), ttl_sec=config.CRED_TTL_SEC)
    except (services.UnknownUserError, services.RevokedError):
        return err("ENROLL_FAILED"), 400
    except ValueError:
        return err("BAD_PUBKEY"), 400
    except services.ContractDriftError as e:
        log_event(log, "contract_drift", detail=str(e))
        return err("MALFORMED", "issuer error"), 500
    log_event(log, "enroll_ok", vid=args["verifier_id"])
    response: dict = {"credential": payload}
    if config.OTP_ENABLED:
        user = repo.get_user(DB, redeemed["user_id"])
        if user is None:
            return err("MALFORMED", "issuer error"), 500
        response["otp_secret"] = services.otp_secret_for(
            user["master_secret"], args["verifier_id"])
    return jsonify(response)


@app.post("/admin/users/<user_id>/enrollment-code")
@admin_required
def enrollment_code(user_id: str):
    """Mint a single-use enrollment code (returned ONCE)."""
    if repo.get_user(DB, user_id) is None:
        return err("UNKNOWN_CODE", "no such user"), 404
    code = repo.create_enrollment_code(DB, user_id, config.ENROLL_CODE_TTL_SEC)
    repo.audit(DB, "admin", "enrollment-code", "")
    return {"code": code, "user_id": user_id,
            "expires_in": config.ENROLL_CODE_TTL_SEC}


@app.post("/admin/revoke")
@admin_required
def revoke():
    """Revoke a user and bump the bundle version."""
    try:
        args = RevokeSchema().load(request.get_json(force=True))
    except ValidationError as e:
        return err("MALFORMED", str(e.messages)), 400
    except Exception:
        return err("MALFORMED"), 400
    if repo.get_user(DB, args["user_id"]) is None:
        return err("UNKNOWN_CODE", "no such user"), 404
    repo.set_revoked(DB, args["user_id"])
    version = repo.bump_bundle_version(DB)
    repo.audit(DB, "admin", "revoke", "")
    log_event(log, "revoke", v=version)
    return {"ok": True, "v": version}


@app.post("/admin/rotate")
@admin_required
def rotate():
    """Stage a rotation key, or activate the staged one.

    Rotation chain: bundle N (signed by K1) advertises next_pub=K2; verifiers
    learn K2; activating K2 makes it the signer. A key the chain never
    announced is rejected by verifiers.
    """
    try:
        args = RotateSchema().load(request.get_json(silent=True) or {})
    except ValidationError as e:
        return err("MALFORMED", str(e.messages)), 400
    if os.environ.get("ISSUER_PRIV_HEX"):
        return err("MALFORMED", "key is env-managed; rotate ISSUER_PRIV_HEX"), 409
    if args.get("activate"):
        staged = _staged_key()
        if staged is None:
            return err("MALFORMED", "nothing staged"), 400
        repo.deactivate_all_keys(DB)
        if not repo.activate_key(DB, staged["pub"]):
            return err("MALFORMED", "activation failed"), 500
        version = repo.bump_bundle_version(DB)
        repo.audit(DB, "admin", "rotate-activate", "")
        log_event(log, "key_activated", v=version)
        return {"ok": True, "pub": staged["pub"], "v": version}
    from shared.crypto import ed25519_keypair

    _active_key()  # ensure an active row predates the staged one (staged = inactive NEWER than active)
    priv_hex, pub_hex = ed25519_keypair()
    repo.store_key(DB, priv_hex, pub_hex, active=False)
    version = repo.bump_bundle_version(DB)
    repo.audit(DB, "admin", "rotate-stage", "")
    log_event(log, "key_staged", v=version)
    return {"ok": True, "staged_pub": pub_hex,
            "fingerprint": services.fingerprint(pub_hex), "v": version}


@app.get("/admin/otp-secrets")
@admin_required
def otp_secrets():
    """Per-shop OTP secrets for adult, non-revoked users ONLY (admin channel)."""
    if not config.OTP_ENABLED:
        return err("OTP_DISABLED"), 404
    verifier_id = request.args.get("vid", request.args.get("verifier_id", "SHOP-A"))
    if len(verifier_id) > 32:
        return err("MALFORMED", "vid too long"), 400
    out = {}
    for user in repo.all_user_status(DB):
        if user["revoked"] or not services.is_adult(user["dob"]):
            continue
        from shared.crypto import pseudonym

        out[pseudonym(user["master_secret"], verifier_id)] = \
            services.otp_secret_for(user["master_secret"], verifier_id)
    return jsonify({"vid": verifier_id, "secrets": out})


@app.get("/holder/")
def holder_page():
    """Holder PWA, same-origin with /enroll (offline-capable after install)."""
    holder_dir = os.path.join(os.path.dirname(BASE), "holder")
    return send_from_directory(holder_dir, "index.html")


@app.get("/holder/<path:filename>")
def holder_files(filename):
    """Holder assets (app.js, sw.js, manifest, static/)."""
    holder_dir = os.path.join(os.path.dirname(BASE), "holder")
    return send_from_directory(holder_dir, filename)


@app.get("/")
def index():
    """Admin dashboard: IDs + status only, never DOBs."""
    users = [{"id": u["id"], "revoked": bool(u["revoked"])} for u in repo.list_users(DB)]
    key = _active_key()
    staged = _staged_key()
    return render_template("issuer.html", users=users, iss=ISSUER_ID,
                           fingerprint=services.fingerprint(key["pub"]),
                           staged_fp=services.fingerprint(staged["pub"]) if staged else None,
                           version=repo.bundle_version(DB))


repo.init_db(DB)


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    repo.init_db(DB)
    app.run(port=int(os.environ.get("PORT", 5001)), debug=config.DEBUG)
