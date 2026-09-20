"""Verifier service routes (thin Flask layer over verifier.service / verifier.repo).

Offline-first: caches trustbundle.json, zero issuer calls at check time.

Module globals (DB, TRUST, SECRETS_PATH, KEYS_DIR, VERIFIER_ID, NONCE_TTL_SEC,
_nonces) are the documented override points used by tests — wrappers below
read them at call time and pass them explicitly into the service layer.
"""
import json
import logging
import os
import time

from flask import Flask, jsonify, render_template, request, Response, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

from shared import config
from shared.crypto import CLOCK_SKEW_SEC, gen_nonce
from shared.schemas import CRED_MAX_BYTES, TRUSTBUNDLE_REQUIRED_FIELDS
from verifier import repo, service

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("verifier")

BASE = os.path.dirname(os.path.abspath(__file__))
DB = config.file_path(config.VERIFIER_DB_ENV, "receipts.db", BASE)
TRUST = config.file_path(config.TRUSTBUNDLE_ENV, "trustbundle.json", BASE)
VERIFIER_ID = os.environ.get(config.VERIFIER_ID_ENV, config.VERIFIER_ID_DEFAULT)

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app,
                  default_limits=config.DEFAULT_LIMITS,
                  storage_uri=os.environ.get(config.RATELIMIT_STORAGE_ENV,
                                             config.RATELIMIT_STORAGE_DEFAULT))
_nonces: dict[str, float] = {}
NONCE_TTL_SEC = config.NONCE_TTL_SEC

SECRETS_PATH = config.file_path(config.OTP_SECRETS_ENV, "otp_secrets.json", BASE)

KEYS_DIR = os.environ.get(config.RECEIPT_KEY_DIR_ENV,
                          os.path.join(os.path.dirname(BASE), "keys"))


class VerifySchema(Schema):
    """POST /verify body."""
    cred = fields.Dict(required=True)
    nonce = fields.Str(validate=lambda s: len(s) <= 64, load_default="")


# --- compat wrappers (used by tests; read globals at call time) ---
def db():
    """Open the receipts database."""
    return repo.connect(DB)


def init_db():
    """Create receipt + replay tables (idempotent)."""
    repo.init_db(DB)


def trust() -> dict | None:
    """Cached trust bundle, or None before pairing."""
    if not os.path.exists(TRUST):
        return None
    with open(TRUST) as f:
        return json.load(f)


def _receipt_key() -> str:
    """HMAC key for the receipt chain (persisted under KEYS_DIR)."""
    return service.load_receipt_key(KEYS_DIR)


def _chain_hash(prev_hash: str, ts: int, verifier_id: str, q: str,
                result: str, nonce_hash: str, sig_hash: str) -> str:
    """One chain link (re-exported from verifier.service for tests/auditors)."""
    return service.chain_entry(prev_hash, ts, verifier_id, q, result,
                               nonce_hash, sig_hash, _receipt_key())


def _prune_nonces(now: float | None = None) -> None:
    """Drop expired challenges from the live registry."""
    service.prune_nonces(_nonces, time.time() if now is None else now,
                         NONCE_TTL_SEC)


def _load_secrets() -> dict:
    """Demo-only OTP shared secrets (separate store, never the trustbundle)."""
    if not os.path.exists(SECRETS_PATH):
        return {}
    with open(SECRETS_PATH) as f:
        return json.load(f)


def decide(cred: dict, nonce: str) -> tuple[str, str]:
    """Verify one credential against cached trust (see verifier.service)."""
    return service.decide_decision(
        cred, nonce, trust=trust(), nonces=_nonces, now=time.time(),
        ttl=NONCE_TTL_SEC, skew=CLOCK_SKEW_SEC, max_bytes=CRED_MAX_BYTES)


def log_receipt(q: str, result: str, nonce: str | None, sig) -> str:
    """Append one PII-free receipt; returns the entry hash."""
    if result not in ("YES", "NO"):
        raise ValueError(f"unknown result: {result!r}")
    key = _receipt_key()
    ts = int(time.time())
    nonce_hash = service.peppered(nonce or "-", key)
    sig_hash = service.peppered(json.dumps(sig, sort_keys=True)
                                if isinstance(sig, dict) else str(sig), key)
    return repo.append_receipt(
        DB, ts=ts, verifier_id=VERIFIER_ID, q=q, result=result,
        nonce_hash=nonce_hash, sig_hash=sig_hash,
        entry_hash_of=lambda prev: service.chain_entry(
            prev, ts, VERIFIER_ID, q, result, nonce_hash, sig_hash, key))


@app.get("/healthz")
def healthz():
    """Liveness probe (also reports pairing state)."""
    return {"ok": True, "verifier": VERIFIER_ID, "trust": bool(trust())}


@app.get("/challenge")
def challenge():
    """Issue a fresh single-use challenge nonce."""
    _prune_nonces()
    nonce = gen_nonce()
    _nonces[nonce] = time.time()
    return {"nonce": nonce, "verifier": VERIFIER_ID}


@app.post("/verify")
@limiter.limit(config.LIMIT_VERIFY)
def verify():
    """Verify a credential; responds with YES/NO + machine reason + mode."""
    try:
        args = VerifySchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"result": "NO", "reason": "MALFORMED", "detail": str(e)}, 400
    cred, nonce = args["cred"], args.get("nonce", "")
    if not isinstance(cred, dict):
        return {"result": "NO", "reason": "MALFORMED"}, 400
    # replay: static QR reused with a *different* fresh nonce fails unless holder re-signed
    result, reason = decide(cred, nonce)
    if not service.check_reason(reason):  # internal contract drift, never caller input
        log.error(json.dumps({"event": "reason_drift", "reason": reason}))
        return {"result": "NO", "reason": "MALFORMED"}, 500
    mode = "challenge" if nonce else "static"
    eh = log_receipt(f"over_18:{mode}", result, nonce or str(cred.get("n")),
                     cred.get("s"))
    log.info(json.dumps({"event": "verify", "result": result,
                         "reason": reason, "receipt": eh}))
    return jsonify({"result": result, "reason": reason, "mode": mode, "receipt": eh})


@app.post("/verify_code")
@limiter.limit(config.LIMIT_VERIFY)
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
    step = int(time.time() // config.OTP_STEP_SEC)
    matched_uid = service.match_otp_code(_load_secrets(), code, VERIFIER_ID, step)
    if repo.is_code_used(DB, code):
        log_receipt("over_18:otp", "NO", code, "otp-reuse")
        return {"result": "NO", "reason": "REPLAY"}
    repo.mark_code_used(DB, code, int(time.time()))
    if matched_uid is None:
        result, reason = "NO", "BAD_OTP"
    else:
        result, reason = service.otp_status(matched_uid, trust() or {})
    eh = log_receipt("over_18:otp", result, code, "otp")
    return {"result": result, "reason": reason, "receipt": eh}


@app.get("/receipts")
def receipts():
    """Newest-first PII-free receipts (shop UI + auditor)."""
    return jsonify(repo.list_receipts(DB))


@app.get("/receipts.csv")
def receipts_csv():
    """Full log as CSV."""
    out = ["id,ts,verifier,q,result,nonce_hash,sig_hash,prev_hash,entry_hash"]
    out += [",".join(map(str, [r["id"], r["ts"], r["verifier_id"], r["q"],
                               r["result"], r["nonce_hash"], r["sig_hash"],
                               r["prev_hash"], r["entry_hash"]]))
            for r in repo.all_receipts(DB)]
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
    required = os.environ.get(config.PAIRING_TOKEN_ENV)
    if required:
        presented = data.get("pairing_token") or request.headers.get("X-Pairing-Token")
        if not service.pairing_ok(presented, required):
            log.warning(json.dumps({"event": "sync_rejected"}))
            return {"result": "NO", "reason": "BAD_PAIRING_TOKEN"}, 403
    else:
        log.warning(json.dumps({"event": "sync_open_mode",
                                "note": "set PAIRING_TOKEN to lock pairing"}))
    tb = dict(data)
    shape_error = service.validate_bundle(tb)
    if shape_error:
        return {"result": "NO", "reason": shape_error,
                "detail": f"needs {sorted(TRUSTBUNDLE_REQUIRED_FIELDS)}"}, 400
    pinned = trust()
    sig = tb.pop("s", None)
    # The signature covers issuer material only — operator-supplied extras
    # (pairing token, locally provisioned OTP secrets) are excluded so they
    # can ride along without breaking the issuer signature.
    sig_body = service.bundle_sig_body(tb)
    if pinned and pinned.get("pubkey_hex"):
        if not sig or not service.verify_bundle_sig(sig_body, sig, pinned["pubkey_hex"]):
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
    """Shop screen (simple enough for a non-technical operator)."""
    return render_template("verifier.html", verifier=VERIFIER_ID,
                           has_trust=bool(trust()))


init_db()  # import-safe (idempotent): needed for gunicorn/Vercel


# Dual hosting: serve at root AND under /verifier (Vercel services subpath).
# Assigned here (not after the __main__ guard) so local runs match deploys.
from shared.wsgi import PrefixStrip as _PS  # noqa: E402
app.wsgi_app = _PS(app.wsgi_app, ["/verifier"])
if config.BEHIND_PROXY:  # Render/Vercel terminate TLS at the edge
    from werkzeug.middleware.proxy_fix import ProxyFix as _PF  # noqa: E402
    app.wsgi_app = _PF(app.wsgi_app, x_for=1, x_proto=1)


@app.get("/holder/")
def holder_page():
    """Serve the holder web page same-origin (used on hosted deployments)."""
    holder_dir = os.path.join(os.path.dirname(BASE), "holder")
    return send_from_directory(holder_dir, "index.html")


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    init_db()
    app.run(port=int(os.environ.get("PORT", 5002)), debug=False)
