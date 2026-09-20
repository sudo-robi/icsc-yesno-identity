"""Verifier service routes (thin Flask layer over verifier.services/repo).

Env: VERIFIER_DB, TRUSTBUNDLE_PATH, OTP_SECRETS_PATH, VERIFIER_ID, ADMIN_TOKEN
(required outside debug), OTP_ENABLED, NONCE_TTL_SEC, RATELIMIT_*, BEHIND_PROXY.
"""
import json
import os
import time

from flask import jsonify, render_template, request, Response, send_from_directory
from marshmallow import Schema, fields, ValidationError

from shared import config
from shared.crypto import key_fingerprint
from shared.errors import err
from verifier import repo, services
from shared.web import admin_required, base_logger, log_event, make_app, require_admin_configured

log = base_logger("verifier")

require_admin_configured()

BASE = os.path.dirname(os.path.abspath(__file__))
DB = config.VERIFIER_DB
VERIFIER_ID = config.VERIFIER_ID
SECRETS_PATH = config.OTP_SECRETS_PATH

app, limiter = make_app("verifier", config.RATELIMIT_DEFAULT)


class VerifySchema(Schema):
    """POST /verifier/verify body: credential + holder proof (both required)."""
    c = fields.Dict(required=True)
    p = fields.Dict(required=True)


def _trust() -> dict | None:
    return repo.get_bundle(DB)


def _secrets() -> dict:
    if not os.path.exists(SECRETS_PATH):
        return {}
    with open(SECRETS_PATH) as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _receipt(q: str, result: str, reason: str) -> str:
    """Append a PII-free receipt: no raw nonce/credential/code, and no
    derivatives of them either — only the public outcome fields are chained."""
    key = services.load_receipt_key(DB)
    ts = int(time.time())
    return repo.append_receipt(
        DB, ts=ts, verifier_id=VERIFIER_ID, q=q, result=result, reason=reason,
        entry_hash_of=lambda prev: services.chain_entry(
            prev, ts, VERIFIER_ID, q, result, reason, key))


@app.get("/healthz")
def healthz():
    """Liveness probe."""
    paired = _trust()
    return {"ok": True, "verifier": VERIFIER_ID, "trust": bool(paired),
            "v": (paired or {}).get("v")}


@app.get("/status")
def status():
    """Public pairing status: bundle version + iss + fingerprint + expiry."""
    paired = _trust()
    if not paired:
        return {"paired": False}
    from issuer.services import fingerprint as _fp

    return {"paired": True, "bundle_v": paired.get("v"), "iss": paired.get("iss"),
            "fingerprint": _fp(paired.get("pub", "")),
            "bundle_exp": paired.get("exp")}


@app.get("/challenge")
@limiter.limit(config.RATELIMIT_SENSITIVE)
def challenge():
    """Mint a fresh single-use challenge {n, vid, exp} for the shop QR."""
    now = int(time.time())
    issued = services.mint_challenge(verifier_id=VERIFIER_ID, now=now,
                                    ttl_sec=config.NONCE_TTL_SEC)
    repo.prune_nonces(DB, now - config.NONCE_TTL_SEC)
    repo.add_nonce(DB, issued["n"], VERIFIER_ID, now, issued["exp"])
    return jsonify(issued)


@app.post("/verify")
@limiter.limit(config.RATELIMIT_SENSITIVE)
def verify():
    """Verify a {credential, proof} presentation. Always YES/NO + reason."""
    try:
        args = VerifySchema().load(request.get_json(force=True))
    except ValidationError as e:
        return {"result": "NO", "reason": "MALFORMED"}, 400
    except Exception:
        return {"result": "NO", "reason": "MALFORMED"}, 400
    cred, proof = args["c"], args["p"]

    def consume(nonce: str, min_issued: float, now_ts: float):
        row = repo.consume_nonce(DB, nonce, int(min_issued), int(now_ts))
        return dict(row) if row else None

    result, reason = services.decide(
        cred, proof, len(request.data), trust=_trust(), verifier_id=VERIFIER_ID,
        now=time.time(), consume_nonce=consume)
    if not services.check_reason(reason):  # internal drift, never caller input
        log_event(log, "reason_drift", reason=reason)
        return {"result": "NO", "reason": "MALFORMED"}, 500
    mode = "proof"
    receipt = _receipt(f"over_18:{mode}", result, reason)
    log_event(log, "verify", result=result, reason=reason)
    return jsonify({"result": result, "reason": reason, "mode": mode,
                    "receipt": receipt})


@app.post("/verify_code")
@limiter.limit(config.RATELIMIT_OTP)
def verify_code():
    """Feature-phone OTP path (flagged). Code identifies the holder sub, then
    bundle status lists are enforced. Invalid codes are never recorded."""
    if not config.OTP_ENABLED:
        return err("OTP_DISABLED"), 404
    try:
        data = request.get_json(force=True)
    except Exception:
        return {"result": "NO", "reason": "MALFORMED"}, 400
    if not isinstance(data, dict):
        return {"result": "NO", "reason": "MALFORMED"}, 400
    code = str(data.get("code", ""))
    step = int(time.time() // config.OTP_STEP_SEC)
    repo.prune_codes(DB, step - config.OTP_GRACE_STEPS)
    matched = services.match_otp_code(_secrets(), code, VERIFIER_ID, step)
    if matched is None:
        receipt = _receipt("over_18:otp", "NO", "BAD_OTP")
        return {"result": "NO", "reason": "BAD_OTP", "receipt": receipt}
    if repo.is_code_used(DB, matched, step):
        receipt = _receipt("over_18:otp", "NO", "UNKNOWN_CHALLENGE")
        return {"result": "NO", "reason": "UNKNOWN_CHALLENGE", "receipt": receipt}
    repo.mark_code_used(DB, matched, step, int(time.time()))
    result, reason = services.otp_status(matched, _trust() or {})
    receipt = _receipt("over_18:otp", result, reason)
    log_event(log, "verify_code", result=result, reason=reason)
    return {"result": result, "reason": reason, "receipt": receipt}


@app.post("/sync")
@admin_required
def sync():
    """Pair (or re-pair) with a signed issuer bundle. First sync is TOFU: the
    key fingerprint is returned for out-of-band operator confirmation."""
    try:
        data = request.get_json(force=True)
    except Exception:
        return err("MALFORMED"), 400
    if not isinstance(data, dict):
        return err("MALFORMED"), 400
    bundle = data.get("bundle", data)
    pinned = _trust()
    accepted, reason = services.check_bundle(bundle, pinned=pinned, now=time.time())
    if not accepted and reason in ("BADSIG", "ROLLBACK", "ISSUER_MISMATCH"):
        log_event(log, "sync_rejected", reason=reason or "unknown")
        return err(reason or "BADSIG"), 409
    if not accepted:
        return err("MALFORMED", "bundle shape"), 400
    if pinned is None or not pinned.get("pub"):
        repo.save_bundle(DB, bundle)
        log_event(log, "sync_tofu", iss=bundle.get("iss"), v=bundle.get("v"))
        return {"ok": True, "tofu": True, "fingerprint": key_fingerprint(bundle["pub"]),
                "note": "confirm fingerprint out-of-band"}, 200
    repo.save_bundle(DB, bundle)
    log_event(log, "sync_ok", v=bundle.get("v"))
    return {"ok": True, "v": bundle.get("v")}


@app.post("/admin/otp-secrets")
@admin_required
def provision_otp_secrets():
    """Store operator-provisioned OTP secrets (0600 file, never the bundle)."""
    try:
        data = request.get_json(force=True)
    except Exception:
        return err("MALFORMED"), 400
    if not isinstance(data, dict) or not isinstance(data.get("secrets"), dict):
        return err("MALFORMED"), 400
    with open(SECRETS_PATH, "w") as f:
        json.dump(data["secrets"], f, indent=2)
    try:
        os.chmod(SECRETS_PATH, 0o600)
    except OSError:
        pass
    return {"ok": True, "count": len(data["secrets"])}


def _signed_head():
    rows = repo.all_receipts(DB)
    key = services.load_receipt_key(DB)
    if not rows:
        return None, key
    head = rows[-1]["entry_hash"]
    ts = int(time.time())
    sig = services.sign_head(key, head, ts)
    return {"head": head, "ts": ts, "sig": sig}, key


@app.get("/receipts")
@admin_required
def receipts():
    """PII-free receipts + signed chain head (admin only)."""
    head, _key = _signed_head()
    rows = repo.list_receipts(DB)
    pub = services.receipt_pub(DB)
    return jsonify({"rows": rows, "head": head, "receipt_pub": pub})


@app.get("/receipts.csv")
@admin_required
def receipts_csv():
    """CSV export (fields escaped) + signed head."""
    import csv
    import io

    head, _key = _signed_head()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "ts", "verifier_id", "q", "result", "reason",
                     "prev_hash", "entry_hash"])
    for row in repo.all_receipts(DB):
        writer.writerow([row["id"], row["ts"], row["verifier_id"], row["q"],
                         row["result"], row["reason"],
                         row["prev_hash"], row["entry_hash"]])
    writer.writerow([])
    writer.writerow(["head", (head or {}).get("head"), (head or {}).get("ts"),
                     (head or {}).get("sig")])
    writer.writerow(["receipt_pub", services.receipt_pub(DB)])
    return Response(buf.getvalue(), mimetype="text/csv")


@app.get("/sw-shop.js")
def shop_sw():
    """Shop service worker (must live at root scope to cover /)."""
    return send_from_directory(os.path.join(BASE, "static"), "sw-shop.js")


@app.get("/app.webmanifest")
def shop_manifest():
    """Shop PWA manifest."""
    return send_from_directory(os.path.join(BASE, "static"), "app.webmanifest")


@app.get("/")
def index():
    """Shop screen (full UI lands in Phase E; paste flow works now)."""
    return render_template("verifier.html", verifier=VERIFIER_ID,
                           paired=bool(_trust()))


repo.init_db(DB)


if __name__ == "__main__":  # pragma: no cover - dev entrypoint
    repo.init_db(DB)
    app.run(port=int(os.environ.get("PORT", 5002)), debug=config.DEBUG)
