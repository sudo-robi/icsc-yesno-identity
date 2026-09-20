"""Shared Flask plumbing: app factory, admin auth, security headers, CORS.

Both services get identical hardening. No business logic here.
"""
import hmac
import json
import logging
import os
from functools import wraps

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from shared import config
from shared.errors import err


def base_logger(name: str) -> logging.Logger:
    """JSON-lines logger. Callers must never pass PII/secrets as fields."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    return logging.getLogger(name)


def log_event(log: logging.Logger, event: str, **fields) -> None:
    """Emit one structured log line. Values must be codes/counts, never PII."""
    log.info(json.dumps({"event": event, **fields}))


def admin_token() -> str:
    """Read at request time so tests/redeploys can rotate without reimport."""
    return os.environ.get("ADMIN_TOKEN", "")


def require_admin_configured() -> None:
    """Refuse to start without ADMIN_TOKEN outside debug (fail fast, loudly)."""
    if not admin_token() and not config.DEBUG:
        raise RuntimeError("ADMIN_TOKEN must be set (or FLASK_DEBUG=1 for local demo)")


def admin_required(view):
    """Bearer-token gate. 401 missing, 403 wrong (constant-time compare)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        scheme, _, presented = auth.partition(" ")
        required = admin_token()
        if scheme.lower() != "bearer" or not presented:
            return err("BAD_ADMIN_TOKEN", "missing bearer token"), 401
        if not hmac.compare_digest(presented, required):
            return err("BAD_ADMIN_TOKEN"), 403
        return view(*args, **kwargs)
    return wrapped


def make_app(name: str, default_limit: str) -> tuple[Flask, Limiter]:
    """Flask app + limiter with storage URI from env. Caller adds routes."""
    app = Flask(name)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB
    limiter = Limiter(
        get_remote_address, app=app,
        default_limits=[default_limit],
        storage_uri=os.environ.get("RATELIMIT_STORAGE_URI",
                                   config.RATELIMIT_STORAGE_URI),
    )

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; "
            "frame-ancestors 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(self)"
        origin = request.headers.get("Origin", "")
        if origin and origin in config.CORS_ALLOW_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        return resp

    if config.BEHIND_PROXY:
        app.wsgi_app = ProxyFix(app.wsgi_app,  # type: ignore[attr-defined]
                                x_for=config.PROXY_HOPS, x_proto=config.PROXY_HOPS)
    return app, limiter
