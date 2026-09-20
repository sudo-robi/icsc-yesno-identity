"""Central configuration: every path, TTL, limit and env-var name in one place.

Values are resolved at import; per-request secrets (admin/pairing tokens) are
read from the environment at request time by the routes. Tests override the
thin ``DB``/``TRUST``/… globals in ``issuer.app`` / ``verifier.app`` — those
wrappers pass the values down explicitly, so overrides keep working.
"""
import os

ON_VERCEL = os.environ.get("VERCEL") == "1"
BEHIND_PROXY = os.environ.get("BEHIND_PROXY") == "1"


def file_path(env_name: str, filename: str, base_dir: str) -> str:
    """Env override, else /tmp on serverless, else a file under base_dir."""
    default = f"/tmp/{filename}" if ON_VERCEL else os.path.join(base_dir, filename)
    return os.environ.get(env_name, default)


def dir_path(env_name: str, dirname: str, base_dir: str) -> str:
    """Env override, else /tmp/keys on serverless, else a dir under base_dir."""
    default = "/tmp/keys" if ON_VERCEL else os.path.join(base_dir, dirname)
    return os.environ.get(env_name, default)


# --- issuer defaults (evaluated in issuer/app.py with its own BASE) ---
ISSUER_DB_ENV = "ISSUER_DB"
ISSUER_KEYDIR_ENV = "ISSUER_KEYDIR"
ISSUER_ID_ENV = "ISSUER_ID"
ISSUER_ID_DEFAULT = "NIMC-TEST-01"
ISSUER_ADMIN_TOKEN_ENV = "ISSUER_ADMIN_TOKEN"
ISSUER_PRIV_HEX_ENV = "ISSUER_PRIV_HEX"

# --- verifier defaults (evaluated in verifier/app.py with its own BASE) ---
VERIFIER_DB_ENV = "VERIFIER_DB"
TRUSTBUNDLE_ENV = "TRUSTBUNDLE_PATH"
OTP_SECRETS_ENV = "OTP_SECRETS_PATH"
RECEIPT_KEY_DIR_ENV = "RECEIPT_KEY_DIR"
VERIFIER_ID_ENV = "VERIFIER_ID"
VERIFIER_ID_DEFAULT = "SHOP-A"
PAIRING_TOKEN_ENV = "PAIRING_TOKEN"
RECEIPT_HMAC_KEY_ENV = "RECEIPT_HMAC_KEY"

# --- timing ---
NONCE_TTL_SEC = 300
OTP_STEP_SEC = 30
OTP_GRACE_STEPS = 1  # accept current + previous 30s step
USED_CODE_STEPS_KEPT = 2  # prune anything older on every OTP check

# --- rate limits / infra ---
DEFAULT_LIMITS = ["200/hour"]
LIMIT_ISSUE = "30/minute"
LIMIT_VERIFY = "60/minute"
RATELIMIT_STORAGE_ENV = "RATELIMIT_STORAGE_URI"
RATELIMIT_STORAGE_DEFAULT = "memory://"
