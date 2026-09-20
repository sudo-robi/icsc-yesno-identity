"""Central configuration: every tunable comes from the environment with a safe
default. Services read these at import for paths and at request time for
secrets, so tests can override freely.
"""
import os

DEBUG = os.environ.get("FLASK_DEBUG", "") == "1"

ISSUER_ID = os.environ.get("ISSUER_ID", "NIMC-TEST-01")
VERIFIER_ID = os.environ.get("VERIFIER_ID", "SHOP-A")

ISSUER_DB = os.environ.get("ISSUER_DB", "issuer/issuer.db")
VERIFIER_DB = os.environ.get("VERIFIER_DB", "verifier/receipts.db")
ISSUER_KEYDIR = os.environ.get("ISSUER_KEYDIR", "keys")
ISSUER_PRIV_HEX = os.environ.get("ISSUER_PRIV_HEX", "")
OTP_SECRETS_PATH = os.environ.get("OTP_SECRETS_PATH", "verifier/otp_secrets.json")

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

CRED_TTL_SEC = min(int(os.environ.get("CRED_TTL_SEC", "3600")), 7 * 86400)
CLOCK_SKEW_SEC = 30
PROOF_TS_WINDOW_SEC = 60
NONCE_TTL_SEC = int(os.environ.get("NONCE_TTL_SEC", "300"))
OTP_STEP_SEC = 30
OTP_GRACE_STEPS = 1
BUNDLE_TTL_SEC = int(os.environ.get("BUNDLE_TTL_SEC", str(7 * 86400)))
ENROLL_CODE_TTL_SEC = int(os.environ.get("ENROLL_CODE_TTL_SEC", str(24 * 3600)))

OTP_ENABLED = os.environ.get("OTP_ENABLED", "1") == "1"

RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200/hour")
RATELIMIT_SENSITIVE = os.environ.get("RATELIMIT_SENSITIVE", "60/minute")
RATELIMIT_OTP = os.environ.get("RATELIMIT_OTP", "10/minute")
BEHIND_PROXY = os.environ.get("BEHIND_PROXY") == "1"
PROXY_HOPS = int(os.environ.get("PROXY_HOPS", "1"))
CORS_ALLOW_ORIGINS = [o.strip() for o in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",")
                      if o.strip()]

# SSE revocation push: issuer URL for auto-sync (empty = disabled)
ISSUER_URL = os.environ.get("ISSUER_URL", "")
