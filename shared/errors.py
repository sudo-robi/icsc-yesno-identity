"""Stable reason/error codes shared by issuer, verifier, docs and tests."""


class SchemaError(ValueError):
    """Raised when signed material carries unknown or mistyped fields."""


REASONS = frozenset({
    # verifier decision outcomes
    "OK", "OK_OTP", "NOT_ADULT", "EXPIRED", "BADSIG", "REVOKED",
    "UNKNOWN_CHALLENGE", "BAD_PROOF", "WRONG_VERIFIER", "ISSUER_MISMATCH",
    "MALFORMED", "TOO_LARGE", "NO_TRUSTBUNDLE", "STALE_BUNDLE", "BAD_OTP",
    # endpoint errors ({"error": CODE})
    "UNKNOWN_CODE", "CODE_USED", "CODE_EXPIRED", "REVOKED_USER", "BAD_PUBKEY",
    "BAD_ADMIN_TOKEN", "ROLLBACK", "OTP_DISABLED", "ENROLL_FAILED",
})


def err(code: str, detail: str | None = None) -> dict:
    """Consistent endpoint error shape. Code must be in REASONS."""
    if code not in REASONS:
        raise ValueError(f"unknown error code: {code!r}")
    body: dict[str, str] = {"error": code}
    if detail is not None:
        body["detail"] = detail
    return body
