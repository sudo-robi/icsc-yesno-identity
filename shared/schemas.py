"""Data contracts: single source of truth for the credential + trustbundle shapes.

Imported by issuer/app.py (issue/sign path) and verifier/app.py (verify path),
so both sides can never disagree on which fields are signed — the exact class
of bug (stray ``n: None`` in the signed body) that once broke verification.
agency: backend-architect | ECC: backend-patterns (contract governance).
"""

# Fields covered by the Ed25519 signature. "n" is optional: present only when
# the holder answered a live verifier challenge at issue time.
CRED_REQUIRED_FIELDS = frozenset({"v", "iss", "uid_p", "a", "r", "exp", "s"})
CRED_OPTIONAL_FIELDS = frozenset({"n"})
CRED_SIGNED_FIELDS = frozenset({"v", "iss", "uid_p", "a", "r", "exp", "n"})

TRUSTBUNDLE_REQUIRED_FIELDS = frozenset({"iss", "pubkey_hex", "v"})

# Verifier decision reasons (stable API: shop UI + tests + docs depend on these).
REASONS = frozenset({
    "OK", "OK_OTP", "NOT_ADULT", "EXPIRED", "BADSIG", "REVOKED", "REPLAY",
    "MALFORMED", "TOO_LARGE", "NO_TRUSTBUNDLE", "UNKNOWN_CHALLENGE", "BAD_OTP",
})

CRED_MAX_BYTES = 4096


def _is_plain_int(value: object) -> bool:
    """True for real ints only — bools are not accepted as ints."""
    return isinstance(value, int) and not isinstance(value, bool)


def unsigned_body(cred: dict) -> dict:
    """The exact dict that is signed / verified. Drops "s", keeps "n" iff present."""
    return {k: cred[k] for k in CRED_SIGNED_FIELDS if k in cred}


def malformed(cred: object) -> bool:
    """Shape + field-type validation. Anything failing here is caller input
    (400/MALFORMED), never a signature question. Note: ``exp`` must be an int
    (floats/bools rejected — JSON numbers decode unambiguously for our issuers),
    ``r`` must be exactly 0 or 1."""
    if not isinstance(cred, dict):
        return True
    if not CRED_REQUIRED_FIELDS.issubset(cred.keys()):
        return True
    if not _is_plain_int(cred.get("exp")):
        return True
    for key in ("uid_p", "a", "iss"):
        if not isinstance(cred.get(key), str):
            return True
    if not _is_plain_int(cred.get("r")) or cred["r"] not in (0, 1):
        return True
    if "n" in cred and not isinstance(cred["n"], str):
        return True
    return False
