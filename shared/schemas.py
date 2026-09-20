"""Data contracts: exact signed shapes. Unknown extra fields are REJECTED,
not ignored — a signer and verifier can never silently disagree.
"""
from shared.errors import SchemaError

CRED_SIGNED_FIELDS = frozenset({"v", "iss", "sub", "vid", "a", "r", "iat", "exp", "cnf"})
CRED_REQUIRED_FIELDS = CRED_SIGNED_FIELDS | {"s"}

BUNDLE_SIGNED_FIELDS = frozenset(
    {"v", "iss", "vid", "pub", "next_pub", "revoked", "minors", "iat", "exp"})
BUNDLE_REQUIRED_FIELDS = BUNDLE_SIGNED_FIELDS | {"s"}

CHALLENGE_FIELDS = frozenset({"n", "vid", "exp"})
PROOF_FIELDS = frozenset({"n", "ts", "sig"})

CRED_MAX_BYTES = 2048  # full {c,p} presentation payload cap


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def signed_body(cred: dict) -> dict:
    """The exact dict covered by the issuer signature. Raises SchemaError if
    the credential carries fields outside the contract."""
    unknown = set(cred.keys()) - CRED_REQUIRED_FIELDS
    if unknown:
        raise SchemaError(f"unknown credential fields: {sorted(unknown)}")
    return {k: cred[k] for k in CRED_SIGNED_FIELDS}


def validate_credential(cred: object) -> str | None:
    """Shape + type validation. Returns None if OK, else a reason code."""
    if not isinstance(cred, dict):
        return "MALFORMED"
    if not CRED_REQUIRED_FIELDS.issubset(cred.keys()):
        return "MALFORMED"
    try:
        signed_body(cred)
    except SchemaError:
        return "MALFORMED"
    if not _is_plain_int(cred.get("exp")) or not _is_plain_int(cred.get("iat")):
        return "MALFORMED"
    for key in ("sub", "vid", "a", "iss", "cnf"):
        if not isinstance(cred.get(key), str):
            return "MALFORMED"
    if not _is_plain_int(cred.get("r")) or cred["r"] not in (0, 1):
        return "MALFORMED"
    if not _is_plain_int(cred.get("v")):
        return "MALFORMED"
    return None


def validate_proof(proof: object) -> str | None:
    """Shape + type validation for a holder proof. None if OK, else reason."""
    if not isinstance(proof, dict):
        return "MALFORMED"
    if set(proof.keys()) != PROOF_FIELDS:
        return "MALFORMED"
    if not isinstance(proof.get("n"), str):
        return "MALFORMED"
    if not _is_plain_int(proof.get("ts")):
        return "MALFORMED"
    if not isinstance(proof.get("sig"), str):
        return "MALFORMED"
    return None


def validate_challenge(ch: object) -> str | None:
    """Shape + type validation for a shop challenge. None if OK, else reason."""
    if not isinstance(ch, dict):
        return "MALFORMED"
    if set(ch.keys()) != CHALLENGE_FIELDS:
        return "MALFORMED"
    if not isinstance(ch.get("n"), str):
        return "MALFORMED"
    if not isinstance(ch.get("vid"), str):
        return "MALFORMED"
    if not _is_plain_int(ch.get("exp")):
        return "MALFORMED"
    return None


def validate_bundle_shape(bundle: object) -> str | None:
    """Shape + type validation for a trust bundle (signature checked separately)."""
    if not isinstance(bundle, dict):
        return "MALFORMED"
    if not BUNDLE_REQUIRED_FIELDS.issubset(bundle.keys()):
        return "MALFORMED"
    unknown = set(bundle.keys()) - BUNDLE_REQUIRED_FIELDS
    if unknown:
        return "MALFORMED"
    if not isinstance(bundle.get("pub"), str) or len(bundle["pub"]) != 64:
        return "MALFORMED"
    nxt = bundle.get("next_pub")
    if nxt is not None and (not isinstance(nxt, str) or len(nxt) != 64):
        return "MALFORMED"
    if not _is_plain_int(bundle.get("v")):
        return "MALFORMED"
    if not _is_plain_int(bundle.get("iat")) or not _is_plain_int(bundle.get("exp")):
        return "MALFORMED"
    if not isinstance(bundle.get("revoked"), list):
        return "MALFORMED"
    if not isinstance(bundle.get("minors"), list):
        return "MALFORMED"
    if not isinstance(bundle.get("iss"), str) or not isinstance(bundle.get("vid"), str):
        return "MALFORMED"
    if not isinstance(bundle.get("s"), str):
        return "MALFORMED"
    return None


def bundle_sig_body(bundle: dict) -> dict:
    """The exact dict the issuer signs (everything except "s")."""
    return {k: bundle[k] for k in BUNDLE_SIGNED_FIELDS}
