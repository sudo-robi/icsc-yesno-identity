"""Schemas: exact credential / trustbundle / revlist contracts."""
CRED_EXAMPLE = {
    "v": 1, "iss": "NIMC-TEST-01", "uid_p": "a3f9c1e2b4d5a607",
    "a": "over_18", "r": 1, "exp": 1710000300, "n": None, "s": "sig_b64u",
}
TRUSTBUNDLE_EXAMPLE = {"iss": "NIMC-TEST-01", "pubkey_hex": "…64 hex…", "v": 2}
REVLIST_EXAMPLE = {"v": 5, "at": 1710000000, "revoked": ["U003"], "s": "sig_b64u"}
