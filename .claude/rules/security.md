# Security — enforced (from everything-claude-code/rules/security.md)
- No hardcoded secrets. Private keys in env `ISSUER_PRIV_HEX` or `keys/` (gitignored).
- All inputs validated (marshmallow schemas, QR size cap 4096 chars).
- Parameterized queries only (sqlite3 ? placeholders).
- Rate limit: /verify 60/min, /issue 30/min.
- Error messages never leak DOB/name/key material — return reason codes only.
- If issue found: STOP, run security review, fix CRITICAL first, rotate keys.
