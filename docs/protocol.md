# Protocol: Yes/No Identity (offline-first)

All JSON. Encoding is base64url without padding. Signing covers canonical JSON
(sorted keys, `(",", ":")` separators, UTF-8, no floats — `shared/canonical.py`).

## Actors and keys

- **Issuer** (Ed25519): holds synthetic user records, signs credentials + bundles.
- **Holder** (ECDSA P-256 per shop): key generated on-device via WebCrypto
  (`extractable: false`, IndexedDB). One key per `verifier_id` so shops cannot
  link a customer by holder public key. Exchanged as base64url raw uncompressed
  points (65 bytes, `0x04` prefix). WebCrypto returns raw `r||s` (IEEE P1363);
  the backend converts to DER before verifying.
- **Verifier** (Ed25519 receipt key): generated once, kept server-side.

## Pseudonyms

`sub` = first 16 **bytes** of `HMAC-SHA256(user_master_secret, verifier_id)`,
hex-encoded (32 chars). Pairwise per shop: two shops see different `sub` values
for the same person and cannot join records.

## Enrollment (one time per holder+shop)

1. Admin mints a single-use code: `POST /admin/enrollment-code` → shown once
   (only its SHA-256 is stored, 24h expiry).
2. Holder enters code + shop → generates a P-256 key for that shop → posts
   `/issuer/enroll {code, verifier_id, holder_pub}` → issuer returns the
   credential (+ OTP secret when flagged).
3. Issuer computes over-18 with a **calendar** check (`dob+18y <= today`,
   Feb 29 → Feb 28). Only the boolean `r` and the pseudonym go in the credential;
   DOB never leaves the issuer.

## Credential (issuer-signed)

```json
{"v":1,"iss":"ID","sub":"…32hex…","vid":"SHOP-A","a":"over_18","r":0|1,
 "iat":int,"exp":int,"cnf":"holder-pub-b64u","s":"issuer-sig-b64u"}
```

`exp = iat + CRED_TTL_SEC` (default 3600). The signed body is exactly the fields
except `s` (`shared/schemas.py::signed_body`); unknown extra fields are rejected,
not ignored.

**TTL trade-off (explicit):** because the credential is bound to the holder key
*and* every presentation needs a fresh challenge proof, a longer TTL is safe
against replay — a screenshot alone never verifies. Revocation delay is bounded
by TTL *and* by bundle sync frequency, whichever bites first.

## Presentation (fully offline for both sides)

1. Shop screen shows a challenge QR: `{"n":nonce,"vid":verifier_id,"exp":ts}`.
2. Holder scans it (or pastes), builds a proof:
   `msg = canonical(["yn-proof-v1", sha256(credential_canonical), n, vid, ts])`
   `proof = {"n":n, "ts":ts, "sig": ECDSA_P256_sign(holder_key_for_vid, msg)}`
   and shows a QR of `{"c":credential,"p":proof}`. Payload must stay under
   2048 bytes.
3. Shop scans it → `POST /verifier/verify {"c":…, "p":…}`.

## Verifier decision order (each failure maps to a stable reason code)

`NO_TRUSTBUNDLE` → `MALFORMED` → `TOO_LARGE` → `WRONG_VERIFIER`
(`cred.vid` ≠ this verifier) → `ISSUER_MISMATCH` → `EXPIRED` (30s skew) →
`BADSIG` (issuer sig via pinned key) → `UNKNOWN_CHALLENGE` (nonce not
issued/expired/used) → `BAD_PROOF` (holder sig over `msg` with `cnf` key;
`ts` within 60s) → `REVOKED` (`sub` in bundle list) → `NOT_ADULT` (`r` ≠ 1) → `OK`.

The nonce is consumed atomically (`DELETE … RETURNING`, rowcount check) on ANY
attempt that passes the `UNKNOWN_CHALLENGE` step, so it is single-use even under
concurrent requests. Nonces live in SQLite with a TTL (not process memory), so
multiple workers behave correctly. **There is no code path that accepts a
credential without a fresh proof.**

## Trust bundle (signed, per verifier)

```json
{"v":int,"iss":ID,"vid":verifier_id,"pub":"issuer-pub-hex",
 "next_pub":"…|null","revoked":[sub,…],"iat":int,"exp":int,"s":sig}
```

- `GET /issuer/bundle?vid=SHOP-A` returns it (public, signed).
- Pairing: operator sends it to `POST /verifier/sync` with the admin token.
  First sync is trust-on-first-use: the verifier returns the issuer key
  fingerprint (first 8 bytes, grouped) for the operator to confirm out-of-band.
  Afterwards the pinned key verifies every bundle signature.
- Rejected: lower `v` than stored, wrong `vid`/`iss`, bad signature, past `exp`.
- Rotation: a key change is accepted **only** via `next_pub` signed by the
  currently pinned key (rotation chain).
- Sync works over network, or offline by USB/QR: the verifier UI accepts a
  pasted bundle (admin drawer).

## OTP fallback (reduced assurance, flagged, built last)

At enrollment the issuer derives a per-user-per-shop OTP secret (deterministic
HMAC, stateless). The shop receives secrets **only** for adult, non-revoked
users via `GET /issuer/admin/otp-secrets?vid=` (admin token) into
`POST /verifier/admin/otp-secrets`, stored in a `0600` file separate from the
trust bundle, mapping `secret → sub`.

Code = 6-digit `HMAC-SHA256(secret, verifier_id|30s-step)`, checked for the
current and previous step. On match the verifier ALSO enforces adult +
not-revoked via the mapped `sub`. Used codes are stored per `(sub, step)` and
pruned. Raw codes are never logged or stored.

Stated plainly: OTP mode lets the shop generate valid codes (it holds the
secrets), unlike QR mode where only the holder's device can sign. Reduced
assurance, honest trade-off for basic phones.

## Receipts (privacy-preserving audit log)

Rows: `id, ts, verifier_id, q, result, reason, prev_hash, entry_hash` — no PII,
no raw nonce/credential/code (and no derivatives of them). Appends run inside
one `BEGIN IMMEDIATE` transaction (read prev hash + insert) so the chain cannot
fork. The verifier signs the chain head periodically and on export with its
Ed25519 key; `/receipts` (+`.csv`, admin token) export rows + signed head +
receipt pubkey. `scripts/verify_receipts.py` rechecks chain + signature.
