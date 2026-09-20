# Protocol: Yes/No age verification (offline-first Flask project)

Source of truth: `shared/canonical.py`, `shared/crypto.py`, `shared/schemas.py`,
`issuer/services.py`, `verifier/services.py`, routes in `issuer/app.py` + `verifier/app.py`.
Encoding is base64url without padding (`shared/crypto.py::b64u_encode`).
All signatures cover canonical JSON: sorted keys, `(",", ":")` separators, UTF-8,
floats rejected (`shared/canonical.py::canonical`).

## 1. Actors and keys

| Actor | Key | Custody (per code) |
|---|---|---|
| Issuer | Ed25519 signing key, raw 32-byte keys as hex (`shared/crypto.py::ed25519_keypair`). Active key from `ISSUER_PRIV_HEX` env or `0600` file `keys/issuer_priv.hex`, imported into the keys table once; rotations live in the keys table (`issuer/services.py::ensure_active_key`). | `issuer/services.py`, `issuer/app.py::_active_key` |
| Holder | ECDSA P-256 key **per `verifier_id`**, exchanged as base64url uncompressed point (65 bytes, `0x04` prefix; `shared/crypto.py::p256_pubkey_from_b64u`). WebCrypto signs raw `r\|\|s` (IEEE P1363, 64 bytes); backend converts to DER before verify (`p1363_to_der` → `p256_verify` with SHA-256). | Validated at enroll (`issuer/services.py::issue_credential`), used at verify (`verifier/services.py::decide`) |
| Verifier | Ed25519 receipt-signing key, generated once via `ed25519_keypair`, kept in verifier DB kv store (`verifier/services.py::load_receipt_key`, `receipt_pub`). | `verifier/app.py::_receipt`, `/receipts` export |

## 2. Pseudonym derivation

`sub = HMAC-SHA256(master_secret_hex, verifier_id)` truncated to the first **16 bytes**,
hex-encoded (32 chars) — `shared/crypto.py::pseudonym`:

```python
digest = hmac.new(bytes.fromhex(master_secret_hex), verifier_id.encode(), hashlib.sha256).digest()
return digest[:16].hex()
```

Pairwise per shop: two `verifier_id` values give different `sub`, so shops cannot
join records. Used as credential `sub`, bundle list entries, and OTP-secret map keys.

## 3. Enrollment flow (one time per holder + shop)

1. Admin mints a single-use code: `POST /admin/users/<user_id>/enrollment-code`
   (`issuer/app.py`; only the SHA-256 of the code is stored — `issuer/repo.py`;
   TTL `ENROLL_CODE_TTL_SEC`, default 24h per `shared/config.py`). Returned ONCE.
2. Holder posts `POST /enroll` with `{code, verifier_id, holder_pub}`
   (`EnrollSchema` in `issuer/app.py`: `code` 1–128 chars, `verifier_id` 1–32 chars,
   `holder_pub` 1–128 chars b64u). Repo atomically consumes the code
   (`repo.consume_enrollment_code` → `ok` / `CODE_USED` / `CODE_EXPIRED` / `UNKNOWN_CODE`).
3. Issuer runs `issuer/services.py::issue_credential`: unknown user → `UNKNOWN_CODE`
   (400); `user["revoked"]` → `REVOKED_USER` (403); bad P-256 point → `BAD_PUBKEY`
   (400). Adult flag via calendar-correct 18+ check `dob + 18y <= today`
   (Feb 29 → Feb 28 on non-leap years; `is_adult`). DOB never leaves the issuer —
   only boolean `r` and pseudonym `sub` are issued.
4. Response is `{"credential": {...}}`, plus `{"otp_secret": hex}` iff `OTP_ENABLED`
   (`issuer/app.py::enroll`). OTP secret is deterministic per user per shop:
   `HMAC-SHA256(user_master_secret, "otp|<verifier_id>")` hex
   (`issuer/services.py::otp_secret_for`) — issuer is stateless for OTP.

## 4. EXACT credential JSON shape

Signed fields (`shared/schemas.py::CRED_SIGNED_FIELDS`):

```
v, iss, sub, vid, a, r, iat, exp, cnf, did
```

Required = signed fields + `s`. **Unknown extra fields are REJECTED**
(`signed_body` raises `SchemaError` → `MALFORMED`), never ignored.

```json
{"v": 1, "iss": "NIMC-TEST-01", "sub": "<32-hex pseudonym>", "vid": "SHOP-A",
 "a": "over_18", "r": 0, "iat": 1700000000, "exp": 1700003600,
 "cnf": "<holder P-256 pub b64u>", "did": "<32-hex device fingerprint>",
 "s": "<issuer Ed25519 sig b64u>"}
```

Built by `issuer/services.py::issue_credential`:

```python
{"v": 1, "iss": issuer_id, "sub": pseudonym(master_secret, verifier_id),
 "vid": verifier_id, "a": "over_18", "r": 1 if is_adult(dob) else 0,
 "iat": int(now), "exp": int(now) + ttl_sec, "cnf": holder_pub_b64u,
 "did": sha256_hex(f"{holder_pub_b64u}|{verifier_id}")[:32],
 "s": ed25519_sign(priv_hex, canonical(signed_body(payload)))}
```

- `r` is plain int `0 | 1` (bools rejected); `v`, `iat`, `exp` plain ints;
  `sub`, `vid`, `a`, `iss`, `cnf` strings (`validate_credential`).
- `exp = iat + CRED_TTL_SEC` (default `3600`, `shared/config.py`).
- Type validation failures → `MALFORMED`; full presentation `{c, p}` capped at
  `CRED_MAX_BYTES = 2048` bytes (`shared/schemas.py`).

## 5. Challenge / proof message format

- Challenge minted by `verifier/services.py::mint_challenge`, served at
  `GET /challenge` (`verifier/app.py`; stored via `repo.add_nonce`, pruned to
  `NONCE_TTL_SEC`, default 300s): exactly `{n, vid, exp}`
  (`CHALLENGE_FIELDS`), `n = secrets.token_hex(16)` (32 hex chars).
- Proof posted to `POST /verify` as `{"c": cred, "p": proof}` (`VerifySchema`;
  **both required**). Proof shape is exactly `{n, ts, sig}` (`PROOF_FIELDS`;
  `n` str, `ts` plain int, `sig` str raw P1363 b64u — `validate_proof`).
- Exact signed bytes (`verifier/services.py::proof_message`):

```python
canonical(["yn-proof-v1", cred_canonical_sha, nonce, vid, ts, did])
# cred_canonical_sha = sha256_hex(canonical(signed_body(cred)))
# did = cred.get("did", "")  # device fingerprint for auditability
```

i.e. the canonical JSON list `["yn-proof-v1", sha256, n, vid, ts]` where `sha256`
is the hex SHA-256 of the canonical credential body, `n` the challenge nonce,
`vid` **the verifier's own id** (recomputed server-side, so a proof for another
shop cannot verify), `ts` the holder timestamp (must be within
`PROOF_TS_WINDOW_SEC = 60`s of `now`). Verified with `cred["cnf"]` via
`p256_verify`. **There is no code path that accepts a credential without a
fresh holder proof** (`decide` docstring).

## 6. Verifier decision order with every reason code

`verifier/services.py::decide(cred, proof, raw_len, trust, verifier_id, now,
consume_nonce, ...)`. First match wins, returns `(YES/NO, reason)`:

1. `trust is None` → `NO / NO_TRUSTBUNDLE`
2. `validate_credential(cred)` fails → `NO / MALFORMED`
3. `raw_len > max_bytes` (2048) → `NO / TOO_LARGE`
4. `cred["vid"] != verifier_id` → `NO / WRONG_VERIFIER`
5. `cred["iss"] != trust["iss"]` → `NO / ISSUER_MISMATCH`
6. `cred["exp"] + CLOCK_SKEW_SEC (30) < now` → `NO / EXPIRED`
7. `signed_body` raises → `NO / MALFORMED`; `ed25519_verify(trust["pub"], cred["s"],
   canonical(body))` false → `NO / BADSIG`
8. `proof is None` → `NO / BAD_PROOF`
9. `validate_proof(proof)` fails → `NO / <returned code>` (in practice `MALFORMED`;
   exact equality on `{n, ts, sig}` plus types is enforced)
10. `consume_nonce(proof["n"], now - NONCE_TTL_SEC, now)` returns None
    (never issued, expired, already used) → `NO / UNKNOWN_CHALLENGE`.
    Consumption is an atomic single-use take delegated to the repo, so concurrent
    claimants cannot double-spend.
11. `abs(now - proof["ts"]) > PROOF_TS_WINDOW_SEC (60)` → `NO / BAD_PROOF`
12. `p256_verify(cred["cnf"], proof["sig"], proof_message(...))` false →
    `NO / BAD_PROOF`
13. `cred["sub"] in trust["revoked"]` → `NO / REVOKED`
14. `cred["sub"] in trust["minors"]` → `NO / NOT_ADULT`
15. `cred["a"] != "over_18" or cred["r"] != 1` → `NO / NOT_ADULT`
16. else → `YES / OK`

All reasons are members of `shared/errors.py::REASONS`; `verifier/app.py::verify`
rejects any drift with 500. Every `/verify` attempt that reaches a decision
appends a receipt with mode `over_18:proof`.

## 7. Trust-bundle format + rotation chain + TOFU

Signed fields (`shared/schemas.py::BUNDLE_SIGNED_FIELDS`):

```
v, iss, vid, pub, next_pub, revoked, minors, iat, exp
```

Required = signed fields + `s`; unknown extras → `MALFORMED`
(`validate_bundle_shape`). `pub` is 64-char hex; `next_pub` is 64-char hex or
`null`; `revoked` / `minors` are sorted lists of pseudonym hex;
`v`, `iat`, `exp` plain ints.

```json
{"v": 3, "iss": "NIMC-TEST-01", "vid": "SHOP-A", "pub": "<64-hex Ed25519>",
 "next_pub": "<64-hex Ed25519 or null>", "revoked": ["<sub>", "..."],
 "minors": ["<sub>", "..."], "iat": 1700000000, "exp": 1700604800, "s": "<sig b64u>"}
```

Built by `issuer/services.py::build_bundle` (pseudonyms only, no PII; revoked
and minors sorted; `exp = issued_at + BUNDLE_TTL_SEC`, default 7 days;
signed via `ed25519_sign(priv, canonical(bundle_sig_body(body)))`).
Served publicly at `GET /bundle?vid=SHOP-A` (`issuer/app.py`; `vid` ≤ 32 chars).

Pairing / sync (`POST /sync`, `verifier/app.py`, admin token;
body `{"bundle": {...}}` or the bare bundle):

- First sync with no pinned key and a well-shaped, unexpired bundle → accept
  (TOFU). Server stores it and returns the key fingerprint for **out-of-band
  operator confirmation**: `key_fingerprint` = first 8 bytes of `pub` hex,
  grouped `XXXX XXXX XXXX XXXX` (`shared/crypto.py`), plus `"tofu": true`.
- Later syncs (`verifier/services.py::check_bundle`): reject `EXPIRED`
  (`exp <= now`); reject `ISSUER_MISMATCH` if `iss`/`vid` differ from pinned;
  reject `ROLLBACK` if `bundle["v"] < pinned["v"]`; accept iff the body verifies
  under the **pinned `pub` OR the chained `next_pub`**; else `BADSIG`.
  `BADSIG` / `ROLLBACK` / `ISSUER_MISMATCH` → HTTP 409; other failures → 400.
- Rotation chain (`POST /admin/rotate`, `issuer/app.py`): without `activate`,
  stage a fresh keypair (inactive) and bump the bundle version; the current
  bundle `N` (signed by K1) then advertises `next_pub = K2`. With
  `{"activate": true}`, the staged key becomes active and the version bumps.
  A key the chain never announced is rejected by verifiers. Rotation is refused
  with 409 while `ISSUER_PRIV_HEX` env manages the key. Both stage and activate
  bump `repo.bundle_version`, so `v` is monotonic.

## 8. OTP fallback design

**⚠️ TRUST MODEL WARNING:** OTP mode is weaker **by design**.

Purpose-built for feature phones; reduced assurance **by design** (the shop holds
the secrets and can mint codes — unlike QR mode where only the holder device
can sign). Gated by `OTP_ENABLED` (`shared/config.py`); both
`GET /issuer/admin/otp-secrets` and `POST /verify_code` return `OTP_DISABLED`
(404) when off.

### Trust comparison: QR mode vs OTP mode

| Aspect | QR mode (P-256) | OTP mode (HMAC) |
|---|---|---|
| Who can mint valid proofs | Only the holder device (private key) | Anyone with the OTP secret (shop staff) |
| Replay protection | Fresh challenge nonce (single-use) | HMAC step window (30s) + single-use |
| Device binding | `cnf` key bound to holder device | None — code works on any phone |
| Revocation enforcement | Bundle check on every verify | Bundle check on every verify |
| Assumption | Holder device is trusted | Shop operator is trusted |
| Use case | Smartphones with camera | Feature phones (dumb phones) |

**Bottom line:** OTP mode trusts the shop operator not to mint fake codes.
QR mode only trusts the holder's device. Use OTP only when QR scanning is
impossible (feature phones, poor camera, accessibility needs).

- Provisioning (admin channel only): `GET /admin/otp-secrets?vid=` on the issuer
  returns `{vid, secrets}` where `secrets` maps **`sub → otp_secret`** and
  contains **adult, non-revoked users only** (`issuer/app.py::otp_secrets`).
  The operator posts that map to `POST /admin/otp-secrets` on the verifier,
  which writes it to a `0600` file (`OTP_SECRETS_PATH`), never into the bundle.
- Code (`shared/crypto.py::otp_code`):
  `code = HMAC-SHA256(secret, "<verifier_id>|<step>") mod 10^6`, zero-padded to
  6 digits, with `step = floor(now / OTP_STEP_SEC)` (`OTP_STEP_SEC = 30`).
- Verify (`POST /verify_code`, `verifier/app.py`): `match_otp_code` scans every
  `sub → secret` for the current step **and `OTP_GRACE_STEPS = 1` previous step**.
  No match → `NO / BAD_OTP` (receipted, code not recorded). Match + reuse of
  `(sub, step)` (`repo.is_code_used`, pruned) → `NO / UNKNOWN_CHALLENGE`.
  Otherwise mark `(sub, step)` used and enforce bundle status
  (`otp_status`): revoked → `NO / REVOKED`; minor → `NO / NOT_ADULT`; else
  `YES / OK_OTP`. Invalid codes are never recorded; raw codes are never logged
  or stored. Rate-limited (`RATELIMIT_SENSITIVE`).

## 9. Receipt format

PII-free append-only log (`verifier/app.py::_receipt`, `verifier/services.py`):

- Row: `id, ts, verifier_id, q, result, reason` + `prev_hash, entry_hash`.
  `q` is only the public query string (`over_18:proof` or `over_18:otp`).
  **No raw nonce / credential / code, and no derivatives of them**, are stored
  or hashed in.
- Chain link (`chain_entry`): `HMAC-SHA256(key, "<prev>|<ts>|<vid>|<q>|<result>|<reason>")`
  hex, where `key` is the verifier receipt key from the kv store.
- Head signing (`sign_head`): `ed25519_sign(receipt_priv,
  canonical({"head": head_hash, "ts": ts}))` — done periodically and on export.
- Export (admin token): `GET /receipts` → `{rows, head: {head, ts, sig},
  receipt_pub}`; `GET /receipts.csv` → same rows plus `head` and `receipt_pub`
  lines. Auditors recheck the chain + signature (see `scripts/verify_receipts.py`).
