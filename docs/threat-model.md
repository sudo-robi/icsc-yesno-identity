# Threat model and known limits

Scope: the code read for this doc is `shared/canonical.py`, `shared/crypto.py`,
`shared/schemas.py`, `issuer/services.py` (enrollment / bundle / rotation),
`verifier/services.py` (decision order, nonce handling, OTP, receipts), and the
routes in `issuer/app.py` + `verifier/app.py`.

## Assets

- Holder P-256 private keys (per `verifier_id`; never leave the device in QR mode;
  `cnf` binding in `issuer/services.py::issue_credential` / `verifier/services.py::decide`).
- Issuer Ed25519 signing key + user table (`master_secret`, `dob`, `revoked`) —
  DB file and `keys/issuer_priv.hex` (0600) must be protected (`issuer/services.py::ensure_active_key`).
- Verifier pinned trust bundle (`revoked` + `minors` pseudonym lists), OTP secrets
  file (`0600`, `sub → secret`), nonce/code-reuse stores, receipt chain + receipt
  signing key (`verifier/app.py`, `verifier/services.py`).
- Credentials themselves: bearer tokens inside their window (see limits).

## Actors

- **Holder (customer):** trusted with their own device, NOT trusted to be honest
  about age — hence proofs over `cnf`, not claims.
- **Shop operator / verifier admin:** trusted to run the verifier faithfully and
  confirm the TOFU fingerprint out-of-band; NOT trusted with customer PII
  (yes/no only + PII-free receipts).
- **Issuer admin (ADMIN_TOKEN holder):** fully trusted — can mint enrollment codes,
  revoke users, rotate keys, read per-shop OTP secrets. Compromise = total
  compromise of issuance; rotation chain + audit log bound the blast radius.
- **Attacker:** can copy QRs/screenshots, craft unsigned claims, replay traffic,
  brute-force public endpoints, steal a holder phone — but has no issuer key,
  no holder private key, and cannot break Ed25519 / P-256 / SHA-256 / HMAC.

## Attack → mitigation

| Attack | Mitigation (with code reference) |
|---|---|
| Replay (screenshot / QR copy / sniffed `{c,p}`) | Fresh challenge `n = token_hex(16)` stored server-side and **consumed
  atomically single-use** (`mint_challenge`, `decide` step 10 via `consume_nonce`; `repo.consume_nonce`). Static or reused presentations → `UNKNOWN_CHALLENGE`. Holder `ts` must be within 60 s (`PROOF_TS_WINDOW_SEC`) → else `BAD_PROOF`. |
| Cross-phone copy (credential moved to attacker's phone) | Proof must verify under the `cnf` P-256 key bound at enrollment
  (`p256_verify(cred["cnf"], ...)` over `["yn-proof-v1", sha256, n, vid, ts]`);
  the key never leaves the victim device → `BAD_PROOF`. |
| Minor using an adult's credential | Same `cnf` binding (`BAD_PROOF`); plus minors enroll as `r = 0` and appear
  in the bundle `minors` list → `NOT_ADULT` even with a valid signature. |
| Forged issuer credential (no issuer key) | Issuer Ed25519 signature over canonical body, verified against the pinned
  bundle `pub` (`BADSIG`). Unknown extra fields rejected, not ignored (`MALFORMED`). |
| Forged / tampered trust bundle at pairing or sync | Admin token on `POST /sync`; first sync is TOFU with fingerprint
  (`key_fingerprint`, first 8 bytes grouped) for out-of-band confirmation.
  Later syncs require signature from pinned `pub` **or** chained `next_pub`,
  matching `iss`/`vid`, monotonic `v`, future `exp` (`check_bundle`);
  violations → `BADSIG` / `ROLLBACK` / `ISSUER_MISMATCH` / `EXPIRED`. Rotation
  accepted **only** via announced `next_pub` (`POST /admin/rotate` chain);
  env-managed keys refuse rotation (409). |
| Stale revocation (revoked/minor user still verifies) | Delay is bounded and explicit: credential TTL (`CRED_TTL_SEC`, default
  3600 s) **and** bundle sync frequency — revocation lands in the next bundle's
  `revoked` list and every verify re-checks `sub` against it (`REVOKED` /
  `NOT_ADULT`). Never zero; operators must sync. |
| OTP brute force / code replay | 6-digit `HMAC(secret, vid\|step)` over 30 s steps, current + 1 grace step
  only; matches are single-use per `(sub, step)` (`is_code_used` /
  `mark_code_used`, pruned) → reuse is `UNKNOWN_CHALLENGE`; misses are `BAD_OTP`.
  Rate limits (`RATELIMIT_SENSITIVE`) apply; matched codes still enforce bundle
  `revoked` / `minors` (`otp_status`). Raw codes never logged or stored. |
| Device theft (unlocked showing phone, live QR) | Accepted residual risk (see limits): a live `{c,p}` pair verifies for
  ~60 s. At rest, theft without the holder P-256 key is useless — copied
  credentials alone fail `BAD_PROOF`. No biometric binding exists. |
| Malicious / imposter shop (wrong verifier, second shop replay) | Credentials are `vid`-bound twice: `cred["vid"] != verifier_id` →
  `WRONG_VERIFIER`, and the proof message is recomputed with the verifier's own
  `vid`, so a proof minted for shop B fails at shop A (`BAD_PROOF`). |

## Honest known limits

- **Bearer credentials within the window:** whoever holds a live `{c,p}` pair
  *is* the holder for ~60 s (`PROOF_TS_WINDOW_SEC` + single-use nonce). Theft of
  an unlocked showing phone is accepted risk.
- **Device binding (``did`` field):** each credential includes a `did` (SHA-256
  fingerprint of `holder_pub|verifier_id`) signed into the credential. The proof
  message includes the `did` for auditability. This prevents casual credential
  sharing between devices but does NOT bind to hardware — a copied private key
  still works. Full WebAuthn/FIDO2 attestation (biometric + hardware binding)
  is the production target but out of scope for this prototype.
- **No biometric binding** of holder to person (out of scope) — `cnf` binds a
  device key, not a face. The `did` field adds device-level auditability but
  not hardware attestation.
- **Issuer-side visibility:** enrollment shows the issuer the user + shop + time
  (`POST /enroll {code, verifier_id, holder_pub}`); unlinkability against the
  issuer is NOT provided. No anonymous/static issuance mode exists.
- **Revocation window:** bounded by credential TTL *and* bundle sync frequency,
  never zero. A revoked user keeps verifying until their credential expires and
  the shop syncs a fresh bundle.
- **OTP weaker by design:** the shop holds the OTP secrets and can mint valid
  codes; assurance rests on operator honesty + `(sub, step)` single-use + bundle
  status checks. It exists for basic phones, not as an equivalent factor.
  **Trust comparison:** QR mode trusts only the holder device (private key).
  OTP mode trusts the shop operator (they hold the HMAC secret). Use OTP only
  when QR scanning is impossible (feature phones, poor camera, accessibility).
  See `docs/protocol.md` section 8 for a full comparison table.
- **Ephemeral targets:** server-side nonce / reuse / receipt state lives in
  SQLite/kv files; serverless `/tmp` and diskless containers reset it (re-pair
  after). Receipt HMAC proves tampering to outsiders, not to someone holding
  both the DB and the receipt key.
- **Enrollment is trust-on-operator:** `/enroll` hands a credential to whoever
  presents a valid single-use code — code distribution is a human process
  outside the system.
