# Threat model and known limits

## Assets
- Holder private keys (per-shop P-256, on-device, non-extractable).
- Issuer signing key + user master secrets (server-side).
- Verifier pinned bundle, OTP secrets file, receipt chain + signing key.
- The credentials themselves (bearer tokens — see below).

## Actors
- **Holder** (customer): trusted with their own device, not trusted to be
  honest about age (hence proofs, not claims).
- **Shop operator**: trusted to run the verifier faithfully, NOT trusted with
  customer PII (hence yes/no only + PII-free receipts).
- **Issuer admin**: fully trusted (can enroll/revoke/rotate). Compromise =
  total compromise of issuance; rotation chain + audit log bound the blast radius.
- **Attacker**: can copy QRs/screenshots, craft unsigned claims, replay traffic,
  brute-force endpoints, reach any public endpoint, steal a holder phone — but
  has no issuer key and cannot break Ed25519/P-256/SHA-256/HMAC.

## Attacks considered
| Attack | Mitigation |
|---|---|
| Screenshot / QR copy replay | Fresh challenge consumed atomically; static QRs never verify (`UNKNOWN_CHALLENGE`/`BAD_PROOF`) |
| Credential copied to another phone | Proof must be signed by the `cnf` holder key, which never leaves the victim's device (`BAD_PROOF`) |
| Minor with adult's credential | Same `cnf` binding (`BAD_PROOF`); minors also enroll as `r=0` |
| Forged credential, no issuer key | `BADSIG` (pinned-key verification) |
| Forged/rogue issuer via pairing | Admin token + TOFU fingerprint confirm + signature chain (`next_pub`) + rollback reject |
| Stale revocation | Delay window bounded by credential TTL *and* bundle sync frequency (documented, demoed) |
| Tampered receipt log | HMAC chain (concurrency-safe append) + Ed25519-signed head; `verify_receipts.py` |
| OTP guessing | 60s window + single-use `(sub, step)` + rate limits; status still enforced |
| Verifier imposter shop | Credentials are `vid`-bound (`WRONG_VERIFIER`) |
| Traffic sniffing | TLS in production; challenge/response values are single-use anyway |

## Honest known limits
- **Bearer credentials within the window**: whoever holds a live `{c,p}` pair
  *is* the holder for ~60s. Theft of an unlocked showing phone is accepted risk.
- **No biometric binding** of holder to person (out of scope).
- **Issuer-side unlinkability is NOT provided**: challenge-mode issuance shows
  the issuer user + shop + time. (No static/anonymous issuance mode exists.)
- **Revocation delay window**: bounded by TTL and sync frequency, never zero.
- **OTP mode is weaker by design**: the shop holds the secrets and can mint codes.
- **Receipt chain vs DB+key holder**: proves tampering to outsiders, not to
  someone holding both the DB and the HMAC key.
- **Ephemeral targets**: serverless `/tmp` and diskless containers reset state
  (re-pair after). Render needs the paid disk; Vercel is unsuitable for the verifier.
- **Enrollment is trust-on-operator**: `/enroll` hands credentials to whoever
  presents a valid code — code distribution is a human process outside the system.
