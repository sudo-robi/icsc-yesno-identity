# Yes/No Identity Verification — ICSC Track B

[![ci](https://github.com/sudo-robi/icsc-yesno-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/sudo-robi/icsc-yesno-identity/actions/workflows/ci.yml)

**ICSC** = ICSC 2026 Universities Hackathon. **Track B** = "Digital Identity & Trust:
Proving a Fact Without Revealing the Whole Record" — answering one question
(`over_18?`) with a trustworthy yes/no instead of handing over the full ID record.

Status: working prototype with production-structured code (service layers, 90%+ tested,
CI green). Identity data is synthetic; the cryptography is real (Ed25519, HMAC, hash chains).

## How it works (30 seconds)
1. **Issuer** signs `over_18=true` (5-min expiry) for a fake NIN record.
2. **Holder** shows a QR (or 6-digit code for basic phones).
3. **Verifier** sends a fresh nonce per check, verifies offline against a cached
   issuer public key, and shows only green YES / red NO — plus a PII-free receipt.

Architecture: [`docs/architecture.mmd`](docs/architecture.mmd) (Mermaid — paste into the
[Mermaid live editor](https://mermaid.live) to render).

## Run it (one path, ~2 min)
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
bash run.sh        # seeds synthetic DB, generates issuer keys, pairs trustbundle. Starts nothing.
PORT=5001 .venv/bin/python -m issuer.app &
PORT=5002 .venv/bin/python -m verifier.app &
# Issuer http://localhost:5001 — Verifier http://localhost:5002
# Holder: open holder/index.html (file works offline), set Issuer URL + Shop, fetch credential
# Smoke: ISSUER_URL=http://localhost:5001 VERIFIER_URL=http://localhost:5002 \
#          .venv/bin/python scripts/live_demo.py   # expects YES + NO + BADSIG + REPLAY
```

## Deploy
- **Render** (recommended): New → Blueprint → file `deploy/render.blueprint.yaml`
  (issuer + verifier services, gunicorn, single worker). Free tier has **no disk**,
  so redeploys reset SQLite/keys/receipts — re-pair afterwards; uncomment the disk
  blocks + paid instance type for persistence.
- **Vercel** (`vercel.json` services: `/issuer/*`, `/verifier/*`, `/holder/*`): works but
  storage is ephemeral `/tmp` per service and challenges can't cross instances —
  demo only, re-pair takes 10s.

## Demo (5 min, live attack demos)
1. Issue U001 → paste into verifier → YES (`mode: static`).
2. Screenshot the QR to a second phone → verify against a fresh challenge → REPLAY (copy blocked).
3. Answer the challenge (holder asks the issuer to embed the live nonce) → YES (`mode: challenge`, single-use).
4. Paste `{"a":"over_18","r":1,"s":"fake"}` → BADSIG.
5. Airplane mode ON → static check still YES (cached trustbundle, zero issuer calls at check time).
6. Revoke U001 on the issuer → old bundle still passes (delay window) → re-pair the
   signed `/bundle` → REVOKED. The 5-min credential expiry bounds the window.

Two modes, stated plainly: **challenge mode** (holder online, replay-proof, single-use
nonce) and **static mode** (holder offline, accepted within the 5-min expiry — a
deliberate offline trade-off, and the response says which mode was used).

## Receipts (PII-free audit trail)
`GET /receipts` + `/receipts.csv` — entries with no name/DOB, linked by an
HMAC chain keyed from `keys/receipt_hmac.key` (generated once, `0600`).
A key-less auditor replays the chain to detect edits; concurrent writes are
serialized so the chain can't fork. Honest scope: anyone holding *both* the DB
and the key can rewrite history — the chain proves tampering to outsiders,
nothing more. OTP/nonce material is stored peppered so public receipts can't
be brute-forced back into codes.

## Honest limits
- Revocation has a delay window by design (bounded by the 300s credential expiry).
  Revocation is real end to end: the issuer publishes per-verifier pseudonyms in a
  signed `/bundle`, the verifier pins the key and rejects rollbacks.
- OTP fallback enforces holder status (revoked/minor codes fail) but uses demo
  pre-shared secrets in a **separate** secrets store (`otp_secrets.json`), never the
  trustbundle. The verifier holding the secret is demo-only; production would use
  per-user TOTP provisioning.
- Pairing (`POST /verifier/sync`) is open by default for demos — set `PAIRING_TOKEN`
  to lock it (body field `pairing_token` or `X-Pairing-Token` header), else anyone
  reaching the verifier could swap its trusted keys. Same for issuer ops
  (`/revoke`, `/rotate`) via `ISSUER_ADMIN_TOKEN`.
- Enrollment is an explicit prototype boundary: `/issue` and `/otp` hand a signed
  credential to anyone presenting a user ID, so nonce binding proves *freshness for
  a shop at a time* — not presenter identity. Real deployment needs identity
  proofing at enrollment.
- Privacy trade-off: challenge mode shows the issuer the user + shop + time per
  check and needs the holder online. Static mode keeps the holder fully offline
  (and the issuer blind) at the cost of the 5-min replay window.
- Same-shop repeat visits are linkable (attributable receipts); cross-shop visits
  can't be joined (pairwise pseudonyms). Per-visit pseudonyms are future work.
- Single worker (`--workers 1`): the challenge registry and SQLite live in-process.
  Render free tier has no disk, so redeploys reset state like serverless — the paid
  disk block in the blueprint fixes that when you outgrow demo tier.

## Adoption (hypothesis, not a legal opinion)
Shops that photocopy IDs become data controllers holding personal data — under
Nigeria's NDPA 2023 (which replaced the NDPR 2019, enforced by the NDPC) that means
real obligations. A yes/no check lets a shop *avoid holding personal data at all*.
NIMC already holds NIN records, so it is the natural issuer; banks/telcos join as
second issuers to cut SIM-fraud. Shops adopt because a 1-tap offline check is faster
than a photocopy drawer and carries no PII-storage risk.

## Build notes
How this was built (agents, skills, TDD workflow): see [AGENTS.md](AGENTS.md).
