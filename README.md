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
- **Render** (persistent, recommended): New → Blueprint → file `deploy/render.blueprint.yaml`
  (issuer + verifier services, gunicorn).
- **Vercel** (`vercel.json` services: `/issuer/*`, `/verifier/*`, `/holder/*`): works but
  storage is ephemeral `/tmp` per service — keys/receipts reset on cold starts, re-pair takes 10s.

## Demo (5 min, live attack demos)
1. Issue U001 → paste into verifier → YES.
2. Screenshot the QR to a second phone → verify against a fresh challenge → REPLAY (copy blocked).
3. Answer the challenge (holder fetches credential embedding the nonce) → YES.
4. Paste `{"a":"over_18","r":1,"s":"fake"}` → BADSIG.
5. Airplane mode ON → still YES (cached trustbundle, zero issuer calls at check time).
6. Old revocation list still passes, synced v5 → REVOKED. The 5-min credential expiry bounds the window.

## Receipts (PII-free audit trail)
`GET /receipts` + `/receipts.csv` — hash-chained entries with no name/DOB.
An auditor replays the chain to detect tampering. Cross-shop visits can't be linked
(pairwise pseudonyms); repeat visits to the *same* shop stay linkable so receipts
remain attributable — documented trade-off, per-visit pseudonyms are future work.

## Honest limits
- Revocation has a delay window by design (bounded by the 300s credential expiry).
- OTP fallback uses demo pre-shared secrets kept in a **separate** secrets store
  (`otp_secrets.json`), never in the trustbundle. The verifier holding the secret is
  demo-only; production would use per-user TOTP provisioning.
- Pairing (`POST /verifier/sync`) is open by default for demos — set `PAIRING_TOKEN`
  to lock it (body field `pairing_token` or `X-Pairing-Token` header), else anyone
  reaching the verifier could swap its trusted keys.
- Same-shop repeat visits are linkable (see above).

## Adoption (hypothesis, not a legal opinion)
Shops that photocopy IDs become data controllers holding personal data — under
Nigeria's NDPA 2023 (which replaced the NDPR 2019, enforced by the NDPC) that means
real obligations. A yes/no check lets a shop *avoid holding personal data at all*.
NIMC already holds NIN records, so it is the natural issuer; banks/telcos join as
second issuers to cut SIM-fraud. Shops adopt because a 1-tap offline check is faster
than a photocopy drawer and carries no PII-storage risk.

## Build notes
How this was built (agents, skills, TDD workflow): see [AGENTS.md](AGENTS.md).
