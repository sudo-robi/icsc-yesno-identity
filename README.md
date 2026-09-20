# Yes/No Identity Verification — Track B (offline-first, production-ready)

Proving `over_18?` without revealing the record. Synthetic data only.

## Live
- GitHub: https://github.com/sudo-robi/icsc-yesno-identity
- Deploy targets: Render blueprint `deploy/render.blueprint.yaml` (persistent services,
  gunicorn) or Vercel services (`vercel.json`: `/issuer/*`, `/verifier/*`, `/holder/*`).
  - Pair once: `GET <issuer>/pubkey` → `POST <verifier>/sync` (honest pairing ceremony)
  - Smoke: `ISSUER_URL=... VERIFIER_URL=... .venv/bin/python scripts/live_demo.py`
    (defaults to localhost:5001/5002; expects YES + NO + BADSIG + REPLAY)
- Serverless limits (honest): ephemeral `/tmp` per service — keys/receipts reset on
  cold starts, re-pair takes 10s. Persistent deployments use Render.

## Run offline (judges, no internet)
```bash
pip install -r requirements.txt
bash run.sh
PORT=5001 python3 -m issuer.app & PORT=5002 python3 -m verifier.app &
# Issuer http://localhost:5001 — Verifier http://localhost:5002 — Holder holder/index.html
```

## Free deploy (Render)
Repo has `deploy/render.blueprint.yaml` (issuer + verifier web services, gunicorn).
Render deploy: New → Blueprint → set blueprint file to `deploy/render.blueprint.yaml`.

## Demo (5 min)
1. Issue U001 → paste into verifier → YES
2. `GET /challenge`, verify static QR with fresh nonce → REPLAY (copied QR blocked)
3. Sign nonce live → YES (holder signs challenge)
4. Paste `{"a":"over_18","r":1,"s":"fake"}` → BADSIG
5. Airplane mode ON → still YES (cached trustbundle, zero issuer calls)
6. Old revlist v4 → YES, sync v5 → REVOKED. 5-min expiry bounds exposure.

## Receipts (PII-free)
`/receipts` + `/receipts.csv` — hash-chained, no name/DOB. Tamper breaks chain.

## Limits (honest)
- Revocation has a delay window (by design, bounded by 300s expiry).
- OTP fallback needs pre-shared secret in trustbundle for demo.
- Pairwise pseudonym stops cross-shop linking; same-shop repeat visits still linkable (by design for receipts).

## Adoption
NIMC runs the issuer (already holds NIN, kills photocopy NDPR liability).
Banks/telcos as 2nd issuer. Shops adopt: 1-tap offline check, no PII storage risk.

## Agents/Skills used
See AGENTS.md — backend-architect, mobile-app-builder, devops-automator,
security-architect, api-tester + ECC tdd-workflow, security-review, verification-loop.
