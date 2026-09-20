# Yes/No Identity — offline age checks without showing ID

[![ci](https://github.com/sudo-robi/icsc-yesno-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/sudo-robi/icsc-yesno-identity/actions/workflows/ci.yml)

A shop learns ONLY whether a customer is over 18 (YES/NO) — never name, birth
date or national ID — and the check works with the shop device **offline**.
Synthetic data only; the cryptography is real (Ed25519, P-256, HMAC).

**ICSC** = ICSC 2026 Universities Hackathon. **Track B** = Digital Identity &
Trust: proving a fact without revealing the whole record.

Status: working prototype with layered code (routes → services → repo),
130+ tests, 90%+ coverage, CI green. Not production software — see
[docs/threat-model.md](docs/threat-model.md) for honest limits.

## How it works (30 seconds)
1. **Issuer** (test agency) holds fake NIN records, enrolls holder device keys,
   and publishes a signed trust bundle (public key + revocations).
2. **Holder PWA** generates its own P-256 key per shop, enrolls once with a
   one-time code, then answers shop challenges with on-device signatures.
3. **Shop app** shows a challenge QR, scans the holder's `{credential, proof}`
   QR, verifies offline against the pinned bundle, and shows YES/NO.

Architecture: [`docs/architecture.mmd`](docs/architecture.mmd) (paste into the
[Mermaid live editor](https://mermaid.live)). Protocol: [`docs/protocol.md`](docs/protocol.md).

## Run it (2 minutes)
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
bash run.sh
# Issuer  http://localhost:5001/  (admin dashboard)
# Holder  http://localhost:5001/holder/  (installable PWA)
# Shop    http://localhost:5002/
# run.sh prints ADMIN_TOKEN + a demo enrollment code, and pairs the shop.
```
`run.sh` only: seeds synthetic data, starts both services, pairs the demo shop.
The smoke test: `ADMIN_TOKEN=... .venv/bin/python scripts/demo.py` — expects
YES, NO(minor), BADSIG, replay blocked, forged-bundle rejected, revoked after sync.

## Demo (5 minutes, live)
1. Admin dashboard → mint an enrollment code for U001.
2. Holder PWA → enroll with the code → credential card appears.
3. Shop → New challenge → holder scans it → holder shows ID QR → shop scans → **YES**.
4. Screenshot the holder QR, replay it → **blocked** (challenge consumed).
5. Forge a credential by hand → **BADSIG**. Airplane mode on both → still works.
6. Admin revokes U001 → old bundle still passes (delay window) → re-sync bundle → **REVOKED**.

## Deploy
- **Render** (recommended): `deploy/render.blueprint.yaml` — services with a
  **persistent disk** (paid instance required for disks; free tier resets state).
- **Docker**: `docker compose -f deploy/compose.yml up --build` (needs `ADMIN_TOKEN`).
- **Vercel/serverless: unsuitable for the verifier** — `/tmp` resets wipe the nonce
  registry, receipts and pairing. Stateless issuer-only hosting is possible but pointless
  for the demo; not supported.
- **Camera note**: QR scanning needs HTTPS or localhost (`getUserMedia` rule).
  Plain-HTTP LAN IPs get the paste-JSON fallback; the README demo uses paste or localhost.

## Adoption (hypothesis, not a legal opinion)
Shops that photocopy IDs become data controllers holding personal data — under
Nigeria's NDPA 2023 (replacing NDPR 2019, enforced by the NDPC) that means real
obligations. A yes/no check lets a shop *avoid holding personal data at all*.
NIMC already holds NIN records, so it is the natural issuer; banks/telcos join as
second issuers to cut SIM-fraud. Shops adopt because a 1-tap offline check is faster
than a photocopy drawer and carries no PII-storage risk.
