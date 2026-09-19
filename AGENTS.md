# ICSC Track B — Yes/No Identity Verification (offline-first)
# Integrated with everything-claude-code + agency-agents to the fullest.

## Active agent roster (agency-agents)
- Engineering: backend-architect (Issuer APIs), frontend-developer (shop UI),
  mobile-app-builder (Holder web + WebView), devops-automator (Render + CI),
  database-optimizer (SQLite -> Postgres-ready via SQLAlchemy-style repos),
  api-tester + test-automation-engineer (attack tests + E2E)
- Security: security-architect, appsec-engineer, secrets-credential-engineer
  (Ed25519 lifecycle, trustbundle versioning, revocation honesty)
- Testing: evidence-collector, reality-checker (demo proof + limits slide)

## ECC enforcement (everything-claude-code)
- Rules: security (no secrets, validate input, rate-limit, no PII leak),
  testing (80%+ coverage, unit+integration+E2E), coding-style, git-workflow
- Skills: backend-patterns (service/repo layers), tdd-workflow (RED->GREEN),
  security-review checklist, verification-loop (verify after every module)
- Commands: /tdd for new endpoints, /code-review before merge, /verify for attack demos

## Production contract
- Offline-first: verifier caches trustbundle.json, zero live issuer calls at check time
- Short-lived creds: exp = now + 300s, skew 30s, revocation list versioned
- PII-free receipts: hash-chained, exportable CSV
- Free deploy: Render (gunicorn), full offline fallback via run.sh
