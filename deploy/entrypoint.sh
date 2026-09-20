#!/bin/sh
set -e

: "${ADMIN_TOKEN:?Set ADMIN_TOKEN env var}"

# Seed synthetic users on first boot (idempotent)
python scripts/seed.py --db "${ISSUER_DB:-/data/issuer.db}" 2>/dev/null || true

# Initialize verifier DB
python -c "import verifier.repo as r, os; r.init_db(os.environ.get('VERIFIER_DB', '/data/receipts.db'))" 2>/dev/null || true

# Start the selected service
if [ "$APP" = "verifier" ]; then
  exec gunicorn verifier.app:app --bind 0.0.0.0:${PORT:-5002} --workers 1
else
  exec gunicorn issuer.app:app --bind 0.0.0.0:${PORT:-5001} --workers 1
fi
