#!/bin/bash
# Demo entrypoint: starts issuer :5001 + verifier :5002, seeds synthetic data,
# pairs the demo shop, and prints the admin token + a demo enrollment code.
# No real PII anywhere. Requires: python3, pip, the requirements installed.
set -e
cd "$(dirname "$0")"

if [ -z "$ADMIN_TOKEN" ]; then
  export ADMIN_TOKEN
  ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
  echo "generated ADMIN_TOKEN (export it to reuse): $ADMIN_TOKEN"
fi
export ISSUER_DB="${ISSUER_DB:-issuer/issuer.db}"
export VERIFIER_DB="${VERIFIER_DB:-verifier/receipts.db}"
export OTP_ENABLED="${OTP_ENABLED:-1}"

PY=${PY:-python3}
[ -x .venv/bin/python ] && PY=.venv/bin/python

$PY scripts/seed.py --db "$ISSUER_DB" >/dev/null
$PY -c "import verifier.repo as r, os; r.init_db(os.environ.get('VERIFIER_DB', 'verifier/receipts.db'))"

PORT=5001 $PY -m issuer.app & ISSUER_PID=$!
PORT=5002 $PY -m verifier.app & VERIFIER_PID=$!
trap 'kill $ISSUER_PID $VERIFIER_PID 2>/dev/null' EXIT

for i in $(seq 1 50); do
  curl -sf http://localhost:5001/healthz >/dev/null && \
  curl -sf http://localhost:5002/healthz >/dev/null && break
  sleep 0.2
done

echo "--- pairing demo shop (signed bundle -> sync) ---"
BUNDLE=$(curl -sf "http://localhost:5001/bundle?vid=SHOP-A")
curl -sf -X POST http://localhost:5002/sync \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$BUNDLE" | $PY -c "import json,sys; print('sync:', json.load(sys.stdin))"
CODE=$(curl -sf -X POST http://localhost:5001/admin/users/U001/enrollment-code \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -d '{}' | $PY -c "import json,sys; print(json.load(sys.stdin)['code'])")

echo ""
echo "Issuer:  http://localhost:5001/  (admin dashboard)"
echo "Holder:  http://localhost:5001/holder/"
echo "Shop:    http://localhost:5002/"
echo "Demo enrollment code (U001, single-use): $CODE"
echo ""
echo "Smoke: ADMIN_TOKEN=$ADMIN_TOKEN $PY scripts/demo.py"
wait
