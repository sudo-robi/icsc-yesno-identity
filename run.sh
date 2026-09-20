#!/bin/bash
# Offline fallback: airplane-mode demo. No internet needed after pip install.
# Seeds the synthetic DB, generates issuer keys, and pairs the verifier with a
# REAL signed bundle (same /bundle -> /sync flow as production, done via files).
set -e
cd "$(dirname "$0")"
python3 -c "import issuer.app as a; a.init_db(); a.load_keys()"
python3 -c "import verifier.app as a; a.init_db()"
python3 -c "
import json, issuer.app as i
priv, pub = i.load_keys()
bundle = i.build_bundle('SHOP-A', priv, pub)
open('verifier/trustbundle.json','w').write(json.dumps(bundle, indent=2))
print('paired signed trustbundle v%s offline' % bundle['v'])
"
echo "Start: PORT=5001 python3 -m issuer.app & PORT=5002 python3 -m verifier.app"
