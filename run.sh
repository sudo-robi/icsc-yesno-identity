#!/bin/bash
# Offline fallback: airplane-mode demo. No internet needed after pip install.
set -e
cd "$(dirname "$0")"
python3 -c "import issuer.app as a; a.init_db(); a.load_keys()"
python3 -c "import verifier.app as a; a.init_db()"
python3 -c "
import json, issuer.app as i
i.DB='issuer/issuer.db'
_, pub = i.load_keys()
import sqlite3
tb={'iss':'NIMC-TEST-01','pubkey_hex':pub,'v':1,'revoked_uids':[],'otp_secrets':{}}
open('verifier/trustbundle.json','w').write(json.dumps(tb,indent=2))
print('paired trustbundle v1 offline')
"
echo "Start: PORT=5001 python3 -m issuer.app & PORT=5002 python3 -m verifier.app"
