#!/usr/bin/env python3
"""Verify a verifier receipt log: chain links + Ed25519 head signature.

Usage: python scripts/verify_receipts.py --db verifier/receipts.db
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import verifier.repo as repo
import verifier.services as services
from shared.canonical import canonical
from shared.crypto import ed25519_verify


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a receipt database.")
    parser.add_argument("--db", default=os.environ.get("VERIFIER_DB", "verifier/receipts.db"))
    args = parser.parse_args()

    rows = repo.all_receipts(args.db)
    print(f"{len(rows)} receipts")
    if not rows:
        print("EMPTY chain (valid, nothing to check)")
        return 0
    key = services.load_receipt_key(args.db)
    prev = "GENESIS"
    for row in rows:
        if row["prev_hash"] != prev:
            print(f"FORK/BREAK at id {row['id']}: prev link mismatch")
            return 1
        expect = services.chain_entry(
            row["prev_hash"], row["ts"], row["verifier_id"], row["q"],
            row["result"], row["reason"], key)
        if expect != row["entry_hash"]:
            print(f"TAMPER at id {row['id']}: entry hash mismatch")
            return 1
        prev = row["entry_hash"]
    head, ts = rows[-1]["entry_hash"], rows[-1]["ts"]
    sig = services.sign_head(key, head, ts)
    pub = services.receipt_pub(args.db)
    if not ed25519_verify(pub, sig, canonical({"head": head, "ts": ts})):
        print("HEAD-SIGNATURE INVALID")
        return 1
    print(f"chain OK, head {head[:16]}… signed by {pub[:16]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
