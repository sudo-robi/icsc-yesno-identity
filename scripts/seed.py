#!/usr/bin/env python3
"""Seed the issuer database with synthetic users (no real PII, ever).

Usage: python scripts/seed.py [--db issuer/issuer.db]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import issuer.repo as repo


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed synthetic issuer users.")
    parser.add_argument("--db", default=os.environ.get("ISSUER_DB", "issuer/issuer.db"))
    args = parser.parse_args()
    repo.init_db(args.db)
    inserted = repo.seed_users(args.db)
    print(f"seeded {inserted} synthetic users into {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
