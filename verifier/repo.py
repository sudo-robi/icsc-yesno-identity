"""Verifier repository: SQLite access for receipts + OTP replay memory.

Callers pass an explicit db path, so service code is testable without Flask
and without touching module globals.
"""
import logging
import sqlite3

log = logging.getLogger("verifier.repo")


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with dict-like rows."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create tables (idempotent). Migrates the legacy single-column used_codes
    schema: replay memory only ever matters inside the 60s OTP window, so
    dropping it on upgrade is harmless (documented)."""
    conn = connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS receipts
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INT, verifier_id TEXT,
                     q TEXT, result TEXT, nonce_hash TEXT, sig_hash TEXT,
                     prev_hash TEXT, entry_hash TEXT)""")
    old = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='used_codes'").fetchone()
    if old and "step" not in (old["sql"] or ""):
        conn.execute("DROP TABLE used_codes")
    conn.execute("""CREATE TABLE IF NOT EXISTS used_codes
                    (code TEXT, step INT, ts INT, PRIMARY KEY (code, step))""")
    conn.commit()
    conn.close()


def append_receipt(db_path: str, *, ts: int, verifier_id: str, q: str,
                   result: str, nonce_hash: str, sig_hash: str,
                   entry_hash_of) -> str:
    """Append one receipt in a single IMMEDIATE transaction so concurrent
    writers serialize on the chain head instead of forking it.

    ``entry_hash_of(prev_hash)`` builds the link hash; kept injectable so the
    HMAC key handling stays in the service layer.
    """
    conn = connect(db_path)
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        prev = conn.execute(
            "SELECT entry_hash FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev["entry_hash"] if prev else "GENESIS"
        entry_hash = entry_hash_of(prev_hash)
        conn.execute("INSERT INTO receipts "
                     "(ts,verifier_id,q,result,nonce_hash,sig_hash,prev_hash,entry_hash)"
                     " VALUES (?,?,?,?,?,?,?,?)",
                     (ts, verifier_id, q, result, nonce_hash, sig_hash,
                      prev_hash, entry_hash))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return entry_hash


def list_receipts(db_path: str, limit: int = 100) -> list[dict]:
    """Newest-first receipts for the shop UI / auditor."""
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT * FROM receipts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def all_receipts(db_path: str) -> list[dict]:
    """Oldest-first full log for CSV export / chain audit."""
    conn = connect(db_path)
    rows = conn.execute("SELECT * FROM receipts ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def verify_chain(rows: list[dict], entry_hash_of) -> bool:
    """Recompute every link from stored fields. Any edit breaks the chain."""
    prev = "GENESIS"
    for row in rows:
        if row["prev_hash"] != prev:
            return False
        if row["entry_hash"] != entry_hash_of(row):
            return False
        prev = row["entry_hash"]
    return True


def is_code_used(db_path: str, code: str, step: int) -> bool:
    """Was this code value already spent *in this step*? A value recurring in a
    later 30s window is a different code instance and starts fresh."""
    conn = connect(db_path)
    hit = conn.execute("SELECT 1 FROM used_codes WHERE code=? AND step=?",
                       (code, step)).fetchone()
    conn.close()
    return hit is not None


def mark_code_used(db_path: str, code: str, step: int, ts: int) -> None:
    conn = connect(db_path)
    conn.execute("INSERT OR IGNORE INTO used_codes VALUES (?,?,?)",
                 (code, step, ts))
    conn.commit()
    conn.close()


def prune_codes(db_path: str, min_step: int) -> None:
    """Drop replay memory outside the grace window (keeps the table tiny)."""
    conn = connect(db_path)
    conn.execute("DELETE FROM used_codes WHERE step < ?", (min_step,))
    conn.commit()
    conn.close()
