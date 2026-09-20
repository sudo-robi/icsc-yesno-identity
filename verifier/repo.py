"""Verifier repository: SQLite access. Explicit paths, parameterized SQL only."""
import json
import logging
import sqlite3

log = logging.getLogger("verifier.repo")


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with dict-like rows (generous busy timeout for
    concurrent writers; writers still serialize via IMMEDIATE transactions)."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create tables (idempotent)."""
    conn = connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS nonces
                    (nonce TEXT PRIMARY KEY, vid TEXT, issued_at INT, exp INT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS receipts
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INT, verifier_id TEXT,
                     q TEXT, result TEXT, reason TEXT,
                     prev_hash TEXT, entry_hash TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS otp_used
                    (sub TEXT, step INT, ts INT, PRIMARY KEY (sub, step))""")
    conn.commit()
    conn.close()


def kv_get(db_path: str, key: str) -> str | None:
    conn = connect(db_path)
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    conn.close()
    return row["v"] if row else None


def kv_set(db_path: str, key: str, value: str) -> None:
    conn = connect(db_path)
    conn.execute("INSERT INTO kv(k,v) VALUES (?,?) "
                 "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    conn.commit()
    conn.close()


def get_bundle(db_path: str) -> dict | None:
    """Pinned trust bundle, or None before pairing."""
    raw = kv_get(db_path, "bundle")
    return json.loads(raw) if raw else None


def save_bundle(db_path: str, bundle: dict) -> None:
    kv_set(db_path, "bundle", json.dumps(bundle))


def add_nonce(db_path: str, nonce: str, vid: str, issued_at: int, exp: int) -> None:
    conn = connect(db_path)
    conn.execute("INSERT OR REPLACE INTO nonces VALUES (?,?,?,?)",
                 (nonce, vid, issued_at, exp))
    conn.commit()
    conn.close()


def consume_nonce(db_path: str, nonce: str, min_issued_at: int, now_ts: int) -> dict | None:
    """Atomically take a fresh nonce (single-use even under concurrency).

    Returns the row, or None when unknown/expired/already spent — exactly one
    concurrent claimant wins the DELETE.
    """
    conn = connect(db_path)
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("DELETE FROM nonces WHERE nonce=? AND issued_at>? AND exp>? "
                           "RETURNING nonce, vid, issued_at, exp",
                           (nonce, min_issued_at, now_ts)).fetchone()
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return dict(row) if row else None


def prune_nonces(db_path: str, min_issued_at: int) -> None:
    conn = connect(db_path)
    conn.execute("DELETE FROM nonces WHERE issued_at<=?", (min_issued_at,))
    conn.commit()
    conn.close()


def append_receipt(db_path: str, *, ts: int, verifier_id: str, q: str,
                   result: str, reason: str, entry_hash_of) -> str:
    """Append one receipt in a single IMMEDIATE transaction (no forks)."""
    conn = connect(db_path)
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        prev = conn.execute(
            "SELECT entry_hash FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev["entry_hash"] if prev else "GENESIS"
        entry_hash = entry_hash_of(prev_hash)
        conn.execute("INSERT INTO receipts "
                     "(ts,verifier_id,q,result,reason,prev_hash,entry_hash)"
                     " VALUES (?,?,?,?,?,?,?)",
                     (ts, verifier_id, q, result, reason, prev_hash, entry_hash))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return entry_hash


def list_receipts(db_path: str, limit: int = 100) -> list[dict]:
    """Newest-first receipts."""
    conn = connect(db_path)
    rows = conn.execute("SELECT * FROM receipts ORDER BY id DESC LIMIT ?",
                        (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def all_receipts(db_path: str) -> list[dict]:
    """Oldest-first full log for export/audit."""
    conn = connect(db_path)
    rows = conn.execute("SELECT * FROM receipts ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def is_code_used(db_path: str, sub: str, step: int) -> bool:
    conn = connect(db_path)
    hit = conn.execute("SELECT 1 FROM otp_used WHERE sub=? AND step=?",
                       (sub, step)).fetchone()
    conn.close()
    return hit is not None


def mark_code_used(db_path: str, sub: str, step: int, ts: int) -> None:
    conn = connect(db_path)
    conn.execute("INSERT OR IGNORE INTO otp_used VALUES (?,?,?)", (sub, step, ts))
    conn.commit()
    conn.close()


def prune_codes(db_path: str, min_step: int) -> None:
    conn = connect(db_path)
    conn.execute("DELETE FROM otp_used WHERE step < ?", (min_step,))
    conn.commit()
    conn.close()
