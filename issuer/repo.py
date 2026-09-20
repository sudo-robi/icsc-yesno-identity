"""Issuer repository: all SQLite access. Pure data mapping, no business logic.

Callers pass an explicit db path, so service code is testable without Flask
and without touching module globals.
"""
import logging
import secrets
import sqlite3
import time

log = logging.getLogger("issuer.repo")

SEED_USERS: list[tuple[str, str, str, int]] = [
    # (id, full_name, dob, revoked) — synthetic seed data, never real PII.
    ("U001", "Ada Test (adult)", "2000-05-12", 0),
    ("U002", "Bola Test (minor)", "2010-03-01", 0),
    ("U003", "Revoked Test", "1999-01-01", 1),
]


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with dict-like rows."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create tables + seed synthetic users (idempotent)."""
    conn = connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                    (id TEXT PRIMARY KEY, full_name TEXT, dob TEXT,
                     revoked INT DEFAULT 0, master_secret TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS revlist
                    (v INT PRIMARY KEY, atTs INT)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        for uid, name, dob, revoked in SEED_USERS:
            conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                         (uid, name, dob, revoked, secrets.token_hex(16)))
        log.info("seeded synthetic users (no real PII)")
    if conn.execute("SELECT COUNT(*) c FROM revlist").fetchone()["c"] == 0:
        conn.execute("INSERT INTO revlist VALUES (1,?)", (int(time.time()),))
    conn.commit()
    conn.close()


def get_user(db_path: str, user_id: str) -> dict | None:
    """Fetch one user as a plain dict, or None."""
    conn = connect(db_path)
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users(db_path: str) -> list[dict]:
    """All users (id/dob/revoked) for the operator dashboard."""
    conn = connect(db_path)
    rows = conn.execute("SELECT id, dob, revoked FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def all_user_status(db_path: str) -> list[dict]:
    """Full status rows for bundle building (id/dob/revoked/master_secret)."""
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT id, dob, revoked, master_secret FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_revoked(db_path: str, user_id: str) -> None:
    conn = connect(db_path)
    conn.execute("UPDATE users SET revoked=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()


def revlist_version(db_path: str) -> int:
    conn = connect(db_path)
    row = conn.execute("SELECT * FROM revlist ORDER BY v DESC LIMIT 1").fetchone()
    conn.close()
    return row["v"]


def bump_revlist(db_path: str) -> int:
    """Append a new revocation-list version; return it."""
    conn = connect(db_path)
    version = conn.execute("SELECT MAX(v) m FROM revlist").fetchone()["m"] + 1
    conn.execute("INSERT INTO revlist VALUES (?,?)", (version, int(time.time())))
    conn.commit()
    conn.close()
    return version


def revoked_user_ids(db_path: str) -> list[str]:
    conn = connect(db_path)
    rows = conn.execute("SELECT id FROM users WHERE revoked=1").fetchall()
    conn.close()
    return [r["id"] for r in rows]
