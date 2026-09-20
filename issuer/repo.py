"""Issuer repository: SQLite access. Explicit paths, parameterized SQL only."""
import hashlib
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
    ("U004", "Leap Test (2008-02-29)", "2008-02-29", 0),
]


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with dict-like rows (generous busy timeout for
    concurrent writers; writers still serialize via IMMEDIATE transactions)."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: str) -> None:
    """Create tables (idempotent)."""
    conn = connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                    (id TEXT PRIMARY KEY, full_name TEXT, dob TEXT,
                     revoked INT DEFAULT 0, master_secret TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS enrollment_codes
                    (code_hash TEXT PRIMARY KEY, user_id TEXT,
                     used_at INT, expires_at INT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS keys
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, priv TEXT, pub TEXT,
                     created_at INT, active INT DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS bundle_versions
                    (v INT PRIMARY KEY, at INT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INT,
                     actor TEXT, action TEXT, detail TEXT)""")
    conn.commit()
    conn.close()


def seed_users(db_path: str) -> int:
    """Insert synthetic users once. Returns number inserted."""
    conn = connect(db_path)
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] > 0:
        conn.close()
        return 0
    for uid, name, dob, revoked in SEED_USERS:
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                     (uid, name, dob, revoked, secrets.token_hex(16)))
    conn.execute("INSERT INTO bundle_versions VALUES (1,?)", (int(time.time()),))
    conn.commit()
    conn.close()
    log.info("seeded synthetic users (no real PII)")
    return len(SEED_USERS)


def get_user(db_path: str, user_id: str) -> dict | None:
    """Fetch one user as a plain dict, or None."""
    conn = connect(db_path)
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users(db_path: str) -> list[dict]:
    """All users with status (no bulk secrets)."""
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


def bundle_version(db_path: str) -> int:
    conn = connect(db_path)
    row = conn.execute("SELECT MAX(v) m FROM bundle_versions").fetchone()
    conn.close()
    return row["m"] or 1


def bump_bundle_version(db_path: str) -> int:
    conn = connect(db_path)
    version = (conn.execute("SELECT MAX(v) m FROM bundle_versions").fetchone()["m"] or 0) + 1
    conn.execute("INSERT INTO bundle_versions VALUES (?,?)", (version, int(time.time())))
    conn.commit()
    conn.close()
    return version


def create_enrollment_code(db_path: str, user_id: str, ttl_sec: int) -> str:
    """Create a single-use code; return it ONCE (only the hash is stored)."""
    code = secrets.token_urlsafe(24)
    digest = hashlib.sha256(code.encode()).hexdigest()
    now = int(time.time())
    conn = connect(db_path)
    conn.execute("INSERT INTO enrollment_codes VALUES (?,?,?,?)",
                 (digest, user_id, None, now + ttl_sec))
    conn.commit()
    conn.close()
    return code


def consume_enrollment_code(db_path: str, code: str) -> dict:
    """Atomically redeem a code. Returns {ok, user_id} or {ok:False, reason}."""
    digest = hashlib.sha256(code.encode()).hexdigest()
    now = int(time.time())
    conn = connect(db_path)
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT * FROM enrollment_codes WHERE code_hash=?",
                           (digest,)).fetchone()
        if row is None:
            result: dict = {"ok": False, "reason": "UNKNOWN_CODE"}
        elif row["used_at"] is not None:
            result = {"ok": False, "reason": "CODE_USED"}
        elif row["expires_at"] < now:
            result = {"ok": False, "reason": "CODE_EXPIRED"}
        else:
            conn.execute("UPDATE enrollment_codes SET used_at=? WHERE code_hash=?",
                         (now, digest))
            result = {"ok": True, "user_id": row["user_id"]}
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return result


def active_key(db_path: str) -> dict | None:
    """The signing key (at most one active)."""
    conn = connect(db_path)
    row = conn.execute("SELECT * FROM keys WHERE active=1 ORDER BY id DESC LIMIT 1"
                       ).fetchone()
    conn.close()
    return dict(row) if row else None


def staged_key(db_path: str) -> dict | None:
    """The staged rotation key: an inactive key NEWER than the active one.

    After activation the previous key drops back to plain inactive history and
    is no longer "staged", so a second activate correctly reports nothing staged.
    """
    conn = connect(db_path)
    active = conn.execute("SELECT id FROM keys WHERE active=1 ORDER BY id DESC LIMIT 1"
                          ).fetchone()
    active_id = active["id"] if active else 0
    row = conn.execute("SELECT * FROM keys WHERE active=0 AND id>? "
                       "ORDER BY id DESC LIMIT 1", (active_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def store_key(db_path: str, priv_hex: str, pub_hex: str, active: bool) -> int:
    """Persist a keypair; returns its row id."""
    conn = connect(db_path)
    cur = conn.execute("INSERT INTO keys(priv,pub,created_at,active) VALUES (?,?,?,?)",
                       (priv_hex, pub_hex, int(time.time()), 1 if active else 0))
    rowid = cur.lastrowid or 0
    conn.commit()
    conn.close()
    return rowid


def deactivate_all_keys(db_path: str) -> None:
    conn = connect(db_path)
    conn.execute("UPDATE keys SET active=0")
    conn.commit()
    conn.close()


def activate_key(db_path: str, pub_hex: str) -> bool:
    """Make the key with this pub the active signer. Returns False if unknown."""
    conn = connect(db_path)
    cur = conn.execute("UPDATE keys SET active=1 WHERE pub=?", (pub_hex,))
    hit = cur.rowcount > 0
    if hit:
        conn.execute("UPDATE keys SET active=0 WHERE pub!=?", (pub_hex,))
    conn.commit()
    conn.close()
    return hit


def audit(db_path: str, actor: str, action: str, detail: str = "") -> None:
    """Append-only operator audit (no PII in detail)."""
    conn = connect(db_path)
    conn.execute("INSERT INTO audit(ts,actor,action,detail) VALUES (?,?,?,?)",
                 (int(time.time()), actor, action, detail))
    conn.commit()
    conn.close()
