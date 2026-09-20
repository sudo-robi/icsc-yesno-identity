// Vercel Postgres client for Issuer database
// Tables: users, enrollment_codes, keys, bundle_versions, audit

import { sql } from '@vercel/postgres';
import type { Ed25519Keypair } from './crypto.js';

export interface User {
  id: string;
  full_name: string;
  dob: string;          // ISO date YYYY-MM-DD
  revoked: boolean;
  master_secret: string; // 32-char hex
}

export interface EnrollmentCode {
  code_hash: string;     // SHA-256 hex
  user_id: string;
  used_at: number | null;
  expires_at: number;
}

export interface KeyRow {
  id: number;
  priv: string;          // 64-char hex
  pub: string;           // 64-char hex
  created_at: number;
  active: boolean;
}

export interface BundleVersion {
  v: number;
  at: number;
}

export interface AuditEntry {
  id: number;
  ts: number;
  actor: string;
  action: string;
  detail: string;
}

// ============================================================================
// Initialization
// ============================================================================

export async function initDb(): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      full_name TEXT,
      dob TEXT,
      revoked INT DEFAULT 0,
      master_secret TEXT
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS enrollment_codes (
      code_hash TEXT PRIMARY KEY,
      user_id TEXT,
      used_at INT,
      expires_at INT
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS keys (
      id SERIAL PRIMARY KEY,
      priv TEXT,
      pub TEXT,
      created_at INT,
      active INT DEFAULT 0
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS bundle_versions (
      v INT PRIMARY KEY,
      at INT
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS audit (
      id SERIAL PRIMARY KEY,
      ts INT,
      actor TEXT,
      action TEXT,
      detail TEXT
    );
  `;
  
  // Ensure bundle_versions has at least v=1
  const versions = await sql`SELECT MAX(v) as max_v FROM bundle_versions`;
  if (!versions.rows[0]?.max_v) {
    await sql`INSERT INTO bundle_versions (v, at) VALUES (1, ${Date.now()})`;
  }
}

// ============================================================================
// Users
// ============================================================================

export async function getUser(userId: string): Promise<User | null> {
  const result = await sql`SELECT * FROM users WHERE id = ${userId}`;
  if (result.rows.length === 0) return null;
  return result.rows[0] as User;
}

export async function listUsers(): Promise<Pick<User, 'id' | 'revoked'>[]> {
  const result = await sql`SELECT id, revoked FROM users ORDER BY id`;
  return result.rows as Pick<User, 'id' | 'revoked'>[];
}

export async function allUserStatus(): Promise<User[]> {
  const result = await sql`SELECT id, dob, revoked, master_secret FROM users ORDER BY id`;
  return result.rows as User[];
}

export async function setRevoked(userId: string): Promise<void> {
  await sql`UPDATE users SET revoked = 1 WHERE id = ${userId}`;
}

export async function seedUsers(): Promise<number> {
  const SEED_USERS: Array<{ id: string; full_name: string; dob: string; revoked: number }> = [
    { id: 'U001', full_name: 'Ada Test (adult)', dob: '2000-05-12', revoked: 0 },
    { id: 'U002', full_name: 'Bola Test (minor)', dob: '2010-03-01', revoked: 0 },
    { id: 'U003', full_name: 'Revoked Test', dob: '1999-01-01', revoked: 1 },
    { id: 'U004', full_name: 'Leap Test (2008-02-29)', dob: '2008-02-29', revoked: 0 }
  ];
  
  let inserted = 0;
  for (const u of SEED_USERS) {
    const existing = await getUser(u.id);
    if (!existing) {
      const { ed25519Keypair } = await import('./crypto.js');
      const masterSecret = ed25519Keypair().priv; // reuse as random 32-byte hex
      await sql`
        INSERT INTO users (id, full_name, dob, revoked, master_secret)
        VALUES (${u.id}, ${u.full_name}, ${u.dob}, ${u.revoked}, ${masterSecret})
      `;
      inserted++;
    }
  }
  
  if (inserted > 0) {
    await sql`INSERT INTO bundle_versions (v, at) VALUES (1, ${Date.now()})`;
  }
  
  return inserted;
}

// ============================================================================
// Enrollment Codes
// ============================================================================

export async function createEnrollmentCode(
  userId: string, 
  ttlSec: number
): Promise<{ code: string; codeHash: string }> {
  const { ed25519Keypair } = await import('./crypto.js');
  const { sha256Hex } = await import('./crypto.js');
  
  // Generate random code
  const code = crypto.randomUUID().replace(/-/g, '').slice(0, 32);
  const codeHash = await sha256Hex(new TextEncoder().encode(code));
  
  const now = Math.floor(Date.now() / 1000);
  await sql`
    INSERT INTO enrollment_codes (code_hash, user_id, used_at, expires_at)
    VALUES (${codeHash}, ${userId}, NULL, ${now + ttlSec})
  `;
  
  return { code, codeHash };
}

export interface ConsumeCodeResult {
  ok: boolean;
  user_id?: string;
  reason?: string;
}

export async function consumeEnrollmentCode(code: string): Promise<ConsumeCodeResult> {
  const { sha256Hex } = await import('./crypto.js');
  const codeHash = await sha256Hex(new TextEncoder().encode(code));
  const now = Math.floor(Date.now() / 1000);
  
  // Atomic check-and-update using single query with WHERE clause
  const result = await sql`
    UPDATE enrollment_codes 
    SET used_at = ${now}
    WHERE code_hash = ${codeHash}
      AND used_at IS NULL
      AND expires_at > ${now}
    RETURNING user_id
  `;
  
  if (result.rowCount === 0) {
    // Check why it failed
    const check = await sql`
      SELECT * FROM enrollment_codes WHERE code_hash = ${codeHash}
    `;
    if (check.rows.length === 0) {
      return { ok: false, reason: 'UNKNOWN_CODE' };
    }
    const row = check.rows[0] as EnrollmentCode;
    if (row.used_at !== null) return { ok: false, reason: 'CODE_USED' };
    if (row.expires_at <= now) return { ok: false, reason: 'CODE_EXPIRED' };
    return { ok: false, reason: 'UNKNOWN_CODE' };
  }
  
  return { ok: true, user_id: result.rows[0].user_id as string };
}

// ============================================================================
// Keys (Ed25519 signing keys)
// ============================================================================

export async function getActiveKey(): Promise<KeyRow | null> {
  const result = await sql`
    SELECT * FROM keys WHERE active = 1 ORDER BY id DESC LIMIT 1
  `;
  if (result.rows.length === 0) return null;
  return result.rows[0] as KeyRow;
}

export async function getStagedKey(): Promise<KeyRow | null> {
  const active = await sql`SELECT id FROM keys WHERE active = 1 ORDER BY id DESC LIMIT 1`;
  const activeId = active.rows[0]?.id ?? 0;
  
  const result = await sql`
    SELECT * FROM keys WHERE active = 0 AND id > ${activeId} ORDER BY id DESC LIMIT 1
  `;
  if (result.rows.length === 0) return null;
  return result.rows[0] as KeyRow;
}

export async function storeKey(privHex: string, pubHex: string, active: boolean): Promise<number> {
  const result = await sql`
    INSERT INTO keys (priv, pub, created_at, active)
    VALUES (${privHex}, ${pubHex}, ${Math.floor(Date.now() / 1000)}, ${active ? 1 : 0})
    RETURNING id
  `;
  return result.rows[0].id as number;
}

export async function deactivateAllKeys(): Promise<void> {
  await sql`UPDATE keys SET active = 0`;
}

export async function activateKey(pubHex: string): Promise<boolean> {
  const result = await sql`
    UPDATE keys SET active = 1 WHERE pub = ${pubHex}
  `;
  if (result.rowCount === 0) return false;
  
  await sql`UPDATE keys SET active = 0 WHERE pub != ${pubHex}`;
  return true;
}

export async function ensureActiveKey(): Promise<KeyRow> {
  let key = await getActiveKey();
  if (!key) {
    const { ed25519Keypair } = await import('./crypto.js');
    const kp = ed25519Keypair();
    await storeKey(kp.priv, kp.pub, true);
    key = { id: 1, priv: kp.priv, pub: kp.pub, created_at: Math.floor(Date.now() / 1000), active: true };
  }
  return key;
}

export async function bumpBundleVersion(): Promise<number> {
  const result = await sql`
    INSERT INTO bundle_versions (v, at)
    SELECT COALESCE(MAX(v), 0) + 1, ${Math.floor(Date.now() / 1000)} FROM bundle_versions
    RETURNING v
  `;
  return result.rows[0].v as number;
}

export async function getBundleVersion(): Promise<number> {
  const result = await sql`SELECT MAX(v) as v FROM bundle_versions`;
  return result.rows[0]?.v as number ?? 1;
}

// ============================================================================
// Audit
// ============================================================================

export async function audit(
  actor: string, 
  action: string, 
  detail: string = ''
): Promise<void> {
  await sql`
    INSERT INTO audit (ts, actor, action, detail)
    VALUES (${Math.floor(Date.now() / 1000)}, ${actor}, ${action}, ${detail})
  `;
}

// ============================================================================
// Bundle building (used by issuer)
// ============================================================================

import { ed25519Sign, pseudonym as pseudonymFn } from './crypto.js';
import { canonical, bundleSignedBody } from './canonical.js';

export async function buildBundle(options: {
  verifierId: string;
  users: User[];
  revVersion: number;
  issuedAt: number;
  ttlSec: number;
  issuerId: string;
  privHex: string;
  pubHex: string;
  nextPub: string | null;
}): Promise<any> {
  const { verifierId, users, revVersion, issuedAt, ttlSec, issuerId, privHex, pubHex, nextPub } = options;
  
  const revoked: string[] = [];
  const minors: string[] = [];
  
  for (const u of users) {
    const sub = pseudonymFn(u.master_secret, verifierId);
    if (u.revoked) {
      revoked.push(sub);
    } else if (!isAdult(u.dob)) {
      minors.push(sub);
    }
  }
  
  revoked.sort();
  minors.sort();
  
  const body: Record<string, unknown> = {
    v: revVersion,
    iss: issuerId,
    vid: verifierId,
    pub: pubHex,
    next_pub: nextPub,
    revoked,
    minors,
    iat: issuedAt,
    exp: issuedAt + ttlSec
  };
  
  const bodyCanonical = canonical(body);
  const bodyBytes = new TextEncoder().encode(bodyCanonical);
  const s = ed25519Sign(privHex, bodyBytes);
  
  return { ...body, s };
}

export function isAdult(dob: string): boolean {
  const [year, month, day] = dob.split('-').map(Number);
  const dobDate = new Date(year, month - 1, day);
  const today = new Date();
  
  let age = today.getFullYear() - dobDate.getFullYear();
  const monthDiff = today.getMonth() - dobDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dobDate.getDate())) {
    age--;
  }
  
  return age >= 18;
}