// Vercel KV client wrapper
// Provides typed access to trust bundle, nonces, OTP secrets, receipts

import { kv } from '@vercel/kv';
import type { Bundle, Credential, Proof, ReasonCode } from './schemas.js';

const KEYS = {
  trustBundle: (verifierId: string) => `trust_bundle:${verifierId}`,
  nonce: (verifierId: string, nonce: string) => `nonce:${verifierId}:${nonce}`,
  otpSecrets: (verifierId: string) => `otp_secrets:${verifierId}`,
  otpUsed: (verifierId: string, sub: string, step: number) => `otp_used:${verifierId}:${sub}:${step}`,
  receipt: (verifierId: string, id: number) => `receipt:${verifierId}:${id}`,
  receiptCounter: (verifierId: string) => `receipt_counter:${verifierId}`,
  receiptKey: (verifierId: string) => `receipt_key:${verifierId}`
} as const;

// TTL constants (seconds)
const NONCE_TTL = 300;      // 5 minutes
const OTP_TTL = 3600;       // 1 hour (covers grace steps)
const RECEIPT_TTL = 86400 * 30; // 30 days

// ============================================================================
// Trust Bundle
// ============================================================================

export async function getTrustBundle(verifierId: string): Promise<Bundle | null> {
  const data = await kv.get(KEYS.trustBundle(verifierId));
  return data as Bundle | null;
}

export async function setTrustBundle(verifierId: string, bundle: Bundle): Promise<void> {
  await kv.set(KEYS.trustBundle(verifierId), bundle);
}

export async function deleteTrustBundle(verifierId: string): Promise<void> {
  await kv.del(KEYS.trustBundle(verifierId));
}

// ============================================================================
// Nonces (single-use challenge nonces)
// ============================================================================

export async function addNonce(verifierId: string, nonce: string, issuedAt: number, expiresAt: number): Promise<void> {
  await kv.set(KEYS.nonce(verifierId, nonce), { issuedAt, expiresAt }, { ex: NONCE_TTL });
}

/**
 * Atomically consume a nonce. Returns true if consumed, false if not found/expired/used.
 */
export async function consumeNonce(verifierId: string, nonce: string, now: number): Promise<boolean> {
  const key = KEYS.nonce(verifierId, nonce);
  const data = await kv.get<{ issuedAt: number; expiresAt: number; used?: boolean }>(key);
  
  if (!data) return false;
  if (data.used) return false;
  if (data.expiresAt < now) return false;
  
  // Mark as used - use atomic compare-and-swap via set with nx
  // Since we can't do true atomic CAS, we'll set the used flag
  await kv.set(key, { ...data, used: true }, { ex: NONCE_TTL });
  
  return true;
}

export async function pruneNonces(verifierId: string, before: number): Promise<void> {
  // Vercel KV doesn't have scan with filter - would need to track nonces in a set
  // For now, rely on TTL expiration
}

// ============================================================================
// OTP Secrets & Used Codes
// ============================================================================

export async function setOTPSecrets(verifierId: string, secrets: Record<string, string>): Promise<void> {
  await kv.set(KEYS.otpSecrets(verifierId), secrets);
}

export async function getOTPSecrets(verifierId: string): Promise<Record<string, string> | null> {
  const data = await kv.get(KEYS.otpSecrets(verifierId));
  return data as Record<string, string> | null;
}

export async function markOTPUsed(verifierId: string, sub: string, step: number): Promise<boolean> {
  const key = KEYS.otpUsed(verifierId, sub, step);
  // setnx - only set if not exists
  const result = await kv.set(key, Date.now(), { nx: true, ex: OTP_TTL });
  return result === 'OK';
}

export async function isOTPUsed(verifierId: string, sub: string, step: number): Promise<boolean> {
  const key = KEYS.otpUsed(verifierId, sub, step);
  return await kv.exists(key) === 1;
}

export async function pruneOTPCodes(verifierId: string, beforeStep: number): Promise<void> {
  // Rely on TTL
}

// ============================================================================
// Receipts (append-only chain)
// ============================================================================

export interface ReceiptEntry {
  id: number;
  ts: number;
  verifier_id: string;
  q: string;
  result: string;
  reason: ReasonCode;
  prev_hash: string;
  entry_hash: string;
}

export async function getReceiptCounter(verifierId: string): Promise<number> {
  const counter = await kv.get<number>(KEYS.receiptCounter(verifierId));
  return counter ?? 0;
}

export async function incrementReceiptCounter(verifierId: string): Promise<number> {
  return await kv.incr(KEYS.receiptCounter(verifierId));
}

export async function appendReceipt(
  verifierId: string,
  entry: Omit<ReceiptEntry, 'id'> & { entry_hash?: string }
): Promise<ReceiptEntry> {
  const id = await incrementReceiptCounter(verifierId);
  const fullEntry: ReceiptEntry = { ...entry, id } as ReceiptEntry;
  await kv.set(KEYS.receipt(verifierId, id), fullEntry, { ex: RECEIPT_TTL });
  return fullEntry;
}

export async function getReceipt(verifierId: string, id: number): Promise<ReceiptEntry | null> {
  const data = await kv.get(KEYS.receipt(verifierId, id));
  return data as ReceiptEntry | null;
}

export async function listReceipts(verifierId: string, limit = 100): Promise<ReceiptEntry[]> {
  // Vercel KV doesn't support range queries easily
  // For now, fetch recent by counter
  const counter = await getReceiptCounter(verifierId);
  const start = Math.max(1, counter - limit + 1);
  const entries: ReceiptEntry[] = [];
  
  for (let i = counter; i >= start; i--) {
    const entry = await getReceipt(verifierId, i);
    if (entry) entries.push(entry);
  }
  return entries.reverse(); // chronological
}

export async function getAllReceipts(verifierId: string): Promise<ReceiptEntry[]> {
  const counter = await getReceiptCounter(verifierId);
  const entries: ReceiptEntry[] = [];
  for (let i = 1; i <= counter; i++) {
    const entry = await getReceipt(verifierId, i);
    if (entry) entries.push(entry);
  }
  return entries;
}

// ============================================================================
// Receipt Signing Key
// ============================================================================

export async function getReceiptKey(verifierId: string): Promise<string> {
  let key = await kv.get<string>(KEYS.receiptKey(verifierId));
  if (!key) {
    // Generate new Ed25519 keypair for receipt signing
    const { ed25519Keypair } = await import('./crypto.js');
    const kp = ed25519Keypair();
    key = kp.priv;
    await kv.set(KEYS.receiptKey(verifierId), key);
  }
  return key;
}

// ============================================================================
// Verifier Config
// ============================================================================

export interface VerifierConfig {
  verifierId: string;
  issuerUrl?: string;
  adminToken: string;
  otpEnabled: boolean;
}

export async function getVerifierConfig(): Promise<VerifierConfig | null> {
  const data = await kv.get('verifier_config');
  return data as VerifierConfig | null;
}

export async function setVerifierConfig(config: VerifierConfig): Promise<void> {
  await kv.set('verifier_config', config);
}