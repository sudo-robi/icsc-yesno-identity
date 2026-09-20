// Crypto utilities - port of shared/crypto.py using @noble libraries
// Ed25519 for issuer/receipts, P-256 for holder proofs, HMAC for pseudonyms/OTP
// Base64url everywhere, no padding

import * as ed25519 from '@noble/ed25519';
import { p256 } from '@noble/curves/p256';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// DER encoding for ECDSA signatures (RFC 3279)
function encodeDssSignature(r: bigint, s: bigint): Uint8Array {
  const rBytes = bigIntToBytes(r);
  const sBytes = bigIntToBytes(s);
  
  // Remove leading zeros
  const rTrimmed = rBytes[rBytes[0] === 0 ? 1 : 0] ? rBytes.slice(rBytes.findIndex(b => b !== 0)) : rBytes;
  const sTrimmed = sBytes[sBytes[0] === 0 ? 1 : 0] ? sBytes.slice(sBytes.findIndex(b => b !== 0)) : sBytes;
  
  // Add 0x00 if high bit set (to ensure positive integer)
  const rFinal = rTrimmed[0] >= 0x80 ? new Uint8Array([0, ...rTrimmed]) : rTrimmed;
  const sFinal = sTrimmed[0] >= 0x80 ? new Uint8Array([0, ...sTrimmed]) : sTrimmed;
  
  // Build DER sequence
  const rLen = rFinal.length;
  const sLen = sFinal.length;
  const totalLen = 2 + rLen + 2 + sLen;
  
  const der = new Uint8Array(2 + totalLen);
  der[0] = 0x30; // SEQUENCE
  der[1] = totalLen;
  der[2] = 0x02; // INTEGER
  der[3] = rLen;
  der.set(rFinal, 4);
  der[4 + rLen] = 0x02; // INTEGER
  der[5 + rLen] = sLen;
  der.set(sFinal, 6 + rLen);
  
  return der;
}

// ============================================================================
// Base64url encoding
// ============================================================================

export function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function b64uDecode(text: string): Uint8Array {
  if (typeof text !== 'string') {
    throw new TypeError('b64u input must be string');
  }
  const pad = '='.repeat((4 - (text.length % 4)) % 4);
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// ============================================================================
// Hashing
// ============================================================================

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(bytes));
}

// ============================================================================
// Key fingerprint (operator-facing)
// ============================================================================

export function keyFingerprint(pubHex: string): string {
  const raw = pubHex.slice(0, 16);
  return raw.match(/.{1,4}/g)?.join(' ') ?? raw;
}

// ============================================================================
// Ed25519 (Issuer signing + Receipts)
// ============================================================================

export interface Ed25519Keypair {
  priv: string;  // 64-char hex (32 bytes)
  pub: string;   // 64-char hex (32 bytes)
}

export function ed25519Keypair(): Ed25519Keypair {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return {
    priv: bytesToHex(priv),
    pub: bytesToHex(pub)
  };
}

export function ed25519Sign(privHex: string, data: Uint8Array): string {
  const priv = hexToBytes(privHex);
  const sig = ed25519.sign(data, priv);
  return b64uEncode(sig);
}

export function ed25519Verify(pubHex: string, sigB64u: string, data: Uint8Array): boolean {
  try {
    const pub = hexToBytes(pubHex);
    const sig = b64uDecode(sigB64u);
    return ed25519.verify(sig, data, pub);
  } catch {
    return false;
  }
}

// ============================================================================
// HMAC Pseudonyms (Pairwise per verifier)
// ============================================================================

/**
 * Pairwise pseudonym: first 16 bytes of HMAC-SHA256(master_secret, verifier_id), hex (32 chars)
 * Different per shop, so shops cannot join records.
 */
export function pseudonym(masterSecretHex: string, verifierId: string): string {
  const key = hexToBytes(masterSecretHex);
  const msg = new TextEncoder().encode(verifierId);
  const mac = hmac(sha256, key, msg);
  return bytesToHex(mac.slice(0, 16));
}

/**
 * OTP code = HMAC-SHA256(secret, verifier_id|step) mod 10^6, zero-padded to 6 digits
 */
export function otpCode(secretHex: string, verifierId: string, step: number): string {
  const key = hexToBytes(secretHex);
  const msg = new TextEncoder().encode(`${verifierId}|${step}`);
  const mac = hmac(sha256, key, msg);
  const hex = bytesToHex(mac);
  const num = parseInt(hex, 16) % 1_000_000;
  return num.toString().padStart(6, '0');
}

/**
 * OTP secret per user per shop: HMAC-SHA256(user_master_secret, "otp|<verifier_id>")
 */
export function otpSecretFor(masterSecretHex: string, verifierId: string): string {
  const key = hexToBytes(masterSecretHex);
  const msg = new TextEncoder().encode(`otp|${verifierId}`);
  const mac = hmac(sha256, key, msg);
  return bytesToHex(mac);
}

// ============================================================================
// P-256 (Holder proofs - WebCrypto compatible)
// WebCrypto produces raw r||s (IEEE P1363, 64 bytes)
// We convert to DER for @noble verification
// ============================================================================

export interface P256PublicKey {
  x: bigint;
  y: bigint;
}

/**
 * Parse base64url uncompressed P-256 point (65 bytes, 0x04 prefix)
 */
export function parseP256PubKey(b64u: string): P256PublicKey {
  const raw = b64uDecode(b64u);
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error('P-256 public key must be 65-byte uncompressed point');
  }
  const x = bytesToBigInt(raw.slice(1, 33));
  const y = bytesToBigInt(raw.slice(33, 65));
  return { x, y };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/**
 * Convert WebCrypto raw r||s (64 bytes) to DER format for @noble
 */
export function p1363ToDer(rawSigB64u: string): Uint8Array {
  const raw = b64uDecode(rawSigB64u);
  if (raw.length !== 64) {
    throw new Error('P-256 signature must be 64-byte raw r||s');
  }
  const r = bytesToBigInt(raw.slice(0, 32));
  const s = bytesToBigInt(raw.slice(32, 64));
  return encodeDssSignature(r, s);
}

/**
 * Verify WebCrypto P-256/SHA-256 signature
 */
export function p256Verify(pubB64u: string, rawSigB64u: string, msg: Uint8Array): boolean {
  try {
    const pub = parseP256PubKey(pubB64u);
    const sig = p1363ToDer(rawSigB64u);
    // @noble/curves p256.verify expects public key as Uint8Array (uncompressed 65 bytes)
    const pubKey = new Uint8Array(65);
    pubKey[0] = 0x04;
    // Convert bigint x,y to 32-byte big-endian
    pubKey.set(bigIntToBytes(pub.x, 32), 1);
    pubKey.set(bigIntToBytes(pub.y, 32), 33);
    return p256.verify(sig, msg, pubKey);
  } catch {
    return false;
  }
}

function bigIntToBytes(value: bigint, length: number = 32): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Generate P-256 keypair for testing (returns base64url uncompressed public key)
 */
export async function generateP256Keypair(): Promise<{ priv: Uint8Array; pubB64u: string }> {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv);
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(pub.slice(0, 32), 1);
  raw.set(pub.slice(32, 64), 33);
  return {
    priv,
    pubB64u: b64uEncode(raw)
  };
}

/**
 * Get Ed25519 public key from private key (for receipt verification)
 */
export function receiptPub(privHex: string): string {
  const priv = hexToBytes(privHex);
  const pub = ed25519.getPublicKey(priv);
  return bytesToHex(pub);
}

/**
 * Simple canonical JSON for receipt signing (inline to avoid circular deps)
 */
function canonicalReceipt(value: { head: string; ts: number }): string {
  return JSON.stringify(value);
}

/**
 * Receipt chain entry: HMAC-SHA256(key, "<prev>|<ts>|<vid>|<q>|<result>|<reason>")
 */
export function chainEntry(
  prev: string,
  ts: number,
  vid: string,
  q: string,
  result: string,
  reason: string,
  key: string
): string {
  const msg = `${prev}|${ts}|${vid}|${q}|${result}|${reason}`;
  const mac = hmac(sha256, hexToBytes(key), new TextEncoder().encode(msg));
  return bytesToHex(mac);
}

/**
 * Sign receipt chain head: Ed25519 signature of canonical({head: head_hash, ts: ts})
 */
export function signHead(privHex: string, headHash: string, ts: number): string {
  const body = canonicalReceipt({ head: headHash, ts });
  const bodyBytes = new TextEncoder().encode(body);
  return ed25519Sign(privHex, bodyBytes);
}

// Alias for fingerprint
export const fingerprint = keyFingerprint;