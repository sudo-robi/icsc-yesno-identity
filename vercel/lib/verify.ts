// Verifier decision engine - port of verifier/services.py::decide
// Core verification logic for credential + proof

import type { 
  Credential, Proof, Bundle, ReasonCode, Challenge 
} from './schemas.js';
import { 
  validateCredential, validateProof, validateChallenge,
  checkReason, err, REASONS 
} from './schemas.js';
import { 
  canonical, credentialSignedBody, bundleSignedBody 
} from './canonical.js';
import { 
  ed25519Verify, p256Verify, pseudonym 
} from './crypto.js';

export const CLOCK_SKEW_SEC = 30;
export const NONCE_TTL_SEC = 300;
export const PROOF_TS_WINDOW_SEC = 60;
export const CRED_TTL_SEC = 3600;
export const BUNDLE_TTL_SEC = 7 * 86400;

// ============================================================================
// Proof message construction
// ============================================================================

export function proofMessage(
  credCanonicalSha: string,
  nonce: string,
  verifierId: string,
  ts: number,
  did: string = ''
): string {
  // canonical(["yn-proof-v1", cred_canonical_sha, nonce, vid, ts, did])
  const arr = ['yn-proof-v1', credCanonicalSha, nonce, verifierId, ts, did];
  return canonical(arr);
}

// ============================================================================
// OTP status check (after code match)
// ============================================================================

export function otpStatus(sub: string, trust: Bundle | null): [string, ReasonCode] {
  if (!trust) return ['NO', 'NO_TRUSTBUNDLE'];
  if (trust.revoked.includes(sub)) return ['NO', 'REVOKED'];
  if (trust.minors.includes(sub)) return ['NO', 'NOT_ADULT'];
  return ['YES', 'OK_OTP'];
}

// ============================================================================
// Main decision function
// ============================================================================

export interface DecideOptions {
  cred: Credential;
  proof: Proof;
  rawLen: number;
  trust: Bundle | null;
  verifierId: string;
  now: number;
  consumeNonce: (nonce: string, minIssued: number, nowTs: number) => Promise<boolean>;
}

export async function decide(options: DecideOptions): Promise<[string, ReasonCode]> {
  const { cred, proof, rawLen, trust, verifierId, now, consumeNonce } = options;
  
  // 1. trust is None → NO / NO_TRUSTBUNDLE
  if (!trust) {
    return ['NO', 'NO_TRUSTBUNDLE'];
  }
  
  // 2. validate_credential(cred) fails → NO / MALFORMED
  const credValidation = validateCredential(cred);
  if (credValidation) {
    return ['NO', credValidation];
  }
  
  // 3. raw_len > max_bytes (2048) → NO / TOO_LARGE
  if (rawLen > 2048) {
    return ['NO', 'TOO_LARGE'];
  }
  
  // 4. cred["vid"] != verifier_id → NO / WRONG_VERIFIER
  if (cred.vid !== verifierId) {
    return ['NO', 'WRONG_VERIFIER'];
  }
  
  // 5. cred["iss"] != trust["iss"] → NO / ISSUER_MISMATCH
  if (cred.iss !== trust.iss) {
    return ['NO', 'ISSUER_MISMATCH'];
  }
  
  // 6. cred["exp"] + CLOCK_SKEW_SEC < now → NO / EXPIRED
  if (cred.exp + CLOCK_SKEW_SEC < now) {
    return ['NO', 'EXPIRED'];
  }
  
  // 7. Verify issuer signature
  let signedBody: Record<string, unknown>;
  try {
    signedBody = credentialSignedBody(cred);
  } catch {
    return ['NO', 'MALFORMED'];
  }
  
  const bodyCanonical = canonical(signedBody);
  const bodyBytes = new TextEncoder().encode(bodyCanonical);
  
  if (!ed25519Verify(trust.pub, cred.s, bodyBytes)) {
    return ['NO', 'BADSIG'];
  }
  
  // 8. proof is required
  if (!proof) {
    return ['NO', 'BAD_PROOF'];
  }
  
  // 9. validate_proof(proof) fails → NO / MALFORMED
  const proofValidation = validateProof(proof);
  if (proofValidation) {
    return ['NO', proofValidation];
  }
  
  // 10. consume_nonce - atomic single-use take
  const nonceConsumed = await consumeNonce(proof.n, now - NONCE_TTL_SEC, now);
  if (!nonceConsumed) {
    return ['NO', 'UNKNOWN_CHALLENGE'];
  }
  
  // 11. timestamp window check
  if (Math.abs(now - proof.ts) > PROOF_TS_WINDOW_SEC) {
    return ['NO', 'BAD_PROOF'];
  }
  
  // 12. Verify holder proof signature
  const credSigned = credentialSignedBody(cred);
  const credCanon = canonical(credSigned);
  const credHash = await import('./crypto.js').then(m => m.sha256Hex(new TextEncoder().encode(credCanon)));
  
  const msgStr = proofMessage(credHash, proof.n, verifierId, proof.ts, cred.did || '');
  const msg = new TextEncoder().encode(msgStr);
  
  if (!p256Verify(cred.cnf, proof.sig, msg)) {
    return ['NO', 'BAD_PROOF'];
  }
  
  // 13. Check revocation list
  if (trust.revoked.includes(cred.sub)) {
    return ['NO', 'REVOKED'];
  }
  
  // 14. Check minors list
  if (trust.minors.includes(cred.sub)) {
    return ['NO', 'NOT_ADULT'];
  }
  
  // 15. Check adult flag
  if (cred.a !== 'over_18' || cred.r !== 1) {
    return ['NO', 'NOT_ADULT'];
  }
  
  // 16. All checks passed
  return ['YES', 'OK'];
}

// ============================================================================
// Bundle validation (for sync)
// ============================================================================

export interface CheckBundleResult {
  accepted: boolean;
  reason: string;
}

export async function checkBundle(
  bundle: Bundle,
  pinned: Bundle | null,
  now: number
): Promise<CheckBundleResult> {
  // Shape validation
  const { validateBundleShape } = await import('./schemas.js');
  const shapeError = validateBundleShape(bundle);
  if (shapeError) {
    return { accepted: false, reason: shapeError };
  }
  
  // Expiry check
  if (bundle.exp <= now) {
    return { accepted: false, reason: 'EXPIRED' };
  }
  
  // First sync (TOFU) - no pinned key
  if (!pinned || !pinned.pub) {
    // Verify signature
    const body = bundleSignedBody(bundle);
    const bodyBytes = new TextEncoder().encode(canonical(body));
    if (!ed25519Verify(bundle.pub, bundle.s, bodyBytes)) {
      return { accepted: false, reason: 'BADSIG' };
    }
    return { accepted: true, reason: 'OK' };
  }
  
  // Later syncs - must match issuer and verifier
  if (bundle.iss !== pinned.iss || bundle.vid !== pinned.vid) {
    return { accepted: false, reason: 'ISSUER_MISMATCH' };
  }
  
  // Rollback check
  if (bundle.v < pinned.v) {
    return { accepted: false, reason: 'ROLLBACK' };
  }
  
  // Verify signature under pinned pub OR chained next_pub
  const body = bundleSignedBody(bundle);
  const bodyBytes = new TextEncoder().encode(canonical(body));
  
  let verified = ed25519Verify(pinned.pub, bundle.s, bodyBytes);
  
  if (!verified && pinned.next_pub) {
    verified = ed25519Verify(pinned.next_pub, bundle.s, bodyBytes);
  }
  
  if (!verified) {
    return { accepted: false, reason: 'BADSIG' };
  }
  
  return { accepted: true, reason: 'OK' };
}

// ============================================================================
// Build bundle (issuer side)
// ============================================================================

import type { User } from './db.js';
import { ed25519Sign, pseudonym as pseudonymFn } from './crypto.js';

export interface BuildBundleOptions {
  verifierId: string;
  users: User[];
  revVersion: number;
  issuedAt: number;
  ttlSec: number;
  issuerId: string;
  privHex: string;
  pubHex: string;
  nextPub: string | null;
}

export async function buildBundle(options: BuildBundleOptions): Promise<Bundle> {
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
  
  return { ...body, s } as Bundle;
}

function isAdult(dob: string): boolean {
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