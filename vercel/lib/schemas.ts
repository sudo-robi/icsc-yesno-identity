// Zod schemas - port of shared/schemas.py
// Exact signed shapes. Unknown extra fields are REJECTED, not ignored.

import { z } from 'zod';

// ============================================================================
// Constants
// ============================================================================

export const CRED_SIGNED_FIELDS = [
  'v', 'iss', 'sub', 'vid', 'a', 'r', 'iat', 'exp', 'cnf', 'did'
] as const;

export const CRED_REQUIRED_FIELDS = [...CRED_SIGNED_FIELDS, 's'];

export const BUNDLE_SIGNED_FIELDS = [
  'v', 'iss', 'vid', 'pub', 'next_pub', 'revoked', 'minors', 'iat', 'exp'
] as const;

export const BUNDLE_REQUIRED_FIELDS = [...BUNDLE_SIGNED_FIELDS, 's'];

export const CHALLENGE_FIELDS = ['n', 'vid', 'exp'] as const;
export const PROOF_FIELDS = ['n', 'ts', 'sig'] as const;

export const CRED_MAX_BYTES = 2048;

// ============================================================================
// Type helpers
// ============================================================================

function plainInt(): z.ZodNumber | z.ZodEffects<z.ZodNumber, number, number> {
  return z.number().int().refine(n => !Number.isNaN(n), 'must be integer');
}

function hexString(len?: number): z.ZodString {
  const schema = z.string().regex(/^[0-9a-f]+$/i, 'must be hex');
  if (len) return schema.length(len);
  return schema;
}

function b64uString(): z.ZodString {
  return z.string().regex(/^[A-Za-z0-9_-]+$/, 'must be base64url');
}

// ============================================================================
// Credential schemas
// ============================================================================

export const CredentialSignedSchema = z.object({
  v: plainInt(),
  iss: z.string().min(1).max(64),
  sub: hexString(32),
  vid: z.string().min(1).max(32),
  a: z.literal('over_18'),
  r: z.union([z.literal(0), z.literal(1)]),
  iat: plainInt(),
  exp: plainInt(),
  cnf: b64uString(),
  did: hexString(32)
}).strict();

export const CredentialSchema = CredentialSignedSchema.extend({
  s: b64uString()
}).strict();

export type Credential = z.infer<typeof CredentialSchema>;
export type CredentialSigned = z.infer<typeof CredentialSignedSchema>;

// ============================================================================
// Proof schema
// ============================================================================

export const ProofSchema = z.object({
  n: z.string().min(1).max(64),
  ts: plainInt(),
  sig: b64uString()
}).strict();

export type Proof = z.infer<typeof ProofSchema>;

// ============================================================================
// Challenge schema
// ============================================================================

export const ChallengeSchema = z.object({
  n: z.string().length(32).regex(/^[0-9a-f]+$/, 'nonce must be 32-char hex'),
  vid: z.string().min(1).max(32),
  exp: plainInt()
}).strict();

export type Challenge = z.infer<typeof ChallengeSchema>;

// ============================================================================
// Bundle schemas
// ============================================================================

export const BundleSignedSchema = z.object({
  v: plainInt(),
  iss: z.string().min(1).max(64),
  vid: z.string().min(1).max(32),
  pub: hexString(64),
  next_pub: z.union([hexString(64), z.null()]),
  revoked: z.array(hexString(32)),
  minors: z.array(hexString(32)),
  iat: plainInt(),
  exp: plainInt()
}).strict();

export const BundleSchema = BundleSignedSchema.extend({
  s: b64uString()
}).strict();

export type Bundle = z.infer<typeof BundleSchema>;
export type BundleSigned = z.infer<typeof BundleSignedSchema>;

// ============================================================================
// Verification request
// ============================================================================

export const VerifyRequestSchema = z.object({
  c: CredentialSchema,
  p: ProofSchema
}).strict();

export type VerifyRequest = z.infer<typeof VerifyRequestSchema>;

// ============================================================================
// OTP verification request
// ============================================================================

export const VerifyCodeRequestSchema = z.object({
  code: z.string().length(6).regex(/^\d{6}$/, 'code must be 6 digits')
}).strict();

export type VerifyCodeRequest = z.infer<typeof VerifyCodeRequestSchema>;

// ============================================================================
// Admin schemas
// ============================================================================

export const EnrollmentCodeRequestSchema = z.object({
  user_id: z.string().min(1).max(32)
}).strict();

export const RevokeRequestSchema = z.object({
  user_id: z.string().min(1).max(32)
}).strict();

export const RotateRequestSchema = z.object({
  activate: z.boolean().default(false)
}).strict();

export const SyncRequestSchema = z.object({
  bundle: BundleSchema
}).strict();

export const OTPSecretsRequestSchema = z.object({
  secrets: z.record(z.string().length(32), z.string().length(64))
}).strict();

// ============================================================================
// Validation helpers (return error code or null)
// ============================================================================

export const REASONS = [
  'NO_TRUSTBUNDLE', 'MALFORMED', 'TOO_LARGE', 'WRONG_VERIFIER',
  'ISSUER_MISMATCH', 'EXPIRED', 'BADSIG', 'BAD_PROOF', 'UNKNOWN_CHALLENGE',
  'REVOKED', 'NOT_ADULT', 'OK', 'OK_OTP', 'BAD_OTP',
  'ENROLL_FAILED', 'REVOKED_USER', 'BAD_PUBKEY', 'UNKNOWN_CODE',
  'CODE_USED', 'CODE_EXPIRED', 'ROLLBACK', 'OTP_DISABLED', 'UNAUTHORIZED'
] as const;

export type ReasonCode = typeof REASONS[number];

export function checkReason(reason: string): reason is ReasonCode {
  return REASONS.includes(reason as ReasonCode);
}

function isPlainInt(n: unknown): n is number {
  return Number.isInteger(n) && !Number.isNaN(n);
}

export function validateCredential(cred: unknown): ReasonCode | null {
  const result = CredentialSchema.safeParse(cred);
  if (!result.success) return 'MALFORMED';
  return null;
}

export function validateProof(proof: unknown): ReasonCode | null {
  const result = ProofSchema.safeParse(proof);
  if (!result.success) return 'MALFORMED';
  return null;
}

export function validateChallenge(ch: unknown): ReasonCode | null {
  const result = ChallengeSchema.safeParse(ch);
  if (!result.success) return 'MALFORMED';
  return null;
}

export function validateBundleShape(bundle: unknown): ReasonCode | null {
  const result = BundleSchema.safeParse(bundle);
  if (!result.success) return 'MALFORMED';
  return null;
}

// ============================================================================
// Error response helper
// ============================================================================

export function err(code: ReasonCode, detail?: string): Response {
  const body = detail ? { error: code, detail } : { error: code };
  const status = code === 'MALFORMED' ? 400 :
                 code === 'UNKNOWN_CODE' || code === 'CODE_USED' || code === 'CODE_EXPIRED' || code === 'BAD_PUBKEY' || code === 'ENROLL_FAILED' ? 400 :
                 code === 'REVOKED_USER' ? 403 :
                 code === 'UNAUTHORIZED' ? 401 :
                 code === 'BADSIG' || code === 'ROLLBACK' || code === 'ISSUER_MISMATCH' ? 409 :
                 code === 'OTP_DISABLED' ? 404 : 500;
  return Response.json(body, { status });
}