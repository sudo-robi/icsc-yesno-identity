// Canonical JSON serialization - mirrors shared/canonical.py exactly
// Sorted keys, (",", ":") separators, UTF-8, no floats

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalError';
  }
}

function isPlainObject(obj: unknown): obj is Record<string, unknown> {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
}

function isInteger(value: unknown): value is number {
  return Number.isInteger(value);
}

export function canonical(value: unknown): string {
  if (typeof value === 'number') {
    if (!isInteger(value)) {
      throw new CanonicalError('Floats are not allowed in canonical JSON');
    }
    return value.toString();
  }
  
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  
  if (Array.isArray(value)) {
    return '[' + value.map(canonical).join(',') + ']';
  }
  
  // Object - sort keys
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonical(value));
}

/**
 * Extract signed body from credential - mirrors shared/schemas.py::signed_body
 */
export function credentialSignedBody(cred: Record<string, unknown>): Record<string, unknown> {
  const CRED_SIGNED_FIELDS = [
    'v', 'iss', 'sub', 'vid', 'a', 'r', 'iat', 'exp', 'cnf', 'did'
  ] as const;
  
  const CRED_REQUIRED_FIELDS = [...CRED_SIGNED_FIELDS, 's'];
  
  const unknown = Object.keys(cred).filter(k => !CRED_REQUIRED_FIELDS.includes(k));
  if (unknown.length > 0) {
    throw new CanonicalError(`Unknown credential fields: ${unknown.sort().join(', ')}`);
  }
  
  const body: Record<string, unknown> = {};
  for (const k of CRED_SIGNED_FIELDS) {
    if (!(k in cred)) {
      throw new CanonicalError(`Missing required credential field: ${k}`);
    }
    body[k] = cred[k];
  }
  return body;
}

/**
 * Extract signed body from bundle - mirrors shared/schemas.py::bundle_sig_body
 */
export function bundleSignedBody(bundle: Record<string, unknown>): Record<string, unknown> {
  const BUNDLE_SIGNED_FIELDS = [
    'v', 'iss', 'vid', 'pub', 'next_pub', 'revoked', 'minors', 'iat', 'exp'
  ] as const;
  
  const BUNDLE_REQUIRED_FIELDS = [...BUNDLE_SIGNED_FIELDS, 's'];
  
  const unknown = Object.keys(bundle).filter(k => !BUNDLE_REQUIRED_FIELDS.includes(k));
  if (unknown.length > 0) {
    throw new CanonicalError(`Unknown bundle fields: ${unknown.sort().join(', ')}`);
  }
  
  const body: Record<string, unknown> = {};
  for (const k of BUNDLE_SIGNED_FIELDS) {
    if (!(k in bundle)) {
      throw new CanonicalError(`Missing required bundle field: ${k}`);
    }
    body[k] = bundle[k];
  }
  return body;
}