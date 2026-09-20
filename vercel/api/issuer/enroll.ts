// Issuer API: POST /api/issuer/enroll
// Redeem single-use enrollment code for holder key

import { initDb, consumeEnrollmentCode, getUser, allUserStatus, ensureActiveKey, bumpBundleVersion, audit, isAdult } from '../../lib/db.js';
import { ed25519Sign, pseudonym, otpSecretFor, sha256Hex } from '../../lib/crypto.js';
import { validateCredential, CredentialSchema, err } from '../../lib/schemas.js';
import { canonical, credentialSignedBody } from '../../lib/canonical.js';

export const config = {
  runtime: 'edge'
};

function getIssuerId(): string {
  return process.env.ISSUER_ID ?? 'NIMC-TEST-01';
}

function getCredTtl(): number {
  return parseInt(process.env.CRED_TTL_SEC ?? '3600', 10);
}

function getOtpEnabled(): boolean {
  return process.env.OTP_ENABLED !== 'false';
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  await initDb();
  
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return err('MALFORMED');
  }
  
  const b = body as Record<string, unknown>;
  
  const code = typeof b.code === 'string' ? b.code.trim() : '';
  const verifierId = typeof b.verifier_id === 'string' ? b.verifier_id.trim() : '';
  const holderPub = typeof b.holder_pub === 'string' ? b.holder_pub.trim() : '';
  
  if (!code || !verifierId || !holderPub) return err('MALFORMED');
  if (verifierId.length > 32) return err('MALFORMED');
  if (holderPub.length > 128) return err('MALFORMED');
  
  // Consume enrollment code
  const redeemed = await consumeEnrollmentCode(code);
  if (!redeemed.ok) {
    return err(redeemed.reason as any);
  }
  
  const user = await getUser(redeemed.user_id!);
  if (!user) return err('MALFORMED', 'ENROLL_FAILED');
  if (user.revoked) return err('MALFORMED', 'REVOKED_USER');
  
  // Verify holder_pub is valid P-256 point (basic check)
  try {
    const { parseP256PubKey } = await import('../../lib/crypto.js');
    parseP256PubKey(holderPub);
  } catch {
    return err('MALFORMED', 'BAD_PUBKEY');
  }
  
  // Get active issuer key
  const activeKey = await ensureActiveKey();
  const stagedKey = await import('../../lib/db.js').then(m => m.getStagedKey?.());
  
  // Build credential
  const now = Math.floor(Date.now() / 1000);
  const ttlSec = getCredTtl();
  const issuerId = getIssuerId();
  
  const sub = pseudonym(user.master_secret, verifierId);
  const adult = isAdult(user.dob);
  
  const credBody = {
    v: 1,
    iss: issuerId,
    sub,
    vid: verifierId,
    a: 'over_18' as const,
    r: adult ? 1 : 0,
    iat: now,
    exp: now + ttlSec,
    cnf: holderPub,
    did: (await sha256Hex(new TextEncoder().encode(`${holderPub}|${verifierId}`))).slice(0, 32)
  };
  
  const signedBody = credentialSignedBody(credBody);
  const sig = ed25519Sign(activeKey.priv, new TextEncoder().encode(canonical(signedBody)));
  
  const credential = { ...credBody, s: sig };
  
  // Validate
  const validation = validateCredential(credential);
  if (validation) {
    console.error('Credential validation failed:', validation);
    return err('MALFORMED', 'issuer error');
  }
  
  await audit('holder', 'enroll', verifierId);
  
  const response: Record<string, unknown> = { credential };
  
  if (getOtpEnabled()) {
    response.otp_secret = otpSecretFor(user.master_secret, verifierId);
  }
  
  return Response.json(response);
}