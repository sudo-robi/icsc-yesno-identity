// Issuer API: GET /api/issuer/admin/otp-secrets
// Per-shop OTP secrets for adult, non-revoked users only (admin channel)

import { initDb, allUserStatus, isAdult } from '@/lib/db.js';
import { pseudonym, otpSecretFor } from '@/lib/crypto.js';
import { getAdminToken } from '@/lib/auth.js';

export const config = {
  runtime: 'edge'
};

function getOtpEnabled(): boolean {
  return process.env.OTP_ENABLED !== 'false';
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const adminToken = getAdminToken(req);
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED', detail: 'admin token required' }, { status: 401 });
  }
  
  if (!getOtpEnabled()) {
    return Response.json({ error: 'OTP_DISABLED' }, { status: 404 });
  }
  
  await initDb();
  
  const url = new URL(req.url);
  const verifierId = url.searchParams.get('vid') ?? url.searchParams.get('verifier_id') ?? 'SHOP-A';
  
  if (verifierId.length > 32) {
    return Response.json({ error: 'MALFORMED', detail: 'vid too long' }, { status: 400 });
  }
  
  const users = await allUserStatus();
  const secrets: Record<string, string> = {};
  
  for (const u of users) {
    if (u.revoked || !isAdult(u.dob)) continue;
    const sub = pseudonym(u.master_secret, verifierId);
    secrets[sub] = otpSecretFor(u.master_secret, verifierId);
  }
  
  return Response.json({ vid: verifierId, secrets });
}