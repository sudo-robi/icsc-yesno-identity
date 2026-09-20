// Verifier API: POST /api/verifier/sync
// Pair with signed issuer bundle (admin only)

import { getVerifierConfig, getTrustBundle, setTrustBundle } from '../../lib/kv.js';
import { checkBundle } from '../../lib/verify.js';
import { keyFingerprint } from '../../lib/crypto.js';
import { getAdminToken } from '../../lib/auth.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const config = await getVerifierConfig();
  if (!config) {
    return Response.json({ error: 'MALFORMED', detail: 'verifier not configured' }, { status: 400 });
  }
  
  // Admin auth
  const adminToken = getAdminToken(req);
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED', detail: 'admin token required' }, { status: 401 });
  }
  
  const verifierId = config.verifierId;
  
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const b = body as Record<string, unknown>;
  const bundle = (b.bundle ?? b) as Record<string, unknown>;
  
  const pinned = await getTrustBundle(verifierId);
  const now = Date.now() / 1000;
  
  const { accepted, reason } = await checkBundle(bundle as any, pinned, now);
  
  if (!accepted && ['BADSIG', 'ROLLBACK', 'ISSUER_MISMATCH'].includes(reason)) {
    console.log('sync_rejected', reason);
    return Response.json({ error: reason }, { status: 409 });
  }
  
  if (!accepted) {
    return Response.json({ error: 'MALFORMED', detail: 'bundle shape' }, { status: 400 });
  }
  
  if (!pinned || !pinned.pub) {
    await setTrustBundle(verifierId, bundle as any);
    console.log('sync_tofu', bundle.iss, bundle.v);
    return Response.json({ 
      ok: true, 
      tofu: true, 
      fingerprint: keyFingerprint(bundle.pub as string),
      note: 'confirm fingerprint out-of-band' 
    });
  }
  
  await setTrustBundle(verifierId, bundle as any);
  console.log('sync_ok', bundle.v);
  return Response.json({ ok: true, v: bundle.v });
}