// Issuer API: POST /api/issuer/admin/rotate
// Stage or activate rotation key

import { initDb, getActiveKey, getStagedKey, storeKey, deactivateAllKeys, activateKey, bumpBundleVersion, audit } from '@/lib/db.js';
import { ed25519Keypair } from '@/lib/crypto.js';
import { publishRotation } from '@/lib/realtime.js';
import { getAdminToken } from '@/lib/auth.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const adminToken = getAdminToken(req);
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED', detail: 'admin token required' }, { status: 401 });
  }
  
  // Env-managed keys refuse rotation
  if (process.env.ISSUER_PRIV_HEX) {
    return Response.json({ error: 'MALFORMED', detail: 'key is env-managed; rotate ISSUER_PRIV_HEX' }, { status: 409 });
  }
  
  await initDb();
  
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    body = {};
  }
  
  const b = body as Record<string, unknown>;
  const activate = b.activate === true;
  
  if (activate) {
    const staged = await getStagedKey();
    if (!staged) {
      return Response.json({ error: 'MALFORMED', detail: 'nothing staged' }, { status: 400 });
    }
    
    await deactivateAllKeys();
    const ok = await activateKey(staged.pub);
    if (!ok) {
      return Response.json({ error: 'MALFORMED', detail: 'activation failed' }, { status: 500 });
    }
    
    const version = await bumpBundleVersion();
    await audit('admin', 'rotate-activate', '');
    await publishRotation(version, staged.pub);
    
    return Response.json({ ok: true, pub: staged.pub, v: version });
  }
  
  // Stage new key
  const active = await getActiveKey();
  // Ensure active exists first (for ordering)
  if (!active) {
    await ensureActiveKey();
  }
  
  const kp = ed25519Keypair();
  await storeKey(kp.priv, kp.pub, false);
  const version = await bumpBundleVersion();
  await audit('admin', 'rotate-stage', '');
  await publishRotation(version, kp.pub);
  
  const { fingerprint } = await import('@/lib/crypto.js');
  
  return Response.json({ 
    ok: true, 
    staged_pub: kp.pub, 
    fingerprint: fingerprint(kp.pub), 
    v: version 
  });
}

async function ensureActiveKey(): Promise<void> {
  const { getActiveKey, storeKey } = await import('@/lib/db.js');
  const { ed25519Keypair } = await import('@/lib/crypto.js');
  const key = await getActiveKey();
  if (!key) {
    const kp = ed25519Keypair();
    await storeKey(kp.priv, kp.pub, true);
  }
}