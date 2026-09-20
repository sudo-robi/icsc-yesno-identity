// Issuer API: GET /api/issuer/bundle?vid=SHOP-A
// Signed per-verifier trust bundle

import { initDb, allUserStatus, getActiveKey, getStagedKey, getBundleVersion, buildBundle, isAdult } from '../../lib/db.js';
import { ed25519Sign, pseudonym } from '../../lib/crypto.js';
import { canonical, bundleSignedBody } from '../../lib/canonical.js';
import { BUNDLE_TTL_SEC } from '../../lib/verify.js';

export const config = {
  runtime: 'edge'
};

function getIssuerId(): string {
  return process.env.ISSUER_ID ?? 'NIMC-TEST-01';
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  await initDb();
  
  const url = new URL(req.url);
  const verifierId = url.searchParams.get('vid') ?? url.searchParams.get('verifier_id') ?? 'SHOP-A';
  
  if (verifierId.length > 32) {
    return Response.json({ error: 'MALFORMED', detail: 'vid too long' }, { status: 400 });
  }
  
  const activeKey = await getActiveKey();
  if (!activeKey) {
    return Response.json({ error: 'NO_ACTIVE_KEY' }, { status: 500 });
  }
  
  const stagedKey = await getStagedKey();
  const users = await allUserStatus();
  const version = await getBundleVersion();
  const now = Math.floor(Date.now() / 1000);
  const issuerId = getIssuerId();
  
  const bundle = await buildBundle({
    verifierId,
    users,
    revVersion: version,
    issuedAt: now,
    ttlSec: BUNDLE_TTL_SEC,
    issuerId,
    privHex: activeKey.priv,
    pubHex: activeKey.pub,
    nextPub: stagedKey?.pub ?? null
  });
  
  return Response.json(bundle);
}