// Verifier API: GET /api/verifier/challenge
// Mint fresh single-use challenge

import { getVerifierConfig, addNonce } from '../../lib/kv.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const config = await getVerifierConfig();
  if (!config) {
    return Response.json({ error: 'MALFORMED', detail: 'verifier not configured' }, { status: 400 });
  }
  
  const verifierId = config.verifierId;
  const now = Math.floor(Date.now() / 1000);
  const { NONCE_TTL_SEC } = await import('../../lib/verify.js');
  
  const nonce = crypto.randomUUID().replace(/-/g, '').slice(0, 32);
  const issued = { n: nonce, vid: verifierId, exp: now + NONCE_TTL_SEC };
  
  await addNonce(verifierId, nonce, now, issued.exp);
  
  return Response.json(issued);
}