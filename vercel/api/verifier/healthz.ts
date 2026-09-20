// Verifier API: GET /api/verifier/healthz
// Liveness probe

import { getVerifierConfig, getTrustBundle } from '../../lib/kv.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const config = await getVerifierConfig();
  if (!config) {
    return Response.json({ ok: false, error: 'not configured' }, { status: 500 });
  }
  
  const paired = await getTrustBundle(config.verifierId);
  
  return Response.json({ 
    ok: true, 
    verifier: config.verifierId, 
    trust: !!paired,
    v: (paired as any)?.v 
  });
}