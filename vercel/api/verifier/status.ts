// Verifier API: GET /api/verifier/status
// Public pairing status

import { getVerifierConfig, getTrustBundle } from '../../lib/kv.js';
import { fingerprint } from '../../lib/crypto.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const config = await getVerifierConfig();
  if (!config) {
    return Response.json({ paired: false });
  }
  
  const paired = await getTrustBundle(config.verifierId);
  
  if (!paired) {
    return Response.json({ paired: false });
  }
  
  const days = Math.max(0, Math.round((paired.exp - Date.now() / 1000) / 86400));
  
  return Response.json({ 
    paired: true, 
    bundle_v: paired.v, 
    iss: paired.iss,
    fingerprint: fingerprint(paired.pub),
    bundle_exp: paired.exp,
    expires_in_days: days
  });
}