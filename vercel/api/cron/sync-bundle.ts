// Cron job: POST /api/cron/sync-bundle
// Periodic bundle sync from issuer

import { getVerifierConfig, getTrustBundle, setTrustBundle } from '../../lib/kv.js';
import { checkBundle } from '../../lib/verify.js';
import { Bundle } from '../../lib/schemas.js';

export const config = {
  runtime: 'edge'
};

// Verify cron secret
export default async function handler(req: Request): Promise<Response> {
  const cronSecret = req.headers.get('x-vercel-cron-secret') ?? req.headers.get('authorization')?.replace('Bearer ', '');
  
  if (cronSecret !== process.env.CRON_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  const config = await getVerifierConfig();
  if (!config || !config.issuerUrl) {
    return Response.json({ ok: false, error: 'verifier not configured or no issuer_url' }, { status: 400 });
  }
  
  try {
    const response = await fetch(`${config.issuerUrl}/bundle?vid=${config.verifierId}`);
    if (!response.ok) {
      return Response.json({ ok: false, error: `issuer returned ${response.status}` }, { status: 502 });
    }
    
    const bundle = await response.json() as Bundle;
    const pinned = await getTrustBundle(config.verifierId);
    const now = Date.now() / 1000;
    
    const { accepted, reason } = await checkBundle(bundle, pinned, now);
    
    if (!accepted) {
      return Response.json({ ok: false, error: reason }, { status: 400 });
    }
    
    await setTrustBundle(config.verifierId, bundle);
    
    return Response.json({ ok: true, synced: true, v: bundle.v });
  } catch (error) {
    console.error('cron sync error:', error);
    return Response.json({ ok: false, error: String(error) }, { status: 500 });
  }
}