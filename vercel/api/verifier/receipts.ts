// Verifier API: GET /api/verifier/receipts
// PII-free receipts + signed chain head (admin only)

import { getVerifierConfig, getAllReceipts, getReceiptKey, listReceipts } from '../../lib/kv.js';
import { signHead, receiptPub } from '../../lib/crypto.js';
import { getAdminToken } from '../../lib/auth.js';

export const config = {
  runtime: 'edge'
};

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  const config = await getVerifierConfig();
  if (!config) {
    return Response.json({ error: 'Not configured' }, { status: 500 });
  }
  
  // Admin auth
  const adminToken = getAdminToken(req);
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED' }, { status: 401 });
  }
  
  const verifierId = config.verifierId;
  
  const rows = await listReceipts(verifierId);
  const key = await getReceiptKey(verifierId);
  
  let head: { head: string; ts: number; sig: string } | null = null;
  if (rows.length > 0) {
    const headHash = rows[rows.length - 1].entry_hash;
    const ts = Math.floor(Date.now() / 1000);
    const sig = signHead(key, headHash, ts);
    head = { head: headHash, ts, sig };
  }
  
  const pub = receiptPub(key);
  
  return Response.json({ rows, head, receipt_pub: pub });
}