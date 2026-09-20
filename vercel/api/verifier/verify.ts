// Verifier API: POST /api/verifier/verify
// Verify credential + proof presentation

import { getVerifierConfig, getTrustBundle, consumeNonce, appendReceipt, getReceiptKey, getReceiptCounter, getReceipt } from '../../lib/kv.js';
import { decide } from '../../lib/verify.js';
import { checkReason, err } from '../../lib/schemas.js';
import { canonical } from '../../lib/canonical.js';
import { chainEntry, signHead } from '../../lib/crypto.js';

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
  
  const verifierId = config.verifierId;
  
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const b = body as Record<string, unknown>;
  const cred = b.c as Record<string, unknown>;
  const proof = b.p as Record<string, unknown>;
  
  if (!cred || !proof) {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const rawLen = JSON.stringify(body).length;
  const trust = await getTrustBundle(verifierId);
  const now = Date.now() / 1000;
  
  const consumeFn = async (nonce: string, minIssued: number, nowTs: number) => {
    return await consumeNonce(verifierId, nonce, Math.floor(nowTs));
  };
  
  const [result, reason] = await decide({
    cred: cred as any,
    proof: proof as any,
    rawLen,
    trust,
    verifierId,
    now,
    consumeNonce: consumeFn
  });
  
  if (!checkReason(reason)) {
    console.error('reason_drift', reason);
    return Response.json({ error: 'MALFORMED', detail: 'internal error' }, { status: 500 });
  }
  
  // Append receipt
  const key = await getReceiptKey(verifierId);
  const ts = Math.floor(now);
  const q = 'over_18:proof';
  
  const counter = await getReceiptCounter(verifierId);
  let prevHash = '';
  if (counter > 0) {
    const prev = await getReceipt(verifierId, counter);
    prevHash = prev?.entry_hash ?? '';
  }
  
  const entryHash = chainEntry(prevHash, ts, verifierId, q, result, reason, key);
  
  await appendReceipt(verifierId, {
    ts,
    verifier_id: verifierId,
    q,
    result,
    reason,
    prev_hash: prevHash,
    entry_hash: entryHash
  });
  
  // Sign head periodically
  if (ts % 10 === 0) {
    const { getAllReceipts } = await import('../../lib/kv.js');
    const all = await getAllReceipts(verifierId);
    if (all.length > 0) {
      const head = all[all.length - 1].entry_hash;
      signHead(key, head, ts);
    }
  }
  
  return Response.json({ result, reason, mode: 'proof', receipt: entryHash });
}