// Verifier API: POST /api/verifier/verify_code
// Feature-phone OTP path

import { getVerifierConfig, getOTPSecrets, isOTPUsed, markOTPUsed, getTrustBundle, appendReceipt, getReceiptKey, getReceiptCounter, getReceipt } from '../../lib/kv.js';
import { otpStatus } from '../../lib/verify.js';
import { otpCode } from '../../lib/crypto.js';
import { checkReason, ReasonCode } from '../../lib/schemas.js';
import { chainEntry, signHead } from '../../lib/crypto.js';

export const config = {
  runtime: 'edge'
};

function getOtpEnabled(): boolean {
  return process.env.OTP_ENABLED !== 'false';
}

function getOtpStepSec(): number {
  return parseInt(process.env.OTP_STEP_SEC ?? '30', 10);
}

function getOtpGraceSteps(): number {
  return parseInt(process.env.OTP_GRACE_STEPS ?? '1', 10);
}

async function appendReceiptFn(verifierId: string, q: string, result: string, reason: ReasonCode): Promise<string> {
  const { appendReceipt, getReceiptKey } = await import('../../lib/kv.js');
  const { chainEntry } = await import('../../lib/crypto.js');
  
  const key = await getReceiptKey(verifierId);
  const ts = Math.floor(Date.now() / 1000);
  
  const counter = await getReceiptCounter(verifierId);
  let prevHash = '';
  if (counter > 0) {
    const { getReceipt } = await import('../../lib/kv.js');
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
  
  return entryHash;
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  if (!getOtpEnabled()) {
    return Response.json({ error: 'OTP_DISABLED' }, { status: 404 });
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
  const code = typeof b.code === 'string' ? b.code.trim() : '';
  
  if (!code || code.length !== 6) {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const now = Date.now() / 1000;
  const step = Math.floor(now / getOtpStepSec());
  const grace = getOtpGraceSteps();
  
  const secrets = await getOTPSecrets(verifierId);
  if (!secrets) {
    const receipt = await appendReceiptFn(verifierId, 'over_18:otp', 'NO', 'BAD_OTP');
    return Response.json({ result: 'NO', reason: 'BAD_OTP', receipt, mode: 'otp' });
  }
  
  let matchedSub: string | null = null;
  
  // Check current step and grace steps
  for (let s = step; s >= step - grace; s--) {
    for (const [sub, secret] of Object.entries(secrets)) {
      const expected = otpCode(secret, verifierId, s);
      if (expected === code) {
        matchedSub = sub;
        break;
      }
    }
    if (matchedSub) break;
  }
  
  if (!matchedSub) {
    const receipt = await appendReceiptFn(verifierId, 'over_18:otp', 'NO', 'BAD_OTP');
    return Response.json({ result: 'NO', reason: 'BAD_OTP', receipt, mode: 'otp' });
  }
  
  // Check if already used
  if (await isOTPUsed(verifierId, matchedSub, step)) {
    const receipt = await appendReceiptFn(verifierId, 'over_18:otp', 'NO', 'UNKNOWN_CHALLENGE');
    return Response.json({ result: 'NO', reason: 'UNKNOWN_CHALLENGE', receipt, mode: 'otp' });
  }
  
  await markOTPUsed(verifierId, matchedSub, step);
  
  const trust = await getTrustBundle(verifierId);
  const [result, reason] = otpStatus(matchedSub, trust) as [string, import('../../lib/schemas.js').ReasonCode];
  
  const receipt = await appendReceiptFn(verifierId, 'over_18:otp', result, reason);
  
  return Response.json({ 
    result, 
    reason, 
    receipt, 
    mode: 'otp',
    trust_note: 'OTP mode: shop operator holds secrets; QR mode (P-256) is stronger'
  });
}