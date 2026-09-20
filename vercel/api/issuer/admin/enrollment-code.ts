// Issuer API: POST /api/issuer/admin/enrollment-code
// Mint single-use enrollment code (admin only)

import { initDb, getUser, createEnrollmentCode, audit, bumpBundleVersion } from '../../../lib/db.js';
import { err } from '../../../lib/schemas.js';
import { getAdminToken } from '../../../lib/auth.js';

export const config = {
  runtime: 'edge'
};

function getEnrollCodeTtl(): number {
  return parseInt(process.env.ENROLL_CODE_TTL_SEC ?? '86400', 10);
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  // Admin auth
  const adminToken = getAdminToken(req);
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED', detail: 'admin token required' }, { status: 401 });
  }
  
  await initDb();
  
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const b = body as Record<string, unknown>;
  const userId = typeof b.user_id === 'string' ? b.user_id.trim() : '';
  
  if (!userId || userId.length > 32) {
    return Response.json({ error: 'MALFORMED' }, { status: 400 });
  }
  
  const user = await getUser(userId);
  if (!user) {
    return Response.json({ error: 'UNKNOWN_CODE', detail: 'no such user' }, { status: 404 });
  }
  
  const ttlSec = getEnrollCodeTtl();
  const { code } = await createEnrollmentCode(userId, ttlSec);
  
  await audit('admin', 'enrollment-code', userId);
  
  return Response.json({ 
    code, 
    user_id: userId, 
    expires_in: ttlSec 
  });
}