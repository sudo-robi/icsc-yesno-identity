// Issuer API: POST /api/issuer/admin/revoke
// Revoke a user and bump bundle version

import { initDb, getUser, setRevoked, bumpBundleVersion, audit } from '@/lib/db.js';
import { publishRevocation } from '@/lib/realtime.js';
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
  
  await setRevoked(userId);
  const version = await bumpBundleVersion();
  await audit('admin', 'revoke', userId);
  
  // Publish revocation event for realtime sync
  await publishRevocation(version, userId);
  
  return Response.json({ ok: true, v: version });
}