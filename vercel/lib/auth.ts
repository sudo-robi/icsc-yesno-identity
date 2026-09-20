// Auth helper for admin endpoints

export function getAdminToken(req: Request): string | null {
  const auth = req.headers.get('authorization');
  if (!auth) return null;
  
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  
  return parts[1];
}

export function requireAdmin(req: Request): Response | null {
  const token = getAdminToken(req);
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return Response.json({ error: 'UNAUTHORIZED', detail: 'admin token required' }, { status: 401 });
  }
  return null;
}