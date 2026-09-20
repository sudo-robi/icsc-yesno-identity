// Issuer API: GET /api/issuer/healthz
// Liveness probe

export const config = {
  runtime: 'edge'
};

function getIssuerId(): string {
  return process.env.ISSUER_ID ?? 'NIMC-TEST-01';
}

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }
  
  return Response.json({ ok: true, iss: getIssuerId() });
}