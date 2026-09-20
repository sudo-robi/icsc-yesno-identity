# Vercel Deployment Guide

## ⚠️ Current Architecture Incompatibility

**This project cannot deploy to Vercel as-is.** The README documents this:

> **Vercel/serverless: unsuitable** — `/tmp` resets wipe state. Not supported.

### Why It Fails on Vercel

| Component | Current Implementation | Vercel Limitation |
|-----------|------------------------|-------------------|
| **Issuer DB** | SQLite (`issuer/issuer.db`) | Ephemeral `/tmp` — resets on every deploy/cold start |
| **Verifier DB** | SQLite (`verifier/receipts.db`) | Same — no persistent local filesystem |
| **Trust Bundle** | File-based (`verifier/repo.py`) | Lost on cold start; shop must re-pair |
| **Nonce Store** | SQLite + in-memory | Single-use nonces broken across instances |
| **OTP Secrets** | JSON file (`otp_secrets.json`) | Lost on deploy |
| **SSE Push** | Long-lived HTTP connections | Vercel Functions timeout at 10s (Hobby) / 60s (Pro) |
| **Background Sync** | `verifier/sync_queue.py` thread | No background processes in serverless |

---

## Required Architecture Changes for Vercel

### 1. Database → Vercel Postgres / Neon / Supabase

```python
# issuer/repo.py → use asyncpg or psycopg
import os
import asyncpg

async def get_pool():
    return await asyncpg.create_pool(os.environ["POSTGRES_URL"])

# All SQL queries need parameterized $1, $2 instead of ?
```

### 2. File State → Vercel KV (Redis)

```python
# verifier/repo.py
from vercel_kv import get, set, delete

async def save_bundle(bundle: dict):
    await set("trust_bundle", json.dumps(bundle))

async def get_bundle() -> dict | None:
    data = await get("trust_bundle")
    return json.loads(data) if data else None
```

### 3. SSE → Vercel Edge Functions + WebSockets

```typescript
// app/api/events/route.ts (Edge Runtime)
export const runtime = 'edge';

export async function GET() {
  const stream = new ReadableStream({
    async start(controller) {
      // Subscribe to Redis pub/sub or use Ably/Pusher
      const encoder = new TextEncoder();
      // Push events: controller.enqueue(encoder.encode(...))
    }
  });
  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' }});
}
```

### 4. Background Sync → Vercel Cron Jobs

```json
// vercel.json
{
  "crons": [{
    "path": "/api/sync-bundle",
    "schedule": "*/5 * * * *"
  }]
}
```

### 5. Session/State → Signed Cookies or JWT

```python
# Replace in-memory state with signed cookies
from itsdangerous import TimestampSigner
signer = TimestampSigner(os.environ["SECRET_KEY"])
```

---

## Minimal Vercel Project Structure

```
vercel/
├── api/
│   ├── issuer/
│   │   ├── enroll.ts          # POST /api/issuer/enroll
│   │   ├── bundle.ts          # GET /api/issuer/bundle?vid=SHOP-A
│   │   ├── admin/
│   │   │   ├── revoke.ts      # POST /api/issuer/admin/revoke
│   │   │   ├── rotate.ts      # POST /api/issuer/admin/rotate
│   │   │   └── otp-secrets.ts # GET/POST /api/issuer/admin/otp-secrets
│   │   └── events.ts          # GET /api/issuer/events (SSE/Edge)
│   ├── verifier/
│   │   ├── challenge.ts       # GET /api/verifier/challenge
│   │   ├── verify.ts          # POST /api/verifier/verify
│   │   ├── verify_code.ts     # POST /api/verifier/verify_code
│   │   ├── sync.ts            # POST /api/verifier/sync
│   │   ├── receipts.ts        # GET /api/verifier/receipts
│   │   └── health.ts          # GET /api/verifier/healthz
│   └── sync-bundle.ts         # Cron: POST /api/sync-bundle
├── lib/
│   ├── db.ts                  # Vercel Postgres client
│   ├── kv.ts                  # Vercel KV client
│   ├── crypto.ts              # Ed25519, P-256, HMAC (port from shared/crypto.py)
│   ├── canonical.ts           # Canonical JSON (port from shared/canonical.py)
│   └── schemas.ts             # Validation (port from shared/schemas.py)
├── vercel.json                # Config + crons
└── package.json
```

---

## Environment Variables Required

```bash
# Vercel Dashboard → Settings → Environment Variables
POSTGRES_URL=postgres://user:pass@host/db?sslmode=require
KV_REST_API_URL=https://api.vercel.com/v1/kv/namespace
KV_REST_API_TOKEN=your_kv_token
SECRET_KEY=32-byte-hex-for-signing
ISSUER_ID=NIMC-TEST-01
ADMIN_TOKEN=your-admin-token
OTP_ENABLED=true
```

---

## Deploy Commands

```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Link project (first time)
vercel link

# 3. Add env vars
vercel env add POSTGRES_URL
vercel env add KV_REST_API_TOKEN
# ... repeat for all

# 4. Deploy
vercel --prod
```

---

## Alternative: Deploy to Fly.io / Render / Railway (Recommended)

These platforms support:
- ✅ Persistent volumes (SQLite works)
- ✅ Long-running processes (SSE, background threads)
- ✅ No cold starts
- ✅ WebSocket/SSE native support

```bash
# Fly.io (current config works)
fly launch --name yn-issuer --copy-config -c deploy/fly-issuer.toml
fly launch --name yn-verifier --copy-config -c deploy/fly-verifier.toml

# Render (Blueprint in repo)
# Push to GitHub → Render → New → Blueprint
```

---

## Figma Integration

Design tokens exported to [`figma-tokens.json`](figma-tokens.json) — compatible with:

- **Figma Tokens Studio** plugin: Import → Paste JSON
- **Figma Variables** (native): Use token values directly
- **Style Dictionary**: `npx style-dictionary build` → outputs for any platform

```bash
# Quick test in Figma
# 1. Install "Tokens Studio for Figma" plugin
# 2. Open plugin → Settings → Sync → Import JSON
# 3. Paste contents of figma-tokens.json
# 4. Tokens appear as Figma Variables / Styles
```

---

## Summary

| Platform | Effort | Verdict |
|----------|--------|---------|
| **Vercel** | High (rewrite storage, SSE, background) | Not recommended for this architecture |
| **Fly.io** | Zero (configs exist) | ✅ Recommended |
| **Render** | Zero (Blueprint exists) | ✅ Recommended |
| **Railway** | Low (add volumes) | ✅ Good alternative |

**Recommendation:** Use Fly.io or Render as configured. Vercel requires a near-complete backend rewrite to serverless patterns.