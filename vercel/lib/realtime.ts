// Realtime integration for Vercel (replaces SSE)
// Uses Ably for real-time revocation/rotation push to verifiers
// If ABLY_API_KEY is not set, functions become no-ops

import type { VerifierConfig } from './kv.js';

let ablyClient: any = null;
let verifierConfig: VerifierConfig | null = null;

function getAblyClass(): any {
  try {
    return require('@ably/ably-js').Ably;
  } catch {
    return null;
  }
}

export function getAblyClient(): any {
  return ablyClient;
}

export async function initRealtime(config: VerifierConfig): Promise<void> {
  verifierConfig = config;
  
  if (!config.issuerUrl) {
    console.warn('No ISSUER_URL configured, realtime disabled');
    return;
  }
  
  const ablyKey = process.env.ABLY_API_KEY;
  if (!ablyKey) {
    console.warn('No ABLY_API_KEY configured, realtime disabled');
    return;
  }
  
  const Ably = getAblyClass();
  if (!Ably) {
    console.warn('@ably/ably-js not installed, realtime disabled');
    return;
  }
  
  ablyClient = new Ably({ key: ablyKey, clientId: `verifier-${config.verifierId}` });
  
  const channel = ablyClient.channels.get('issuer-events');
  
  await channel.subscribe('revocation', async () => {
    await handleBundleUpdate();
  });
  
  await channel.subscribe('rotation', async () => {
    await handleBundleUpdate();
  });
  
  await channel.subscribe('bundle_update', async () => {
    await handleBundleUpdate();
  });
  
  setInterval(() => {
    channel.publish('heartbeat', { ts: Date.now() });
  }, 30000);
  
  console.log('Ably realtime initialized for', config.verifierId);
}

async function handleBundleUpdate(): Promise<void> {
  if (!verifierConfig || !verifierConfig.issuerUrl) return;
  
  try {
    const response = await fetch(`${verifierConfig.issuerUrl}/bundle?vid=${verifierConfig.verifierId}`);
    if (!response.ok) {
      console.error('Failed to fetch bundle:', response.status);
      return;
    }
    
    const bundle: any = await response.json();
    
    const { getTrustBundle, setTrustBundle } = await import('./kv.js');
    const { checkBundle } = await import('./verify.js');
    
    const pinned = await getTrustBundle(verifierConfig.verifierId);
    const { accepted } = await checkBundle(bundle, pinned, Date.now() / 1000);
    
    if (accepted) {
      await setTrustBundle(verifierConfig.verifierId, bundle);
      console.log('Bundle synced via Ably:', bundle.v);
    } else {
      console.error('Bundle rejected via Ably');
    }
  } catch (error) {
    console.error('Bundle sync error:', error);
  }
}

export async function closeRealtime(): Promise<void> {
  if (ablyClient) {
    await ablyClient.close();
    ablyClient = null;
  }
}

// ============================================================================
// Issuer-side: publish events (called from issuer API routes)
// ============================================================================

export async function publishRevocation(version: number, userId: string): Promise<void> {
  const ablyKey = process.env.ABLY_API_KEY;
  if (!ablyKey) return;
  
  const Ably = getAblyClass();
  if (!Ably) return;
  
  const ably = new Ably({ key: ablyKey, clientId: 'issuer' });
  const channel = ably.channels.get('issuer-events');
  
  await channel.publish('revocation', { v: version, user_id: userId });
  await ably.close();
}

export async function publishRotation(version: number, pub: string): Promise<void> {
  const ablyKey = process.env.ABLY_API_KEY;
  if (!ablyKey) return;
  
  const Ably = getAblyClass();
  if (!Ably) return;
  
  const ably = new Ably({ key: ablyKey, clientId: 'issuer' });
  const channel = ably.channels.get('issuer-events');
  
  await channel.publish('rotation', { v: version, pub });
  await ably.close();
}

export async function publishBundleUpdate(version: number): Promise<void> {
  const ablyKey = process.env.ABLY_API_KEY;
  if (!ablyKey) return;
  
  const Ably = getAblyClass();
  if (!Ably) return;
  
  const ably = new Ably({ key: ablyKey, clientId: 'issuer' });
  const channel = ably.channels.get('issuer-events');
  
  await channel.publish('bundle_update', { v: version });
  await ably.close();
}