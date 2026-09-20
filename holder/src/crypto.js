// Crypto helpers for holder app
export function b64uEncode(bytes) {
  let bin = '';
  bytes.forEach(b => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function canonicalJSON(value) {
  if (typeof value === 'number' && !Number.isInteger(value)) throw new Error('no-floats');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => {
    return JSON.stringify(k) + ':' + canonicalJSON(value[k]);
  }).join(',') + '}';
}

export async function sha256hexBytes(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map(b =>
    b.toString(16).padStart(2, '0')
  ).join('');
}

export function stripSig(cred) {
  const out = {};
  Object.keys(cred).forEach(k => { if (k !== 's') out[k] = cred[k]; });
  return out;
}

export async function hmacCode(keyBytes, msg) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
  const hex = Array.from(mac).map(b => b.toString(16).padStart(2, '0')).join('');
  return String(parseInt(hex, 16) % 1000000).padStart(6, '0');
}

export async function generateKey() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}