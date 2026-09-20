// API wrapper for holder app
let issuerUrl = 'http://localhost:5001';

export function setIssuerUrl(url) {
  issuerUrl = url.replace(/\/+$/, '');
}

export function getIssuerUrl() {
  return issuerUrl;
}

export async function apiPost(path, body) {
  const res = await fetch(issuerUrl + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (e) {}
  return { status: res.status, ok: res.ok, data };
}

export function enrollError(status, data) {
  if (status === 404 || (data && data.error === 'UNKNOWN_CODE')) return 'Unknown enrollment code.';
  if (data && data.error === 'CODE_USED') return 'This code was already used — ask for a new one.';
  if (data && data.error === 'CODE_EXPIRED') return 'This code expired — ask for a new one.';
  if (status === 403) return 'This ID is revoked and cannot be enrolled.';
  if (data && data.error === 'BAD_PUBKEY') return "This browser couldn't make a key. Try another.";
  if (status === 429) return 'Too many tries — wait a minute.';
  return `Enrollment failed (${status}). Check the Issuer URL.`;
}