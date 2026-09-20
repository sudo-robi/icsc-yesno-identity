/* Shop service worker: precache the shop shell so the page fully loads with no
 * network. API calls (POST /verify, /challenge, /sync, /receipts) always go to
 * the network — on a real shop device that is localhost, which works offline.
 * Supports wake lock for camera scanning sessions.
 */
const CACHE = 'yn-shop-v2';
const SHELL = [
  '/',
  '/static/shop.css',
  '/static/shop.js',
  '/static/app.webmanifest',
  '/static/icon.svg',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/vendor/qrcode-lib.js',
  '/static/vendor/scanutil.js',
  '/static/vendor/scanner.js',
  '/static/vendor/jsqr.min.js'
];

function isApi(url) {
  return /^\/(verify|verify_code|challenge|sync|receipts|admin|healthz|status)/.test(url.pathname);
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || isApi(url)) return; // API: network only
  event.respondWith(
    caches.match(event.request).then((hit) =>
      hit || fetch(event.request).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return res;
      })
    )
  );
});

// Wake lock is handled in main thread via navigator.wakeLock
// SW can't directly request wake lock but can persist state

// Background sync for challenge refresh
self.addEventListener('sync', (event) => {
  if (event.tag === 'challenge-refresh') {
    event.waitUntil(refreshChallengeInBackground());
  }
});

async function refreshChallengeInBackground() {
  try {
    const res = await fetch('/challenge');
    const data = await res.json();
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    clients.forEach((client) => client.postMessage({ type: 'challenge-updated', nonce: data.nonce }));
  } catch (e) {
    // Offline, will retry on next sync
  }
}