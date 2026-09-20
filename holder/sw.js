/* Holder service worker: precache the app shell so the PWA fully loads and
 * functions with no network once installed. API calls (/enroll) always go to
 * the network and fail gracefully in the UI when offline.
 * Supports background sync for enrollment retry when offline.
 */
const CACHE = 'yn-holder-v2';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './static/app.css',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './static/vendor/qrcode-lib.js',
  './static/vendor/scanutil.js',
  './static/vendor/scanner.js',
  './static/vendor/jsqr.min.js'
];

const API_PATHS = ['/enroll'];

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
  const isApi = API_PATHS.some((p) => url.pathname.startsWith(p));
  if (event.request.method !== 'GET' || isApi) return; // API: network only
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

// Background sync for enrollment retry
self.addEventListener('sync', (event) => {
  if (event.tag === 'enrollment-retry') {
    event.waitUntil(retryEnrollment());
  }
});

async function retryEnrollment() {
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  clients.forEach((client) => client.postMessage({ type: 'enrollment-retry' }));
}

// Listen for messages from main thread
self.addEventListener('message', (event) => {
  if (event.data?.type === 'queue-enrollment') {
    // Store enrollment request in IndexedDB for background sync
    // This would need coordination with main thread
  }
});