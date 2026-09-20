/* Shop service worker: precache the shop shell so the page fully loads with no
 * network. API calls (POST /verify, /challenge, /sync, /receipts) always go to
 * the network — on a real shop device that is localhost, which works offline.
 */
var CACHE = "yn-shop-v1";
var SHELL = [
  "/",
  "/static/shop.css",
  "/static/shop.js",
  "/static/app.webmanifest",
  "/static/icon.svg",
  "/static/vendor/qrcode-lib.js",
  "/static/vendor/scanutil.js",
  "/static/vendor/scanner.js",
  "/static/vendor/jsqr.min.js"
];

function isApi(url) {
  return /^\/(verify|verify_code|challenge|sync|receipts|admin|healthz|status)/.test(url.pathname);
}

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) { return cache.addAll(SHELL); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) { return k !== CACHE; })
        .map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (event) {
  var url = new URL(event.request.url);
  if (event.request.method !== "GET" || isApi(url)) return; // API: network only
  event.respondWith(
    caches.match(event.request).then(function (hit) {
      return hit || fetch(event.request).then(function (res) {
        var copy = res.clone();
        caches.open(CACHE).then(function (cache) { cache.put(event.request, copy); });
        return res;
      });
    })
  );
});
