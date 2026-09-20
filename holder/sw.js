/* Holder service worker: precache the app shell so the PWA fully loads and
 * functions with no network once installed. API calls (/enroll) always go to
 * the network and fail gracefully in the UI when offline.
 */
var CACHE = "yn-holder-v1";
var SHELL = [
  "./",
  "./index.html",
  "./app.js",
  "./manifest.webmanifest",
  "./static/app.css",
  "./static/icon.svg",
  "./static/icon-192.png",
  "./static/icon-512.png",
  "./static/vendor/qrcode-lib.js",
  "./static/vendor/scanutil.js",
  "./static/vendor/scanner.js",
  "./static/vendor/jsqr.min.js"
];

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
  var isApi = url.pathname.indexOf("/enroll") === 0 || url.pathname.indexOf("/otp") === 0;
  if (event.request.method !== "GET" || isApi) return; // API: network only
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
