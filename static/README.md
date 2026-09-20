# Vendored runtime libraries (offline-first: no CDN, ever)

Per-app copies live under `holder/static/vendor/` and `verifier/static/vendor/`
so each app is self-contained (PWA precache, Flask static). This directory
holds the canonical copies plus the shared scanner sources.

| File | Project | License | Source | Fetched |
|------|---------|---------|--------|---------|
| `qrcode-lib.js` | qrcode-generator (kazuhikoarase) | MIT | https://github.com/kazuhikoarase/qrcode-generator (`js/dist/qrcode.js`) | 2026-09-20 |
| `jsqr.min.js` | jsQR (cozmo) v1.4.0 | Apache-2.0 | https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js | 2026-09-20 |
| `scanutil.js` | own code | MIT (this repo) | — | — |
| `scanner.js` | own code (holder/verifier copies) | MIT (this repo) | — | — |

`qrcode-lib.js` keeps its upstream MIT header. `jsqr.min.js`'s Apache-2.0 grant
is in the upstream LICENSE, attributed here. Verified with a Node round-trip
(`tests/test_qr_stack.mjs`): encode with qrcode-generator, rasterize, decode
with jsQR — a presentation-sized payload decodes exactly. Re-run
`node --test tests/` after any update.
