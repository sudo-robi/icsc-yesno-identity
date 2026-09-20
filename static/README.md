# Vendored runtime libraries (offline-first: no CDN, ever)

| File | Project | License | Source | Fetched |
|------|---------|---------|--------|---------|
| `qrcode-lib.js` | qrcode-generator (kazuhikoarase) | MIT | https://github.com/kazuhikoarase/qrcode-generator (`js/dist/qrcode.js`) | 2026-09-20 |
| `jsqr.min.js` | jsQR (cozmo) v1.4.0 | Apache-2.0 | https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js | 2026-09-20 |

Both files are byte-identical to upstream (license headers intact; jsQR's
Apache-2.0 grant is in the project's LICENSE, attributed here). Verified with
a Node round-trip (`tests/test_qr_stack.mjs`): encode with qrcode-generator,
rasterize, decode with jsQR — realistic credential payload decodes exactly.
Re-verify after any update with `node --test tests/`.
