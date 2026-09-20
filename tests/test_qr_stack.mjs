/* Node round-trip test for the vendored QR stack (no camera, no DOM).
 * Encodes with static/vendor/qrcode-lib.js, rasterizes by hand, decodes with
 * static/vendor/jsqr.min.js. A presentation-sized payload must decode EXACTLY.
 * Run: node --test tests/test_qr_stack.mjs   (also wired into CI)
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const vendor = path.join(root, "static");
// Browser script: run in global scope so `var qrcode` attaches to globalThis.
(0, eval)(fs.readFileSync(path.join(vendor, "qrcode-lib.js"), "utf8"));
const require = createRequire(import.meta.url);
const jsQR = require(path.join(vendor, "jsqr.min.js")); // absolute path: no resolution

function rasterize(qr, scale = 6, quietModules = 4) {
  const n = qr.getModuleCount();
  const size = (n + quietModules * 2) * scale;
  const px = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!qr.isDark(r, c)) continue;
      for (let y = 0; y < scale; y++) {
        for (let x = 0; x < scale; x++) {
          const i = (r + quietModules) * scale + y;
          const j = (c + quietModules) * scale + x;
          const o = (i * size + j) * 4;
          px[o] = px[o + 1] = px[o + 2] = 0;
          px[o + 3] = 255;
        }
      }
    }
  }
  return { px, size };
}

function qrDecode(text) {
  const qr = globalThis.qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const { px, size } = rasterize(qr);
  const out = jsQR(px, size, size);
  assert.ok(out, "jsQR must detect the code");
  return out.data;
}

describe("vendored QR stack", () => {
  it("round-trips a presentation-sized payload exactly", () => {
    const text = JSON.stringify({
      c: {
        v: 1, iss: "NIMC-TEST-01", sub: "ab".repeat(16), vid: "SHOP-A",
        a: "over_18", r: 1, iat: 100, exp: 9999999999, cnf: "Z".repeat(86), s: "Y".repeat(86)
      },
      p: { n: "f".repeat(32), ts: 1999999999, sig: "Z".repeat(86) }
    });
    assert.ok(text.length > 400, "payload should be realistically large");
    assert.ok(text.length < 2048, "payload must fit the 2048-byte cap");
    assert.equal(qrDecode(text), text);
  });

  it("round-trips a short challenge payload", () => {
    const text = JSON.stringify({ n: "9f3a2b1c4d5e6f70", vid: "SHOP-A", exp: 9999 });
    assert.equal(qrDecode(text), text);
  });
});
