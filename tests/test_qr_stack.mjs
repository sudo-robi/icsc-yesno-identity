/* Node round-trip test for the vendored QR stack (no camera, no DOM).
 * Encodes with static/qrcode-lib.js, rasterizes by hand, decodes with
 * static/jsqr.min.js. A credential-sized payload must decode EXACTLY.
 * Run: node --test tests/test_qr_stack.mjs   (also wired into CI)
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
// Browser script: run in global scope so `var qrcode` attaches to globalThis.
(0, eval)(fs.readFileSync(path.join(root, "static/qrcode-lib.js"), "utf8"));
const require = createRequire(import.meta.url);
const jsQR = require("../static/jsqr.min.js");

function rasterize(qr, scale = 8, quietModules = 4) {
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

describe("vendored QR stack", () => {
  it("round-trips a credential-sized payload exactly", () => {
    const text = JSON.stringify({
      v: 1, iss: "NIMC-TEST-01", uid_p: "a3f9c1e2b4d5a607",
      a: "over_18", r: 1, exp: 1999999999, n: "f".repeat(32), s: "Z".repeat(86)
    });
    assert.ok(text.length > 200, "payload should be realistically large");
    const qr = globalThis.qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const { px, size } = rasterize(qr);
    const out = jsQR(px, size, size);
    assert.ok(out, "jsQR must detect the code");
    assert.equal(out.data, text);
  });

  it("round-trips a short challenge nonce", () => {
    const qr = globalThis.qrcode(0, "M");
    qr.addData("9f3a2b1c4d5e6f70");
    qr.make();
    const { px, size } = rasterize(qr);
    assert.equal(jsQR(px, size, size).data, "9f3a2b1c4d5e6f70");
  });
});
