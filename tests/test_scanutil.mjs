/* Node unit tests for static/scanutil.js (no camera, no DOM).
 * Run: node --test tests/test_scanutil.mjs   (also wired into CI)
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import ScanUtil from "../static/scanutil.js";

const { validateCredential, parseChallenge, MAX_BYTES } = ScanUtil;

const GOOD = JSON.stringify({
  v: 1, iss: "NIMC-TEST-01", uid_p: "abcd1234efgh5678",
  a: "over_18", r: 1, exp: 9999999999, s: "sig"
});

describe("validateCredential", () => {
  it("accepts a well-formed credential", () => {
    const r = validateCredential(GOOD);
    assert.equal(r.ok, true);
    assert.equal(r.cred.uid_p, "abcd1234efgh5678");
  });

  it("rejects empty / non-string input", () => {
    assert.equal(validateCredential("").ok, false);
    assert.equal(validateCredential(null).ok, false);
    assert.equal(validateCredential(42).ok, false);
  });

  it("caps payload size at the server limit before parsing", () => {
    // 5000 x's is not JSON — must fail on SIZE, not on parse, so a giant
    // blob never reaches the parser.
    const r = validateCredential("x".repeat(5000));
    assert.equal(r.ok, false);
    assert.equal(r.error, "too-large");
    assert.equal(MAX_BYTES, 4096);
  });

  it("rejects malformed JSON and non-objects", () => {
    assert.equal(validateCredential("{oops").error, "not-json");
    assert.equal(validateCredential("[1,2]").error, "not-object");
    assert.equal(validateCredential("42").error, "not-object");
  });

  it("names the first missing field", () => {
    const slim = JSON.parse(GOOD);
    delete slim.s;
    const r = validateCredential(JSON.stringify(slim));
    assert.equal(r.ok, false);
    assert.equal(r.error, "missing-field:s");
  });
});

describe("parseChallenge", () => {
  it("accepts raw nonce strings", () => {
    assert.equal(parseChallenge("9f3a2b"), "9f3a2b");
  });

  it("accepts JSON-wrapped nonces", () => {
    assert.equal(parseChallenge('{"nonce":"abc123"}'), "abc123");
  });

  it("rejects junk, blanks and oversize input", () => {
    assert.equal(parseChallenge(""), null);
    assert.equal(parseChallenge("  "), null);
    assert.equal(parseChallenge("<svg></svg>"), null);
    assert.equal(parseChallenge("has space"), null);
    assert.equal(parseChallenge("x".repeat(65)), null);
    assert.equal(parseChallenge(null), null);
    assert.equal(parseChallenge('{"nope":1}'), null);
  });
});
