/* Node unit tests for static/scanutil.js (no camera, no DOM).
 * Run: node --test tests/test_scanutil.mjs   (also wired into CI)
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import ScanUtil from "../static/scanutil.js";

const { validateCredential, validatePresentation, parseChallenge,
        REASON_MESSAGES, MAX_BYTES, REQUIRED_CRED_FIELDS } = ScanUtil;

const GOOD_CRED = JSON.stringify({
  v: 1, iss: "NIMC-TEST-01", sub: "ab".repeat(16), vid: "SHOP-A",
  a: "over_18", r: 1, iat: 100, exp: 9999999999, cnf: "k", s: "sig"
});
const GOOD_PROOF = { n: "abc123", ts: 1000, sig: "sig" };

describe("validateCredential", () => {
  it("accepts a well-formed credential", () => {
    const r = validateCredential(GOOD_CRED);
    assert.equal(r.ok, true);
    assert.equal(r.cred.sub, "ab".repeat(16));
  });

  it("requires the new contract fields", () => {
    assert.deepEqual(REQUIRED_CRED_FIELDS.sort(),
      ["a", "cnf", "exp", "iat", "iss", "r", "s", "sub", "v", "vid"].sort());
  });

  it("rejects empty / non-string input", () => {
    assert.equal(validateCredential("").ok, false);
    assert.equal(validateCredential(null).ok, false);
    assert.equal(validateCredential(42).ok, false);
  });

  it("caps payload size at the server limit before parsing", () => {
    const r = validateCredential("x".repeat(5000));
    assert.equal(r.ok, false);
    assert.equal(r.error, "too-large");
    assert.equal(MAX_BYTES, 2048);
  });

  it("rejects malformed JSON and non-objects", () => {
    assert.equal(validateCredential("{oops").error, "not-json");
    assert.equal(validateCredential("[1,2]").error, "not-object");
    assert.equal(validateCredential("42").error, "not-object");
  });

  it("names the first missing field", () => {
    const slim = JSON.parse(GOOD_CRED);
    delete slim.cnf;
    const r = validateCredential(JSON.stringify(slim));
    assert.equal(r.ok, false);
    assert.equal(r.error, "missing-field:cnf");
  });
});

describe("validatePresentation", () => {
  const good = JSON.stringify({ c: JSON.parse(GOOD_CRED), p: GOOD_PROOF });

  it("accepts a well-formed {c, p} presentation", () => {
    const r = validatePresentation(good);
    assert.equal(r.ok, true);
    assert.equal(r.p.n, "abc123");
  });

  it("rejects missing/bad proofs and oversize blobs", () => {
    assert.equal(validatePresentation(JSON.stringify({ c: JSON.parse(GOOD_CRED) })).error,
      "missing-proof");
    assert.equal(validatePresentation(JSON.stringify(
      { c: JSON.parse(GOOD_CRED), p: { n: "x" } })).error, "missing-proof");
    assert.equal(validatePresentation("x".repeat(5000)).error, "too-large");
    assert.equal(validatePresentation("{oops").error, "not-json");
  });
});

describe("parseChallenge", () => {
  it("accepts full challenge JSON", () => {
    const ch = JSON.stringify({ n: "abc123", vid: "SHOP-A", exp: 9999 });
    assert.deepEqual(parseChallenge(ch), { n: "abc123", vid: "SHOP-A", exp: 9999 });
  });

  it("accepts raw nonce strings", () => {
    assert.deepEqual(parseChallenge("9f3a2b"), { n: "9f3a2b" });
  });

  it("rejects junk, blanks and oversize input", () => {
    assert.equal(parseChallenge(""), null);
    assert.equal(parseChallenge("  "), null);
    assert.equal(parseChallenge("<svg></svg>"), null);
    assert.equal(parseChallenge("has space"), null);
    assert.equal(parseChallenge("x".repeat(513)), null);
    assert.equal(parseChallenge(null), null);
    assert.equal(parseChallenge('{"nope":1}'), null);
  });
});

describe("REASON_MESSAGES", () => {
  it("covers every verifier decision code in plain language", () => {
    for (const code of ["OK", "OK_OTP", "EXPIRED", "UNKNOWN_CHALLENGE", "BAD_PROOF",
                        "REVOKED", "NOT_ADULT", "WRONG_VERIFIER", "BADSIG",
                        "ISSUER_MISMATCH", "MALFORMED", "TOO_LARGE",
                        "NO_TRUSTBUNDLE", "BAD_OTP"]) {
      assert.ok(REASON_MESSAGES[code], `missing message for ${code}`);
      assert.ok(REASON_MESSAGES[code].length > 5);
    }
  });
});
