/* scanutil.js — pure, camera-free scanning helpers.
 * Shared by the shop and holder pages; unit-tested in Node (tests/test_scanutil.mjs).
 * No DOM, no network. Works as a browser global (ScanUtil) or a Node module.
 *
 * Mirrors the server contracts: MAX_BYTES matches shared/schemas.py
 * CRED_MAX_BYTES; REQUIRED_CRED_FIELDS matches the credential shape.
 */
(function (root) {
  "use strict";

  var MAX_BYTES = 2048;

  var REQUIRED_CRED_FIELDS = ["v", "iss", "sub", "vid", "a", "r", "iat", "exp", "cnf", "s"];

  // Plain-language reason map shared by the shop UI (tested in Node).
  var REASON_MESSAGES = {
    OK: "Verified — over 18.",
    OK_OTP: "Verified by fallback code.",
    EXPIRED: "Credential expired, ask the customer to refresh.",
    REPLAY: "Copied or reused QR.",
    UNKNOWN_CHALLENGE: "Old or reused screen, scan again.",
    BAD_PROOF: "This ID isn't on the customer's device.",
    REVOKED: "This ID was revoked.",
    NOT_ADULT: "Under 18.",
    WRONG_VERIFIER: "This ID is for a different shop.",
    BADSIG: "Invalid signature — possible forgery.",
    ISSUER_MISMATCH: "Untrusted issuer for this checker.",
    MALFORMED: "Unreadable code — try again.",
    TOO_LARGE: "Code too large to be valid.",
    NO_TRUSTBUNDLE: "This checker isn't paired yet.",
    BAD_OTP: "Wrong code — ask the customer to read it again."
  };

  function validateCredential(text) {
    if (typeof text !== "string" || text.length === 0) {
      return { ok: false, error: "empty" };
    }
    if (text.length > MAX_BYTES) {
      return { ok: false, error: "too-large" };
    }
    var cred;
    try {
      cred = JSON.parse(text);
    } catch (e) {
      return { ok: false, error: "not-json" };
    }
    if (!cred || typeof cred !== "object" || Array.isArray(cred)) {
      return { ok: false, error: "not-object" };
    }
    for (var i = 0; i < REQUIRED_CRED_FIELDS.length; i++) {
      if (!(REQUIRED_CRED_FIELDS[i] in cred)) {
        return { ok: false, error: "missing-field:" + REQUIRED_CRED_FIELDS[i] };
      }
    }
    return { ok: true, cred: cred };
  }

  // A presentation QR holds {"c": credential, "p": proof}; validate the pair.
  function validatePresentation(text) {
    if (typeof text !== "string" || text.length === 0) {
      return { ok: false, error: "empty" };
    }
    if (text.length > MAX_BYTES) {
      return { ok: false, error: "too-large" };
    }
    var obj;
    try {
      obj = JSON.parse(text);
    } catch (e) {
      return { ok: false, error: "not-json" };
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      return { ok: false, error: "not-object" };
    }
    var checked = validateCredential(JSON.stringify(obj.c || null));
    if (!checked.ok) return checked;
    if (!obj.p || typeof obj.p !== "object" ||
        typeof obj.p.n !== "string" || typeof obj.p.ts !== "number" ||
        typeof obj.p.sig !== "string") {
      return { ok: false, error: "missing-proof" };
    }
    return { ok: true, c: checked.cred, p: obj.p };
  }

  function parseChallenge(text) {
    if (typeof text !== "string") return null;
    var t = text.trim();
    if (!t || t.length > 512) return null;
    try {
      var obj = JSON.parse(t);
      if (obj && typeof obj.n === "string" && obj.n) return obj;
    } catch (e) { /* not JSON: treat as a raw nonce below */ }
    if (/^[A-Za-z0-9]+$/.test(t)) return { n: t };
    return null;
  }

  var api = {
    MAX_BYTES: MAX_BYTES,
    REQUIRED_CRED_FIELDS: REQUIRED_CRED_FIELDS,
    REASON_MESSAGES: REASON_MESSAGES,
    validateCredential: validateCredential,
    validatePresentation: validatePresentation,
    parseChallenge: parseChallenge
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ScanUtil = api;
  }
})(typeof self !== "undefined" ? self : globalThis);
