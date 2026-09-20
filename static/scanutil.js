/* scanutil.js — pure, camera-free scanning helpers.
 * Shared by the shop and holder pages; unit-tested in Node (tests/test_scanutil.mjs).
 * No DOM, no network. Works as a browser global (ScanUtil) or a Node module.
 */
(function (root) {
  "use strict";

  // Must match shared/schemas.py CRED_MAX_BYTES (server rejects above it anyway).
  var MAX_BYTES = 4096;

  var REQUIRED_CRED_FIELDS = ["v", "iss", "uid_p", "a", "r", "exp", "s"];

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

  function parseChallenge(text) {
    if (typeof text !== "string") return null;
    var t = text.trim();
    if (!t || t.length > 64) return null;
    try {
      var obj = JSON.parse(t);
      if (obj && typeof obj.nonce === "string" && obj.nonce) return obj.nonce;
    } catch (e) { /* not JSON: treat as a raw nonce below */ }
    if (/^[A-Za-z0-9]+$/.test(t)) return t;
    return null;
  }

  var api = {
    MAX_BYTES: MAX_BYTES,
    REQUIRED_CRED_FIELDS: REQUIRED_CRED_FIELDS,
    validateCredential: validateCredential,
    parseChallenge: parseChallenge
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ScanUtil = api;
  }
})(typeof self !== "undefined" ? self : globalThis);
