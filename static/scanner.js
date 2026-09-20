/* scanner.js — shared QR camera component (shop + holder pages).
 * Plain script, no build step. Needs ScanUtil (scanutil.js) loaded first.
 * Backend order: BarcodeDetector when available, else vendored jsQR on canvas
 * frames. All UI text flows through callbacks so pages own their messaging.
 *
 * Usage:
 *   var s = Scanner.create({ video: videoEl, onResult: fn(text), onNotice: fn(msg) });
 *   s.start(); // -> {ok:true} or {ok:false, reason:'denied'|'missing'|'insecure'|'busy'|'unsupported'}
 *   s.stop(); s.nextCamera(); s.toggleTorch();
 */
(function (root) {
  "use strict";

  function createScanner(opts) {
    var video = opts.video;
    var onResult = opts.onResult || function () {};
    var onNotice = opts.onNotice || function () {};
    var intervalMs = opts.intervalMs || 450;
    var cooldownMs = opts.cooldownMs || 7000;

    var stream = null, timer = null, scanning = false;
    var lastText = "", lastAt = 0, busy = false;
    var deviceIds = [], deviceIdx = 0, torchOn = false;
    var canvas = document.createElement("canvas");
    var ctx = canvas.getContext("2d", { willReadFrequently: true });

    function hasCameraAPI() {
      return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
    }

    function decodeFrame() {
      // Preferred: native BarcodeDetector. Fallback: vendored jsQR.
      if (typeof BarcodeDetector !== "undefined") {
        return new BarcodeDetector({ formats: ["qr_code"] }).detect(video)
          .then(function (hits) {
            return (hits.length && hits[0].rawValue) || null;
          });
      }
      if (typeof jsQR === "undefined") return Promise.resolve(null);
      var w = video.videoWidth, h = video.videoHeight;
      if (!w || !h) return Promise.resolve(null);
      canvas.width = w; canvas.height = h;
      ctx.drawImage(video, 0, 0, w, h);
      try {
        var hit = jsQR(ctx.getImageData(0, 0, w, h).data, w, h);
        return Promise.resolve(hit && hit.data ? hit.data : null);
      } catch (e) { return Promise.resolve(null); }
    }

    function poll() {
      if (!scanning || busy || video.readyState !== 4) return;
      decodeFrame().then(function (text) {
        if (!scanning || !text) return;
        var now = Date.now();
        if (text === lastText && now - lastAt < cooldownMs) return; // debounce
        lastText = text; lastAt = now;
        busy = true;
        try { onResult(text); } finally { busy = false; }
      }).catch(function () { /* frame hiccup: keep scanning */ });
    }

    function openStream(deviceId) {
      var constraints = { video: { facingMode: "environment" } };
      if (deviceId) constraints = { video: { deviceId: { exact: deviceId } } };
      return navigator.mediaDevices.getUserMedia(constraints).then(function (st) {
        stream = st;
        video.srcObject = stream;
        return video.play().then(function () { return st; });
      });
    }

    var api = {
      backend: function () {
        if (!hasCameraAPI()) return "none";
        return (typeof BarcodeDetector !== "undefined") ? "native" : "jsqr";
      },
      isScanning: function () { return scanning; },
      torchSupported: function () {
        var track = stream && stream.getVideoTracks()[0];
        return !!(track && track.getCapabilities && track.getCapabilities().torch);
      },
      start: function () {
        if (scanning) return Promise.resolve({ ok: true });
        if (!window.isSecureContext) return Promise.resolve({ ok: false, reason: "insecure" });
        if (!hasCameraAPI()) return Promise.resolve({ ok: false, reason: "missing" });
        if (typeof BarcodeDetector === "undefined" && typeof jsQR === "undefined") {
          return Promise.resolve({ ok: false, reason: "unsupported" });
        }
        var startWith = deviceIds.length ? deviceIds[deviceIdx] : null;
        return openStream(startWith).then(function () {
          scanning = true;
          timer = setInterval(poll, intervalMs);
          return { ok: true };
        }).catch(function (err) {
          if (err && (err.name === "NotAllowedError" || err.name === "SecurityError")) {
            return { ok: false, reason: "denied" };
          }
          if (err && err.name === "NotReadableError") {
            return { ok: false, reason: "busy" };
          }
          return { ok: false, reason: "missing" };
        });
      },
      stop: function () {
        scanning = false;
        if (timer) { clearInterval(timer); timer = null; }
        if (stream) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          stream = null;
        }
        video.srcObject = null;
        torchOn = false;
      },
      nextCamera: function () {
        if (deviceIds.length < 2 || !scanning) return Promise.resolve(false);
        deviceIdx = (deviceIdx + 1) % deviceIds.length;
        api.stop();
        return api.start().then(function (r) { return r.ok; });
      },
      toggleTorch: function () {
        var track = stream && stream.getVideoTracks()[0];
        if (!track || !track.getCapabilities || !track.getCapabilities().torch) {
          return Promise.resolve(false);
        }
        torchOn = !torchOn;
        return track.applyConstraints({ advanced: [{ torch: torchOn }] })
          .then(function () { return torchOn; })
          .catch(function () { return false; });
      },
      refreshCameras: function () {
        if (!hasCameraAPI() || !navigator.mediaDevices.enumerateDevices) {
          return Promise.resolve([]);
        }
        return navigator.mediaDevices.enumerateDevices().then(function (devs) {
          deviceIds = devs.filter(function (d) { return d.kind === "videoinput"; })
            .map(function (d) { return d.deviceId; });
          deviceIdx = 0;
          return deviceIds;
        }).catch(function () { return []; });
      }
    };

    // Release the camera when the page hides/unloads (spec: never hold it).
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) api.stop();
    });
    window.addEventListener("pagehide", function () { api.stop(); });

    return api;
  }

  function drawQR(canvas, text) {
    // Canvas QR via the vendored lib (no HTML parsing of server data).
    if (typeof qrcode === "undefined") return false;
    var ctx = canvas.getContext("2d");
    var size = canvas.width, quiet = Math.round(size * 0.05);
    ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, size, size);
    try {
      var qr = qrcode(0, "M");
      qr.addData(text);
      qr.make();
      var n = qr.getModuleCount();
      var cell = (size - quiet * 2) / n;
      ctx.fillStyle = "#000000";
      for (var r = 0; r < n; r++)
        for (var c = 0; c < n; c++)
          if (qr.isDark(r, c)) ctx.fillRect(quiet + c * cell, quiet + r * cell, cell + 1, cell + 1);
      return true;
    } catch (e) { return false; }
  }

  var exports_ = { createScanner: createScanner, drawQR: drawQR };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = exports_;
  } else {
    root.QRScanner = exports_;
  }
})(typeof self !== "undefined" ? self : globalThis);
