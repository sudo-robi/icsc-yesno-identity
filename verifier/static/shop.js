/* Shop app: scan -> verify -> full-screen result. Plain script, no modules.
 * All server/client text via textContent — never innerHTML.
 */
"use strict";

var scanner = null, resetTimer = null;

function $(id){ return document.getElementById(id); }
function say(msg){ $("msg").textContent = msg; }
function reasons(){ return (window.ScanUtil && ScanUtil.REASON_MESSAGES) || {}; }

function showResult(ok, word, icon, why){
  var box = $("result");
  box.className = "show " + (ok ? "yes" : "no");
  $("resultIcon").textContent = icon;
  $("resultWord").textContent = word;
  $("resultWord").style.color = ok ? "var(--ok)" : "var(--no)";
  $("resultWhy").textContent = why;
  if (resetTimer) clearTimeout(resetTimer);
  resetTimer = setTimeout(hideResult, 4000);
}
function hideResult(){ $("result").className = ""; }

async function api(path, opts){
  var res = await fetch(path, opts);
  var text = await res.text();
  try { return {status: res.status, ok: res.ok, json: JSON.parse(text)}; }
  catch (e) { return {status: res.status, ok: false, json: null}; }
}

async function refreshStatus(){
  try {
    var r = await api("/healthz");
    var tb = $("trustBadge");
    if (r.ok && r.json.trust) {
      tb.textContent = "Trust bundle v" + r.json.v + " loaded";
      tb.className = "badge ok";
    } else {
      tb.textContent = "Trust bundle missing — pair this checker";
      tb.className = "badge bad";
    }
  } catch (e) {
    $("trustBadge").textContent = "Trust: ?"; $("trustBadge").className = "badge";
  }
  try {
    var s = await api("/status");
    if (s.ok && s.json.paired && s.json.bundle_exp) {
      var days = Math.max(0, Math.round((s.json.bundle_exp - Date.now() / 1000) / 86400));
      $("trustBadge").textContent += ", expires in " + days + "d";
    }
  } catch (e) { /* status optional */ }
  var online = navigator.onLine;
  var nb = $("netBadge");
  nb.textContent = online ? "Online" : "Offline — checks still work";
  nb.className = "badge " + (online ? "ok" : "bad");
}
window.addEventListener("online", refreshStatus);
window.addEventListener("offline", refreshStatus);

async function freshChallenge(auto){
  try {
    var r = await api("/challenge");
    var nonce = r.json.nonce;
    $("nonce").textContent = nonce;
    var challenge = JSON.stringify({n: nonce, vid: document.title.replace("Shop check — ", ""), exp: 0});
    if (window.QRScanner) QRScanner.drawQR($("challengeQR"), challenge);
  } catch (e) {
    if (!auto) say("Couldn't fetch a challenge — check the connection.");
    $("nonce").textContent = "unavailable";
  }
}

function currentNonce(){
  var t = $("nonce").textContent;
  return (t && t !== "…" && t !== "unavailable") ? t : "";
}

async function doVerify(presentationText){
  var check = window.ScanUtil
    ? ScanUtil.validatePresentation(presentationText)
    : {ok: false, error: "no-validator"};
  if (!check.ok) {
    showResult(false, "NO", "✕",
      check.error === "too-large" ? reasons().TOO_LARGE
      : "That doesn't look like an ID QR — keep scanning.");
    return;
  }
  var btn = $("verifyBtn"); btn.disabled = true; say("Checking…");
  hideResult();
  try {
    // NOTE: only {c, p} go over the wire. The proof already carries the
    // challenge nonce the shop fetched above, which the server registered.
    var res = await fetch("/verify", {method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({c: check.c, p: check.p})});
    var text = await res.text(), j = null;
    try { j = JSON.parse(text); } catch (e) {}
    if (!j) showResult(false, "NO", "✕", "Checker gave an unclear answer. Try again.");
    else if (j.result === "YES") showResult(true, "YES", "✓", reasons()[j.reason] || j.reason);
    else showResult(false, "NO", "✕", reasons()[j.reason] || ("Refused (" + j.reason + ")."));
  } catch (e) {
    showResult(false, "NO", "✕", "Can't reach the checker. It may be restarting.");
  } finally { btn.disabled = false; say(""); loadRecent(); }
}

/* ---- camera ---- */
function scannerReady(){ return !!(window.QRScanner && window.ScanUtil); }

function describeStartFailure(reason){
  return {
    insecure: "Camera needs HTTPS or localhost — paste the code instead (see README).",
    denied: "Camera blocked. Allow access in the browser, or paste the code instead.",
    busy: "Camera is in use by another app. Close it or paste the code instead.",
    missing: "No camera found — paste the code instead.",
    unsupported: "This browser can't scan — paste the code instead."
  }[reason] || "Camera unavailable — paste the code instead.";
}

async function toggleScan(){
  if (scanner && scanner.isScanning()) { stopScanUI(); return; }
  if (!scannerReady()) { say(describeStartFailure("unsupported")); return; }
  scanner = QRScanner.createScanner({
    video: $("video"),
    onResult: function (text) {
      var check = ScanUtil.validatePresentation(text);
      if (!check.ok) {
        say(check.error === "too-large" ? reasons().TOO_LARGE
          : "That doesn't look like an ID QR — keep scanning.");
        return; // keep scanning
      }
      stopScanUI();
      doVerify(text);
    }
  });
  $("backendNote").textContent = scanner.backend() === "native"
    ? "Fast native scan." : scanner.backend() === "jsqr"
    ? "Compatibility scan (slower)." : "";
  var cams = await scanner.refreshCameras();
  $("switchBtn").hidden = cams.length < 2;
  $("videoWrap").hidden = false;
  var r = await scanner.start();
  if (!r.ok) {
    stopScanUI();
    say(describeStartFailure(r.reason));
    return;
  }
  $("scanBtn").textContent = "Stop camera";
  $("torchBtn").hidden = !scanner.torchSupported();
  say("Point the camera at the QR code.");
}
function stopScanUI(){
  if (scanner) scanner.stop();
  $("videoWrap").hidden = true;
  $("scanBtn").textContent = "Start camera";
  $("torchBtn").hidden = true;
}
async function toggleTorch(){
  if (!scanner) return;
  var on = await scanner.toggleTorch();
  $("torchBtn").textContent = on ? "Torch: on" : "Torch: off";
}
async function switchCamera(){
  if (!scanner) return;
  if (!await scanner.nextCamera()) say("Couldn't switch camera.");
  else if (!scanner.torchSupported()) $("torchBtn").hidden = true;
}
function verifyPasted(){
  var t = $("credInput").value.trim();
  if (!t) { say("Paste the customer's code first, or start the camera."); return; }
  doVerify(t);
}

/* ---- admin drawer (token in memory only) ---- */
function adminHeaders(){
  var h = {"Content-Type": "application/json"};
  var t = $("adminToken").value;
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}
async function loadAdminReceipts(){
  var box = $("adminReceipts");
  while (box.firstChild) box.removeChild(box.firstChild);
  var res;
  try {
    res = await fetch("/receipts", {headers: adminHeaders()});
  } catch (e) { say("Can't reach the checker."); return; }
  if (res.status === 401 || res.status === 403) {
    say("Enter the admin token to view receipts."); return;
  }
  var data = await res.json();
  var p = document.createElement("p");
  p.className = "muted";
  p.textContent = "Chain head: " + ((data.head && data.head.head) || "empty");
  box.appendChild(p);
  var table = document.createElement("table");
  var head = document.createElement("tr");
  ["Time", "Result", "Reason"].forEach(function(h){
    var th = document.createElement("th"); th.textContent = h; head.appendChild(th);
  });
  table.appendChild(head);
  (data.rows || []).slice(0, 20).forEach(function(row){
    var tr = document.createElement("tr");
    [new Date(row.ts * 1000).toLocaleString(), row.result, row.reason].forEach(function(v){
      var td = document.createElement("td"); td.textContent = v; tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  box.appendChild(table);
}
async function exportCsv(){
  var res;
  try { res = await fetch("/receipts.csv", {headers: adminHeaders()}); }
  catch (e) { say("Can't reach the checker."); return; }
  if (res.status === 401 || res.status === 403) {
    say("Enter the admin token to export."); return;
  }
  var blob = await res.blob();
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "receipts.csv";
  document.body.appendChild(a);
  a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
async function syncBundle(){
  var text = $("bundleInput").value.trim();
  if (!text) { say("Paste a signed bundle first."); return; }
  var bundle;
  try { bundle = JSON.parse(text); }
  catch (e) { say("That isn't valid JSON."); return; }
  var res;
  try {
    res = await fetch("/sync", {method: "POST", headers: adminHeaders(),
      body: JSON.stringify(bundle)});
  } catch (e) { say("Can't reach the checker."); return; }
  if (res.status === 401 || res.status === 403) { say("Wrong or missing admin token."); return; }
  var j = await res.json();
  if (res.ok) {
    say(j.tofu ? "Paired. Confirm the key fingerprint out-of-band!" : "Bundle synced, v" + j.v + ".");
    refreshStatus();
  } else {
    say("Sync refused: " + (j.error || res.status) + ".");
  }
}

/* ---- recent checks ---- */
async function loadRecent(){
  try {
    var r = await api("/receipts");
    if (!r.ok || !r.json.length) return;
    var tb = $("recentBody");
    while (tb.firstChild) tb.removeChild(tb.firstChild);
    r.json.slice(0, 5).forEach(function(row){
      var tr = document.createElement("tr");
      [[new Date(row.ts * 1000).toLocaleTimeString()],
       [row.result], [(row.q || "").split(":")[1] || "—"]].forEach(function(pair, i){
        var td = document.createElement("td");
        td.textContent = pair[0];
        if (i === 1) td.style.color = pair[0] === "YES" ? "var(--ok)" : "var(--no)";
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
  } catch (e) { /* receipts need admin; optional here */ }
}

/* ---- init (no inline handlers: CSP script-src 'self') ---- */
(function init(){
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function(){
      navigator.serviceWorker.register("/sw-shop.js").catch(function(){});
    });
  }
  // /receipts is admin-gated; the public recent list degrades silently.
  $("verifyBtn").addEventListener("click", verifyPasted);
  $("scanBtn").addEventListener("click", toggleScan);
  $("torchBtn").addEventListener("click", toggleTorch);
  $("switchBtn").addEventListener("click", switchCamera);
  $("nonceBtn").addEventListener("click", function(){ freshChallenge(false); });
  $("receiptsBtn").addEventListener("click", loadAdminReceipts);
  $("csvBtn").addEventListener("click", exportCsv);
  $("syncBtn").addEventListener("click", syncBundle);
  $("result").addEventListener("click", hideResult);
  var camOk = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  if (!camOk) {
    var noCam = $("noCamMsg");
    noCam.hidden = false;
    noCam.textContent = "No camera on this device — paste the code below.";
  } else if (!window.isSecureContext) {
    var noCam2 = $("noCamMsg");
    noCam2.hidden = false;
    noCam2.textContent = "Camera needs HTTPS or localhost — serve securely or paste the code below.";
  }
  refreshStatus(); freshChallenge(false); loadRecent();
  setInterval(function(){ freshChallenge(true); }, 120000);
})();
