/* Holder app: device keys (WebCrypto P-256, non-extractable, IndexedDB),
 * enrollment, challenge proofs, QR display, OTP fallback.
 * All rendering via textContent / canvas — never innerHTML on server data.
 */
"use strict";

/* ---------- tiny helpers ---------- */
function $(id){ return document.getElementById(id); }

function showError(msg){
  const el = $("err");
  el.textContent = msg;
  el.hidden = false;
  el.classList.remove("animate-fade-in");
  void el.offsetWidth;
  el.classList.add("animate-fade-in");
}

function clearError(){
  const el = $("err");
  el.textContent = "";
  el.hidden = true;
}

function showOk(msg){
  const el = $("okmsg");
  el.textContent = msg;
  el.hidden = false;
  el.classList.remove("animate-fade-in");
  void el.offsetWidth;
  el.classList.add("animate-fade-in");
}

/* ---------- animation helpers ---------- */
function animateIn(el, animation = "animate-scale-in"){
  if (!el) return;
  el.hidden = false;
  el.classList.remove(animation);
  void el.offsetWidth;
  el.classList.add(animation);
}

function animateOut(el, animation = "animate-fade-in", duration = 150){
  if (!el) return Promise.resolve();
  return new Promise(resolve => {
    el.classList.remove("animate-scale-in");
    el.style.animation = `fadeIn ${duration}ms ease-out reverse forwards`;
    setTimeout(() => {
      el.hidden = true;
      el.style.animation = "";
      resolve();
    }, duration);
  });
}

function pulseElement(el, duration = 300){
  if (!el) return;
  el.classList.remove("animate-pulse");
  void el.offsetWidth;
  el.classList.add("animate-pulse");
  setTimeout(() => el.classList.remove("animate-pulse"), duration);
}

/* ---------- crypto helpers ---------- */
function b64uEncode(bytes){
  var bin = "";
  bytes.forEach(function(b){ bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hexToBytes(hex){
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function canonicalJSON(value){
  if (typeof value === "number" && !Number.isInteger(value)) throw new Error("no-floats");
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(value).sort().map(function(k){
    return JSON.stringify(k) + ":" + canonicalJSON(value[k]);
  }).join(",") + "}";
}
async function sha256hexBytes(bytes){
  var digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map(function(b){
    return b.toString(16).padStart(2, "0");
  }).join("");
}

/* ---------- IndexedDB device store ---------- */
var DB_NAME = "yn-holder", STORE = "creds";
function idb(){
  return new Promise(function(resolve, reject){
    var req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = function(event){
      event.target.result.createObjectStore(STORE, {keyPath: "vid"});
    };
    req.onsuccess = function(event){ resolve(event.target.result); };
    req.onerror = function(event){ reject(event.target.error); };
  });
}
async function idbAll(){
  var db = await idb();
  return new Promise(function(resolve, reject){
    var out = [];
    var tx = db.transaction(STORE, "readonly").objectStore(STORE).openCursor();
    tx.onsuccess = function(e){
      var c = e.target.result;
      if (c) { out.push(c.value); c.continue(); } else { db.close(); resolve(out); }
    };
    tx.onerror = function(){ db.close(); reject(tx.error); };
  });
}
async function idbPut(record){
  var db = await idb();
  return new Promise(function(resolve, reject){
    var tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(record);
    tx.oncomplete = function(){ db.close(); resolve(); };
    tx.onerror = function(){ db.close(); reject(tx.error); };
  });
}

/* ---------- state ---------- */
var activeVid = null;
var challengeScanner = null;
var tickTimer = null, otpTimer = null;

function issuer(){ return $("iss").value.replace(/\/+$/, ""); }

async function apiPost(path, body){
  var res = await fetch(issuer() + path, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)});
  var text = await res.text(), data = null;
  try { data = JSON.parse(text); } catch (e) {}
  return {status: res.status, ok: res.ok, data: data};
}
function enrollError(status, data){
  if (status === 404 || (data && data.error === "UNKNOWN_CODE")) return "Unknown enrollment code.";
  if (data && data.error === "CODE_USED") return "This code was already used — ask for a new one.";
  if (data && data.error === "CODE_EXPIRED") return "This code expired — ask for a new one.";
  if (status === 403) return "This ID is revoked and cannot be enrolled.";
  if (data && data.error === "BAD_PUBKEY") return "This browser couldn't make a key. Try another.";
  if (status === 429) return "Too many tries — wait a minute.";
  return "Enrollment failed (" + status + "). Check the Issuer URL.";
}

/* ---------- enrollment ---------- */
async function enroll(){
  clearError();
  var code = $("enrollCode").value.trim(), vid = $("enrollShop").value;
  if (!code) { showError("Enter the enrollment code first."); return; }
  var btn = $("enrollBtn"); btn.disabled = true; btn.textContent = "Working…";
  try {
    if (!window.crypto || !crypto.subtle) throw new Error("no-crypto");
    var key = await crypto.subtle.generateKey(
      {name: "ECDSA", namedCurve: "P-256"}, false, ["sign"]);
    var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
    var pub = b64uEncode(raw);
    var r = await apiPost("/enroll", {code: code, verifier_id: vid, holder_pub: pub});
    if (!r.ok || !r.data || !r.data.credential) {
      showError(enrollError(r.status, r.data)); return;
    }
    await idbPut({vid: vid, cred: r.data.credential, key: key.privateKey,
      otp_secret: r.data.otp_secret || null, enrolled_at: Date.now()});
    $("enrollCode").value = "";
    showOk("Enrolled for " + vid + ". Your key never leaves this phone.");
    renderHome();
  } catch (e) {
    showError(e && e.message === "no-crypto"
      ? "This browser can't make secure keys (needs HTTPS or localhost)."
      : "Can't reach the issuer. Check the Issuer URL and your connection.");
  } finally { btn.disabled = false; btn.textContent = "Get my ID"; }
}

/* ---------- home ---------- */
function fmtTime(s){
  var m = Math.floor(s / 60), r = s % 60;
  return m + ":" + (r < 10 ? "0" : "") + r;
}
function credState(cred){
  var s = cred.exp - Math.floor(Date.now() / 1000);
  if (s <= 0) return {label: "Expired", live: false};
  return {label: s < 600 ? "Expires in " + fmtTime(s) : "Valid", live: true, left: s};
}
async function renderHome(){
  clearError();
  var list = [];
  try { list = await idbAll(); }
  catch (e) { showError("Device storage unavailable — this browser can't keep keys."); return; }
  const hasCreds = list.length > 0;
  await animateOut($("onboardState"), "animate-fade-in", 100);
  await animateOut($("homeState"), "animate-fade-in", 100);
  $("onboardState").hidden = hasCreds;
  $("homeState").hidden = !hasCreds;
  if (hasCreds) animateIn($("homeState"));
  else animateIn($("onboardState"));
  var wrap = $("credList");
  while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
  if (!list.length) return;
  list.forEach(function(rec, i){
    var st = credState(rec.cred);
    var row = document.createElement("div");
    row.className = "credrow animate-scale-in";
    row.style.animationDelay = (i * 50) + "ms";
    var info = document.createElement("div");
    var title = document.createElement("strong");
    title.textContent = rec.vid;
    var sub = document.createElement("div");
    sub.className = "muted";
    var offlineNote = navigator.onLine ? "" : " · offline";
    sub.textContent = st.live ? st.label + offlineNote : st.label;
    info.appendChild(title); info.appendChild(sub);
    row.appendChild(info);
    var btn = document.createElement("button");
    btn.textContent = "Show ID";
    btn.disabled = !st.live;
    btn.addEventListener("click", function(){ openChallenge(rec.vid); });
    row.appendChild(btn);
    if (rec.otp_secret) {
      var otpBtn = document.createElement("button");
      otpBtn.textContent = "Code";
      otpBtn.addEventListener("click", function(){ openOtp(rec.vid); });
      row.appendChild(otpBtn);
    }
    wrap.appendChild(row);
    if (st.live && st.left < 600 && navigator.onLine) {
      sub.textContent += " · near expiry: ask the issuer for a new code to renew";
    }
  });
}
function showOnboard(){
  $("onboardState").hidden = false;
  $("onboardState").scrollIntoView();
}
async function backHome(){
  stopChallengeScan();
  if (tickTimer) clearInterval(tickTimer);
  if (otpTimer) clearInterval(otpTimer);
  await Promise.all([
    animateOut($("showState")),
    animateOut($("challengeState")),
    animateOut($("otpState"))
  ]);
  renderHome();
}

/* ---------- challenge + proof ---------- */
function openChallenge(vid){
  activeVid = vid;
  clearError();
  animateOut($("homeState"), "animate-fade-in", 100).then(() => {
    $("homeState").hidden = true;
    animateIn($("challengeState"));
  });
}
function stopChallengeScan(){
  if (challengeScanner) { challengeScanner.stop(); challengeScanner = null; }
  var v = $("scanVideo"); v.hidden = true;
  $("scanHint").hidden = true;
  $("scanBtn").textContent = "Scan shop QR";
}
async function toggleChallengeScan(){
  var video = $("scanVideo");
  if (challengeScanner && challengeScanner.isScanning()) { stopChallengeScan(); return; }
  if (!window.QRScanner || !window.ScanUtil) {
    showError("Scanner files missing offline — paste the challenge instead."); return;
  }
  challengeScanner = QRScanner.createScanner({
    video: video,
    onResult: function(text){
      var ch = null;
      try {
        var obj = JSON.parse(text);
        if (obj && typeof obj.n === "string") ch = obj;
      } catch (e) { /* raw nonce below */ }
      var nonce = ch ? ch.n : (window.ScanUtil.parseChallenge(text) || null);
      if (!nonce) { showError("That QR doesn't look like a shop challenge."); return; }
      if (ch && ch.vid && ch.vid !== activeVid) {
        showError("That challenge is for a different shop (" + ch.vid + ").");
        return;
      }
      stopChallengeScan();
      answerWithNonce(nonce);
    }
  });
  video.hidden = false; $("scanHint").hidden = false;
  $("scanHint").textContent = "Point at the shop's QR.";
  $("scanBtn").textContent = "Stop scanning";
  var r = await challengeScanner.start();
  if (!r.ok) {
    stopChallengeScan();
    showError({
      insecure: "Camera needs HTTPS or localhost — paste the challenge instead.",
      denied: "Camera blocked. Allow access or paste the challenge instead.",
      busy: "Camera is in use by another app.",
      missing: "No camera found — paste the challenge instead.",
      unsupported: "This browser can't scan — paste the challenge instead."
    }[r.reason] || "Camera unavailable — paste the challenge instead.");
  }
}
async function answerChallenge(){
  var raw = $("challengeInput").value.trim();
  if (!raw) { showError("Paste or scan the shop's challenge first."); return; }
  var nonce = null, challengeVid = null;
  try {
    var obj = JSON.parse(raw);
    if (obj && typeof obj.n === "string") { nonce = obj.n; challengeVid = obj.vid || null; }
  } catch (e) { nonce = window.ScanUtil ? ScanUtil.parseChallenge(raw) : raw; }
  if (!nonce) { showError("That doesn't look like a shop challenge."); return; }
  if (challengeVid && challengeVid !== activeVid) {
    showError("That challenge is for a different shop (" + challengeVid + ")."); return;
  }
  answerWithNonce(nonce);
}
async function answerWithNonce(nonce){
  clearError();
  var btn = $("answerBtn"); btn.disabled = true; btn.textContent = "Signing…";
  try {
    var rec = await findCred(activeVid);
    if (!rec) throw new Error("no-cred");
    var ts = Math.floor(Date.now() / 1000);
    var credCanon = canonicalJSON(stripSig(rec.cred));
    var credHash = await sha256hexBytes(new TextEncoder().encode(credCanon));
    var did = (rec.cred && rec.cred.did) || "";
    var msg = canonicalJSON(["yn-proof-v1", credHash, nonce, activeVid, ts, did]);
    var sigBuf = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"},
      rec.key, new TextEncoder().encode(msg));
    var sig = b64uEncode(new Uint8Array(sigBuf));
    showPresentation({c: rec.cred, p: {n: nonce, ts: ts, sig: sig}}, ts);
    $("challengeInput").value = "";
  } catch (e) {
    showError("Couldn't sign an answer — is this credential still on the device?");
  } finally { btn.disabled = false; btn.textContent = "Show my ID"; }
}
function stripSig(cred){
  var out = {};
  Object.keys(cred).forEach(function(k){ if (k !== "s") out[k] = cred[k]; });
  return out;
}
async function findCred(vid){
  var list = await idbAll();
  for (var i = 0; i < list.length; i++) if (list[i].vid === vid) return list[i];
  return null;
}
function showPresentation(bundle, ts){
  animateOut($("challengeState"), "animate-fade-in", 100).then(() => {
    $("challengeState").hidden = true;
    animateIn($("showState"));
    $("showTitle").textContent = "Show this to the shop";
    var text = JSON.stringify(bundle);
    $("rawJson").textContent = text;
    if (!window.QRScanner || !QRScanner.drawQR($("qrCanvas"), text)) {
      showError("Couldn't draw the QR — use Copy JSON under Advanced.");
      return;
    }
    showOk("Answer ready — valid about a minute.");
    pulseElement($("qrCanvas"), 400);
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(function(){
      var left = 60 - (Math.floor(Date.now() / 1000) - ts);
      $("proofTtl").textContent = left > 0 ? "Use within " + left + "s" : "Expired — answer again.";
      if (left <= 0) clearInterval(tickTimer);
    }, 1000);
  });
}

/* ---------- OTP fallback ---------- */
async function openOtp(vid){
  activeVid = vid;
  animateOut($("homeState"), "animate-fade-in", 100).then(() => {
    $("homeState").hidden = true;
    animateIn($("otpState"));
    tickOtp();
  });
}
async function tickOtp(){
  try {
    var rec = await findCred(activeVid);
    if (!rec || !rec.otp_secret) { showError("No fallback secret on this device."); return; }
    var step = Math.floor(Date.now() / 1000 / 30);
    var code = await hmacCode(hexToBytes(rec.otp_secret), activeVid + "|" + step);
    const otpEl = $("otpCode");
    otpEl.textContent = code.slice(0, 3) + " " + code.slice(3);
    pulseElement(otpEl, 300);
  } catch (e) { showError("Couldn't compute the code."); return; }
  if (otpTimer) clearInterval(otpTimer);
  otpTimer = setInterval(function(){
    var left = 30 - (Math.floor(Date.now() / 1000) % 30);
    $("otpTtl").textContent = "Refreshes in " + left + "s — read it quickly.";
    if (left === 30) tickOtp();
  }, 1000);
}
async function hmacCode(keyBytes, msg){
  var key = await crypto.subtle.importKey("raw", keyBytes, {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  var mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg)));
  var hex = Array.from(mac).map(function(b){ return b.toString(16).padStart(2, "0"); }).join("");
  return String(parseInt(hex, 16) % 1000000).padStart(6, "0");
}

/* ---------- device ---------- */
async function forgetDevice(){
  indexedDB.deleteDatabase(DB_NAME);
  showOk("Device forgotten. Keys are gone permanently.");
  setTimeout(function(){ location.reload(); }, 1200);
}

/* ---------- boot (no inline handlers: CSP script-src 'self') ---------- */
$("enrollBtn").addEventListener("click", enroll);
$("scanBtn").addEventListener("click", toggleChallengeScan);
$("answerBtn").addEventListener("click", answerChallenge);
$("doneBtn").addEventListener("click", backHome);
$("forgetBtn").addEventListener("click", forgetDevice);
if ("serviceWorker" in navigator) {
  window.addEventListener("load", function(){
    navigator.serviceWorker.register("./sw.js").catch(function(){});
  });
}
renderHome();
setInterval(renderHome, 30000); // refresh statuses; expiry countdowns stay truthful
