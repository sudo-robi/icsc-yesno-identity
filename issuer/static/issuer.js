/* Issuer admin page logic. Token lives in a JS variable only — never localStorage. */
"use strict";
function $(id){ return document.getElementById(id); }
function say(msg){ $("msg").textContent = msg; }
function show(obj){ $("out").textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2); }
function adminHeaders(){
  var h = {"Content-Type": "application/json"};
  var t = $("adminToken").value;
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}
function authedFetch(path, body){
  return fetch(path, {method: "POST", headers: adminHeaders(),
    body: body === undefined ? "{}" : JSON.stringify(body)});
}
async function enrollCode(uid){
  say("");
  var res;
  try { res = await authedFetch("/admin/users/" + encodeURIComponent(uid) + "/enrollment-code"); }
  catch (e) { say("Can't reach the issuer service."); return; }
  if (res.status === 401) { say("Enter the admin token first."); return; }
  if (!res.ok) { say("Code creation failed (" + res.status + ")."); return; }
  var data = await res.json();
  show(data);
  say("Copy the enrollment code NOW — it is shown once.");
}
async function revoke(uid){
  say("");
  var res;
  try { res = await authedFetch("/admin/revoke", {user_id: uid}); }
  catch (e) { say("Can't reach the issuer service."); return; }
  if (res.status === 401 || res.status === 403) { say("Wrong or missing admin token."); return; }
  if (!res.ok) { say("Revoke failed (" + res.status + ")."); return; }
  show(await res.text());
  say("Revoked — refreshing table…");
  setTimeout(function(){ location.reload(); }, 2000);
}
async function rotate(activate){
  say("");
  var res;
  try { res = await authedFetch("/admin/rotate", {activate: activate}); }
  catch (e) { say("Can't reach the issuer service."); return; }
  if (res.status === 401 || res.status === 403) { say("Wrong or missing admin token."); return; }
  if (res.status === 409) { say("Key is managed by the environment — rotate it there."); return; }
  if (!res.ok) { say("Rotate failed (" + res.status + ")."); return; }
  show(await res.text());
  say(activate ? "Activated — refreshing…" : "Staged. Bundle now advertises the next key.");
  setTimeout(function(){ location.reload(); }, 2000);
}

/* Boot listeners (no inline handlers: CSP script-src 'self'). Event
 * delegation covers the per-row buttons rendered by Jinja. */
document.getElementById("userTable").addEventListener("click", function (ev) {
  var t = ev.target;
  if (t.dataset && t.dataset.enroll) enrollCode(t.dataset.enroll);
  if (t.dataset && t.dataset.revoke) revoke(t.dataset.revoke);
});
document.getElementById("stageBtn").addEventListener("click", function () { rotate(false); });
document.getElementById("activateBtn").addEventListener("click", function () { rotate(true); });
