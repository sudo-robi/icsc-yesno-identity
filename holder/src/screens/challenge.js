// Challenge screen - scan shop QR and answer
import { $, clearError, showError, animateIn, animateOut, pulseElement } from '../ui.js';
import { canonicalJSON, sha256hexBytes, stripSig, b64uEncode } from '../crypto.js';
import { findCredential, state } from '../state.js';
import { createScanner, parseChallenge } from '../qr.js';
import { showPresentation } from './present.js';

let challengeScanner = null;

export function initChallenge() {
  $('#scanBtn').addEventListener('click', toggleChallengeScan);
  $('#answerBtn').addEventListener('click', answerChallenge);
}

export function openChallenge(vid) {
  state.activeVid = vid;
  clearError();
  animateOut($('#homeState')).then(() => {
    $('#homeState').hidden = true;
    animateIn($('#challengeState'));
  });
}

export function stopChallengeScan() {
  if (challengeScanner) { challengeScanner.stop(); challengeScanner = null; }
  const v = $('#scanVideo');
  const wrapper = $('#videoWrapper');
  animateOut(wrapper).then(() => {
    v.hidden = true;
    wrapper.hidden = true;
  });
  $('#scanHint').hidden = true;
  $('#scanBtn').textContent = 'Scan shop QR';
}

export async function toggleChallengeScan() {
  const video = $('#scanVideo');
  const wrapper = $('#videoWrapper');
  if (challengeScanner && challengeScanner.isScanning()) { stopChallengeScan(); return; }
  if (!window.QRScanner || !window.ScanUtil) {
    showError('Scanner files missing offline — paste the challenge instead.');
    return;
  }
  challengeScanner = createScanner({
    video: video,
    onResult: (text) => {
      let ch = null;
      try {
        const obj = JSON.parse(text);
        if (obj && typeof obj.n === 'string') ch = obj;
      } catch (e) { /* raw nonce below */ }
      const nonce = ch ? ch.n : parseChallenge(text);
      if (!nonce) { showError("That QR doesn't look like a shop challenge."); return; }
      if (ch && ch.vid && ch.vid !== state.activeVid) {
        showError('That challenge is for a different shop (' + ch.vid + ').');
        return;
      }
      stopChallengeScan();
      answerWithNonce(nonce);
    }
  });
  wrapper.hidden = false;
  animateIn(wrapper);
  video.hidden = false;
  $('#scanHint').hidden = false;
  $('#scanHint').textContent = "Point at the shop's QR.";
  $('#scanBtn').textContent = 'Stop scanning';
  const r = await challengeScanner.start();
  if (!r.ok) {
    stopChallengeScan();
    showError({
      insecure: 'Camera needs HTTPS or localhost — paste the challenge instead.',
      denied: 'Camera blocked. Allow access or paste the challenge instead.',
      busy: 'Camera is in use by another app.',
      missing: 'No camera found — paste the challenge instead.',
      unsupported: "This browser can't scan — paste the challenge instead."
    }[r.reason] || 'Camera unavailable — paste the challenge instead.');
  }
}

export async function answerChallenge() {
  const raw = $('#challengeInput').value.trim();
  if (!raw) { showError("Paste or scan the shop's challenge first."); return; }
  let nonce = null, challengeVid = null;
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj.n === 'string') { nonce = obj.n; challengeVid = obj.vid || null; }
  } catch (e) { nonce = parseChallenge(raw); }
  if (!nonce) { showError("That doesn't look like a shop challenge."); return; }
  if (challengeVid && challengeVid !== state.activeVid) {
    showError('That challenge is for a different shop (' + challengeVid + ').');
    return;
  }
  answerWithNonce(nonce);
}

export async function answerWithNonce(nonce) {
  clearError();
  const btn = $('#answerBtn');
  btn.disabled = true;
  btn.textContent = 'Signing…';
  state.signing = true;
  try {
    const rec = findCredential(state.activeVid);
    if (!rec) throw new Error('no-cred');
    const ts = Math.floor(Date.now() / 1000);
    const credCanon = canonicalJSON(stripSig(rec.cred));
    const credHash = await sha256hexBytes(new TextEncoder().encode(credCanon));
    const did = rec.cred.did || '';
    const msg = canonicalJSON(['yn-proof-v1', credHash, nonce, state.activeVid, ts, did]);
    const sigBuf = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      rec.key,
      new TextEncoder().encode(msg)
    );
    const sig = b64uEncode(new Uint8Array(sigBuf));
    showPresentation({ c: rec.cred, p: { n: nonce, ts, sig } }, ts);
    $('#challengeInput').value = '';
  } catch (e) {
    showError("Couldn't sign an answer — is this credential still on the device?");
  } finally {
    btn.disabled = false;
    btn.textContent = 'Show my ID';
    state.signing = false;
  }
}