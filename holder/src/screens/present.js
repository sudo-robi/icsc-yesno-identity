// Presentation screen - show QR to shop
import { $, animateIn, animateOut, showOk, showError, pulseElement } from '../ui.js';
import { drawQR } from '../qr.js';

let tickTimer = null;

export function initPresent() {
  $('#doneBtn').addEventListener('click', backHome);
}

export function showPresentation(bundle, ts) {
  animateOut($('#challengeState')).then(() => {
    $('#challengeState').hidden = true;
    animateIn($('#showState'));
    $('#showTitle').textContent = 'Show this to the shop';
    const text = JSON.stringify(bundle);
    $('#rawJson').textContent = text;
    if (!drawQR($('#qrCanvas'), text)) {
      showError("Couldn't draw the QR — use Copy JSON under Advanced.");
      return;
    }
    showOk('Answer ready — valid about a minute.');
    pulseElement($('#qrCanvas'), 400);
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(() => {
      const left = 60 - (Math.floor(Date.now() / 1000) - ts);
      $('#proofTtl').textContent = left > 0 ? 'Use within ' + left + 's' : 'Expired — answer again.';
      if (left <= 0) clearInterval(tickTimer);
    }, 1000);
  });
}

export function backHome() {
  if (tickTimer) clearInterval(tickTimer);
  animateOut($('#showState'));
  animateOut($('#otpState'));
  $('#showState').hidden = true;
  $('#otpState').hidden = true;
  const { renderHome } = require('./home.js');
  renderHome();
}