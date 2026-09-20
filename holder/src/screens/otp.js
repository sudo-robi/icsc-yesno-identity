// OTP fallback screen
import { $, animateIn, animateOut, showError, pulseElement } from '../ui.js';
import { hexToBytes, hmacCode } from '../crypto.js';
import { findCredential, state } from '../state.js';

let otpTimer = null;

export function initOtp() {
  // No specific init needed
}

export function openOtp(vid) {
  state.activeVid = vid;
  animateOut($('#homeState')).then(() => {
    $('#homeState').hidden = true;
    animateIn($('#otpState'));
    tickOtp();
  });
}

export async function tickOtp() {
  try {
    const rec = findCredential(state.activeVid);
    if (!rec || !rec.otp_secret) { showError('No fallback secret on this device.'); return; }
    const step = Math.floor(Date.now() / 1000 / 30);
    const code = await hmacCode(hexToBytes(rec.otp_secret), state.activeVid + '|' + step);
    const otpEl = $('#otpCode');
    otpEl.textContent = code.slice(0, 3) + ' ' + code.slice(3);
    pulseElement(otpEl, 300);
  } catch (e) { showError("Couldn't compute the code."); return; }
  if (otpTimer) clearInterval(otpTimer);
  otpTimer = setInterval(() => {
    const left = 30 - (Math.floor(Date.now() / 1000) % 30);
    $('#otpTtl').textContent = 'Refreshes in ' + left + 's — read it quickly.';
    if (left === 30) tickOtp();
  }, 1000);
}