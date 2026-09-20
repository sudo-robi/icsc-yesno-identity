// Home screen - credential list
import { $, animateIn, animateOut, credState, showError } from '../ui.js';
import { findCredential, setCredentials, getCredentials } from '../state.js';
import { openChallenge } from './challenge.js';
import { openOtp } from './otp.js';

export function initHome() {
  // Handled by state subscription
}

export async function renderHome() {
  const list = getCredentials();
  const wrap = $('#credList');
  const hasCreds = list.length > 0;

  await animateOut($('#onboardState'));
  await animateOut($('#homeState'));
  $('#onboardState').hidden = hasCreds;
  $('#homeState').hidden = !hasCreds;
  if (hasCreds) animateIn($('#homeState'));
  else animateIn($('#onboardState'));

  while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
  if (!list.length) return;

  list.forEach((rec, i) => {
    const st = credState(rec.cred);
    const row = document.createElement('div');
    row.className = 'credrow animate-scale-in';
    row.style.animationDelay = (i * 50) + 'ms';

    const info = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = rec.vid;
    const sub = document.createElement('div');
    sub.className = 'muted';
    const offlineNote = navigator.onLine ? '' : ' · offline';
    sub.textContent = st.live ? st.label + offlineNote : st.label;
    info.appendChild(title);
    info.appendChild(sub);
    row.appendChild(info);

    const btn = document.createElement('button');
    btn.textContent = 'Show ID';
    btn.disabled = !st.live;
    btn.addEventListener('click', () => openChallenge(rec.vid));
    row.appendChild(btn);

    if (rec.otp_secret) {
      const otpBtn = document.createElement('button');
      otpBtn.textContent = 'Code';
      otpBtn.addEventListener('click', () => openOtp(rec.vid));
      row.appendChild(otpBtn);
    }

    wrap.appendChild(row);

    if (st.live && st.left < 600 && navigator.onLine) {
      sub.textContent += ' · near expiry: ask the issuer for a new code to renew';
    }
  });
}