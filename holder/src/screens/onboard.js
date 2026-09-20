// Onboard/enrollment screen
import { $, showError, clearError, showOk, animateIn, animateOut, pulseElement } from '../ui.js';
import { generateKey, b64uEncode } from '../crypto.js';
import { apiPost, enrollError, getIssuerUrl } from '../api.js';
import { idbPut } from '../idb.js';
import { setState, addCredential, setCredentials } from '../state.js';

export async function initOnboard() {
  $('#enrollBtn').addEventListener('click', enroll);
  $('#addShopBtn').addEventListener('click', showOnboard);
}

export function showOnboard() {
  animateOut($('#homeState')).then(() => {
    $('#homeState').hidden = true;
    $('#onboardState').hidden = false;
    animateIn($('#onboardState'));
    $('#enrollCode').focus();
  });
}

async function enroll() {
  clearError();
  const code = $('#enrollCode').value.trim();
  const vid = $('#enrollShop').value;
  if (!code) { showError('Enter the enrollment code first.'); return; }
  const btn = $('#enrollBtn');
  btn.disabled = true;
  btn.textContent = 'Working…';
  setState({ enrolling: true });
  try {
    const key = await generateKey();
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
    const pub = b64uEncode(raw);
    const r = await apiPost('/enroll', { code, verifier_id: vid, holder_pub: pub });
    if (!r.ok || !r.data || !r.data.credential) {
      showError(enrollError(r.status, r.data));
      return;
    }
    await idbPut({ vid, cred: r.data.credential, key: key.privateKey,
      otp_secret: r.data.otp_secret || null, enrolled_at: Date.now() });
    $('#enrollCode').value = '';
    showOk('Enrolled for ' + vid + '. Your key never leaves this phone.');
    await loadCredentials();
    animateOut($('#onboardState')).then(() => {
      $('#onboardState').hidden = true;
      $('#homeState').hidden = false;
      animateIn($('#homeState'));
    });
  } catch (e) {
    showError(e && e.message === 'no-crypto'
      ? "This browser can't make secure keys (needs HTTPS or localhost)."
      : "Can't reach the issuer. Check the Issuer URL and your connection.");
  } finally {
    btn.disabled = false;
    btn.textContent = 'Get my ID';
    setState({ enrolling: false });
  }
}

export async function loadCredentials() {
  const { idbAll } = await import('../idb.js');
  const list = await idbAll();
  setCredentials(list);
}