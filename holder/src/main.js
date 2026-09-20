// Main entry point for holder app
import { initOnboard, loadCredentials, showOnboard } from './screens/onboard.js';
import { renderHome } from './screens/home.js';
import { initChallenge, stopChallengeScan } from './screens/challenge.js';
import { initPresent } from './screens/present.js';
import { initOtp } from './screens/otp.js';
import { setState } from './state.js';
import { clearError, showError, showOk, $ } from './ui.js';
import { idbAll } from './idb.js';

// Initialize all screens
initOnboard();
initChallenge();
initPresent();
initOtp();

// Load credentials on startup
async function boot() {
  try {
    const list = await idbAll();
    setState({ credentials: list });
    renderHome();
  } catch (e) {
    showError("Device storage unavailable — this browser can't keep keys.");
  }
}

// Service worker registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  });
}

// Global event handlers
$('#forgetBtn').addEventListener('click', async () => {
  await import('./idb.js').then(m => m.clearDB());
  showOk('Device forgotten. Keys are gone permanently.');
  setTimeout(() => location.reload(), 1200);
});

$('#iss').addEventListener('input', (e) => {
  import('./api.js').then(m => m.setIssuerUrl(e.target.value));
});

// Expose showOnboard globally for backward compat
window.showOnboard = showOnboard;
window.clearError = clearError;

boot();

// Periodic refresh
setInterval(() => {
  import('./screens/home.js').then(m => m.renderHome());
}, 30000);