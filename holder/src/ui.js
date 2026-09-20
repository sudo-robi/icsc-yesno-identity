// Toast notification component
export function $(id) { return document.getElementById(id); }

export function showError(msg) {
  const el = document.getElementById('err');
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  el.classList.remove('animate-fade-in');
  void el.offsetWidth;
  el.classList.add('animate-fade-in');
}

export function clearError() {
  const el = document.getElementById('err');
  if (!el) return;
  el.textContent = '';
  el.hidden = true;
}

export function showOk(msg) {
  const el = document.getElementById('okmsg');
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  el.classList.remove('animate-fade-in');
  void el.offsetWidth;
  el.classList.add('animate-fade-in');
}

export function animateIn(el, animation = 'animate-scale-in') {
  if (!el) return;
  el.hidden = false;
  el.classList.remove(animation);
  void el.offsetWidth;
  el.classList.add(animation);
}

export function animateOut(el, duration = 150) {
  if (!el) return Promise.resolve();
  return new Promise(resolve => {
    el.classList.remove('animate-scale-in');
    el.style.animation = `fadeIn ${duration}ms ease-out reverse forwards`;
    setTimeout(() => { el.hidden = true; el.style.animation = ''; resolve(); }, duration);
  });
}

export function pulseElement(el, duration = 300) {
  if (!el) return;
  el.classList.remove('animate-pulse');
  void el.offsetWidth;
  el.classList.add('animate-pulse');
  setTimeout(() => el.classList.remove('animate-pulse'), duration);
}

export function formatTime(s) {
  const m = Math.floor(s / 60), r = s % 60;
  return m + ':' + (r < 10 ? '0' : '') + r;
}

export function credState(cred) {
  const s = cred.exp - Math.floor(Date.now() / 1000);
  if (s <= 0) return { label: 'Expired', live: false };
  return { label: s < 600 ? 'Expires in ' + formatTime(s) : 'Valid', live: true, left: s };
}