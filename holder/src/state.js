// Minimal reactive state store
export const state = {
  activeVid: null,
  credentials: [],
  online: navigator.onLine,
  scanning: false,
  enrolling: false,
  signing: false
};

const listeners = new Set();

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emit() {
  listeners.forEach(fn => fn(state));
}

export function setState(partial) {
  Object.assign(state, partial);
  emit();
}

export function getCredentials() {
  return state.credentials;
}

export function setCredentials(list) {
  state.credentials = list;
  emit();
}

export function addCredential(rec) {
  state.credentials.push(rec);
  emit();
}

export function removeCredential(vid) {
  state.credentials = state.credentials.filter(c => c.vid !== vid);
  emit();
}

export function findCredential(vid) {
  return state.credentials.find(c => c.vid === vid);
}

window.addEventListener('online', () => setState({ online: true }));
window.addEventListener('offline', () => setState({ online: false }));