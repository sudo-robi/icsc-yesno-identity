// IndexedDB wrapper for holder app
const DB_NAME = 'yn-holder';
const STORE = 'creds';

export function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = e => {
      e.target.result.createObjectStore(STORE, { keyPath: 'vid' });
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror = e => reject(e.target.error);
  });
}

export async function idbAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const out = [];
    const tx = db.transaction(STORE, 'readonly').objectStore(STORE).openCursor();
    tx.onsuccess = e => {
      const c = e.target.result;
      if (c) { out.push(c.value); c.continue(); }
      else { db.close(); resolve(out); }
    };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export async function idbPut(record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(record);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export async function idbDelete(vid) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(vid);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export async function clearDB() {
  await indexedDB.deleteDatabase(DB_NAME);
}