// AlienMsg secure secret store (web build).
//
// Values live in localStorage under `alienmsg.<name>` as
// `base64(iv).base64(ciphertext)` encrypted with AES-256-GCM. The key is a
// NON-EXTRACTABLE CryptoKey persisted in IndexedDB: scripts can use it but
// `exportKey` refuses, so a localStorage dump alone cannot reveal secrets.
// Limit: the key material still lives inside the browser profile — this is
// weaker than a hardware keystore (documented PWA tradeoff).
//
// Migration: the previous implementation (flutter_secure_storage_web) kept
// the raw AES key in localStorage under `publicKey` and values under
// `publicKey.<key>`. On first boot we decrypt those values with the legacy
// key and re-encrypt them under the non-extractable key, then delete it.
(() => {
  const DB = 'alienmsg-secure';
  const STORE = 'keys';
  const KEY_ID = 'aes256';
  const PREFIX = 'alienmsg.';

  let keyPromise = null;

  const openDb = () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

  const idbGet = (db, k) => new Promise((resolve, reject) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(k);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

  const idbPut = (db, k, v) => new Promise((resolve, reject) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put(v, k);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });

  const b64e = (buf) =>
      btoa(String.fromCharCode(...new Uint8Array(buf)));
  const b64d = (s) =>
      Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function key() {
    if (!keyPromise) {
      keyPromise = (async () => {
        const db = await openDb();
        let k = await idbGet(db, KEY_ID);
        if (!k) {
          k = await crypto.subtle.generateKey(
              {name: 'AES-GCM', length: 256},
              /* extractable = */ false,
              ['encrypt', 'decrypt']);
          await idbPut(db, KEY_ID, k);
        }
        return k;
      })();
    }
    return keyPromise;
  }

  async function enc(value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv},
        await key(),
        new TextEncoder().encode(value));
    return `${b64e(iv)}.${b64e(ct)}`;
  }

  async function dec(stored) {
    const [ivB64, ctB64] = String(stored).split('.');
    if (!ctB64) return null;
    const pt = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: b64d(ivB64)},
        await key(),
        b64d(ctB64));
    return new TextDecoder().decode(pt);
  }

  async function migrateLegacy() {
    const rawKey = localStorage.getItem('publicKey');
    if (!rawKey) return;
    try {
      const oldKey = await crypto.subtle.importKey(
          'raw', b64d(rawKey), {name: 'AES-GCM'}, false, ['decrypt']);
      for (const k of Object.keys(localStorage)) {
        if (!k.startsWith(`publicKey.${PREFIX}`)) continue;
        const v = localStorage.getItem(k);
        try {
          const [ivB64, ctB64] = String(v).split('.');
          const pt = await crypto.subtle.decrypt(
              {name: 'AES-GCM', iv: b64d(ivB64)}, oldKey, b64d(ctB64));
          const name = k.slice(`publicKey.${PREFIX}`.length);
          localStorage.setItem(PREFIX + name,
              await enc(new TextDecoder().decode(pt)));
        } catch (_) {
          // Undecryptable entry: leave it, drop it below anyway.
        }
        localStorage.removeItem(k);
      }
      localStorage.removeItem('publicKey');
    } catch (_) {
      // Legacy key unreadable: nothing to migrate.
    }
  }

  window.alienSecure = {
    ready: (async () => {
      await key();        // ensure the IDB key exists before any use
      await migrateLegacy();
    })(),
    async get(name) {
      const s = localStorage.getItem(PREFIX + name);
      if (s == null) return null;
      try {
        return await dec(s);
      } catch (_) {
        return null;
      }
    },
    async set(name, value) {
      localStorage.setItem(PREFIX + name, await enc(value));
    },
    async del(name) {
      localStorage.removeItem(PREFIX + name);
    },
  };
})();
