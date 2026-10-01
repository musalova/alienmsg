// AlienMsg service worker — makes the PWA work offline.
//
// Strategy: network-first for everything, cache-aside. Online the app is
// always fresh (auto-updates on every deploy); offline we serve the last
// fetched copy. Runtime caching means no precache list to maintain — every
// successful GET (Flutter engine, canvaskit, our WASM, icons) is cached.
//
// Only same-origin GET requests are handled; anything else passes through.
'use strict';

const CACHE = 'alienmsg-v1';

self.addEventListener('install', (e) => self.skipWaiting());

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    // Drop caches from previous worker versions.
    for (const name of await caches.keys()) {
      if (name !== CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // cross-origin: pass through

  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res.status === 200) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
      }
      return res;
    } catch (_) {
      const cached = await caches.match(req);
      if (cached) return cached;
      // Navigation requests fall back to the app shell.
      if (req.mode === 'navigate') {
        const shell = await caches.match('index.html');
        if (shell) return shell;
      }
      throw _;
    }
  })());
});
