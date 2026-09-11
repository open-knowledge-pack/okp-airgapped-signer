'use strict';

// Bump on every change to any file in FILES. The browser refetches only this
// file past the cache; a new VERSION here is what makes an installed app
// pick up a new index.html.
// Why not a version inside index.html: a cache-first worker would serve the
// old index.html forever, so the browser would never see the new value.
const VERSION = '2026-09-11';

const CACHE = 'gap-signer-' + VERSION;
const FILES = ['./', './index.html', './manifest.webmanifest', './icon-180.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      // Why cache: 'reload': bypass the HTTP cache so a new VERSION installs
      // the bytes the server holds now, not a copy GitHub Pages' 600 s
      // max-age left in the browser.
      .then((cache) => cache.addAll(FILES.map((f) => new Request(f, { cache: 'reload' }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Cache-first, no network fallback: the page is self-contained and its CSP
// lets nothing else load, so an uncached request is a bug, not a need.
self.addEventListener('fetch', (event) => {
  const key = event.request.mode === 'navigate' ? './index.html' : event.request;
  event.respondWith(
    caches.match(key, { ignoreSearch: true })
      .then((hit) => hit || Response.error())
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'version') event.source.postMessage({ version: VERSION });
});
