'use strict';

// Bump on every change to any file in FILES. The browser refetches only this
// file past the cache; a new VERSION here is what makes an installed app
// pick up a new index.html.
// Why not a version inside index.html: a cache-first worker would serve the
// old index.html forever, so the browser would never see the new value.
const VERSION = '2026-10-05.6';

// Why the scope in the name: every app on a github.io host shares one
// origin, and so one set of caches. The cleanup below used to delete every
// cache but this one, which wiped the offline copy of any other app there,
// and a second deployment of this signer under another path would have
// used the same name. A cache now belongs to the scope it was made for,
// and only this scope's older versions are deleted.
// Caches named the old way, 'gap-signer-' + VERSION, are left alone: from
// the name alone they cannot be told apart from another deployment's.
const PREFIX = 'gap-signer:' + self.registration.scope + ':';
const CACHE = PREFIX + VERSION;
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
      .then((keys) => Promise.all(keys
        .filter((k) => k.startsWith(PREFIX) && k !== CACHE)
        .map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Cache-first, no network fallback: the page is self-contained and its CSP
// lets nothing else load, so an uncached request is a bug, not a need.
// Looked up in this version's cache only, not in every cache of the origin,
// where another app's entry could answer.
self.addEventListener('fetch', (event) => {
  const key = event.request.mode === 'navigate' ? './index.html' : event.request;
  event.respondWith(
    caches.open(CACHE)
      .then((cache) => cache.match(key, { ignoreSearch: true }))
      .then((hit) => hit || Response.error())
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'version') event.source.postMessage({ version: VERSION });
});
