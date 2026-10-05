'use strict';

// The service worker deletes only its own scope's older caches.
// Reports through its exit code; needs nothing installed. Run: node sw_caches.js
//
// Every app on a github.io host shares one origin and one set of caches.
// sw.js is run here in Node's vm against a stub of the cache storage holding
// another app's cache, another deployment of this signer under a second
// path, a cache named the old way, and this scope's previous version; then
// install, activate and a fetch are played through it.

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert/strict');

const source = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'sw.js'), 'utf8');
const SCOPE = 'https://user.github.io/js-signer-spectre-deriv/';
const OTHER_SCOPE = 'https://user.github.io/okp-airgapped-signer/';

let checks = 0;
const check = (name, actual, expected) => { assert.deepEqual(actual, expected, name); checks++; };

(async () => {
  // A cache storage stub: name -> Map(url -> response).
  const store = new Map();
  const cacheObject = (name) => ({
    addAll: (reqs) => { for (const r of reqs) store.get(name).set(r.url, 'body of ' + r.url); return Promise.resolve(); },
    match: (key) => Promise.resolve(store.get(name).get(typeof key === 'string' ? new URL(key, SCOPE).href : key.url)),
  });
  const caches = {
    open: (name) => { if (!store.has(name)) store.set(name, new Map()); return Promise.resolve(cacheObject(name)); },
    keys: () => Promise.resolve(Array.from(store.keys())),
    delete: (name) => Promise.resolve(store.delete(name)),
    // A lookup across every cache, as the real caches.match does.
    match: (key) => {
      const url = typeof key === 'string' ? new URL(key, SCOPE).href : key.url;
      for (const m of store.values()) if (m.has(url)) return Promise.resolve(m.get(url));
      return Promise.resolve(undefined);
    },
  };
  const listeners = {};
  const ctx = {
    self: {
      registration: { scope: SCOPE },
      addEventListener: (type, fn) => { listeners[type] = fn; },
      skipWaiting: () => Promise.resolve(),
      clients: { claim: () => Promise.resolve() },
    },
    caches,
    Request: function Request(url) { this.url = new URL(url, SCOPE).href; },
    Response: { error: () => 'NETWORK ERROR' },
    Promise, URL,
  };
  vm.runInNewContext(source, ctx);

  const version = vm.runInNewContext(source + '\n;VERSION', Object.assign({}, ctx, { self: Object.assign({}, ctx.self, { addEventListener() {} }) }));
  const prefix = 'gap-signer:' + SCOPE + ':';
  const own = prefix + version;

  // What the origin holds before this version installs.
  const others = [
    'spectre-web-v2',                                   // another app on the same host
    'gap-signer:' + OTHER_SCOPE + ':2026-01-01.1',      // this signer, deployed under another path
    'gap-signer-2026-09-14.1',                          // a cache named the old way
  ];
  for (const name of others) {
    store.set(name, new Map([[new URL('index.html', name === 'spectre-web-v2' ? 'https://user.github.io/spectre-web-fork/' : OTHER_SCOPE).href, 'theirs']]));
  }
  store.set(prefix + '2026-01-01.1', new Map([[SCOPE + 'index.html', 'old version']]));

  const run = async (type, extra) => {
    let done;
    const event = Object.assign({ waitUntil: (p) => { done = p; }, respondWith: (p) => { done = p; } }, extra);
    listeners[type](event);
    return done;
  };

  await run('install');
  check('install fills this version\'s cache', store.get(own).get(SCOPE + 'index.html'), 'body of ' + SCOPE + 'index.html');

  await run('activate');
  check('every other app\'s and deployment\'s cache survives, and the old-style one', others.every((n) => store.has(n)), true);
  check('this scope\'s previous version is deleted', store.has(prefix + '2026-01-01.1'), false);
  check('this version\'s cache stays', store.has(own), true);
  check('the cache names, after activate', Array.from(store.keys()).sort(), others.concat([own]).sort());

  // A navigation is answered from this version's cache.
  const hit = await run('fetch', { request: { mode: 'navigate', url: SCOPE } });
  check('navigation served from this cache', hit, 'body of ' + SCOPE + 'index.html');

  // A request this cache lacks gets an error, not another cache's entry.
  const foreign = { mode: 'no-cors', url: 'https://user.github.io/spectre-web-fork/index.html' };
  check('stub sanity: the origin-wide lookup would find it', await caches.match(foreign), 'theirs');
  check('a URL only another cache holds is not served', await run('fetch', { request: foreign }), 'NETWORK ERROR');

  console.log(`sw_caches: ${checks} checks passed`);
})().catch((e) => { console.error(e.message); process.exit(1); });
