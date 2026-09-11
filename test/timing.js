// Measure how long the page's pure-JS PBKDF2 actually takes inside jsdom,
// to sanity-check the "100–500 ms" claim in the spec/comments. jsdom on
// modern V8 is roughly comparable to a midrange phone for pure JS arithmetic
// — order-of-magnitude estimate, not a guarantee.

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, {
  runScripts: 'dangerously',
  url: 'file:///index.html',
  pretendToBeVisual: true,
});

setTimeout(async () => {
  const doc = dom.window.document;
  // Fill TV1.
  doc.getElementById('tv1').click();
  const t0 = performance.now();
  doc.getElementById('deriveBtn').click();
  // Wait until the fingerprint is rendered (signals derivation finished).
  while (!doc.getElementById('fp').textContent.trim()) {
    await new Promise((r) => setTimeout(r, 5));
  }
  const t1 = performance.now();
  console.log(`derive (incl. PBKDF2 + UI) on jsdom: ${(t1 - t0).toFixed(0)} ms`);
  process.exit(0);
}, 200);
