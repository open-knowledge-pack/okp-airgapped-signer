'use strict';

// Spectre mode: inputs to 24 words to key, checked against spectre-web-fork.
// Reports through its exit code. Run: node spectre_mode.js (needs jsdom).
//
// The word vectors are those of spectre-web-fork's test/seed-words.mjs,
// which were produced there by the Python reference in its SEED-WORDS.md,
// not by either app. They cover every algorithm version and the two length
// rules (name in UTF-16 units under V0-V2, site under V0-V1), which the
// page's self-test, a single V3 vector, does not reach.
// The key and fingerprint of the first one are the ones SEED-WORDS.md pins.

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
const win = dom.window;
const doc = win.document;
const $ = (id) => doc.getElementById(id);

const ASCII = 'sound average tumble social achieve adapt cement use arm sheriff pear express combine seminar public oppose spider answer woman people leaf wish million snow';
const CYRILLIC_V0_V1 = 'crop metal survey carpet sing evoke case lake hospital vendor struggle void laptop olive icon ancient favorite glue interest midnight brass crack lounge portion';
const R = { name: 'Robert Lee Mitchell', secret: 'banana colored duckling', site: 'wallet' };
const C = { name: 'Роберт Ли Митчелл', secret: 'banana colored duckling', site: 'кошелёк' };
const VECTORS = [
  Object.assign({ counter: 1, version: 0, words: ASCII }, R),
  Object.assign({ counter: 1, version: 1, words: ASCII }, R),
  Object.assign({ counter: 1, version: 2, words: ASCII }, R),
  Object.assign({ counter: 1, version: 3, words: ASCII }, R),
  Object.assign({ counter: 2, version: 3, words: 'jazz program exchange same heavy pioneer circle nasty vacuum pioneer kiwi avoid lady hedgehog flame sword inner silly census boring vanish wheel absent load' }, R),
  Object.assign({ counter: 1, version: 0, words: CYRILLIC_V0_V1 }, C),
  Object.assign({ counter: 1, version: 1, words: CYRILLIC_V0_V1 }, C),
  Object.assign({ counter: 1, version: 2, words: 'maze season dry plunge fix seed demand transfer blush above sadness icon trend mix dinosaur concert gown daughter hurt right act coyote ranch latin' }, C),
  Object.assign({ counter: 1, version: 3, words: 'debate leg universe seed ball aerobic step urban live outdoor mandate fabric mesh swap alcohol glow ball embrace hover mail media pave rare earth' }, C),
];
const PINNED_FP = 'SHA256:56GCTKnyQOHsuIQVNHcPmC0vOYjDzFXebn4Q/73N650';
const PINNED_PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOiLs9b+36JwnWAtcTIKYE28XWx84r5PIFPM4G7ltblH';

const until = async (cond, what) => {
  for (let i = 0; i < 600; i++) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('timed out waiting for ' + what);
};

let checks = 0;
const check = (name, actual, expected) => { assert.equal(actual, expected, name); checks++; };

(async () => {
  for (const v of VECTORS) {
    const r = await win.spectreSeedWords(v.name, v.secret, v.version, v.site, v.counter);
    check(`words ${v.name} V${v.version} ${v.site} #${v.counter}`, r.words.join(' '), v.words);
  }

  // Spectre mode is the default.
  check('Spectre mode on load', $('spectreMode').classList.contains('hidden'), false);
  check('word fields hidden on load', $('wordsMode').classList.contains('hidden'), true);

  // Empty inputs are refused before any work.
  $('spName').value = '';
  $('deriveBtn').click();
  await until(() => $('seedErr').textContent, 'the empty-name error');
  check('empty name refused', $('seedErr').textContent, 'the full name is empty');

  // The documented vector, through the buttons.
  $('spTv').click();
  $('deriveBtn').click();
  await until(() => !$('screen2').classList.contains('hidden'), 'Screen 2');
  check('fingerprint is the one SEED-WORDS.md pins', $('fp').textContent, PINNED_FP);
  check('identity line', $('spIdentity').textContent, 'Robert Lee Mitchell · site wallet · counter 1 · V3');
  check('identicon', $('spIcon').textContent, '═█╗⛄');
  check('test-key banner shown', $('testKeyWarn').classList.contains('hidden'), false);
  check('secret field wiped', $('spSecret').value, '');
  check('words not in the DOM before asked', $('revealBox').textContent, '');
  // Script text holds the vector itself, so only text outside scripts counts.
  const shown = [];
  const walker = doc.createTreeWalker(doc.body, win.NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) if (walker.currentNode.parentNode.nodeName !== 'SCRIPT') shown.push(walker.currentNode.data);
  check('no word appears anywhere in the page', shown.join(' ').includes('tumble social'), false);

  $('exportPubBtn').click();
  check('public key line is the one SEED-WORDS.md pins', $('pubQrPayload').textContent, PINNED_PUB);

  $('revealBtn').click();
  check('reveal shows the 24 words', $('revealBox').textContent, ASCII.split(' ').map((w, i) => (i + 1) + '.' + w).join(''));
  Object.defineProperty(doc, 'hidden', { configurable: true, get: () => true });
  doc.dispatchEvent(new win.Event('visibilitychange'));
  delete doc.hidden;
  check('words gone when the page is hidden', $('revealBox').textContent, '');
  check('reveal button reset', $('revealBtn').textContent, 'Show seed words');

  // Signing works with the Spectre key (the page verifies every signature it makes).
  $('msg').value = 'hello';
  $('signBtn').click();
  check('no sign error', $('signErr').textContent, '');
  check('signature block made', $('sigQrPayload').textContent.startsWith('-----BEGIN SSH SIGNATURE-----'), true);

  $('lockBtn').click();
  check('lock hides the Spectre box', $('spectreBox').classList.contains('hidden'), true);
  check('lock clears the identicon', $('spIcon').textContent, '');
  check('lock keeps the name', $('spName').value, 'Robert Lee Mitchell');

  // A non-default passphrase changes the key.
  $('spSecret').value = 'banana colored duckling';
  $('spSite').value = 'wallet';
  $('passphrase').value = 'x';
  $('deriveBtn').click();
  await until(() => !$('screen2').classList.contains('hidden'), 'Screen 2 with a passphrase');
  check('passphrase changes the key', $('fp').textContent === PINNED_FP, false);
  check('same identicon under a passphrase', $('spIcon').textContent, '═█╗⛄');
  $('lockBtn').click();

  // A bad counter is refused.
  $('spSecret').value = 'banana colored duckling';
  $('spCounter').value = '0';
  $('deriveBtn').click();
  await until(() => $('seedErr').textContent, 'the counter error');
  check('counter 0 refused', $('seedErr').textContent, 'the counter must be a whole number from 1 to 4294967295');
  $('spCounter').value = '1';

  // The 24-word path still works, and its Screen 2 has no Spectre box.
  $('tv1').click();
  check('fill button switches to the word fields', $('wordsMode').classList.contains('hidden'), false);
  $('deriveBtn').click();
  await until(() => !$('screen2').classList.contains('hidden'), 'Screen 2 from words');
  check('no Spectre box in word mode', $('spectreBox').classList.contains('hidden'), true);
  $('lockBtn').click();

  // The page's own self-test, Spectre vector included.
  $('selfTestBtn').click();
  await until(() => !$('selfTestBtn').disabled && !$('selfTestResult').textContent.startsWith('running'), 'the self-test');
  check('self-test passes', $('selfTestResult').className, 'ok');

  console.log(`spectre_mode: ${checks} checks passed`);
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
