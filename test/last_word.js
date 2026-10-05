'use strict';

// "Find word 24": the 8 words that complete 23 given words.
// Reports through its exit code. Run: node last_word.js (needs jsdom).
//
// The page's lastWordCandidates is checked against a second implementation
// here, written on bit strings and Node's crypto rather than on bytes, and
// against the published vectors: the real 24th word of each must be among
// the candidates of its first 23. Every candidate must also pass the page's
// own checksum check. Then the button is driven as a user would.

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert/strict');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
const win = dom.window;
const doc = win.document;
const $ = (id) => doc.getElementById(id);

// The word list, read from the page's own script, since the page is the
// only copy of it in this repository.
const WORDS = win.eval('BIP39_WORDS');
assert.equal(WORDS.length, 2048);

function reference(words23) {
  const bits = words23.map((w) => WORDS.indexOf(w).toString(2).padStart(11, '0')).join('');
  const out = [];
  for (let x = 0; x < 8; x++) {
    const ent = bits + x.toString(2).padStart(3, '0');
    const bytes = Buffer.from(ent.match(/.{8}/g).map((b) => parseInt(b, 2)));
    const cs = crypto.createHash('sha256').update(bytes).digest()[0];
    out.push(WORDS[parseInt(ent.slice(253) + cs.toString(2).padStart(8, '0'), 2)]);
  }
  return out;
}

const PHRASES = [
  ('abandon '.repeat(23) + 'art').trim(),
  ('zoo '.repeat(23) + 'vote').trim(),
  'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless',
  'sound average tumble social achieve adapt cement use arm sheriff pear express combine seminar public oppose spider answer woman people leaf wish million snow',
];

let checks = 0;
const check = (name, actual, expected) => { assert.deepEqual(actual, expected, name); checks++; };

(async () => {
  const rnd = [];
  for (let n = 0; n < 50; n++) {
    const words = [];
    for (let i = 0; i < 23; i++) words.push(WORDS[crypto.randomInt(2048)]);
    rnd.push(words);
  }
  for (const words of PHRASES.map((p) => p.split(' ').slice(0, 23)).concat(rnd)) {
    const got = Array.from(win.lastWordCandidates(words));
    check('candidates match the reference for ' + words.slice(0, 3).join(' ') + '…', got, reference(words));
    for (const w of got) {
      const v = await win.validateMnemonic24(words.concat([w]));
      check('candidate ' + w + ' passes the page checksum', v.ok, true);
    }
  }
  for (const p of PHRASES) {
    const words = p.split(' ');
    check('the real last word is a candidate: ' + words[23], win.lastWordCandidates(words.slice(0, 23)).includes(words[23]), true);
  }

  // The button, as a user would use it.
  $('modeWords').click();
  const tv1 = PHRASES[0].split(' ');
  const inputs = Array.from($('words').querySelectorAll('input'));
  const type = (i, w) => { inputs[i].value = w; inputs[i].dispatchEvent(new win.Event('input', { bubbles: true })); };
  for (let i = 0; i < 23; i++) type(i, tv1[i]);

  $('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 50));
  check('derive with field 24 empty points to the button', $('seedErr').textContent, 'field 24 is empty: "Find word 24" lists the words that complete the other 23');

  $('lastWordBtn').click();
  $('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 50));
  check('derive with the list up says to pick from it', $('seedErr').textContent, 'field 24 is empty: tap one of the 8 words listed under the fields');
  check('and leaves the list in place', $('lastWordBox').classList.contains('hidden'), false);

  type(5, 'xyzzy');
  $('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 50));
  check('an unknown word in 1-23 gets no pointer to the button', $('seedErr').textContent, 'all 24 fields must be filled');
  type(5, 'abandon');

  $('lastWordBtn').click();
  const buttons = Array.from($('lastWordList').querySelectorAll('button'));
  check('8 candidates shown', buttons.length, 8);
  check('they are the reference candidates', buttons.map((b) => b.textContent), reference(tv1.slice(0, 23)));
  buttons.find((b) => b.textContent === 'art').click();
  check('a tap fills field 24', inputs[23].value, 'art');
  check('field 24 is marked good', inputs[23].parentNode.classList.contains('good'), true);
  check('the list is gone after the tap', $('lastWordBox').classList.contains('hidden'), true);

  $('lastWordBtn').click();
  check('a filled field 24 is refused', $('seedErr').textContent, 'field 24 is already filled: clear it to list the words that can go there');

  type(23, '');
  $('lastWordBtn').click();
  check('list shown again', $('lastWordBox').classList.contains('hidden'), false);
  type(5, 'zoo');
  check('an edit takes the list away', $('lastWordBox').classList.contains('hidden'), true);
  check('and empties it', $('lastWordList').textContent, '');

  type(5, '');
  $('lastWordBtn').click();
  check('an empty field among 1-23 is refused', $('seedErr').textContent, 'fill fields 1 to 23 first: field 6 is empty');
  type(5, 'xyzzy');
  $('lastWordBtn').click();
  check('an unknown word is refused', $('seedErr').textContent, 'word #6 ("xyzzy") is not in the BIP39 wordlist');

  // The completed phrase derives tv1's documented key.
  type(5, 'abandon');
  $('lastWordBtn').click();
  Array.from($('lastWordList').querySelectorAll('button')).find((b) => b.textContent === 'art').click();
  $('deriveBtn').click();
  for (let i = 0; i < 100 && $('screen2').classList.contains('hidden'); i++) await new Promise((r) => setTimeout(r, 50));
  check('the completed phrase derives tv1', $('testKeyWarn').textContent.includes('tv1'), true);
  $('lockBtn').click();

  // An open list, then a derivation from the other mode: the list must not
  // survive it. (Only a mode switch can leave the list up while a key is
  // derived; any word-mode route to a key fills field 24, which hides it.)
  $('modeWords').click();
  for (let i = 0; i < 23; i++) type(i, tv1[i]);
  $('lastWordBtn').click();
  check('list up before the Spectre derive', $('lastWordBox').classList.contains('hidden'), false);
  $('spTv').click();
  $('deriveBtn').click();
  for (let i = 0; i < 400 && $('screen2').classList.contains('hidden'); i++) await new Promise((r) => setTimeout(r, 50));
  check('a Spectre derive took the list away', $('lastWordBox').classList.contains('hidden'), true);
  check('and emptied it', $('lastWordList').textContent, '');
  $('lockBtn').click();
  $('modeWords').click();
  check('no list after lock and back to the word fields', $('lastWordBox').classList.contains('hidden'), true);

  console.log(`last_word: ${checks} checks passed`);
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
