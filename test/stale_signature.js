'use strict';

// A signature on screen always belongs to the inputs now in the boxes.
// Reports through its exit code. Run: node stale_signature.js (needs jsdom).
//
// Sign once, then each way of changing or refusing the next Sign must take
// the first block away: the three refusals, a throw inside signing, and
// edits of the message, the namespace and "Sign as a file".

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
const win = dom.window;
const doc = win.document;
const $ = (id) => doc.getElementById(id);

let checks = 0;
const check = (name, actual, expected) => { assert.equal(actual, expected, name); checks++; };
const shown = () => !$('sigQrBox').classList.contains('hidden');
const gone = () => !shown() && $('sigQrPayload').textContent === '' && !$('sigQrImg').hasAttribute('src');

function signA() {
  $('msg').value = 'message A';
  $('namespace').value = 'file';
  $('asFile').checked = true;
  $('signBtn').click();
  assert.equal($('signErr').textContent, '', 'signing A succeeds');
  assert.ok(shown() && $('sigQrPayload').textContent.startsWith('-----BEGIN SSH SIGNATURE-----'), 'A is on screen');
}
const set = (id, value, event) => {
  if (typeof value === 'boolean') $(id).checked = value; else $(id).value = value;
  $(id).dispatchEvent(new win.Event(event, { bubbles: true }));
};

(async () => {
  $('modeWords').click();
  $('tv1').click();
  $('deriveBtn').click();
  for (let i = 0; i < 100 && $('screen2').classList.contains('hidden'); i++) await new Promise((r) => setTimeout(r, 50));
  assert.ok(!$('screen2').classList.contains('hidden'), 'derived tv1');

  // Refusals: the inputs are set without events, as a click on Sign right
  // after typing would find them, so only the Sign handler can clear A.
  const refusals = [
    ['empty message', () => { $('msg').value = ''; }, 'message is empty'],
    ['empty namespace', () => { $('namespace').value = '  '; }, 'namespace is empty: "file" for a file, "git" for a commit object'],
    ['trailing newline in file mode', () => { $('msg').value = 'B\n'; }, 'the text already ends with a newline: remove it, or untick "Sign as a file" to sign it as typed'],
  ];
  for (const [name, change, message] of refusals) {
    signA();
    change();
    $('signBtn').click();
    check(name + ': refused', $('signErr').textContent, message);
    check(name + ': no block of A left', gone(), true);
  }

  // A throw inside signing.
  signA();
  const real = win.sshsigSign;
  win.sshsigSign = () => { throw new Error('boom'); };
  $('msg').value = 'message B';
  $('signBtn').click();
  win.sshsigSign = real;
  check('throw: reported', $('signErr').textContent, 'signing failed: boom');
  check('throw: no block of A left', gone(), true);

  // Edits, each through the event a user's edit fires.
  const edits = [
    ['typing in the message', () => set('msg', 'message A!', 'input')],
    ['editing the namespace', () => set('namespace', 'git', 'input')],
    ['unticking Sign as a file', () => set('asFile', false, 'change')],
  ];
  for (const [name, edit] of edits) {
    signA();
    edit();
    check(name + ': no block of A left', gone(), true);
  }

  // A good Sign after all that still works, and replaces nothing it should keep.
  signA();
  const blockA = $('sigQrPayload').textContent;
  $('msg').value = 'message C';
  $('signBtn').click();
  check('a new Sign shows a new block', shown() && $('sigQrPayload').textContent !== blockA, true);

  console.log(`stale_signature: ${checks} checks passed`);
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
