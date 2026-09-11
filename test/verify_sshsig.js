// Drive index.html in jsdom: tv1 -> derive -> export pub -> sign, then hand
// the DOM output to the real ssh-keygen. Positive and negative cases. The
// page signs as a file by default, so the bytes it signed are MSG plus one
// LF; the bare text is the negative case.
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });

const MSG = 'hello, air gap\nsecond line, no trailing newline';

setTimeout(async () => {
  const doc = dom.window.document;
  doc.getElementById('tv1').click();
  doc.getElementById('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 500));
  doc.getElementById('exportPubBtn').click();
  const pubLine = doc.getElementById('pubQrPayload').textContent;
  doc.getElementById('msg').value = MSG;
  doc.getElementById('signBtn').click();
  const pem = doc.getElementById('sigQrPayload').textContent;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sshsig-'));
  fs.writeFileSync(path.join(dir, 'allowed_signers'), 'signer ' + pubLine + '\n');
  fs.writeFileSync(path.join(dir, 'msg.sig'), pem); fs.writeFileSync(path.join(dir, 'key.pub'), pubLine + '\n');
  console.log('pub line:', pubLine);
  console.log('ssh-keygen -lf:', execFileSync('ssh-keygen', ['-lf', path.join(dir, 'key.pub')]).toString().trim());
  console.log('sig bytes:', pem.length, '\n' + pem);

  const run = (msg) => {
    try {
      return execFileSync('ssh-keygen', ['-Y', 'verify', '-f', path.join(dir, 'allowed_signers'), '-I', 'signer', '-n', 'file', '-s', path.join(dir, 'msg.sig')], { input: msg, stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim();
    } catch (e) { return 'EXIT ' + e.status + ': ' + e.stderr.toString().trim(); }
  };
  console.log('verify as file (+ LF)  :', run(MSG + '\n'));
  console.log('verify bare text (no LF):', run(MSG));
  console.log('verify flipped byte    :', run('Hello' + MSG.slice(5) + '\n'));
  fs.rmSync(dir, { recursive: true });
}, 200);
