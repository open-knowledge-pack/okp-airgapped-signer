const { JSDOM } = require('jsdom'); const fs = require('fs'); const path = require('path'); const os = require('os');
const { execFileSync } = require('child_process');
const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
// The icons documented in specs/main.md. The fourth vector is tv1 under
// the passphrase PROPHET, typed after the vector button has cleared the field.
const ICONS = { tv1: '\u2570\u263a\u2557\u2659', tv2: '\u2550\u2588\u255d\u2690', tv3: '\u255a\u2588\u256f\u2318', 'tv1+PROPHET': '\u255a\u263b\u256f\u2659' };
setTimeout(async () => {
  const doc = dom.window.document;
  for (const tv of ['tv1', 'tv2', 'tv3', 'tv1+PROPHET']) {
    doc.getElementById(tv.split('+')[0]).click();
    if (tv.endsWith('+PROPHET')) doc.getElementById('passphrase').value = 'PROPHET';
    doc.getElementById('deriveBtn').click();
    await new Promise((r) => setTimeout(r, 500));
    doc.getElementById('exportPubBtn').click();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-'));
    fs.writeFileSync(path.join(dir, 'key.pub'), doc.getElementById('pubQrPayload').textContent + '\n');
    const page = doc.getElementById('fp').textContent;
    const ref = execFileSync('ssh-keygen', ['-lf', path.join(dir, 'key.pub')]).toString().split(' ')[1];
    console.log(tv, 'page', page, 'ssh-keygen', ref, page === ref ? 'OK' : 'MISMATCH');
    const icon = doc.getElementById('icon').textContent;
    console.log(tv, 'icon', icon, 'spec', ICONS[tv], icon === ICONS[tv] ? 'OK' : 'MISMATCH');
    doc.getElementById('lockBtn').click();
    console.log(tv, 'after lock fp is', JSON.stringify(doc.getElementById('fp').textContent), 'icon is', JSON.stringify(doc.getElementById('icon').textContent));
    fs.rmSync(dir, { recursive: true });
  }
}, 200);
