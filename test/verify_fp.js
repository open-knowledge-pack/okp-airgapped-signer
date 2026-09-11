const { JSDOM } = require('jsdom'); const fs = require('fs'); const path = require('path'); const os = require('os');
const { execFileSync } = require('child_process');
const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
setTimeout(async () => {
  const doc = dom.window.document;
  for (const tv of ['tv1', 'tv2', 'tv3']) {
    doc.getElementById(tv).click(); doc.getElementById('deriveBtn').click();
    await new Promise((r) => setTimeout(r, 500));
    doc.getElementById('exportPubBtn').click();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-'));
    fs.writeFileSync(path.join(dir, 'key.pub'), doc.getElementById('pubQrPayload').textContent + '\n');
    const page = doc.getElementById('fp').textContent;
    const ref = execFileSync('ssh-keygen', ['-lf', path.join(dir, 'key.pub')]).toString().split(' ')[1];
    console.log(tv, 'page', page, 'ssh-keygen', ref, page === ref ? 'OK' : 'MISMATCH');
    doc.getElementById('lockBtn').click();
    console.log(tv, 'after lock fp is', JSON.stringify(doc.getElementById('fp').textContent));
    fs.rmSync(dir, { recursive: true });
  }
}, 200);
