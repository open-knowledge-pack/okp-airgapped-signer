// Drive the page in jsdom: derive tv1, sign a root-statement line in file mode
// and in raw mode, and check each PEM with the real ssh-keygen.
const { JSDOM } = require('jsdom');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asfile-'));
const line = 'multiproof-merkle-v4 846040d91e4183eca080d8db0f957600e8e6caa6766cbd4d3d5d846ddb4bbfde 0 genesis none';

function verify(sigPem, msgBytes, pubLine) {
  fs.writeFileSync(path.join(tmp, 'msg.sig'), sigPem);
  fs.writeFileSync(path.join(tmp, 'allowed'), `signer ${pubLine}\n`);
  try {
    const out = execFileSync('ssh-keygen', ['-Y', 'verify', '-f', path.join(tmp, 'allowed'), '-I', 'signer', '-n', 'file', '-s', path.join(tmp, 'msg.sig')], { input: msgBytes, stdio: ['pipe', 'pipe', 'pipe'] });
    return out.toString().trim();
  } catch (e) { return 'FAIL: ' + e.stderr.toString().trim(); }
}

setTimeout(async () => {
  const doc = dom.window.document;
  doc.getElementById('tv1').click();
  doc.getElementById('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 3000));
  doc.getElementById('exportPubBtn').click();
  const pubLine = doc.getElementById('pubQrPayload').textContent.trim();
  console.log('pub line:', pubLine);
  const sign = () => { doc.getElementById('signErr').textContent = ''; doc.getElementById('sigQrPayload').textContent = ''; doc.getElementById('signBtn').click(); return { pem: doc.getElementById('sigQrPayload').textContent, err: doc.getElementById('signErr').textContent }; };

  console.log('asFile default checked:', doc.getElementById('asFile').checked);
  doc.getElementById('msg').value = line;
  let r = sign();
  console.log('file mode, against line+LF :', verify(r.pem, line + '\n', pubLine));
  console.log('file mode, against bare line:', verify(r.pem, line, pubLine));

  doc.getElementById('msg').value = line + '\n';
  r = sign();
  console.log('file mode, text ends with LF -> error:', JSON.stringify(r.err), 'pem empty:', r.pem === '');

  doc.getElementById('asFile').checked = false;
  doc.getElementById('msg').value = line;
  r = sign();
  console.log('raw mode, against bare line :', verify(r.pem, line, pubLine));
  console.log('raw mode, against line+LF   :', verify(r.pem, line + '\n', pubLine));

  doc.getElementById('lockBtn').click();
  console.log('after lock, asFile back to checked:', doc.getElementById('asFile').checked);
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(0);
}, 500);
