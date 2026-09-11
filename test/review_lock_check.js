const { JSDOM } = require('jsdom'); const fs = require('fs'); const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
setTimeout(async () => {
  const doc = dom.window.document;
  doc.getElementById('tv1').click(); doc.getElementById('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 500));
  doc.getElementById('exportPubBtn').click();
  const pubB64 = doc.getElementById('pubQrPayload').textContent.split(' ')[1];
  const fp = doc.getElementById('fp').textContent;
  doc.getElementById('msg').value = 'x'; doc.getElementById('signBtn').click();
  const sigLine2 = doc.getElementById('sigQrPayload').textContent.split('\n')[2];
  doc.getElementById('lockBtn').click();
  const after = doc.documentElement.outerHTML;
  console.log('after lock: pub b64 present:', after.includes(pubB64), '| fp value present:', after.includes(fp), '| sig line present:', after.includes(sigLine2), '| "SHA256:" literal present (script source):', after.includes('SHA256:'));
}, 200);
