const { JSDOM } = require('jsdom'); const fs = require('fs'); const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
setTimeout(async () => {
  const doc = dom.window.document;
  doc.getElementById('tv1').click(); doc.getElementById('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 500));
  doc.getElementById('msg').value = 'x'.repeat(5000); doc.getElementById('signBtn').click();
  const pem = doc.getElementById('sigQrPayload').textContent;
  const q = dom.window.qrcode(0, 'M'); q.addData(pem); q.make();
  console.log('pem bytes', pem.length, 'modules', q.getModuleCount(), 'version', (q.getModuleCount() - 17) / 4);
}, 200);
