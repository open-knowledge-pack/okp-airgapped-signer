// Review cross-checks: (1) page PEM == ssh-keygen -Y sign output byte-for-byte,
// (2) namespace mismatch rejected, (3) check-novalidate accepts any key,
// (4) CRLF in textarea: what bytes get signed.
// The page signs as a file by default, so what it signed is MSG plus one LF;
// ssh-keygen is given the same bytes everywhere below.
const { JSDOM } = require('jsdom');
const fs = require('fs'); const path = require('path'); const os = require('os');
const crypto = require('crypto');
// Ed25519 public key from a 32-byte seed via Node's crypto, so the script
// needs no package besides jsdom. The 64-byte secret below is the seed
// followed by the public key, the layout tweetnacl used, kept because the
// page holds the key in that layout and the DOM leak check searches for it.
const pubFromSeed = (seed32) => {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed32)]);
  const spki = crypto.createPublicKey(crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(-32));
};
const { execFileSync } = require('child_process');

const html = fs.readFileSync(path.join(__dirname, '..', 'js-okp-signer', 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'file:///index.html', pretendToBeVisual: true });
const MSG = 'hello, air gap\nsecond line, no trailing newline';

function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function s(b) { b = Buffer.from(b); return Buffer.concat([u32(b.length), b]); }
function opensshPrivKey(seed, pub) {
  const pubBlob = Buffer.concat([s('ssh-ed25519'), s(pub)]);
  let priv = Buffer.concat([u32(0x12345678), u32(0x12345678), s('ssh-ed25519'), s(pub), s(Buffer.concat([Buffer.from(seed), Buffer.from(pub)])), s('')]);
  const pad = []; for (let i = 1; priv.length % 8; i++) { priv = Buffer.concat([priv, Buffer.from([i])]); }
  const body = Buffer.concat([Buffer.from('openssh-key-v1\0'), s('none'), s('none'), s(''), u32(1), s(pubBlob), s(priv)]);
  return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + body.toString('base64').replace(/.{70}/g, '$&\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
}
const run = (args, input) => { try { return execFileSync('ssh-keygen', args, { input, stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim(); } catch (e) { return 'EXIT ' + e.status + ': ' + e.stderr.toString().trim(); } };

setTimeout(async () => {
  const doc = dom.window.document;
  doc.getElementById('tv1').click(); doc.getElementById('deriveBtn').click();
  await new Promise((r) => setTimeout(r, 500));
  doc.getElementById('exportPubBtn').click();
  const pubLine = doc.getElementById('pubQrPayload').textContent;
  doc.getElementById('msg').value = MSG; doc.getElementById('signBtn').click();
  const pem = doc.getElementById('sigQrPayload').textContent;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sshsig-review-'));
  const seed = crypto.pbkdf2Sync(('abandon '.repeat(23) + 'art').trim().normalize('NFKD'), 'mnemonic', 2048, 64, 'sha512').subarray(0, 32);
  const pub = pubFromSeed(seed);
  const secret64 = Buffer.concat([Buffer.from(seed), Buffer.from(pub)]);
  const keyPath = path.join(dir, 'id_ed25519');
  fs.writeFileSync(keyPath, opensshPrivKey(seed, pub), { mode: 0o600 });
  console.log('(1) ssh-keygen -y pub line == page pub line:', run(['-y', '-f', keyPath]) === pubLine);
  fs.writeFileSync(path.join(dir, 'msg'), MSG + '\n');
  console.log('    sign:', run(['-Y', 'sign', '-f', keyPath, '-n', 'file', path.join(dir, 'msg')]));
  const ref = fs.readFileSync(path.join(dir, 'msg.sig'), 'utf8');
  console.log('    ssh-keygen -Y sign output == page PEM byte-for-byte:', ref === pem);

  fs.writeFileSync(path.join(dir, 'allowed_signers'), 'signer ' + pubLine + '\n');
  fs.writeFileSync(path.join(dir, 'page.sig'), pem);
  const V = (ns, msg) => run(['-Y', 'verify', '-f', path.join(dir, 'allowed_signers'), '-I', 'signer', '-n', ns, '-s', path.join(dir, 'page.sig')], msg);
  console.log('(2) verify -n git  :', V('git', MSG + '\n'));
  console.log('    verify -n email:', V('email', MSG + '\n'));
  console.log('    verify -n file :', V('file', MSG + '\n'));
  console.log('(3) check-novalidate -n file (no allowed_signers):', run(['-Y', 'check-novalidate', '-n', 'file', '-s', path.join(dir, 'page.sig')], MSG + '\n'));

  // (4) CRLF handling by the textarea value getter
  doc.getElementById('msg').value = 'a\r\nb';
  console.log('(4) textarea set "a\\r\\nb", .value reads back:', JSON.stringify(doc.getElementById('msg').value));
  doc.getElementById('signBtn').click();
  fs.writeFileSync(path.join(dir, 'page.sig'), doc.getElementById('sigQrPayload').textContent);
  console.log('    verify against "a\\nb\\n"  :', V('file', 'a\nb\n'));
  console.log('    verify against "a\\r\\nb\\n":', V('file', 'a\r\nb\n'));

  // (5) does anything secret land in the DOM after signing?
  const secretHex = secret64.toString('hex'), seedHex = Buffer.from(seed).toString('hex');
  const secretB64 = secret64.toString('base64'), seedB64 = Buffer.from(seed).toString('base64');
  const domText = doc.documentElement.outerHTML;
  console.log('(5) DOM contains seed/secret (hex or b64):', [secretHex, seedHex, secretB64, seedB64].some((x) => domText.includes(x)));
  doc.getElementById('lockBtn').click();
  const after = doc.documentElement.outerHTML;
  console.log('    after lock: DOM contains pub b64 blob or fingerprint:', after.includes(pubLine.split(' ')[1]) || after.includes('SHA256:'), '| any img src left:', !!(doc.getElementById('sigQrImg').getAttribute('src') || doc.getElementById('pubQrImg').getAttribute('src')));
  fs.rmSync(dir, { recursive: true });
}, 200);
