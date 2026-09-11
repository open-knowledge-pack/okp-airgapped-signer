// Validate the pure-JS primitives against Node's `crypto` reference, BEFORE
// we touch index.html. If anything is off — wrong padding, wrong endianness,
// wrong HMAC block size — we catch it here, not in the page.

const crypto = require('crypto');
const sha512 = (bytes) => new Uint8Array(crypto.createHash('sha512').update(bytes).digest());

// === pure-JS SHA-256 ============================================================
// Standard FIPS-180-4. ~50 lines. Uses Uint32Array + DataView; no big-int.
function sha256(bytes) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ]);
  const H = new Uint32Array([
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
  ]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  const len = bytes.length;
  // Pad: append 0x80, then zeros until length ≡ 56 mod 64, then 64-bit BE bit length.
  const padBytes = (len % 64 < 56) ? (56 - (len % 64)) : (120 - (len % 64));
  const total = len + padBytes + 8;
  const padded = new Uint8Array(total);
  padded.set(bytes);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  // 64-bit big-endian bit length. JS numbers are exact up to 2^53, so we split.
  const bitLenLo = (len * 8) >>> 0;
  const bitLenHi = Math.floor(len / 0x20000000) >>> 0; // len * 8 / 2^32 == len / 2^29
  dv.setUint32(total - 8, bitLenHi, false);
  dv.setUint32(total - 4, bitLenLo, false);

  const W = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >>> 3);
      const s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const T1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const T2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e;
      e = (d + T1) >>> 0;
      d = c; c = b; b = a;
      a = (T1 + T2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
  return out;
}

// === HMAC-SHA512 on top of SHA-512 ================================================
// SHA-512 block size = 128 bytes, output = 64 bytes.
function hmacSha512(key, msg) {
  const B = 128;
  let k = key;
  if (k.length > B) k = sha512(k);
  if (k.length < B) {
    const padded = new Uint8Array(B);
    padded.set(k);
    k = padded;
  }
  const opad = new Uint8Array(B);
  const ipad = new Uint8Array(B);
  for (let n = 0; n < B; n++) {
    opad[n] = k[n] ^ 0x5c;
    ipad[n] = k[n] ^ 0x36;
  }
  const inner = new Uint8Array(B + msg.length);
  inner.set(ipad); inner.set(msg, B);
  const innerHash = sha512(inner);
  const outer = new Uint8Array(B + 64);
  outer.set(opad); outer.set(innerHash, B);
  return sha512(outer);
}

// === PBKDF2-HMAC-SHA512 =========================================================
function pbkdf2HmacSha512(password, salt, iters, dkLen) {
  const hLen = 64;
  const blocks = Math.ceil(dkLen / hLen);
  const out = new Uint8Array(blocks * hLen);
  const block = new Uint8Array(salt.length + 4);
  block.set(salt);
  for (let i = 1; i <= blocks; i++) {
    block[salt.length + 0] = (i >>> 24) & 0xff;
    block[salt.length + 1] = (i >>> 16) & 0xff;
    block[salt.length + 2] = (i >>>  8) & 0xff;
    block[salt.length + 3] =  i         & 0xff;
    let U = hmacSha512(password, block);
    const T = new Uint8Array(U); // copy
    for (let j = 1; j < iters; j++) {
      U = hmacSha512(password, U);
      for (let k = 0; k < hLen; k++) T[k] ^= U[k];
    }
    out.set(T, (i - 1) * hLen);
  }
  return out.subarray(0, dkLen);
}

// === Tests ======================================================================
const hex = (u8) => Buffer.from(u8).toString('hex');
let failures = 0;

function check(label, got, want) {
  const ok = got === want;
  console.log(`${ok ? 'OK  ' : 'FAIL'}  ${label}`);
  if (!ok) {
    console.log(`        got:  ${got}`);
    console.log(`        want: ${want}`);
    failures++;
  }
}

// SHA-256 well-known test vectors
const sha256Ref = (s) => crypto.createHash('sha256').update(s).digest('hex');
for (const s of ['', 'abc', 'a', 'The quick brown fox jumps over the lazy dog',
                 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(63),
                 'a'.repeat(64), 'a'.repeat(127), 'a'.repeat(1000000)]) {
  const bytes = new TextEncoder().encode(s);
  check(`SHA-256("${s.length <= 30 ? s : `<${s.length} chars>`}")`,
        hex(sha256(bytes)), sha256Ref(s));
}

// HMAC-SHA512 test vectors (RFC 4231)
const hmacRef = (key, msg) => crypto.createHmac('sha512', key).update(msg).digest('hex');
for (const [keyStr, msgStr, label] of [
  ['', '', 'empty key, empty msg'],
  ['key', 'The quick brown fox jumps over the lazy dog', 'short'],
  ['Jefe', 'what do ya want for nothing?', 'RFC4231 #2'],
  ['k'.repeat(200), 'longer-than-block key', 'key>block'],
]) {
  const k = new TextEncoder().encode(keyStr);
  const m = new TextEncoder().encode(msgStr);
  check(`HMAC-SHA512: ${label}`, hex(hmacSha512(k, m)), hmacRef(k, m));
}

// PBKDF2-HMAC-SHA512 — BIP39 test-vector "abandon..art" should derive the
// canonical seed (well-known constant; matches every BIP39 implementation).
const mnemonic = ('abandon '.repeat(23) + 'art').trim();
const password = new TextEncoder().encode(mnemonic.normalize('NFKD'));
const salt     = new TextEncoder().encode('mnemonic'.normalize('NFKD'));
const seed = pbkdf2HmacSha512(password, salt, 2048, 64);
const refSeed = crypto.pbkdf2Sync(Buffer.from(password), Buffer.from(salt), 2048, 64, 'sha512');
check('PBKDF2 BIP39 "abandon..art" seed', hex(seed), refSeed.toString('hex'));

// Spot-check a non-trivial PBKDF2 — RFC 6070-style with SHA-512.
const p2 = new TextEncoder().encode('password');
const s2 = new TextEncoder().encode('salt');
const dk2 = pbkdf2HmacSha512(p2, s2, 4096, 64);
const ref2 = crypto.pbkdf2Sync('password', 'salt', 4096, 64, 'sha512');
check('PBKDF2 password/salt iters=4096 dkLen=64', hex(dk2), ref2.toString('hex'));

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);
