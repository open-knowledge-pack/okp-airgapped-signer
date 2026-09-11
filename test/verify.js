// Verify that the pubkey hex values claimed in index.html for the 3 test
// vectors match a fresh run of the derivation on Node's crypto.
// Why not the bip39 and tweetnacl packages: they were the only dependencies
// besides jsdom, and Node's crypto has PBKDF2 and Ed25519. The mnemonic
// checksum is not re-validated here; the vectors are known valid.

const crypto = require('crypto');

const mnemonicToSeed = (mnemonic) =>
  crypto.pbkdf2Sync(mnemonic.normalize('NFKD'), 'mnemonic', 2048, 64, 'sha512');

// Ed25519 key from a 32-byte seed: wrap the seed in the PKCS#8 header.
const keyPairFromSeed = (seed32) => {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed32)]);
  const secretKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(secretKey).export({ format: 'der', type: 'spki' });
  return { secretKey, publicKey: new Uint8Array(spki.subarray(-32)) };
};

const vectors = [
  { name: 'tv1', mnemonic: ('abandon '.repeat(23) + 'art').trim(),
    expected: '1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961' },
  { name: 'tv2', mnemonic: ('zoo '.repeat(23) + 'vote').trim(),
    expected: 'ea1c7d41a6d70293194f45206ab4dca257d9c252fe2c53779fdef2a2bd05cd47' },
  { name: 'tv3', mnemonic: 'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless',
    expected: 'e88ff5f87c809d2921bf2ee8bd3a176d6fc66b9f90230920f1246b5472c22c13' },
];

const toHex = (u8) => Buffer.from(u8).toString('hex');

for (const v of vectors) {
  const seed32 = mnemonicToSeed(v.mnemonic).subarray(0, 32);
  const kp = keyPairFromSeed(seed32);
  const pubHex = toHex(kp.publicKey);
  const ok = pubHex === v.expected ? 'OK' : 'MISMATCH';
  console.log(`${v.name}: pub=${pubHex}  expected=${v.expected}  ${ok}`);
}

// Also verify a sign/verify round-trip with tv1.
const seed = mnemonicToSeed(vectors[0].mnemonic).subarray(0, 32);
const kp = keyPairFromSeed(seed);
const msg = new TextEncoder().encode('hello world');
const sig = crypto.sign(null, msg, kp.secretKey);
const ok = crypto.verify(null, msg, crypto.createPublicKey(kp.secretKey), sig);
console.log(`tv1 sign/verify roundtrip: ${ok ? 'OK' : 'FAIL'}`);
