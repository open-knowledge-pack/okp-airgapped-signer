use std/assert
use std/testing *
use encoding.nu [hex-to-bytes bytes-to-hex string-to-bytes]
use ed25519.nu

# RFC 8032 section 7.1 vectors.
@test
def "keypair matches RFC 8032 test 1" [] {
  let kp = ed25519 keypair (hex-to-bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  assert equal (bytes-to-hex $kp.public) "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
}

@test
def "sign matches RFC 8032 test 1 on the empty message" [] {
  let kp = ed25519 keypair (hex-to-bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  assert equal (bytes-to-hex (ed25519 sign [] $kp.secret)) "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
}

@test
def "sign matches RFC 8032 test 2 on a one-byte message" [] {
  let kp = ed25519 keypair (hex-to-bytes "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
  assert equal (bytes-to-hex $kp.public) "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
  assert equal (bytes-to-hex (ed25519 sign [0x72] $kp.secret)) "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
}

@test
def "sign matches RFC 8032 test 3 on a two-byte message" [] {
  let kp = ed25519 keypair (hex-to-bytes "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
  assert equal (bytes-to-hex $kp.public) "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
  assert equal (bytes-to-hex (ed25519 sign [0xaf 0x82] $kp.secret)) "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
}

# Spec test vectors: the seed is the first 32 bytes of the BIP39 seed at an
# empty passphrase (npm bip39), the public key is the one specs/main.md lists.
@test
def "keypair from spec test vector 1 seed" [] {
  let kp = ed25519 keypair (hex-to-bytes "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70")
  assert equal (bytes-to-hex $kp.public) "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961"
}

@test
def "keypair from spec test vector 2 seed" [] {
  let kp = ed25519 keypair (hex-to-bytes "e28a37058c7f5112ec9e16a3437cf363a2572d70b6ceb3b6965447623d620f14")
  assert equal (bytes-to-hex $kp.public) "ea1c7d41a6d70293194f45206ab4dca257d9c252fe2c53779fdef2a2bd05cd47"
}

@test
def "keypair from spec test vector 3 seed" [] {
  let kp = ed25519 keypair (hex-to-bytes "848bbe19cad445e46f35fd3d1a89463583ac2b60b5eb4cfcf955731775a5d9e1")
  assert equal (bytes-to-hex $kp.public) "e88ff5f87c809d2921bf2ee8bd3a176d6fc66b9f90230920f1246b5472c22c13"
}

# Expected from node: nacl.sign.detached("hello\n", keyPair.fromSeed(tv1 seed).secretKey)
@test
def "sign matches tweetnacl for test vector 1 key" [] {
  let kp = ed25519 keypair (hex-to-bytes "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70")
  assert equal (bytes-to-hex (ed25519 sign (string-to-bytes "hello\n") $kp.secret)) "2fb118d9bf2fff2ad704ff4658659ae1a97ea955838a28b61e6eeea472e76fa69aacca5e5291170b0da5567ec9e934fd409749660c59d1a44076d1e67f4a1305"
}

# Why these matter: `first 32` and `skip 32` truncate a short list rather than
# failing, so before the check a 32-byte secret produced a full 64-byte
# signature whose R half was right and whose S half was wrong. It verified as
# false with nothing anywhere reporting an error.
@test
def "keypair refuses a seed that is not 32 bytes" [] {
  let msg = try { ed25519 keypair (0..<16 | each { 0x42 }); "" } catch {|e| $e.msg }
  assert str contains $msg "seed must be 32 bytes"
}

@test
def "sign refuses a secret that is not 64 bytes" [] {
  let kp = ed25519 keypair (0..<32 | each { 0x42 })
  let msg = try { ed25519 sign [1 2 3] ($kp.secret | first 32); "" } catch {|e| $e.msg }
  assert str contains $msg "secret must be 64 bytes"
}

# RFC 8032 test 1: the same seed, message and signature the sign tests use, so
# a verify that passed by rebuilding the signature instead of checking it would
# not show up here. The tamper cases are what separate the two.
const RFC1_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
const RFC1_SIG = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

@test
def "verify accepts RFC 8032 test 1" [] {
  assert equal (ed25519 verify [] (hex-to-bytes $RFC1_SIG) (hex-to-bytes $RFC1_PUBLIC)) true
}

@test
def "verify rejects a message that changed" [] {
  assert equal (ed25519 verify [0] (hex-to-bytes $RFC1_SIG) (hex-to-bytes $RFC1_PUBLIC)) false
}

@test
def "verify accepts what sign just produced" [] {
  let kp = ed25519 keypair (0..<32 | each { 0x42 })
  let msg = string-to-bytes "self-check"
  assert equal (ed25519 verify $msg (ed25519 sign $msg $kp.secret) $kp.public) true
}

# tweetnacl accepts this one: it never checks that S is below the group order,
# so S and S + L both verify and a signature can be altered without the key.
# RFC 8032 section 5.1.7 requires the check. Values generated with tweetnacl,
# which reports true for the second signature.
const MALLEABLE_PUBLIC = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
const MALLEABLE_GOOD = "778cda0634c021fae8b1a9fa655ba13230f6fcfc5c5d519afb0872ec9bf1d64241cc3eed8ad47270d86d30e762ad17677c6fb1797e35bca7eba30388257e020f"
const MALLEABLE_RAISED = "778cda0634c021fae8b1a9fa655ba13230f6fcfc5c5d519afb0872ec9bf1d6422ea0344aa53785c8ae0a288a41a7f67b7c6fb1797e35bca7eba30388257e021f"

@test
def "verify rejects a signature whose S was raised by the group order" [] {
  assert equal (ed25519 verify [] (hex-to-bytes $MALLEABLE_GOOD) (hex-to-bytes $MALLEABLE_PUBLIC)) true
  assert equal (ed25519 verify [] (hex-to-bytes $MALLEABLE_RAISED) (hex-to-bytes $MALLEABLE_PUBLIC)) false
}

@test
def "verify returns false for a public key that is not on the curve" [] {
  let pub = hex-to-bytes "000000000000000000000000000000000000000000000000000000000000002a"
  assert equal (ed25519 verify [0x78] (0..<64 | each { 7 }) $pub) false
}

@test
def "verify refuses a signature that is not 64 bytes" [] {
  let msg = try { ed25519 verify [] [1 2 3] (hex-to-bytes $RFC1_PUBLIC); "" } catch {|e| $e.msg }
  assert str contains $msg "signature must be 64 bytes"
}
