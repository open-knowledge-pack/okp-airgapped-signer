use std/assert
use std/testing *
use sha512.nu *
use encoding.nu *

@test
def "hex-to-bytes reads the pair 0b as a byte, not a binary prefix" [] {
  assert equal (hex-to-bytes "0b00ff") [11 0 255]
}

# sha512.nu keeps each 64-bit word in one i64 and rests on these three facts
# about Nushell ints. A Nushell that changes one fails here, not in a seed.
@test
def "int operators give the 64-bit word semantics sha512 relies on" [] {
  assert equal 0xffffffffffffffff (-1)
  assert equal (0x7fffffffffffffff bit-shl 1) (-2)
  assert equal (-1 bit-shr 1) (-1)
}

@test
def "sha512 of empty input matches FIPS vector" [] {
  assert equal (bytes-to-hex (sha512 [])) "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
}

@test
def "sha512 of abc matches FIPS vector" [] {
  assert equal (bytes-to-hex (sha512 (string-to-bytes "abc"))) "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
}

@test
def "sha512 of the two-block FIPS message" [] {
  let msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  assert equal (bytes-to-hex (sha512 (string-to-bytes $msg))) "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
}

@test
def "sha512 pads a 112-byte message into two blocks" [] {
  # 112 bytes leaves no room for the 16-byte length in the first block.
  let msg = 0..<112 | each { 0x61 }
  # Expected from node: crypto.createHash("sha512").update("a".repeat(112))
  assert equal (bytes-to-hex (sha512 $msg)) "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca"
}

@test
def "hmac-sha512 RFC 4231 case 1" [] {
  let key = 0..<20 | each { 0x0b }
  assert equal (bytes-to-hex (hmac-sha512 $key (string-to-bytes "Hi There"))) "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
}

@test
def "hmac-sha512 RFC 4231 case 2" [] {
  assert equal (bytes-to-hex (hmac-sha512 (string-to-bytes "Jefe") (string-to-bytes "what do ya want for nothing?"))) "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
}

@test
def "hmac-sha512 RFC 4231 case 3" [] {
  let key = 0..<20 | each { 0xaa }
  let data = 0..<50 | each { 0xdd }
  assert equal (bytes-to-hex (hmac-sha512 $key $data)) "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
}

@test
def "hmac-sha512 RFC 4231 case 6 hashes a key longer than the block" [] {
  let key = 0..<131 | each { 0xaa }
  assert equal (bytes-to-hex (hmac-sha512 $key (string-to-bytes "Test Using Larger Than Block-Size Key - Hash Key First"))) "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
}

@test
def "pbkdf2 matches node crypto at 3 iterations" [] {
  # Expected from node: crypto.pbkdf2Sync("password", "salt", 3, 64, "sha512")
  assert equal (bytes-to-hex (pbkdf2-hmac-sha512 (string-to-bytes "password") (string-to-bytes "salt") 3 64)) "b6b07cb2cebf4ad84468391a543824fccffe0e0769dbe6bddf10a65673c4b648e612d44918f9ce9a19a1294cf5140628084ba994c3b21a4ef4741220b811c633"
}

# Expected seeds come from the npm bip39 package:
#   bip39.mnemonicToSeedSync(mnemonic, passphrase)
# Each run takes about 14 s (2048 iterations).
@test
def "pbkdf2 derives the BIP39 test vector 1 seed with passphrase TREZOR" [] {
  let mnemonic = (0..<23 | each { "abandon" } | append "art" | str join " ")
  let seed = pbkdf2-hmac-sha512 (string-to-bytes $mnemonic) (string-to-bytes "mnemonicTREZOR") 2048 64
  assert equal (bytes-to-hex $seed) "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
}

@test
def "pbkdf2 derives the BIP39 test vector 1 seed with an empty passphrase" [] {
  let mnemonic = (0..<23 | each { "abandon" } | append "art" | str join " ")
  let seed = pbkdf2-hmac-sha512 (string-to-bytes $mnemonic) (string-to-bytes "mnemonic") 2048 64
  assert equal (bytes-to-hex $seed) "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
}
