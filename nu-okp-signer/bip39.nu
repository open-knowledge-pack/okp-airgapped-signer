# BIP39 for 24-word mnemonics in pure Nushell: word lookup, checksum, seed.

use bip39-words.nu WORDS
use encoding.nu *
use sha512.nu [pbkdf2-hmac-sha512]

# 24 words carry 264 bits: 256 bits of entropy followed by an 8-bit checksum,
# the first byte of SHA-256 over the entropy. Errors on a wrong word count, an
# unknown word, or a checksum mismatch, so a mistyped mnemonic never derives
# a "close" key silently. Returns the 32 entropy bytes.
export def entropy [words: list<string>]: nothing -> list<int> {
  if ($words | length) != 24 {
    error make {msg: $"expected 24 words, got (($words | length))"}
  }
  # Unknown words become -1: `each` drops a null result, which would shift
  # every later word. Not `error make` inside the closure because Nushell
  # wraps an error raised there as "Eval block failed", and the caller sees that.
  let indexes = $words | each {|w| $WORDS | enumerate | where item == $w | get --optional 0.index | default (-1) }
  let unknown = $indexes | enumerate | where item == -1 | get --optional 0.index
  if $unknown != null {
    error make {msg: $"word #($unknown + 1) \"($words | get $unknown)\" is not in the BIP39 wordlist"}
  }
  let bits = $indexes | each {|index| 0..10 | each {|b| ($index bit-shr (10 - $b)) bit-and 1 } } | flatten
  let bytes = $bits | chunks 8 | each { reduce --fold 0 {|bit, acc| $acc * 2 + $bit } }
  let entropy = $bytes | first 32
  let digest = bytes-to-binary $entropy | hash sha256 --binary | binary-to-bytes $in
  if ($bytes | get 32) != ($digest | get 0) {
    error make {msg: "checksum mismatch: the last word does not match the BIP39 checksum of the previous 23 words"}
  }
  $entropy
}

# The 64-byte BIP39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, over the words
# joined by single spaces, with salt "mnemonic" + passphrase. About 14 s.
export def seed [words: list<string>, passphrase: string = ""]: nothing -> list<int> {
  entropy $words | ignore
  # BIP39 asks for NFKD on both inputs and Nushell has no normalizer. The
  # English word list is ASCII, so only the passphrase can carry non-ASCII.
  # Refuse it: deriving a key that no other tool would derive is worse.
  if not (string-to-bytes $passphrase | all {|b| $b < 128 }) {
    error make {msg: "passphrase must be ASCII: Nushell cannot apply the NFKD normalization BIP39 requires"}
  }
  pbkdf2-hmac-sha512 (string-to-bytes ($words | str join " ")) (string-to-bytes $"mnemonic($passphrase)") 2048 64
}
