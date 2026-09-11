use std/assert
use std/testing *
use encoding.nu *
use bip39.nu
use ed25519.nu

const TV1 = [abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art]
const TV2 = [zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote]

@test
def "entropy of test vector 1 is all zero bytes" [] {
  assert equal (bip39 entropy $TV1) (0..<32 | each { 0 })
}

@test
def "entropy of test vector 2 is all 0xff bytes" [] {
  assert equal (bip39 entropy $TV2) (0..<32 | each { 255 })
}

@test
def "entropy rejects a wrong word count" [] {
  let msg = try { bip39 entropy ($TV1 | first 23); "" } catch {|e| $e.msg }
  assert str contains $msg "expected 24 words"
}

@test
def "entropy names the unknown word" [] {
  let msg = try { bip39 entropy ($TV1 | update 2 "abandom"); "" } catch {|e| $e.msg }
  assert str contains $msg "word #3"
}

@test
def "entropy rejects a checksum mismatch" [] {
  let msg = try { bip39 entropy ($TV1 | update 23 "abandon"); "" } catch {|e| $e.msg }
  assert str contains $msg "checksum"
}

@test
def "seed refuses a non-ASCII passphrase" [] {
  let msg = try { bip39 seed $TV1 "pässword"; "" } catch {|e| $e.msg }
  assert str contains $msg "ASCII"
}

# End to end against specs/main.md: mnemonic to Ed25519 public key. About 15 s each.
@test
def "test vector 1 derives the public key the spec lists" [] {
  let kp = ed25519 keypair (bip39 seed $TV1 | first 32)
  assert equal (bytes-to-hex $kp.public) "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961"
}

@test
def "test vector 1 with passphrase PROPHET derives the public key the spec lists" [] {
  let kp = ed25519 keypair (bip39 seed $TV1 "PROPHET" | first 32)
  assert equal (bytes-to-hex $kp.public) "0abd856befd1aaaacfe339bd573dbbcb979d760926ca2e653b8b98e49faa35f9"
}

# Every word before these two was a bare word, so `true` and `false` became
# booleans and the lookup refused them as typos. Roughly 2.3% of random 24-word
# mnemonics carry one of them, and the holder was told their phrase was wrong.
# The two mnemonics are generated from random entropy against the official
# english.txt; both words are quoted here for the same reason as in the list.
const TV_TRUE = [original nature faith fringe keen feature "true" viable claw door cram grace they share kidney usual total card mule neck game topple gossip penalty]
const TV_FALSE = [similar "false" hero ethics vanish camera parent truly stay black warrior regret know total near shell test hurt decline lucky razor join cage host]

@test
def "every entry of the word list is a string" [] {
  use bip39-words.nu WORDS
  assert equal ($WORDS | where {|w| ($w | describe) != "string" }) []
}

@test
def "entropy accepts a mnemonic holding the word true" [] {
  assert equal (bytes-to-hex (bip39 entropy $TV_TRUE)) "9cb26d482e879aa87a579a2a082cc8b2be098a5e9f81e5c4524549d5f3ca593d"
}

@test
def "entropy accepts a mnemonic holding the word false" [] {
  assert equal (bytes-to-hex (bip39 entropy $TV_FALSE)) "c8ea49ad26df1441680f4bd4e2dfdd5a57bfcba4e62bdf8df8e3c25b2af0480b"
}
