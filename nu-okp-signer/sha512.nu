# SHA-512 (FIPS 180-4), HMAC-SHA512 (RFC 2104) and PBKDF2-HMAC-SHA512
# (RFC 8018). SHA-512 itself is Nushell's builtin `hash sha512` (0.116+).
#
# Why the builtin: a BIP39 derivation took 14 s with SHA-512 written out in
# Nushell, and takes well under a second with it. Not that version behind a
# flag because: on a Nushell without `hash sha512` the module does not parse
# at all, so the flag could never be reached where it would matter. For an
# older Nushell, use the last version that needs only `hash sha256`, with
# SHA-512 written out in nu-okp-signer/sha512.nu: the commit with Change-Id
# wsskrzvstvzoqpwnsokuoxtmtpmlwlnx. The trailer is the same here and in the
# published repo:
#   git log --all --grep='^Change-Id: wsskrzvs'
#
# Callers pass and get list<int> (0..255); PBKDF2 works on binary inside, so
# its 4096 hashes convert nothing.

use encoding.nu [uint32-to-bytes bytes-to-binary binary-to-bytes]

export def main [bytes: list<int>]: nothing -> list<int> {
  bytes-to-binary $bytes | hash sha512 --binary | binary-to-bytes $in
}

# The inner and outer pads of an HMAC key (block size 128).
def hmac-pads [key: binary]: nothing -> record<inner: binary, outer: binary> {
  let k = if ($key | bytes length) > 128 { $key | hash sha512 --binary } else { $key }
  let k = $k | bytes add --end (0..<(128 - ($k | bytes length)) | each { 0x[00] } | bytes collect)

  {
    inner: ($k | bits xor (1..128 | each { 0x[36] } | bytes collect))
    outer: ($k | bits xor (1..128 | each { 0x[5c] } | bytes collect))
  }
}

def hmac-padded [pads: record<inner: binary, outer: binary> msg: binary]: nothing -> binary {
  $pads.outer | bytes add --end ($pads.inner | bytes add --end $msg | hash sha512 --binary) | hash sha512 --binary
}

export def hmac-sha512 [key: list<int> msg: list<int>]: nothing -> list<int> {
  hmac-padded (hmac-pads (bytes-to-binary $key)) (bytes-to-binary $msg) | binary-to-bytes $in
}

export def pbkdf2-hmac-sha512 [password: list<int> salt: list<int> iters: int dklen: int]: nothing -> list<int> {
  let pads = hmac-pads (bytes-to-binary $password)
  let salt = bytes-to-binary $salt

  1..(($dklen + 63) // 64)
  | each {|i|
    mut u = hmac-padded $pads ($salt | bytes add --end (bytes-to-binary (uint32-to-bytes $i)))
    mut t = $u

    for j in 1..<$iters {
      $u = hmac-padded $pads $u
      $t = $t | bits xor $u
    }
    $t
  }
  | bytes collect
  | binary-to-bytes $in
  | first $dklen
}
