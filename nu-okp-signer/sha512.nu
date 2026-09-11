# SHA-512 (FIPS 180-4), HMAC-SHA512 (RFC 2104) and PBKDF2-HMAC-SHA512
# (RFC 8018) in pure Nushell.
#
# Why one int per 64-bit word: a Nushell int is an i64, and three facts about
# it, verified in the 0.115 source, make that a usable 64-bit word. A hex
# literal is parsed as u64 and cast to i64 (nu-parser parse_literals.rs, on
# purpose: "for numbers like 0xffffffffffffffef"), so K and H0 below are the
# FIPS tables verbatim. `bit-shl` is Rust's checked_shl, which drops the bits
# shifted out, and `bit-shr` is checked_shr, which keeps the sign (nu-protocol
# value/mod.rs). Only `+` refuses to wrap, so an addition splits each operand
# into its low 32 bits (`bit-and 0xffffffff`) and its high part (`bit-shr
# 32`); the high sum carries sign extension, which the final `bit-shl 32`
# discards. A test in test_sha512.nu pins the three facts.
#
# Not (hi, lo) pairs, the layout tweetnacl uses and this file used before,
# because: every bitwise step then runs twice. One word per int took a
# compression from 8.4 ms to 3 ms and PBKDF2 from 36 s to 14 s.
#
# Bytes travel as list<int> (0..255). Binary values appear only at the edges.

use encoding.nu [uint32-to-bytes]

const MASK = 0xffffffff

# Round constants, FIPS 180-4 section 4.2.3.
const K = [
  0x428a2f98d728ae22 0x7137449123ef65cd 0xb5c0fbcfec4d3b2f 0xe9b5dba58189dbbc
  0x3956c25bf348b538 0x59f111f1b605d019 0x923f82a4af194f9b 0xab1c5ed5da6d8118
  0xd807aa98a3030242 0x12835b0145706fbe 0x243185be4ee4b28c 0x550c7dc3d5ffb4e2
  0x72be5d74f27b896f 0x80deb1fe3b1696b1 0x9bdc06a725c71235 0xc19bf174cf692694
  0xe49b69c19ef14ad2 0xefbe4786384f25e3 0x0fc19dc68b8cd5b5 0x240ca1cc77ac9c65
  0x2de92c6f592b0275 0x4a7484aa6ea6e483 0x5cb0a9dcbd41fbd4 0x76f988da831153b5
  0x983e5152ee66dfab 0xa831c66d2db43210 0xb00327c898fb213f 0xbf597fc7beef0ee4
  0xc6e00bf33da88fc2 0xd5a79147930aa725 0x06ca6351e003826f 0x142929670a0e6e70
  0x27b70a8546d22ffc 0x2e1b21385c26c926 0x4d2c6dfc5ac42aed 0x53380d139d95b3df
  0x650a73548baf63de 0x766a0abb3c77b2a8 0x81c2c92e47edaee6 0x92722c851482353b
  0xa2bfe8a14cf10364 0xa81a664bbc423001 0xc24b8b70d0f89791 0xc76c51a30654be30
  0xd192e819d6ef5218 0xd69906245565a910 0xf40e35855771202a 0x106aa07032bbd1b8
  0x19a4c116b8d2d0c8 0x1e376c085141ab53 0x2748774cdf8eeb99 0x34b0bcb5e19b48a8
  0x391c0cb3c5c95a63 0x4ed8aa4ae3418acb 0x5b9cca4f7763e373 0x682e6ff3d6b2b8a3
  0x748f82ee5defb2fc 0x78a5636f43172f60 0x84c87814a1f0ab72 0x8cc702081a6439ec
  0x90befffa23631e28 0xa4506cebde82bde9 0xbef9a3f7b2c67915 0xc67178f2e372532b
  0xca273eceea26619c 0xd186b8c721c0c207 0xeada7dd6cde0eb1e 0xf57d4f7fee6ed178
  0x06f067aa72176fba 0x0a637dc5a2c898a6 0x113f9804bef90dae 0x1b710b35131c471b
  0x28db77f523047d84 0x32caab7b40c72493 0x3c9ebe0a15c9bebc 0x431d67c49c100d4c
  0x4cc5d4becb3e42b6 0x597f299cfc657e2a 0x5fcb6fab3ad6faec 0x6c44198c4a475817
]

# Initial hash value, FIPS 180-4 section 5.3.5.
const H0 = [
  0x6a09e667f3bcc908 0xbb67ae8584caa73b 0x3c6ef372fe94f82b 0xa54ff53a5f1d36f1
  0x510e527fade682d1 0x9b05688c2b3e6c1f 0x1f83d9abfb41bd6b 0x5be0cd19137e2179
]

# One compression: state (8 words) absorbs block (16 words).
#
# rotr(x, n) is ((x bit-shr n) bit-and (2^(64 - n) - 1)) bit-or (x bit-shl (64 - n)):
# the mask removes the sign extension of bit-shr, the shift left drops the
# bits that rotate out. Not a def because: 736 rotates per block at 2.6 us
# per custom command call would cost more than the arithmetic itself. The
# masks are written out; the FIPS vectors catch a wrong one.
export def sha512-compress [state: list<int>, block: list<int>]: nothing -> list<int> {
  mut w = $block
  for t in 16..79 {
    let x = $w | get ($t - 15)
    let y = $w | get ($t - 2)
    # sigma0 = rotr 1 ^ rotr 8 ^ shr 7
    let s0 = ((($x bit-shr 1) bit-and 0x7fffffffffffffff) bit-or ($x bit-shl 63)) bit-xor ((($x bit-shr 8) bit-and 0x00ffffffffffffff) bit-or ($x bit-shl 56)) bit-xor (($x bit-shr 7) bit-and 0x01ffffffffffffff)
    # sigma1 = rotr 19 ^ rotr 61 ^ shr 6
    let s1 = ((($y bit-shr 19) bit-and 0x00001fffffffffff) bit-or ($y bit-shl 45)) bit-xor ((($y bit-shr 61) bit-and 0x0000000000000007) bit-or ($y bit-shl 3)) bit-xor (($y bit-shr 6) bit-and 0x03ffffffffffffff)
    let a = $w | get ($t - 16)
    let b = $w | get ($t - 7)
    let lo = ($a bit-and $MASK) + ($s0 bit-and $MASK) + ($b bit-and $MASK) + ($s1 bit-and $MASK)
    let hi = ($a bit-shr 32) + ($s0 bit-shr 32) + ($b bit-shr 32) + ($s1 bit-shr 32) + ($lo bit-shr 32)
    $w = $w | append (($hi bit-shl 32) bit-or ($lo bit-and $MASK))
  }

  mut a = $state.0
  mut b = $state.1
  mut c = $state.2
  mut d = $state.3
  mut e = $state.4
  mut f = $state.5
  mut g = $state.6
  mut h = $state.7

  for kw in ($K | zip $w) {
    # Sigma1 = rotr 14 ^ rotr 18 ^ rotr 41
    let s1 = ((($e bit-shr 14) bit-and 0x0003ffffffffffff) bit-or ($e bit-shl 50)) bit-xor ((($e bit-shr 18) bit-and 0x00003fffffffffff) bit-or ($e bit-shl 46)) bit-xor ((($e bit-shr 41) bit-and 0x00000000007fffff) bit-or ($e bit-shl 23))
    # ch = (e and f) xor (not e and g) == g xor (e and (f xor g))
    let ch = $g bit-xor ($e bit-and ($f bit-xor $g))
    # t1 = h + Sigma1 + ch + K[t] + w[t], kept as low and high sums until used
    let t1l = ($h bit-and $MASK) + ($s1 bit-and $MASK) + ($ch bit-and $MASK) + ($kw.0 bit-and $MASK) + ($kw.1 bit-and $MASK)
    let t1h = ($h bit-shr 32) + ($s1 bit-shr 32) + ($ch bit-shr 32) + ($kw.0 bit-shr 32) + ($kw.1 bit-shr 32) + ($t1l bit-shr 32)
    # Sigma0 = rotr 28 ^ rotr 34 ^ rotr 39
    let s0 = ((($a bit-shr 28) bit-and 0x0000000fffffffff) bit-or ($a bit-shl 36)) bit-xor ((($a bit-shr 34) bit-and 0x000000003fffffff) bit-or ($a bit-shl 30)) bit-xor ((($a bit-shr 39) bit-and 0x0000000001ffffff) bit-or ($a bit-shl 25))
    # maj = (a and b) or (c and (a or b))
    let maj = ($a bit-and $b) bit-or ($c bit-and ($a bit-or $b))
    let t2l = ($s0 bit-and $MASK) + ($maj bit-and $MASK)
    let t2h = ($s0 bit-shr 32) + ($maj bit-shr 32)

    $h = $g
    $g = $f
    $f = $e
    let lo = ($d bit-and $MASK) + ($t1l bit-and $MASK)
    $e = ((($d bit-shr 32) + $t1h + ($lo bit-shr 32)) bit-shl 32) bit-or ($lo bit-and $MASK)
    $d = $c
    $c = $b
    $b = $a
    let lo = ($t1l bit-and $MASK) + $t2l
    $a = (($t1h + $t2h + ($lo bit-shr 32)) bit-shl 32) bit-or ($lo bit-and $MASK)
  }

  [$a $b $c $d $e $f $g $h] | zip $state | each {|p|
    let lo = ($p.0 bit-and $MASK) + ($p.1 bit-and $MASK)
    ((($p.0 bit-shr 32) + ($p.1 bit-shr 32) + ($lo bit-shr 32)) bit-shl 32) bit-or ($lo bit-and $MASK)
  }
}

# Big-endian, 8 bytes per word.
def bytes-to-words [bytes: list<int>]: nothing -> list<int> {
  $bytes | chunks 8 | each {|c|
    ($c.0 bit-shl 56) bit-or ($c.1 bit-shl 48) bit-or ($c.2 bit-shl 40) bit-or ($c.3 bit-shl 32) bit-or ($c.4 bit-shl 24) bit-or ($c.5 bit-shl 16) bit-or ($c.6 bit-shl 8) bit-or $c.7
  }
}

def words-to-bytes [words: list<int>]: nothing -> list<int> {
  $words
  | each {|w| [(($w bit-shr 56) bit-and 0xff) (($w bit-shr 48) bit-and 0xff) (($w bit-shr 40) bit-and 0xff) (($w bit-shr 32) bit-and 0xff) (($w bit-shr 24) bit-and 0xff) (($w bit-shr 16) bit-and 0xff) (($w bit-shr 8) bit-and 0xff) ($w bit-and 0xff)] }
  | flatten
}

# Pad and absorb the last bytes of a message into a state that has already
# absorbed `prior` bytes (a multiple of 128), and return the 64-byte digest.
# HMAC uses this with a precomputed state for the key block, so the per-message
# cost is two compressions instead of four.
export def sha512-tail [state: list<int>, bytes: list<int>, prior: int]: nothing -> list<int> {
  let n = $bytes | length
  let zeros = if ($n mod 128) < 112 { 111 - ($n mod 128) } else { 239 - ($n mod 128) }
  let bits = ($prior + $n) * 8
  let padded = $bytes
    | append 0x80
    | append (0..<$zeros | each { 0 })
    | append (words-to-bytes [0 $bits])
  mut st = $state
  for block in ($padded | chunks 128) {
    $st = sha512-compress $st (bytes-to-words $block)
  }
  words-to-bytes $st
}

export def main [bytes: list<int>]: nothing -> list<int> {
  sha512-tail $H0 $bytes 0
}

# Precompute the inner and outer states for an HMAC key (block size 128).
export def hmac-sha512-key [key: list<int>]: nothing -> record<inner: list<int>, outer: list<int>> {
  let k = if ($key | length) > 128 { main $key } else { $key }
  let k = $k | append (0..<(128 - ($k | length)) | each { 0 })
  {
    inner: (sha512-compress $H0 (bytes-to-words ($k | each {|b| $b bit-xor 0x36 })))
    outer: (sha512-compress $H0 (bytes-to-words ($k | each {|b| $b bit-xor 0x5c })))
  }
}

export def hmac-sha512-keyed [key: record<inner: list<int>, outer: list<int>>, msg: list<int>]: nothing -> list<int> {
  sha512-tail $key.outer (sha512-tail $key.inner $msg 128) 128
}

export def hmac-sha512 [key: list<int>, msg: list<int>]: nothing -> list<int> {
  hmac-sha512-keyed (hmac-sha512-key $key) $msg
}

export def pbkdf2-hmac-sha512 [password: list<int>, salt: list<int>, iters: int, dklen: int]: nothing -> list<int> {
  let key = hmac-sha512-key $password
  mut out = []
  for i in 1..(($dklen + 63) // 64) {
    mut u = hmac-sha512-keyed $key ($salt | append (uint32-to-bytes $i))
    mut t = $u
    for j in 1..<$iters {
      $u = hmac-sha512-keyed $key $u
      $t = $t | zip $u | each {|p| $p.0 bit-xor $p.1 }
    }
    $out = $out | append $t
  }
  $out | first $dklen
}
