# Ed25519 (RFC 8032) key generation, detached signing and verification in pure
# Nushell, ported from tweetnacl (node_modules/tweetnacl/nacl.js).
#
# Field elements are 16 limbs of 16 bits in a list<int>, tweetnacl's layout.
# Why: Nushell ints are overflow-checked i64. A product of two 16-bit limbs,
# summed over 16 terms and folded with the 38x wrap, stays near 2^44, so
# nothing can overflow. Limbs may go negative between reductions; `//` and
# `mod` floor in Nushell, which is what the carry code relies on.
#
# Not constant-time. Nushell cannot promise that, and the signer runs on an
# air-gapped machine where timing is not observable. Scalar multiplication is
# plain double-and-add instead of tweetnacl's conditional-swap ladder.

use sha512.nu *

const GF0 = [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
const GF1 = [1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
# 2 * d, the twisted Edwards curve constant used by the point addition.
const D2 = [0xf159 0x26b2 0x9b94 0xebd6 0xb156 0x8283 0x149a 0x00e0 0xd130 0xeef3 0x80f2 0x198e 0xfce7 0x56df 0xd9dc 0x2406]
# d itself, needed to rebuild x from y when a public key is decompressed.
const D = [0x78a3 0x1359 0x4dca 0x75eb 0xd8ab 0x4141 0x0a4d 0x0070 0xe898 0x7779 0x4079 0x8cc7 0xfe73 0x2b6f 0x6cee 0x5203]
# sqrt(-1) mod p. Decompression first computes one candidate root; when that
# one is wrong, the other is this constant times it.
const I = [0xa0b0 0x4a0e 0x1b27 0xc4ee 0xe478 0xad2f 0x1806 0x2f43 0xd7a7 0x3dfb 0x0099 0x2b4d 0xdf0b 0x4fc1 0x2480 0x2b83]
# Base point coordinates.
const BX = [0xd51a 0x8f25 0x2d60 0xc956 0xa7b2 0x9525 0xc760 0x692c 0xdc5c 0xfdd6 0xe231 0xc0a4 0x53fe 0xcd6e 0x36d3 0x2169]
const BY = [0x6658 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666 0x6666]
# Group order L as 32 little-endian bytes.
const L = [0xed 0xd3 0xf5 0x5c 0x1a 0x63 0x12 0x58 0xd6 0x9c 0xf7 0xa2 0xde 0xf9 0xde 0x14 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0x10]

# --- field arithmetic mod 2^255 - 19 ---------------------------------------
#
# Why the limbs are written out instead of looped: this is the hot path, about
# 4000 multiplications per signature, and the interpreter charges about 2.2 us
# for `get` and 2.6 us for a custom command call against 0.45 us for an
# operator (Nushell 0.115.2). A `$a.3` cell path runs at operator speed, so a
# loop over limb indexes costs ten times the arithmetic it drives. Measured:
# gf-mul 3.1 ms to 0.25 ms, one signature 14 s to 1 s.

def gf-add [a: list<int>, b: list<int>]: nothing -> list<int> {
  [($a.0 + $b.0) ($a.1 + $b.1) ($a.2 + $b.2) ($a.3 + $b.3) ($a.4 + $b.4) ($a.5 + $b.5) ($a.6 + $b.6) ($a.7 + $b.7) ($a.8 + $b.8) ($a.9 + $b.9) ($a.10 + $b.10) ($a.11 + $b.11) ($a.12 + $b.12) ($a.13 + $b.13) ($a.14 + $b.14) ($a.15 + $b.15)]
}

def gf-sub [a: list<int>, b: list<int>]: nothing -> list<int> {
  [($a.0 - $b.0) ($a.1 - $b.1) ($a.2 - $b.2) ($a.3 - $b.3) ($a.4 - $b.4) ($a.5 - $b.5) ($a.6 - $b.6) ($a.7 - $b.7) ($a.8 - $b.8) ($a.9 - $b.9) ($a.10 - $b.10) ($a.11 - $b.11) ($a.12 - $b.12) ($a.13 - $b.13) ($a.14 - $b.14) ($a.15 - $b.15)]
}

# Propagate carries once. The carry out of the top limb is 2^256, which is
# 38 mod p, so it folds back into limb 0.
def gf-carry [a: list<int>]: nothing -> list<int> {
  let c0 = $a.0 // 65536
  let c1 = ($a.1 + $c0) // 65536
  let c2 = ($a.2 + $c1) // 65536
  let c3 = ($a.3 + $c2) // 65536
  let c4 = ($a.4 + $c3) // 65536
  let c5 = ($a.5 + $c4) // 65536
  let c6 = ($a.6 + $c5) // 65536
  let c7 = ($a.7 + $c6) // 65536
  let c8 = ($a.8 + $c7) // 65536
  let c9 = ($a.9 + $c8) // 65536
  let c10 = ($a.10 + $c9) // 65536
  let c11 = ($a.11 + $c10) // 65536
  let c12 = ($a.12 + $c11) // 65536
  let c13 = ($a.13 + $c12) // 65536
  let c14 = ($a.14 + $c13) // 65536
  let c15 = ($a.15 + $c14) // 65536
  [(($a.0 mod 65536) + 38 * $c15) (($a.1 + $c0) mod 65536) (($a.2 + $c1) mod 65536) (($a.3 + $c2) mod 65536) (($a.4 + $c3) mod 65536) (($a.5 + $c4) mod 65536) (($a.6 + $c5) mod 65536) (($a.7 + $c6) mod 65536) (($a.8 + $c7) mod 65536) (($a.9 + $c8) mod 65536) (($a.10 + $c9) mod 65536) (($a.11 + $c10) mod 65536) (($a.12 + $c11) mod 65536) (($a.13 + $c12) mod 65536) (($a.14 + $c13) mod 65536) (($a.15 + $c14) mod 65536)]
}

# Schoolbook product, tweetnacl's M: line k holds every a[i] * b[j] with
# i + j == k, so t0..t30 is the 31-limb product. Limb 16 and up sit at 2^256
# and above and fold down with the 38x wrap.
def gf-mul [a: list<int>, b: list<int>]: nothing -> list<int> {
  let t0 = $a.0 * $b.0
  let t1 = $a.0 * $b.1 + $a.1 * $b.0
  let t2 = $a.0 * $b.2 + $a.1 * $b.1 + $a.2 * $b.0
  let t3 = $a.0 * $b.3 + $a.1 * $b.2 + $a.2 * $b.1 + $a.3 * $b.0
  let t4 = $a.0 * $b.4 + $a.1 * $b.3 + $a.2 * $b.2 + $a.3 * $b.1 + $a.4 * $b.0
  let t5 = $a.0 * $b.5 + $a.1 * $b.4 + $a.2 * $b.3 + $a.3 * $b.2 + $a.4 * $b.1 + $a.5 * $b.0
  let t6 = $a.0 * $b.6 + $a.1 * $b.5 + $a.2 * $b.4 + $a.3 * $b.3 + $a.4 * $b.2 + $a.5 * $b.1 + $a.6 * $b.0
  let t7 = $a.0 * $b.7 + $a.1 * $b.6 + $a.2 * $b.5 + $a.3 * $b.4 + $a.4 * $b.3 + $a.5 * $b.2 + $a.6 * $b.1 + $a.7 * $b.0
  let t8 = $a.0 * $b.8 + $a.1 * $b.7 + $a.2 * $b.6 + $a.3 * $b.5 + $a.4 * $b.4 + $a.5 * $b.3 + $a.6 * $b.2 + $a.7 * $b.1 + $a.8 * $b.0
  let t9 = $a.0 * $b.9 + $a.1 * $b.8 + $a.2 * $b.7 + $a.3 * $b.6 + $a.4 * $b.5 + $a.5 * $b.4 + $a.6 * $b.3 + $a.7 * $b.2 + $a.8 * $b.1 + $a.9 * $b.0
  let t10 = $a.0 * $b.10 + $a.1 * $b.9 + $a.2 * $b.8 + $a.3 * $b.7 + $a.4 * $b.6 + $a.5 * $b.5 + $a.6 * $b.4 + $a.7 * $b.3 + $a.8 * $b.2 + $a.9 * $b.1 + $a.10 * $b.0
  let t11 = $a.0 * $b.11 + $a.1 * $b.10 + $a.2 * $b.9 + $a.3 * $b.8 + $a.4 * $b.7 + $a.5 * $b.6 + $a.6 * $b.5 + $a.7 * $b.4 + $a.8 * $b.3 + $a.9 * $b.2 + $a.10 * $b.1 + $a.11 * $b.0
  let t12 = $a.0 * $b.12 + $a.1 * $b.11 + $a.2 * $b.10 + $a.3 * $b.9 + $a.4 * $b.8 + $a.5 * $b.7 + $a.6 * $b.6 + $a.7 * $b.5 + $a.8 * $b.4 + $a.9 * $b.3 + $a.10 * $b.2 + $a.11 * $b.1 + $a.12 * $b.0
  let t13 = $a.0 * $b.13 + $a.1 * $b.12 + $a.2 * $b.11 + $a.3 * $b.10 + $a.4 * $b.9 + $a.5 * $b.8 + $a.6 * $b.7 + $a.7 * $b.6 + $a.8 * $b.5 + $a.9 * $b.4 + $a.10 * $b.3 + $a.11 * $b.2 + $a.12 * $b.1 + $a.13 * $b.0
  let t14 = $a.0 * $b.14 + $a.1 * $b.13 + $a.2 * $b.12 + $a.3 * $b.11 + $a.4 * $b.10 + $a.5 * $b.9 + $a.6 * $b.8 + $a.7 * $b.7 + $a.8 * $b.6 + $a.9 * $b.5 + $a.10 * $b.4 + $a.11 * $b.3 + $a.12 * $b.2 + $a.13 * $b.1 + $a.14 * $b.0
  let t15 = $a.0 * $b.15 + $a.1 * $b.14 + $a.2 * $b.13 + $a.3 * $b.12 + $a.4 * $b.11 + $a.5 * $b.10 + $a.6 * $b.9 + $a.7 * $b.8 + $a.8 * $b.7 + $a.9 * $b.6 + $a.10 * $b.5 + $a.11 * $b.4 + $a.12 * $b.3 + $a.13 * $b.2 + $a.14 * $b.1 + $a.15 * $b.0
  let t16 = $a.1 * $b.15 + $a.2 * $b.14 + $a.3 * $b.13 + $a.4 * $b.12 + $a.5 * $b.11 + $a.6 * $b.10 + $a.7 * $b.9 + $a.8 * $b.8 + $a.9 * $b.7 + $a.10 * $b.6 + $a.11 * $b.5 + $a.12 * $b.4 + $a.13 * $b.3 + $a.14 * $b.2 + $a.15 * $b.1
  let t17 = $a.2 * $b.15 + $a.3 * $b.14 + $a.4 * $b.13 + $a.5 * $b.12 + $a.6 * $b.11 + $a.7 * $b.10 + $a.8 * $b.9 + $a.9 * $b.8 + $a.10 * $b.7 + $a.11 * $b.6 + $a.12 * $b.5 + $a.13 * $b.4 + $a.14 * $b.3 + $a.15 * $b.2
  let t18 = $a.3 * $b.15 + $a.4 * $b.14 + $a.5 * $b.13 + $a.6 * $b.12 + $a.7 * $b.11 + $a.8 * $b.10 + $a.9 * $b.9 + $a.10 * $b.8 + $a.11 * $b.7 + $a.12 * $b.6 + $a.13 * $b.5 + $a.14 * $b.4 + $a.15 * $b.3
  let t19 = $a.4 * $b.15 + $a.5 * $b.14 + $a.6 * $b.13 + $a.7 * $b.12 + $a.8 * $b.11 + $a.9 * $b.10 + $a.10 * $b.9 + $a.11 * $b.8 + $a.12 * $b.7 + $a.13 * $b.6 + $a.14 * $b.5 + $a.15 * $b.4
  let t20 = $a.5 * $b.15 + $a.6 * $b.14 + $a.7 * $b.13 + $a.8 * $b.12 + $a.9 * $b.11 + $a.10 * $b.10 + $a.11 * $b.9 + $a.12 * $b.8 + $a.13 * $b.7 + $a.14 * $b.6 + $a.15 * $b.5
  let t21 = $a.6 * $b.15 + $a.7 * $b.14 + $a.8 * $b.13 + $a.9 * $b.12 + $a.10 * $b.11 + $a.11 * $b.10 + $a.12 * $b.9 + $a.13 * $b.8 + $a.14 * $b.7 + $a.15 * $b.6
  let t22 = $a.7 * $b.15 + $a.8 * $b.14 + $a.9 * $b.13 + $a.10 * $b.12 + $a.11 * $b.11 + $a.12 * $b.10 + $a.13 * $b.9 + $a.14 * $b.8 + $a.15 * $b.7
  let t23 = $a.8 * $b.15 + $a.9 * $b.14 + $a.10 * $b.13 + $a.11 * $b.12 + $a.12 * $b.11 + $a.13 * $b.10 + $a.14 * $b.9 + $a.15 * $b.8
  let t24 = $a.9 * $b.15 + $a.10 * $b.14 + $a.11 * $b.13 + $a.12 * $b.12 + $a.13 * $b.11 + $a.14 * $b.10 + $a.15 * $b.9
  let t25 = $a.10 * $b.15 + $a.11 * $b.14 + $a.12 * $b.13 + $a.13 * $b.12 + $a.14 * $b.11 + $a.15 * $b.10
  let t26 = $a.11 * $b.15 + $a.12 * $b.14 + $a.13 * $b.13 + $a.14 * $b.12 + $a.15 * $b.11
  let t27 = $a.12 * $b.15 + $a.13 * $b.14 + $a.14 * $b.13 + $a.15 * $b.12
  let t28 = $a.13 * $b.15 + $a.14 * $b.14 + $a.15 * $b.13
  let t29 = $a.14 * $b.15 + $a.15 * $b.14
  let t30 = $a.15 * $b.15
  let o = [($t0 + 38 * $t16) ($t1 + 38 * $t17) ($t2 + 38 * $t18) ($t3 + 38 * $t19) ($t4 + 38 * $t20) ($t5 + 38 * $t21) ($t6 + 38 * $t22) ($t7 + 38 * $t23) ($t8 + 38 * $t24) ($t9 + 38 * $t25) ($t10 + 38 * $t26) ($t11 + 38 * $t27) ($t12 + 38 * $t28) ($t13 + 38 * $t29) ($t14 + 38 * $t30) $t15]
  gf-carry (gf-carry $o)
}

# ref10's fe_invert and fe_pow22523 share every step but their last two, so the
# common part is here: a^(2^250 - 1), plus the a^11 both of them finish with.
# 250 squarings and 10 multiplications, against one multiplication per exponent
# bit for a square-and-multiply loop.
def gf-chain [a: list<int>]: nothing -> record<z250: list<int>, z11: list<int>> {
  let z2 = gf-mul $a $a
  let z8 = gf-sqr-n $z2 2
  let z9 = gf-mul $a $z8
  let z11 = gf-mul $z2 $z9
  let z22 = gf-mul $z11 $z11
  let z_5_0 = gf-mul $z9 $z22
  let z_10_0 = gf-mul (gf-sqr-n $z_5_0 5) $z_5_0
  let z_20_0 = gf-mul (gf-sqr-n $z_10_0 10) $z_10_0
  let z_40_0 = gf-mul (gf-sqr-n $z_20_0 20) $z_20_0
  let z_50_0 = gf-mul (gf-sqr-n $z_40_0 10) $z_10_0
  let z_100_0 = gf-mul (gf-sqr-n $z_50_0 50) $z_50_0
  let z_200_0 = gf-mul (gf-sqr-n $z_100_0 100) $z_100_0
  { z250: (gf-mul (gf-sqr-n $z_200_0 50) $z_50_0), z11: $z11 }
}

# Inverse by Fermat: a^(p - 2), and p - 2 is 2^255 - 21.
def gf-inv [a: list<int>]: nothing -> list<int> {
  let c = gf-chain $a
  gf-mul (gf-sqr-n $c.z250 5) $c.z11
}

# a^((p - 5) / 8), which is a^(2^252 - 3). Decompression uses it to turn the
# ratio that defines x into a candidate square root.
def gf-pow2523 [a: list<int>]: nothing -> list<int> {
  gf-mul (gf-sqr-n (gf-chain $a).z250 2) $a
}

# a^(2^n) by repeated squaring.
def gf-sqr-n [a: list<int>, n: int]: nothing -> list<int> {
  mut c = $a
  # Why 0..<$n and not 1..$n: Nushell reads 1..0 as a descending range and
  # yields [1 0], so n = 0 squared twice and returned a^4 instead of a.
  for _ in 0..<$n { $c = gf-mul $c $c }
  $c
}

# Fully reduce to [0, p) and encode as 32 little-endian bytes.
def gf-pack [n: list<int>]: nothing -> list<int> {
  mut t = gf-carry (gf-carry (gf-carry $n))
  # Twice: subtract p with borrow, keep the result when it did not go negative.
  for _ in 0..1 {
    mut m = [(($t | get 0) - 0xffed)]
    for i in 1..14 {
      let prev = $m | get ($i - 1)
      let borrow = if $prev < 0 { 1 } else { 0 }
      $m = $m | update ($i - 1) ($prev mod 65536) | append (($t | get $i) - 0xffff - $borrow)
    }
    let prev = $m | get 14
    let borrow = if $prev < 0 { 1 } else { 0 }
    let top = ($t | get 15) - 0x7fff - $borrow
    $m = $m | update 14 ($prev mod 65536) | append $top
    if $top >= 0 { $t = $m }
  }
  $t | each {|l| [($l mod 256) ($l // 256)] } | flatten
}

# The inverse of gf-pack for the coordinate itself: 32 little-endian bytes back
# to limbs. The top bit of the last byte carries the sign of x, not part of y,
# so it is dropped here and read separately.
def gf-unpack [bytes: list<int>]: nothing -> list<int> {
  let limbs = $bytes | chunks 2 | each {|c| $c.0 + ($c.1 bit-shl 8) }
  $limbs | update 15 (($limbs | get 15) bit-and 0x7fff)
}

# Both compare fully reduced forms, since one value has many limb encodings.
def gf-eq [a: list<int>, b: list<int>]: nothing -> bool {
  (gf-pack $a) == (gf-pack $b)
}

def gf-parity [a: list<int>]: nothing -> int {
  (gf-pack $a | first) bit-and 1
}

# --- group arithmetic, extended coordinates [x y z t] ----------------------

def point-add [p: list<list<int>>, q: list<list<int>>]: nothing -> list<list<int>> {
  let a = gf-mul (gf-sub $p.1 $p.0) (gf-sub $q.1 $q.0)
  let b = gf-mul (gf-add $p.0 $p.1) (gf-add $q.0 $q.1)
  let c = gf-mul (gf-mul $p.3 $q.3) $D2
  let zz = gf-mul $p.2 $q.2
  let d = gf-add $zz $zz
  let e = gf-sub $b $a
  let f = gf-sub $d $c
  let g = gf-add $d $c
  let h = gf-add $b $a
  [(gf-mul $e $f) (gf-mul $h $g) (gf-mul $g $f) (gf-mul $e $h)]
}

# scalar (32 little-endian bytes) times point, double-and-add from the top bit.
def point-scalarmult [q: list<list<int>>, s: list<int>]: nothing -> list<list<int>> {
  mut p = [$GF0 $GF1 $GF1 $GF0]
  for i in 255..0 {
    $p = point-add $p $p
    if ((($s | get ($i // 8)) bit-shr ($i mod 8)) bit-and 1) == 1 {
      $p = point-add $p $q
    }
  }
  $p
}

def point-scalarbase [s: list<int>]: nothing -> list<list<int>> {
  point-scalarmult [$BX $BY $GF1 (gf-mul $BX $BY)] $s
}

# Compressed encoding: y as 32 bytes, with the low bit of x in the top bit.
def point-pack [p: list<list<int>>]: nothing -> list<int> {
  let zi = gf-inv $p.2
  let x = gf-pack (gf-mul $p.0 $zi)
  let y = gf-pack (gf-mul $p.1 $zi)
  $y | update 31 (($y | get 31) bit-or (($x | get 0) bit-and 1 | $in bit-shl 7))
}

# The reverse: 32 packed bytes back to a point, negated. tweetnacl's unpackneg.
# Returns null when the bytes are not a point on the curve, which is a normal
# outcome for a corrupt or forged key, not an error.
#
# Why negated: the verification equation is R == [s]B - [h]A, and negating here
# lets point-add do the subtraction.
#
# x comes from y by x^2 = (y^2 - 1) / (d*y^2 + 1). The root is computed as
# num * den^3 * (num * den^7)^((p-5)/8), which is a root of the ratio whenever
# one exists; over this field it can land on the wrong one, and multiplying by
# sqrt(-1) moves it to the other. If neither squares back to num, no x exists.
def point-unpack-neg [packed: list<int>]: nothing -> any {
  let y = gf-unpack $packed
  let y2 = gf-mul $y $y
  let num = gf-sub $y2 $GF1
  let den = gf-add $GF1 (gf-mul $y2 $D)
  let den2 = gf-mul $den $den
  let den4 = gf-mul $den2 $den2
  let den6 = gf-mul $den4 $den2
  let t = gf-mul (gf-mul $den6 $num) $den
  let t = gf-mul (gf-mul (gf-mul (gf-pow2523 $t) $num) $den) $den
  let x = gf-mul $t $den
  # Try the other root when the first one does not square back.
  let x = if (gf-eq (gf-mul (gf-mul $x $x) $den) $num) { $x } else { gf-mul $x $I }
  if not (gf-eq (gf-mul (gf-mul $x $x) $den) $num) {
    return null
  }
  # The packed top bit is the sign x should have. Negating when they agree is
  # what makes the returned point -A rather than A.
  let x = if (gf-parity $x) == (($packed | get 31) bit-shr 7) { gf-sub $GF0 $x } else { $x }
  [$x $y $GF1 (gf-mul $x $y)]
}

# --- scalar arithmetic mod L ------------------------------------------------

# Reduce a 64-entry little-endian number (entries may exceed 255 and go
# negative) to 32 bytes mod L. Straight port of tweetnacl modL; `//` floors,
# matching the arithmetic shifts there.
def scalar-modl [x0: list<int>]: nothing -> list<int> {
  mut x = $x0
  for i in 63..32 {
    mut carry = 0
    let xi = $x | get $i
    for j in ($i - 32)..<($i - 12) {
      let v = ($x | get $j) + $carry - 16 * $xi * ($L | get ($j - ($i - 32)))
      $carry = ($v + 128) // 256
      $x = $x | update $j ($v - $carry * 256)
    }
    $x = $x | update ($i - 12) (($x | get ($i - 12)) + $carry) | update $i 0
  }
  mut carry = 0
  let top = ($x | get 31) // 16
  for j in 0..31 {
    let v = ($x | get $j) + $carry - $top * ($L | get $j)
    $carry = $v // 256
    $x = $x | update $j ($v - $carry * 256)
  }
  for j in 0..31 {
    $x = $x | update $j (($x | get $j) - $carry * ($L | get $j))
  }
  mut r = []
  for i in 0..31 {
    let v = $x | get $i
    $x = $x | update ($i + 1) (($x | get ($i + 1)) + ($v // 256))
    $r = $r | append ($v mod 256)
  }
  $r
}

# Is a 32-byte little-endian scalar strictly below the group order? The most
# significant byte is the last one, so compare from the end and let the first
# byte that differs decide.
def scalar-below-l [s: list<int>]: nothing -> bool {
  let diff = $s | reverse | zip ($L | reverse) | where {|p| $p.0 != $p.1 }
  if ($diff | is-empty) { false } else { ($diff | first).0 < ($diff | first).1 }
}

# --- public API ---------------------------------------------------------------

def clamp [d: list<int>]: nothing -> list<int> {
  $d | update 0 (($d | get 0) bit-and 248) | update 31 (((($d | get 31) bit-and 127) bit-or 64))
}

# Keypair from a 32-byte seed. `secret` is the 64-byte tweetnacl form:
# seed followed by public key.
export def keypair [seed: list<int>]: nothing -> record<public: list<int>, secret: list<int>> {
  # Why: `first 32` and `skip 32` truncate a short list instead of failing, so
  # a wrong-sized input derives a plausible key or signature and nothing
  # downstream ever notices. The size is the contract; check it here.
  if ($seed | length) != 32 {
    error make {msg: $"seed must be 32 bytes, got (($seed | length))"}
  }
  let a = clamp (sha512 $seed | first 32)
  let public = point-pack (point-scalarbase $a)
  { public: $public, secret: ($seed | append $public) }
}

# Detached 64-byte signature R || S over msg.
export def sign [msg: list<int>, secret: list<int>]: nothing -> list<int> {
  # Why: a 32-byte secret leaves `skip 32` empty, so the second hash covers
  # R || msg instead of R || public. R stays right and only S goes wrong, which
  # yields a 64-byte signature that looks correct and verifies as false.
  if ($secret | length) != 64 {
    error make {msg: $"secret must be 64 bytes \(seed then public key\), got (($secret | length))"}
  }
  let d = sha512 ($secret | first 32)
  let a = clamp ($d | first 32)
  let prefix = $d | skip 32
  let public = $secret | skip 32
  let r = scalar-modl (sha512 ($prefix | append $msg))
  let big_r = point-pack (point-scalarbase $r)
  let h = scalar-modl (sha512 ($big_r | append $public | append $msg))
  # s = r + h * a mod L, accumulated as 64 little-endian entries.
  mut x = $r | append (0..<32 | each { 0 })
  for i in 0..31 {
    for j in 0..31 {
      $x = $x | update ($i + $j) (($x | get ($i + $j)) + ($h | get $i) * ($a | get $j))
    }
  }
  $big_r | append (scalar-modl $x)
}

# Check a detached signature against a message and a 32-byte public key.
#
# Why this exists: it is a self-check for the air-gapped machine, so a
# signature can be confirmed before it is carried out on a USB stick. It shares
# gf-mul, the point code and sha512 with `sign`, so it is not an independent
# implementation: a fault in the field arithmetic would corrupt both sides and
# they could still agree. What it does catch is everything above that layer, a
# wrong scalar accumulation or a bit flipped in memory after signing.
#
# Not a substitute for `ssh-keygen -Y verify` when accepting someone else's
# signature. Use the outside verifier for that.
#
# Returns true or false. A signature that fails is an answer, not an error, so
# only a wrong-sized argument raises.
export def verify [msg: list<int>, sig: list<int>, public: list<int>]: nothing -> bool {
  if ($sig | length) != 64 {
    error make {msg: $"signature must be 64 bytes, got (($sig | length))"}
  }
  if ($public | length) != 32 {
    error make {msg: $"public key must be 32 bytes, got (($public | length))"}
  }
  let big_r = $sig | first 32
  let s = $sig | skip 32
  # Why: RFC 8032 section 5.1.7 requires S < L. tweetnacl omits the check, and
  # without it a second signature over the same message also verifies.
  if not (scalar-below-l $s) {
    return false
  }
  let neg_a = point-unpack-neg $public
  if $neg_a == null {
    return false
  }
  let h = scalar-modl (sha512 ($big_r | append $public | append $msg))
  let p = point-add (point-scalarmult $neg_a $h) (point-scalarbase $s)
  (point-pack $p) == $big_r
}
