# Conversions between the list<int> byte form the crypto modules use and
# Nushell strings, hex and binary values. Nothing here is cryptographic.

export def string-to-bytes [s: string]: nothing -> list<int> {
  $s | into binary | encode hex --lower | hex-to-bytes $in
}

export def hex-to-bytes [hex: string]: nothing -> list<int> {
  # Why the 0x prefix: `into int --radix 16` still reads the pair "0b" as a
  # binary-literal prefix and fails on it.
  $hex | split chars | chunks 2 | each { str join | $"0x($in)" | into int }
}

export def bytes-to-hex [bytes: list<int>]: nothing -> string {
  $bytes | each {|b| $b + 256 | format number | get lowerhex | str substring 3.. } | str join
}

export def bytes-to-binary [bytes: list<int>]: nothing -> binary {
  bytes-to-hex $bytes | decode hex
}

export def binary-to-bytes [bin: binary]: nothing -> list<int> {
  $bin | encode hex --lower | hex-to-bytes $in
}

# Standard base64 with padding, what OpenSSH uses for key lines and armor.
export def bytes-to-base64 [bytes: list<int>]: nothing -> string {
  bytes-to-binary $bytes | encode base64
}

# Big-endian uint32: the length prefix of an SSH wire string and the block
# index of PBKDF2.
export def uint32-to-bytes [n: int]: nothing -> list<int> {
  [($n bit-shr 24) (($n bit-shr 16) bit-and 0xff) (($n bit-shr 8) bit-and 0xff) ($n bit-and 0xff)]
}
