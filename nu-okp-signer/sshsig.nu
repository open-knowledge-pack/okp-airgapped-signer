# SSHSIG (OpenSSH PROTOCOL.sshsig) for Ed25519 in pure Nushell: the public
# key line, the fingerprint and the armored signature, byte for byte what
# ssh-keygen emits, so `ssh-keygen -Y verify` checks the output unchanged.

use encoding.nu *
use sha512.nu
use ed25519.nu

# Why the namespace is a parameter: SSHSIG bakes it into the signed blob, and
# each verifier asks for one by name. `ssh-keygen -Y verify -n file` for a
# file, and git checks commit signatures under "git" with no way to change
# it, so a block made under "file" can never sign a commit.
const HASH_ALG = "sha512"
const KEY_ALG = "ssh-ed25519"
const MAGIC = "SSHSIG"

# The namespace as bytes, refused when empty or only whitespace: ssh-keygen
# refuses to sign under an empty namespace, and a block nothing else would
# make is a block nothing else would check. One place, so `sign` and `verify`
# agree.
# Not trimmed because: a trim would silently change the signed bytes, and a
# flag value is what the caller typed on purpose. Refuse, do not repair.
def namespace-bytes [namespace: string]: nothing -> list<int> {
  if ($namespace | str trim | is-empty) {
    error make {msg: 'the namespace is empty; "file" for a file, "git" for a commit object'}
  }
  string-to-bytes $namespace
}

# SSH wire string (RFC 4251 section 5): uint32 big-endian length, then bytes.
def ssh-string [bytes: list<int>]: nothing -> list<int> {
  uint32-to-bytes ($bytes | length) | append $bytes
}

# Read one wire string at an offset, and say where the next field starts.
def ssh-string-read [bytes: list<int>, at: int]: nothing -> record<value: list<int>, next: int> {
  if ($bytes | length) < ($at + 4) {
    error make {msg: $"truncated SSHSIG block: no length prefix at byte ($at)"}
  }
  let len = ($bytes | get $at) * 16777216 + ($bytes | get ($at + 1)) * 65536 + ($bytes | get ($at + 2)) * 256 + ($bytes | get ($at + 3))
  let start = $at + 4
  if ($bytes | length) < ($start + $len) {
    error make {msg: $"truncated SSHSIG block: a field at byte ($at) claims ($len) bytes"}
  }
  { value: ($bytes | slice $start..<($start + $len)), next: ($start + $len) }
}

# What Ed25519 actually signs. Note what is absent: the version field and the
# public key, both of which the outer blob carries. Built in one place so
# `sign` and `verify` cannot drift apart on the layout.
def signed-blob [namespace: list<int>, hash_alg: list<int>, digest: list<int>]: nothing -> list<int> {
  string-to-bytes $MAGIC
  | append (ssh-string $namespace)
  | append (ssh-string [])
  | append (ssh-string $hash_alg)
  | append (ssh-string $digest)
}

# The ssh-ed25519 wire blob: string "ssh-ed25519" then string public(32).
export def public-blob [public: list<int>]: nothing -> list<int> {
  ssh-string (string-to-bytes "ssh-ed25519") | append (ssh-string $public)
}

# The line authorized_keys and allowed_signers take.
export def public-line [public: list<int>]: nothing -> string {
  $"ssh-ed25519 (bytes-to-base64 (public-blob $public))"
}

# SHA-256 over the wire blob: the bytes the fingerprint encodes and the icon
# indexes, so both are pictures of one digest.
def public-digest [public: list<int>]: nothing -> binary {
  bytes-to-binary (public-blob $public) | hash sha256 --binary
}

# "SHA256:" + unpadded base64 of SHA-256 over the wire blob, what
# `ssh-keygen -lf` prints and `-Y verify` names in its success line.
export def fingerprint [public: list<int>]: nothing -> string {
  $"SHA256:(public-digest $public | encode base64 --nopad)"
}

# The key icon of specs/main.md: four glyphs indexed by the first four bytes
# of the fingerprint's digest, each modulo its table. Every glyph is part of
# the format, so a change here changes the icon of every existing key.
# Why the public key and not, as Spectre does, a MAC under the secret: the
# icon must be recomputable from the .pub line by anyone. Why a typo check
# and not an identity: 4 x 6 x 4 x 49 pictures, about 12 bits.
const ICON_TABLES = [
  ["╔" "╚" "╰" "═"]
  ["█" "░" "▒" "▓" "☺" "☻"]
  ["╗" "╝" "╯" "═"]
  ["◈" "◎" "◐" "◑" "◒" "◓" "☀" "☁" "☂" "☃" "☄" "★" "☆" "☎" "☏" "⎈" "⌂" "☘" "☢" "☣"
   "♔" "♕" "♖" "♗" "♘" "♙" "♚" "♛" "♜" "♝" "♞" "♟" "♨" "♩" "♪" "♫" "⚐" "⚑" "⚔" "⚖"
   "⚙" "⚠" "⌘" "⏎" "✄" "✆" "✈" "✉" "✌"]
]
export def icon [public: list<int>]: nothing -> string {
  let digest = binary-to-bytes (public-digest $public)
  $ICON_TABLES
  | enumerate
  | each {|t| $t.item | get (($digest | get $t.index) mod ($t.item | length)) }
  | str join
}

# Armored SSHSIG signature over msg. Ed25519 signs a fixed-size blob holding
# SHA-512 of the message, so the output size does not depend on the message.
export def sign [msg: list<int>, secret: list<int>, namespace: string]: nothing -> string {
  let public = $secret | skip 32
  let magic = string-to-bytes $MAGIC
  let namespace = namespace-bytes $namespace
  let ns = ssh-string $namespace
  let reserved = ssh-string []
  let alg = ssh-string (string-to-bytes $HASH_ALG)
  let signed = signed-blob $namespace (string-to-bytes $HASH_ALG) (sha512 $msg)
  let sig = ed25519 sign $signed $secret
  let sig_blob = ssh-string (string-to-bytes $KEY_ALG) | append (ssh-string $sig)
  let blob = $magic
    | append [0 0 0 1]
    | append (ssh-string (public-blob $public))
    | append $ns
    | append $reserved
    | append $alg
    | append (ssh-string $sig_blob)
  # ssh-keygen wraps the base64 at 70 columns; match it.
  let b64 = bytes-to-base64 $blob | split chars | chunks 70 | each { str join } | str join "\n"
  $"-----BEGIN SSH SIGNATURE-----\n($b64)\n-----END SSH SIGNATURE-----\n"
}

# Strip the two armor lines and decode the base64 body back to bytes.
def unarmor [armored: string]: nothing -> list<int> {
  let lines = $armored | lines | each { str trim } | where {|l| $l != "" }
  if ($lines | is-empty) or ($lines | first) != "-----BEGIN SSH SIGNATURE-----" {
    error make {msg: "not an SSHSIG block: the BEGIN SSH SIGNATURE line is missing"}
  }
  if ($lines | last) != "-----END SSH SIGNATURE-----" {
    error make {msg: "not an SSHSIG block: the END SSH SIGNATURE line is missing"}
  }
  let body = $lines | skip 1 | drop 1 | str join ""
  # Why the wrap: `decode base64` reports a bare "Incorrect value." that names
  # neither base64 nor this block, which is no help to whoever pasted it.
  let decoded = try { $body | decode base64 } catch {
    error make {msg: "the body between the SSHSIG armor lines is not valid base64"}
  }
  binary-to-bytes $decoded
}

# Check an armored block against the message, the public key it should have
# been signed with, and the namespace it should have been signed under.
#
# Why the public key is required rather than read from the block: every SSHSIG
# block carries its own key, so checking the signature against that key alone
# proves only that the block is internally consistent. A forger would simply
# embed their own. `ssh-keygen -Y verify` solves this with an allowed_signers
# file; here the caller passes the key it expects, which is the one `derive`
# returned.
#
# Structure is a hard error: bad armor, bad base64, a truncated field or
# trailing bytes mean this is not an SSHSIG block at all, and saying so beats
# returning false. A well-formed block that does not check returns false,
# including a wrong namespace, hash algorithm, key algorithm or public key.
#
# The same caveat as `ed25519 verify`: this shares its code with `sign`, so it
# is a self-check, not an outside opinion. Use `ssh-keygen -Y verify` to accept
# a signature from someone else.
export def verify [msg: list<int>, armored: string, public: list<int>, namespace: string]: nothing -> bool {
  let namespace = namespace-bytes $namespace
  let blob = unarmor $armored
  let magic = string-to-bytes $MAGIC
  if ($blob | slice 0..<($magic | length)) != $magic {
    error make {msg: "not an SSHSIG block: the SSHSIG magic is missing"}
  }
  let version = $blob | slice 6..<10
  if $version != [0 0 0 1] {
    error make {msg: $"unsupported SSHSIG version, expected 1, got ($version)"}
  }
  let key_field = ssh-string-read $blob 10
  let ns_field = ssh-string-read $blob $key_field.next
  let reserved = ssh-string-read $blob $ns_field.next
  let alg_field = ssh-string-read $blob $reserved.next
  let sig_field = ssh-string-read $blob $alg_field.next
  if $sig_field.next != ($blob | length) {
    error make {msg: $"trailing bytes after the SSHSIG signature field: (($blob | length) - $sig_field.next) left over"}
  }
  # The signature field holds its own algorithm string then the 64 raw bytes.
  let sig_alg = ssh-string-read $sig_field.value 0
  let sig_bytes = ssh-string-read $sig_field.value $sig_alg.next
  if $sig_bytes.next != ($sig_field.value | length) {
    error make {msg: "trailing bytes inside the SSHSIG signature field"}
  }
  if $key_field.value != (public-blob $public) {
    return false
  }
  if $ns_field.value != $namespace {
    return false
  }
  if $alg_field.value != (string-to-bytes $HASH_ALG) {
    return false
  }
  if $sig_alg.value != (string-to-bytes $KEY_ALG) {
    return false
  }
  if ($sig_bytes.value | length) != 64 {
    return false
  }
  let signed = signed-blob $ns_field.value $alg_field.value (sha512 $msg)
  ed25519 verify $signed $sig_bytes.value $public
}
