use std/assert
use std/testing *
use encoding.nu *
use ed25519.nu
use sshsig.nu

# Test vector 1 key (seed = first 32 bytes of its BIP39 seed at empty passphrase).
const SEED = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"

@test
def "public-line matches the OpenSSH form" [] {
  let kp = ed25519 keypair (hex-to-bytes $SEED)
  assert equal (sshsig public-line $kp.public) "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3jUuRM0zNnJZPyM0pzDhgKrykN6JqhbUgN5ZTjTilh"
}

@test
def "fingerprint matches ssh-keygen -lf" [] {
  let kp = ed25519 keypair (hex-to-bytes $SEED)
  let dir = mktemp --directory
  $"(sshsig public-line $kp.public)\n" | save $"($dir)/key.pub"
  let listed = ^ssh-keygen -lf $"($dir)/key.pub" | str trim
  rm --recursive $dir
  assert str contains $listed (sshsig fingerprint $kp.public)
  assert equal (sshsig fingerprint $kp.public) "SHA256:Pl5ce4l7GkllU5/k5ThzEWO4KidBNCbhKBaj6oxkZO8"
}

# Expected block computed with node: tweetnacl over the same SSHSIG framing.
@test
def "sign produces the expected armored block" [] {
  let kp = ed25519 keypair (hex-to-bytes $SEED)
  let expected = [
    "-----BEGIN SSH SIGNATURE-----"
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHeNS5EzTM2clk/IzSnMOGAqvKQ"
    "3omqFtSA3llONOKWEAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx"
    "OQAAAECw01BnJ4fIvPNyAAVhTV89J3G2+S3TbvBKYek4yHSnyOiZqWeznuauiYhlxeavtM"
    "/2L55wrhOdLDaMus1J/MoK"
    "-----END SSH SIGNATURE-----"
    ""
  ] | str join "\n"
  assert equal (sshsig sign (string-to-bytes "hello\n") $kp.secret "file") $expected
}

@test
def "ssh-keygen -Y verify accepts the signature and rejects a changed message" [] {
  let kp = ed25519 keypair (hex-to-bytes $SEED)
  let dir = mktemp --directory
  $"signer (sshsig public-line $kp.public)\n" | save $"($dir)/allowed_signers"
  sshsig sign (string-to-bytes "hello\n") $kp.secret "file" | save $"($dir)/msg.sig"
  let good = "hello\n" | ^ssh-keygen -Y verify -f $"($dir)/allowed_signers" -I signer -n file -s $"($dir)/msg.sig" | complete
  let bad = "hello" | ^ssh-keygen -Y verify -f $"($dir)/allowed_signers" -I signer -n file -s $"($dir)/msg.sig" | complete
  rm --recursive $dir
  assert equal $good.exit_code 0 $good.stderr
  assert str contains $good.stdout (sshsig fingerprint $kp.public)
  assert not equal $bad.exit_code 0
}

@test
def "verify accepts the block sign just produced" [] {
  let kp = ed25519 keypair (hex-to-bytes $SEED)
  let msg = string-to-bytes "hello\n"
  assert equal (sshsig verify $msg (sshsig sign $msg $kp.secret "file") $kp.public "file") true
}

# The one case that proves the parser reads the format rather than only its own
# output: ssh-keygen writes the block, nu reads it back. The key is generated
# here and its raw 64-byte secret pulled out of the openssh-key-v1 file, so nu
# can sign with the same key too.
@test
def "verify accepts a block written by ssh-keygen" [] {
  let k = ssh-keygen-fixture
  assert equal (sshsig verify $k.msg $k.block $k.public "file") true
}

@test
def "verify rejects a message that changed" [] {
  let k = ssh-keygen-fixture
  assert equal (sshsig verify ($k.msg | append 0x21) $k.block $k.public "file") false
}

@test
def "verify rejects a public key that did not sign the block" [] {
  let k = ssh-keygen-fixture
  let other = $k.public | update 0 (($k.public | get 0) bit-xor 1)
  assert equal (sshsig verify $k.msg $k.block $other "file") false
}

# ssh-keygen -Y verify fails a signature whose namespace is not the one asked
# for, so this must too. The block is valid and signed by the right key.
@test
def "verify rejects a block signed under another namespace" [] {
  let k = ssh-keygen-fixture
  assert equal (sshsig verify $k.msg $k.email_block $k.public "file") false
}

@test
def "verify names what is wrong with a malformed block" [] {
  let k = ssh-keygen-fixture
  let body = $k.block | lines | skip 1 | drop 1 | str join ""
  let armor = {|b| $"-----BEGIN SSH SIGNATURE-----\n($b)\n-----END SSH SIGNATURE-----\n" }
  let say = {|b| try { sshsig verify $k.msg $b $k.public "file" | into string } catch {|e| $e.msg } }
  assert str contains (do $say "just some text") "BEGIN SSH SIGNATURE"
  assert str contains (do $say ($k.block | str replace "END SSH SIGNATURE" "END NOTHING")) "END SSH SIGNATURE"
  assert str contains (do $say (do $armor ($body | str substring 0..100))) "not valid base64"
  assert str contains (do $say (do $armor ($body | str substring 0..99))) "truncated"
  let longer = bytes-to-base64 ((binary-to-bytes ($body | decode base64)) | append [1 2 3])
  assert str contains (do $say (do $armor $longer)) "trailing bytes"
}

# Builds a real ssh-keygen key and two signed blocks, and returns the raw
# secret so nu can use the same key. Kept out of the tests above so each of
# them reads as one assertion.
def ssh-keygen-fixture []: nothing -> record {
  let dir = mktemp --directory
  run-ssh-keygen [-t ed25519 -N "" -C tester -f $"($dir)/key"]
  "hello from ssh-keygen\n" | save --raw $"($dir)/m.txt"
  "hello from ssh-keygen\n" | save --raw $"($dir)/m2.txt"
  run-ssh-keygen [-Y sign -f $"($dir)/key" -n file $"($dir)/m.txt"]
  run-ssh-keygen [-Y sign -f $"($dir)/key" -n email $"($dir)/m2.txt"]
  # openssh-key-v1: the 15-byte header, three strings, a bare uint32 key count,
  # the public key, then a private section holding two check ints, the key
  # type, the public key again and the 64-byte secret.
  let raw = open --raw $"($dir)/key" | lines | where {|l| not ($l | str contains "-----") } | str join "" | decode base64 | binary-to-bytes $in
  let ciphername = string-at $raw 15
  let kdfname = string-at $raw $ciphername.next
  let kdfoptions = string-at $raw $kdfname.next
  let public = string-at $raw ($kdfoptions.next + 4)
  let private = string-at $raw $public.next
  let keytype = string-at $private.value 8
  let inner_public = string-at $private.value $keytype.next
  let secret = string-at $private.value $inner_public.next
  {
    public: $inner_public.value
    secret: $secret.value
    msg: (string-to-bytes "hello from ssh-keygen\n")
    block: (open --raw $"($dir)/m.txt.sig" | decode)
    email_block: (open --raw $"($dir)/m2.txt.sig" | decode)
  }
}

# One length-prefixed field of an SSH wire blob, and where the next one starts.
def string-at [bytes: list<int>, at: int]: nothing -> record<value: list<int>, next: int> {
  let len = ($bytes | get $at) * 16777216 + ($bytes | get ($at + 1)) * 65536 + ($bytes | get ($at + 2)) * 256 + ($bytes | get ($at + 3))
  { value: ($bytes | slice ($at + 4)..<($at + 4 + $len)), next: ($at + 4 + $len) }
}

# Why `complete` rather than -q: a trailing -q is read as another file to sign,
# and ssh-keygen then exits 255 after writing the signature it was asked for,
# so the failure is silent unless the exit code is checked. This keeps the
# chatter off the test output and turns a real failure into a clear message.
def run-ssh-keygen [args: list<string>]: nothing -> nothing {
  let r = ^ssh-keygen ...$args | complete
  if $r.exit_code != 0 {
    error make {msg: $"ssh-keygen ($args | str join ' ') failed: ($r.stderr)"}
  }
}
