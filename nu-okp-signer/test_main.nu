use std/assert
use std/testing *
use encoding.nu *
use ed25519.nu
use ../nu-okp-signer

const TV1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
const TV1_PUBLIC_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3jUuRM0zNnJZPyM0pzDhgKrykN6JqhbUgN5ZTjTilh"
const HELLO_SIGNATURE = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHeNS5EzTM2clk/IzSnMOGAqvKQ
3omqFtSA3llONOKWEAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECw01BnJ4fIvPNyAAVhTV89J3G2+S3TbvBKYek4yHSnyOiZqWeznuauiYhlxeavtM
/2L55wrhOdLDaMus1J/MoK
-----END SSH SIGNATURE-----
"

# The key record `derive` would return for test vector 1, built from the
# Ed25519 seed directly to skip the 14 s of PBKDF2.
def tv1-key []: nothing -> record {
  let kp = ed25519 keypair (hex-to-bytes "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70")
  { secret: $kp.secret }
}

@test
def "derive normalizes case and spacing and flags the test key" [] {
  let key = ($"  Abandon (($TV1 | split row " " | skip 1 | str join "   ")) \n" | nu-okp-signer derive)
  assert equal $key.public_line $TV1_PUBLIC_LINE
  assert equal $key.fingerprint "SHA256:Pl5ce4l7GkllU5/k5ThzEWO4KidBNCbhKBaj6oxkZO8"
  assert equal $key.icon "╰☺╗♙"
  assert equal $key.test_key "tv1"
}

@test
def "derive takes the passphrase from a record" [] {
  let key = ({mnemonic: $TV1, passphrase: "PROPHET"} | nu-okp-signer derive)
  assert equal $key.test_key "tv1 with passphrase PROPHET"
}

@test
def "derive fails on a bad checksum before any slow work" [] {
  let msg = try { ($TV1 | str replace "art" "abandon") | nu-okp-signer derive | ignore; "" } catch {|e| $e.msg }
  assert str contains $msg "checksum"
}

@test
def "sign appends one LF by default" [] {
  assert equal ("hello" | nu-okp-signer sign (tv1-key)) $HELLO_SIGNATURE
}

@test
def "sign --raw signs the text exactly" [] {
  assert equal ("hello\n" | nu-okp-signer sign (tv1-key) --raw) $HELLO_SIGNATURE
}

@test
def "sign refuses an empty text" [] {
  let msg = try { "" | nu-okp-signer sign {secret: []} | ignore; "" } catch {|e| $e.msg }
  assert str contains $msg "nothing to sign"
}

# ssh-keygen -Y sign refuses an empty namespace ("Too few arguments"), so
# this must too, rather than make a block nothing else would check.
@test
def "sign refuses an empty namespace" [] {
  for ns in ["" "  "] {
    let msg = try { "hello" | nu-okp-signer sign (tv1-key) --namespace $ns | ignore; "" } catch {|e| $e.msg }
    assert str contains $msg "namespace is empty"
  }
}

@test
def "sign refuses text that already ends with a newline" [] {
  let msg = try { "hello\n" | nu-okp-signer sign {secret: []} | ignore; "" } catch {|e| $e.msg }
  assert str contains $msg "already ends with a newline"
}

@test
def "verify accepts the block sign just produced" [] {
  let key = tv1-key
  assert ("hello" | nu-okp-signer verify $key ("hello" | nu-okp-signer sign $key))
}

@test
def "verify rejects the block under a different text" [] {
  let key = tv1-key
  assert not ("goodbye" | nu-okp-signer verify $key ("hello" | nu-okp-signer sign $key))
}

@test
def "verify applies the same LF rule as sign" [] {
  let key = tv1-key
  assert ("hello\n" | nu-okp-signer verify $key ("hello" | nu-okp-signer sign $key) --raw)
}

# The reason `--namespace` exists. Git checks a commit's SSHSIG under the
# namespace "git" and no other, so a block made under the default "file" can
# never sign a commit. The signed bytes are the commit object exactly as
# `git cat-file -p` prints it, hence --raw: it already ends with one LF.
@test
def "sign --namespace git --raw produces a commit signature git verify-commit accepts" [] {
  let key = tv1-key
  let dir = mktemp --directory
  ^git init --quiet --initial-branch=main $dir
  ^git -C $dir -c user.name=tester -c user.email=tester@example.com commit --quiet --allow-empty --message unsigned
  $"tester ($TV1_PUBLIC_LINE)\n" | save $"($dir)/allowed_signers"
  ^git -C $dir config gpg.ssh.allowedSignersFile $"($dir)/allowed_signers"
  let payload = ^git -C $dir cat-file -p HEAD | decode
  let block = $payload | nu-okp-signer sign $key --namespace git --raw
  # The gpgsig header: first line after the keyword, every next line indented by one space.
  let gpgsig = $block | lines | enumerate | each {|l| if $l.index == 0 { $"gpgsig ($l.item)" } else { $" ($l.item)" } } | str join "\n"
  let signed = $payload | str replace --regex '\n\n' $"\n($gpgsig)\n\n"
  let new = $signed | ^git -C $dir hash-object -t commit -w --stdin | str trim
  ^git -C $dir update-ref refs/heads/main $new
  let verified = ^git -C $dir verify-commit HEAD | complete
  rm --recursive $dir
  assert equal $verified.exit_code 0 $verified.stderr
  assert str contains $verified.stderr 'Good "git" signature'
  assert ($payload | nu-okp-signer verify $key $block --namespace git --raw)
  assert not ($payload | nu-okp-signer verify $key $block --raw)
}

@test
def "verify refuses text that already ends with a newline" [] {
  let msg = try { "hello\n" | nu-okp-signer verify {secret: []} $HELLO_SIGNATURE | ignore; "" } catch {|e| $e.msg }
  assert str contains $msg "already ends with a newline"
}
