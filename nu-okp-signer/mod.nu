# nu-okp-signer: the air-gapped Ed25519 signer of
# `../js-okp-signer/index.html`, in pure Nushell. Two commands mirror
# the page's two screens, and a third checks a block back:
#
#   let key = nu-okp-signer derive          # Screen 1: mnemonic to key, about 16 s
#   "text" | nu-okp-signer sign $key        # Screen 2: SSHSIG block, about 1 s
#   "text" | nu-okp-signer verify $key $sig # the page has no equivalent, about 2 s
#
# The key lives only in that variable; nothing is written anywhere. Drop the
# variable, or close the shell, and it is gone.

use bip39.nu
use ed25519.nu
use sshsig.nu
use encoding.nu *

# Why: these mnemonics and this passphrase are published in specs/main.md
# and in the page source, so anyone can sign with these keys.
const TEST_KEYS = {
  "1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961": "tv1"
  "ea1c7d41a6d70293194f45206ab4dca257d9c252fe2c53779fdef2a2bd05cd47": "tv2"
  "e88ff5f87c809d2921bf2ee8bd3a176d6fc66b9f90230920f1246b5472c22c13": "tv3"
  "0abd856befd1aaaacfe339bd573dbbcb979d760926ca2e653b8b98e49faa35f9": "tv1 with passphrase PROPHET"
}

# Derive the signing key from a 24-word BIP39 mnemonic and an optional
# passphrase. With no pipeline input both are asked for on the terminal:
# `input` reads them outside the line editor, so they never reach history.
# The prompts echo what you type, as the page does: the machine is assumed
# air-gapped, and seeing the words is how a typo gets caught.
#
# Pipeline input skips the prompts: a string is the mnemonic (empty
# passphrase), a record {mnemonic, passphrase} gives both.
#
# Returns {fingerprint, icon, public_line, test_key, secret}. Assign it:
# printing the record shows the secret.
#
# The four examples below are the published vectors of `specs/main.md`, the
# same four the page's "Verify test vectors" button checks. Nothing runs
# them: they are here so the check can be run by hand on the air-gapped
# machine, where the test suite and its toolchain are not available. Paste
# one in and compare the icon it prints with the one shown here at a
# glance, and the fingerprint to be sure.
@example "test vector 1, blank passphrase; about 16 s" {
  {mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", passphrase: ""} | nu-okp-signer derive | select fingerprint icon
} --result {fingerprint: "SHA256:Pl5ce4l7GkllU5/k5ThzEWO4KidBNCbhKBaj6oxkZO8", icon: "╰☺╗♙"}
@example "test vector 2, blank passphrase; about 16 s" {
  {mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", passphrase: ""} | nu-okp-signer derive | select fingerprint icon
} --result {fingerprint: "SHA256:h971VXJqQUUkrqQ/nEjpFI2gFjGLOfv2hV3RtPuXWMw", icon: "═█╝⚐"}
@example "test vector 3, blank passphrase; about 16 s" {
  {mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", passphrase: ""} | nu-okp-signer derive | select fingerprint icon
} --result {fingerprint: "SHA256:UZyqW/UIECXHlI1TeX1+XebqEFAcVV3tMSyv+JGPevE", icon: "╚█╯⌘"}
@example "test vector 1 under passphrase PROPHET, which proves the passphrase reaches the salt; about 16 s" {
  {mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", passphrase: "PROPHET"} | nu-okp-signer derive | select fingerprint icon
} --result {fingerprint: "SHA256:2emarN+1I3mvvM6C5bJ6CwZqnl+/j+rloiE5cmRhpfA", icon: "╚☻╯♙"}
export def derive []: [nothing -> record, string -> record, record -> record] {
  let given = $in
  let mnemonic = match ($given | describe --detailed | get type) {
    "nothing" => (input "24 words, space separated: ")
    "string" => $given
    _ => $given.mnemonic
  }
  let passphrase = match ($given | describe --detailed | get type) {
    "nothing" => (input "BIP39 passphrase (blank is the default; a non-blank one becomes part of the key): ")
    "string" => ""
    _ => $given.passphrase
  }
  let words = $mnemonic | str trim | str lowercase | split row --regex '\s+'
  let seed = bip39 seed $words $passphrase
  # Not SLIP-0010/BIP32 because: this is not a crypto wallet. The mnemonic is
  # only a human-friendly encoding of 256 bits of entropy. Sharing a seed with
  # a wallet would be an anti-pattern, so compatibility with Ledger, Solana or
  # SLIP-0010 is a non-goal and users should generate a fresh mnemonic here.
  # The verifier uses the exported public key, not a derivation path, and no
  # second tool has to reproduce this key, so hierarchy buys nothing. What it
  # would cost is the code size and auditability this tool is built for.
  let kp = ed25519 keypair ($seed | first 32)
  let test_key = $TEST_KEYS | get --optional (bytes-to-hex $kp.public)
  if $test_key != null {
    print --stderr $"WARNING: TEST KEY \(($test_key)\). This mnemonic is published; anyone can sign with the same key. Do NOT use for real signing."
  }
  print --stderr $"fingerprint: (sshsig fingerprint $kp.public) (sshsig icon $kp.public)"
  {
    fingerprint: (sshsig fingerprint $kp.public)
    icon: (sshsig icon $kp.public)
    public_line: (sshsig public-line $kp.public)
    test_key: $test_key
    secret: $kp.secret
  }
}

# Sign the text from the pipeline and return the armored SSHSIG block that
# `ssh-keygen -Y verify -n <namespace>` checks.
#
# The namespace is "file" unless said otherwise, the one `ssh-keygen -Y sign
# -n file` uses for arbitrary files. Pass `--namespace git --raw` to sign a
# commit object (`git cat-file -p HEAD`, exactly): git checks commit
# signatures under "git" and under nothing else.
#
# By default the text is signed as a file: exactly one LF is appended, since
# that is how the file on the verifier's disk ends and a forgotten newline
# was the one step of the round trip that went wrong in practice. Text that
# already ends in a newline is refused rather than signed with two. An empty
# text is refused as well, as the page refuses one: signing nothing gives a
# valid block over zero bytes, or over a lone LF in file mode, and a verifier
# cannot tell that from a message lost on the way.
#
# The text is signed exactly as it arrives, CR bytes included. The page
# cannot do that: a textarea turns CR and CRLF into LF before any script
# reads its value, so a CRLF text signed here and on the page gives two
# different signatures. Signing a CRLF file is a thing only this side can
# do; when the two must agree, hand both the same LF-only bytes.
#
# The example below runs the whole chain, mnemonic to signature, on test
# vector 1. Nothing runs it: like the examples on `derive`, it is here so
# the check can be made by hand on the air-gapped machine.
@example "test vector 1 signs the text hello; about 18 s, almost all of it the derivation" {
  "hello" | nu-okp-signer sign ({mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", passphrase: ""} | nu-okp-signer derive)
} --result "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgHeNS5EzTM2clk/IzSnMOGAqvKQ
3omqFtSA3llONOKWEAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECw01BnJ4fIvPNyAAVhTV89J3G2+S3TbvBKYek4yHSnyOiZqWeznuauiYhlxeavtM
/2L55wrhOdLDaMus1J/MoK
-----END SSH SIGNATURE-----
"
export def sign [
  key: record                      # the record `derive` returned
  --raw                            # sign the text exactly as given, no LF appended
  --namespace: string = "file"     # the SSHSIG namespace; "git" for a commit object
]: string -> string {
  sshsig sign ($in | message-bytes $raw sign) $key.secret $namespace
}

# Check an armored SSHSIG block against the text from the pipeline and the
# key `derive` returned. Takes the same text and the same flag `sign` took,
# so a block made here checks here.
#
# This is a self-check on the air-gapped machine, not an outside opinion: it
# shares the field arithmetic and SHA-512 with `sign`, so a fault below that
# layer would corrupt both and they would still agree. What it catches is
# everything above it. To accept a signature from someone else, use
# `ssh-keygen -Y verify` with an allowed_signers file.
#
# Structure is a hard error — bad armor, bad base64, a truncated field. A
# well-formed block that does not check returns false, including one signed
# by another key or under another namespace.
@example "test vector 1 verifies the block it just signed; about 19 s, almost all of it the derivation" {
  let key = {mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", passphrase: ""} | nu-okp-signer derive
  "hello" | nu-okp-signer verify $key ("hello" | nu-okp-signer sign $key)
} --result true
export def verify [
  key: record                      # the record `derive` returned
  block: string                    # the armored SSHSIG block to check
  --raw                            # the text was signed exactly as given, no LF appended
  --namespace: string = "file"     # the namespace the block was signed under
]: string -> bool {
  sshsig verify ($in | message-bytes $raw verify) $block ($key.secret | skip 32) $namespace
}

# The bytes a text stands for, under the rules of `main.md`: refused when
# empty; in file mode, refused when it already ends with a newline and
# given exactly one LF otherwise; in raw mode, the text as it is.
# Why one command: `sign` and `verify` must apply the same rule, or `verify`
# could accept bytes `sign` never produces. The verb only names the caller
# in the error.
def message-bytes [raw: bool, verb: string]: string -> list<int> {
  let text = $in
  if ($text | is-empty) {
    error make {msg: $"the text is empty; there is nothing to ($verb)"}
  }
  let message = if $raw {
    $text
  } else {
    if ($text | str ends-with "\n") {
      error make {msg: $"text already ends with a newline; remove it, or pass --raw to ($verb) the text exactly as given"}
    }
    $text + "\n"
  }
  string-to-bytes $message
}
