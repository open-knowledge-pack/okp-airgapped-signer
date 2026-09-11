# Air-gapped Ed25519 signers: what both implementations must satisfy

## What this is

Two programs that turn a 24-word BIP39 mnemonic into an Ed25519 key and sign text with it, offline.

- `../js-okp-signer/index.html` — one self-contained HTML page, for a phone or a tablet with no network.
  Its own rules are in `js-okp-signer.md`.
- `../nu-okp-signer/` — a Nushell module, for an air-gapped machine with a terminal.
  Its own rules are in `nu-okp-signer.md`.

This document holds only what both must satisfy byte for byte.
A claim that one can meet and the other cannot lives in that one's document, with a sentence saying what the other does instead.
A claim that is true of both but can only be checked in one still lives here, and says where it is checked.

Neither is audited, and neither was written by a cryptographer.
They are an untrusted alternative to `ssh-keygen -Y sign`, for play and for air-gapped devices.

## Input: a 24-word BIP39 mnemonic

Exactly 24 words, from the standard BIP39 English word list, which each implementation carries inside itself.
Each word gives 11 bits, so 24 words are 264 bits: 256 bits of entropy and an 8-bit checksum, the first byte of SHA-256 over the entropy.

A wrong word, a wrong word count or a failing checksum is an error the user sees.
Never a silent wrong key: the whole point of the checksum is that a mistyped word stops the derivation instead of producing a key that signs but that nobody can reproduce.

The words are lower-cased and joined by single spaces before derivation.

## Key derivation

The mnemonic becomes a 64-byte BIP39 seed: PBKDF2-HMAC-SHA512, 2048 iterations, password the joined mnemonic, salt `"mnemonic"` + the passphrase, output 64 bytes.
The first 32 bytes of that seed are the Ed25519 seed, expanded into a keypair the standard way (`nacl.sign.keyPair.fromSeed` on the page, `ed25519 keypair` in the module).
The other 32 bytes are unused.

BIP39 asks for NFKD normalization on the mnemonic and on the passphrase.
The two implementations meet that requirement differently, so how each does it is written in its own document.
The word list is ASCII, so the question only ever arises for the passphrase.

### Why this derivation is intentionally not SLIP-0010 / BIP32

- This is not a crypto wallet.
  The BIP39 mnemonic is used purely as a human-friendly encoding for 256 bits of entropy — nothing more.
- Compatibility with Ledger / Solana / SLIP-0010 is a non-goal.
  Sharing a seed between a crypto wallet and a document-signing tool would be a security anti-pattern; users should generate a fresh mnemonic for this tool.
- The verifier uses the exported public key, not a derivation path.
  There is no second tool that needs to reproduce the same key from the same mnemonic, so hierarchical derivation buys nothing here.
- The primary goal of this tool is minimal code size and auditability.
  SLIP-0010/BIP32 would add significant complexity for zero practical benefit.

This rationale appears as a comment in both implementations, so an auditor reading only the code sees that the choice was deliberate.

## The passphrase

The BIP39 passphrase is part of the tool, not an optional extra.
The same 24 words under different passphrases give different keys, which is how one written-down mnemonic can back several unrelated identities.
Hardcoding it to `""` would throw that property away and would make the tool unable to reproduce a key provisioned anywhere else under a non-empty passphrase.

A blank passphrase is valid, is the canonical BIP39 default, and is what three of the four documented test vectors use.

Both implementations must tell the user, at the point where the passphrase is entered, that blank is fine and is the default, and that a non-blank passphrase becomes part of the key.
The page has room for the rest and says it in full: losing the passphrase loses the key with no recovery, and the same words under a different passphrase give a different key.
The module's prompt is one line and carries the first two points only.

## The documented test vectors

Four mnemonic-and-passphrase pairs, with the public key each must produce, in hex:

- tv1 — `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`, blank passphrase
  → `1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961`
- tv2 — `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote`, blank passphrase
  → `ea1c7d41a6d70293194f45206ab4dca257d9c252fe2c53779fdef2a2bd05cd47`
- tv3 — `letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless`, blank passphrase
  → `e88ff5f87c809d2921bf2ee8bd3a176d6fc66b9f90230920f1246b5472c22c13`
- tv1 under passphrase `"PROPHET"`
  → `0abd856befd1aaaacfe339bd573dbbcb979d760926ca2e653b8b98e49faa35f9`

The first three are canonical BIP39 vectors at the blank passphrase, and they prove the blank-passphrase path is wired.
They say nothing about whether the passphrase argument is used at all, so the fourth exists: one fixed public key at a non-empty passphrase catches both "passphrase silently ignored" and "passphrase mangled — truncated, lower-cased, normalized twice" in one comparison.
The mnemonic is tv1's on purpose, so the passphrase is the only difference from the tv1 case.
`"PROPHET"` is arbitrary; the hex is reproducible against the npm `bip39` package with `bip39.mnemonicToSeedSync(mnemonic, "PROPHET")`.

Both implementations expose a way to run these four derivations and compare the result; each document says what that way is.

### The test-key warning

All three mnemonics, and the `"PROPHET"` passphrase, are published here and in both implementations' source.
Anyone can sign with those keys.

So after a successful derivation, an implementation that has produced one of the four public keys must say so loudly: a test key, published, not for real signing.
The check is on the derived public key, not on how the user got there — it catches "I clicked a test vector and forgot" and "I typed a published mnemonic" with one comparison.

## Output

Three text formats, all OpenSSH's, so nothing custom is needed on the verifying side.

**The signature is SSHSIG** (OpenSSH `PROTOCOL.sshsig`), hash `sha512`, armored as a `-----BEGIN SSH SIGNATURE-----` block with the base64 wrapped at 70 columns, exactly as `ssh-keygen` wraps it.
The verifier must not need a custom tool: `ssh-keygen` is on every Linux and macOS machine, and `-Y verify` is the standard way to check a detached Ed25519 signature over a file.
A raw detached signature over the message bytes — the original design — could only be checked by a script nobody on the verifier's side had.

**The namespace is chosen by the user, `file` by default.**
SSHSIG bakes the namespace into the signed bytes,
and every verifier asks for one by name,
so the signer has to know who will check the block.
`file` is what `ssh-keygen -Y sign -n file` uses for arbitrary files,
so by default signatures from these tools and from `ssh-keygen` are interchangeable
and the verifier's command line is the documented one.
`git` is what git checks a commit's SSH signature under,
with no option to change it;
a block made under `file` can never sign a commit.
Signing a commit means signing the commit object as `git cat-file -p HEAD` prints it,
in raw mode, since that text already ends with one LF,
and putting the block into the commit's `gpgsig` header.
An empty namespace is refused, in both tools,
as `ssh-keygen -Y sign` refuses one.

Ed25519 does not sign the message directly.
It signs a fixed-size blob holding SHA-512 of the message, so the armored block is about 294 bytes whatever the message length.

**The public key is the OpenSSH public-key line**: `ssh-ed25519 <base64 of the ssh-ed25519 wire blob>`.
That is the form `allowed_signers` and `authorized_keys` take, so the verifier pastes it in unchanged.
Raw base64 of the 32 key bytes — the original design — could not be turned into that line without writing code.

**The fingerprint is OpenSSH's**: `SHA256:` followed by the unpadded base64 of SHA-256 over the same wire blob.
It is byte for byte what `ssh-keygen -lf key.pub` prints and what `ssh-keygen -Y verify` names in its success line.
The earlier design — the first 8 bytes of SHA-256 over the raw key, in hex — gave one key two identities, one on the signing device and one in the verifier's terminal, with no way to compare them by eye.

### The signature does not name a signer

An SSHSIG block carries the public key it was made with, so a verifier needs nothing else to check it.
That is not an identity: the embedded key is whatever the signer put there, and a forger embeds their own.
Identity comes only from matching that key against the verifier's `allowed_signers` file.
`ssh-keygen -Y verify` refuses to run without one, which is what keeps this from being a trap.

## What gets signed

Signing as a file is the default: the bytes are the text plus exactly one trailing LF.
Raw is the opt-out: the text exactly as given.

The reason for the default: what these tools sign in practice is a nu-multiproof root statement — one line, and the file on disk ends with one LF.
A forgotten final newline was the one manual step of the round trip that went wrong, and `ssh-keygen` then reports a bad signature for text that looks identical on screen.

In file mode, text that already ends with a newline is refused rather than signed with two.
Neither tool can tell a deliberate second newline from a stray one, and refusing costs one keystroke while a wrong signature costs a whole round trip.

An empty text is refused in both modes, with no signature produced.
A block over zero bytes — or over a lone LF in file mode — is perfectly valid, and the verifier cannot tell it from a message that was lost on the way in.

## Zero persistence

Neither tool writes key material anywhere: no file, no browser storage, no cookie, no environment variable.
The mnemonic, the seed and the private key live in memory for as long as the session lasts, and vanish with it.
The page's offline cache is not an exception: it stores the page, its manifest and its icon, which are the same bytes anyone can fetch, and nothing a user typed.

The surrounding environment can still record what the tool does not.
The page has nothing around it.
The module has a shell around it, and keeps the mnemonic out of its history only on the path where it prompts for one; a mnemonic handed to it as a command argument is recorded like any other command.
Its own document says which path is which.

## What neither may include

- No code that reaches the network when the page is opened from `file://`, and none at all in the module.
  The page carries a service-worker registration for its hosted copy, gated on `https:`; its own document says what that is and why it is not a second file.
- No key storage, and no export of private material.
- No encryption or decryption is offered — signing only.
  The page inlines tweetnacl whole, so its `box` and `secretbox` primitives are present in the file; nothing calls them.
- No multi-sig and no threshold schemes — one key, one signature.

## How a signature is checked

This is the shared recipe, run on the verifier's machine, and it is what both implementations are tested against.

```
echo "signer $(cat key.pub)" > allowed_signers
printf '%s\n' '<the exact text>' | ssh-keygen -Y verify -f allowed_signers -I signer -n file -s msg.sig
```

Expected: `Good "file" signature for signer with ED25519 key SHA256:...`, naming the same fingerprint the signer displayed.

Both sides automate it, differently.
The module's nutest suite shells out to a real `ssh-keygen` and reports pass or fail, and it goes one step further than the page can: it checks a block `ssh-keygen` itself wrote, which is what proves the parser reads the format and not only its own output.
The page's side is `../test/`, jsdom probes that drive the page and hand its own output to a real `ssh-keygen -Y verify` in both signing modes; most of them print what they find for a person to read rather than passing or failing.

What must hold for both implementations:

- A known mnemonic derives the public key documented above, matching a `bip39` and `tweetnacl` reference run.
- The command above succeeds for a message signed in file mode against a file holding that line plus one LF, and fails against the bare line; in raw mode, the reverse.
- One changed byte, or an extra trailing newline, fails with `incorrect signature`.
- Text ending in a newline is refused in file mode, with no signature produced.
- Empty text is refused in both modes, with no signature produced.
- A wrong word, a wrong word count or a bad checksum gives a clear error, not a silent wrong key.
- All four documented vectors derive their documented public key.
- Deriving one of the four raises the test-key warning.

Each document lists what only its own side can be checked for.
