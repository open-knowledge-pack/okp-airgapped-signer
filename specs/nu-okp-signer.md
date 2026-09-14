# nu-okp-signer: the Nushell module

`main.md` holds everything both signers must satisfy.
This document holds only what is true of `../nu-okp-signer/` alone.
The browser page is `js-okp-signer.md`.

## Surface

From the repository root, `use nu-okp-signer` gives three commands: two mirror the page's two screens, and the third has no counterpart there.

```
let key = nu-okp-signer derive          # mnemonic to key, about 16 s
let sig = "text" | nu-okp-signer sign $key  # SSHSIG block, about 1 s
"text" | nu-okp-signer verify $key $sig     # true or false, about 2 s
```

`derive` returns a record `{fingerprint, icon, public_line, test_key, secret}` and prints the fingerprint, plus the test-key warning when it applies, to stderr.
The key icon of `main.md` follows the fingerprint on that stderr line,
after one space,
and is the record's `icon` field.
It must be assigned: printing the record prints the secret key with it.
That is a way to leak the key the page does not have, since the page never puts key material anywhere the user can display it.

`sign` takes the record `derive` returned and gives the armored SSHSIG block.
`--raw` signs the text exactly as given; without it, one LF is appended — file mode, the default `main.md` requires.
`--namespace` names the SSHSIG namespace, `file` unless given;
`--namespace git --raw` over the text `git cat-file -p HEAD` prints is a commit signature `git verify-commit` accepts.

`verify` takes the same key record, the armored block, the same text in the pipeline and the same `--raw` and `--namespace` flags, and returns a bool.
Giving it the same shape as `sign` is the point: a block made here checks here, with nothing to convert by hand.
It refuses an empty text and, in file mode, a text that already ends with a newline, exactly as `sign` does — otherwise it would accept bytes `sign` could never have produced.

## Everything is pure Nushell

The module calls no external command and no library: not `openssl`, not `ssh-keygen`.
SHA-512, the field arithmetic of Ed25519, PBKDF2 and the SSHSIG wire format are all written out in the module, which is why a derivation takes about 16 seconds.
The one exception is SHA-256, which the BIP39 checksum and the fingerprint both need: that is Nushell's builtin `hash sha256`, not code you can read here.
The Ed25519 code is a straight port of tweetnacl's `nacl.js`, the same reference the page inlines, so an auditor can read the two side by side.
Only the test suite reaches outside, and it does so on purpose: it runs the real `ssh-keygen` as an outside oracle, which is worth more than a self-consistent check.

## Errors stop the pipeline

Failures are raised with `error make`, not returned as a `{ok, error}` record the way the page does it.
In a command-line tool the failure should stop the pipeline at its source.

Mnemonic validation lives in one place, in `bip39 entropy` of `bip39.nu`, and `bip39 seed` calls it before doing any work.
So a mistyped mnemonic never reaches PBKDF2, and a bad checksum fails at once instead of after the 16 seconds.
The passphrase check is the exception and sits in `bip39 seed` itself.

## Input is read outside the line editor

With no pipeline input, `derive` asks for the mnemonic and the passphrase with `input`.
That reads outside the line editor, so neither ever reaches shell history.
Both prompts echo what is typed, as the page shows the words: the machine is assumed air-gapped, and seeing the words is how a typo is caught.

Pipeline input skips the prompts — a string is the mnemonic at a blank passphrase, a record `{mnemonic, passphrase}` gives both.
It skips the history protection with them: a record typed at the prompt line is a shell command like any other, and the `@example` blocks show exactly that form.
Read from a file, or use the prompts, when the mnemonic must not be recorded.

## A non-ASCII passphrase is refused

BIP39 asks for NFKD normalization and Nushell has no normalizer.

```
passphrase must be ASCII: Nushell cannot apply the NFKD normalization BIP39 requires
```

Deriving a key that no other BIP39 tool would derive is worse than failing.
So the module satisfies BIP39's NFKD requirement by refusing every input that would need it, where the page satisfies it by normalizing.
The word list is ASCII, so this only ever bites on the passphrase.

The consequence, plainly: a mnemonic provisioned elsewhere under a non-ASCII passphrase cannot be used here.
Use the page for that key.

## The text is signed exactly as given

CR bytes included.
This is the one input this side can sign and the page cannot, because a textarea turns CR and CRLF into LF before any script reads its value.
So the same CRLF text signed in the two places gives two different signatures.

Documented rather than removed: normalizing here would import the browser's limitation into a tool that does not have it, and refusing CR would block signing a legitimate CRLF file.
When the two must agree, give both the same LF-only bytes.

## No QR codes

The two payloads the page turns into QR codes are here as text: `sign` returns the armored block, and the public-key line is the `public_line` field of the key record, which has to be asked for.
Copy-paste of that text is the air-gap channel on this side.

This is a decision, not a gap left for later.
A renderer was considered and dropped, with both ways of getting an encoder judged too expensive for what they buy: porting the page's `qrcode-generator` would make Reed-Solomon, module placement and mask selection the largest and slowest file in the module, and calling `qrencode` would put a binary on the air-gapped machine, dropping the "nothing but `nu`" premise the module is built on.

## Verification

Verification has no counterpart on the page.

`nu-okp-signer verify` is a thin wrapper over `sshsig verify`, which does the work: it strips the armor, walks the wire fields back out, checks the namespace, the hash algorithm, the key algorithm and the embedded public key, rebuilds the blob that was signed, and hands that to `ed25519 verify`.
Underneath it, `ed25519 verify` is the primitive: a raw 64-byte signature over exactly the bytes given.
Both are reachable directly, for a caller who holds bytes rather than text:

```
use nu-okp-signer/sshsig.nu
use nu-okp-signer/ed25519.nu
```

They are a self-check on the air-gapped machine, not an independent implementation: they share `gf-mul`, the point code and SHA-512 with signing, so a fault in the field arithmetic would corrupt both sides and they would still agree.
What they do catch is everything above that layer — a wrong scalar accumulation, a bit flipped in memory after signing.
To accept a signature from someone else, run `ssh-keygen -Y verify`; an outside oracle is worth more than a self-consistent check.

`sshsig verify` takes the public key the caller expects, instead of trusting the key inside the block.
Every SSHSIG block carries its own key, so checking a block against that key alone proves only that the block is internally consistent, and a forger would embed theirs.
`ssh-keygen -Y verify` solves this with an `allowed_signers` file; here the caller passes the key `derive` returned.

A malformed block is a hard error — bad armor, bad base64, a truncated field, trailing bytes.
A well-formed block that does not check returns false, including a wrong namespace, hash algorithm, key algorithm or public key.

Verification enforces `S < L`, the check RFC 8032 section 5.1.7 requires and tweetnacl omits.
Without it a signature can be altered without the key, since `S` and `S + L` both check out.
The page has no verifier to disagree with, but anything built on the tweetnacl it inlines would accept what this side rejects.

## Not constant-time, on purpose

Nushell cannot promise constant time, and the signer runs on an air-gapped machine where timing is not observable.
So scalar multiplication is plain double-and-add rather than the constant-time swap ladder tweetnacl uses.

## No Clear & Lock

There is nothing to wipe in place: the key lives in the variable the user holds.
Dropping that variable, or closing the shell, is the whole of the lock.

## The self-check is `@example` blocks

There is no self-test command matching the page's Verify test vectors button.
The equivalent is `@example` attributes, which `--help` prints: four on `derive`, holding the four documented vectors of `main.md` as pipeline records with the fingerprint and the icon each must produce; one on `sign`, holding the whole chain from tv1 to the SSHSIG block over "hello"; and one on `verify`, running that block back through the check.

Nothing runs them.
They are documentation, and their point is that the check can be made by hand on the air-gapped machine, where no test toolchain exists: read `--help`, paste one in, compare what it prints with what is printed there.
Each names the time to expect: about 16 seconds for a derivation, about 18 for the signing example and about 19 for the verifying one, nearly all of it the derivation each starts with.

The nutest suite stays what it is — a development-time check that needs the dev toolchain and cannot run on a bare air-gapped machine.

## Checked only here

These are the requirements only this side can be tested against; the module's nutest suite covers all of them.

- `verify` accepts what `sign` produced and rejects it under a different text.
- `sshsig verify` accepts a block written by `ssh-keygen` itself, which is what proves the parser reads the format and not only its own output, and rejects a block under an expected key that did not sign it or under another namespace.
- `ed25519 verify` rejects a signature whose `S` was raised by one group order.
- A non-ASCII passphrase is refused before any derivation runs.

## Not verified

Signing text that holds a CR byte — the one input only this side can sign — has no test.
The suite covers the LF and raw cases only.

Two rejection paths the code has and the suite never reaches: a block whose hash algorithm is not `sha512`, and a signature whose `S` is exactly `L` rather than above it.
