# js-okp-signer: the browser page

`main.md` holds everything both signers must satisfy.
This document holds only what is true of `../js-okp-signer/index.html` alone.
The Nushell side is `nu-okp-signer.md`.

## One file, and three that are not part of it

Everything the signer needs is inlined in `index.html`: tweetnacl, the QR generator, the BIP39 English word list, the CSS, the application code.
No external fetch, no CDN link, and, with the one exception named below, none of the signer's own code or style outside that file.
The page must work opened as a local `file://` URL on a device in airplane mode, and that is still the air-gapped case.

Three files sit beside it — `manifest.webmanifest`, `sw.js`, `icon-180.png` — and none of them is part of the page.
`sw.js` is the one piece of the signer's own JavaScript that lives outside `index.html`, and it runs in a worker, for the hosted copy only, never under `file://`.
Saving `index.html` to a phone brings none of the three, and nothing the page's script fetches reaches them; the head declares the manifest and the touch icon either way.
They exist for the hosted copy, described below.

It stays one file on purpose.
A second copy without the service-worker lines was considered and rejected: two copies of 5400 lines that must stay identical except for twenty would drift, the provenance hashes and the four documented vectors would be pinned twice, and the premise of the tool is that an auditor reads one file.

The content security policy is a meta tag in the head, verbatim:

```
default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: 'self'; manifest-src 'self'; worker-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'
```

`form-action`, `frame-ancestors` and `base-uri` are named explicitly because CSP's `default-src` fallback does not cover those three directives.
Leaving them out would leave their implicit defaults in place — `frame-ancestors *` among them — which this tool should not allow.

`manifest-src`, `worker-src` and the `'self'` in `img-src` are the three the hosted copy needs, and they are what `default-src 'none'` would otherwise block.
Under `file://` nothing is fetched from any of them.

## The hosted copy

The folder is published as a GitHub Pages site by `.github/workflows/pages.yml`, which uploads `js-okp-signer/` verbatim, so the bytes served equal the bytes in git.
A workflow deploy rather than "deploy from a branch" is why the folder can carry its own name: that mode serves only `/` or `/docs`.

Why hosting exists at all: on iPhone a downloaded HTML file cannot run.
Files opens it in QuickLook, which renders the page but runs no scripts, and Safari does not open local files.
Add to Home Screen is the only path there without extra software.

`sw.js` is a cache-first service worker with no network fallback, caching the page, the manifest and the icon on first launch.
It does not cache itself, which is what the version paragraph below rests on.
No fallback because the page is self-contained and its CSP loads nothing else, so an uncached request is a bug, not a need.
Registration is gated on `location.protocol === 'https:'`: under `file://` `navigator.serviceWorker` still exists but `register()` rejects, so the gate is the protocol, not the property, and the `file://` copy behaves exactly as it did before any of this existed.
A line in the page shows `offline copy: ready, version ...`, or the failure, because a worker that failed to register would otherwise be discovered offline.

The cache version lives in `sw.js`, not in the page, and must be bumped whenever any file in the folder changes.
`sw.js` is the only file the browser refetches past the cache, so a version inside a cache-first page would never be seen.

There is deliberately no integrity check inside the page: the code that would print a hash is the code being checked, and any script in the same page can patch what it shows.
The check lives outside the browser — fetch the URL and hash it, and compare with `git show master:js-okp-signer/index.html | sha256sum`.
That checks the server, not the phone:
the worker serves the page it cached on the first launch until `VERSION` changes,
so an app installed while the server held a wrong page keeps it after the server is fixed,
and the check passes while the phone runs the wrong page.
The README says so and gives the sequence that closes the gap
— remove and re-add the app right after a match, so the install fetches what was just hashed.

## Crypto in plain JavaScript, not `crypto.subtle`

SHA-256, HMAC-SHA512 and PBKDF2-HMAC-SHA512 are written in plain JavaScript, layered on the SHA-512 that tweetnacl already brings.

- `crypto.subtle` on `file://` depends on the browser and its version.
  Older iOS Safari and older Android WebViews either omit it or treat `file://` as a non-secure context, where `crypto.subtle` is `undefined` and key derivation silently breaks.
  The page is meant for old, locked-down, offline devices, so this is a real failure mode.
- An auditor reading only this file sees every byte from mnemonic to signature.
  With `crypto.subtle` they would have to trust the browser instead.
- The specification fixes the algorithms, not the API, so plain JavaScript meets it and runs in more places.
- The cost is a few kilobytes and a derivation that takes roughly 100 to 500 ms instead of being native.
  The Derive Key button shows "Deriving…" and is disabled for that time, and the derivation yields to the event loop once so that repaint actually lands before the blocking loop starts.

NFKD normalization happens inside `bip39Seed`, on the joined mnemonic and on `"mnemonic"` + passphrase.
The UI passes the passphrase field's value verbatim — no trim, no normalization on the way in.
This is how the page meets BIP39's NFKD requirement; the module refuses the inputs that would need it instead.

## Screen 1: seed entry

Twenty-four separate input fields, numbered.
Each field validates as you type: the word is lower-cased and trimmed in place, and the field is marked good or bad against the word list.
Space or Enter moves to the next field; Enter in the last field derives.
Space in the last field does nothing at all: the key is swallowed, no space is typed and no derivation starts.

The passphrase input sits below the fields as a single line, `type="password"`, with a "show" checkbox that switches it to `type="text"` and back.
Why hidden by default:
a phone keyboard learns the words typed into a text field and can sync what it learned,
so a passphrase typed there can leave the air-gapped device;
a password field is the one input the keyboard does not learn from.
The field was `type="text"` before,
on the grounds that shoulder-surfing is out of scope and a visible field lets the user catch a typo that would otherwise silently derive a different key.
Both grounds still hold, and the checkbox keeps the second:
tick it to read back what was typed.
Typing while it is ticked is typing into a text field again, learning included, and the label says so.
A password field also invites the browser's password manager, which syncs:
the field carries `autocomplete="new-password"`, since `off` is widely ignored on password fields.
That token means "a new password, as when creating an account", so saved passwords are not offered;
a browser may instead offer to generate one, or to save what was typed,
and the label says to decline, which covers both.
Whether a field outside any form gets either offer depends on the browser and has not been tested.
Clear & Lock unticks it.
Its help text says what `main.md` requires it to say.

Buttons: Derive Key, Paste full phrase, Clear words.
Behind a collapsed "Test vectors (development only)" section: three fill buttons, the Verify test vectors button, and the line where that self-test reports.

### Pasting

A paste of 24 words or more is treated as a whole phrase: exactly 24 replaces all 24 fields, so stale words from an earlier vector cannot survive, and more than 24 is refused with a message naming how many words came.
A shorter paste splices from the focused field onward.
A splice that would run past field 24 is refused whole, with the fields left as they were, and the message names how many words came and where they would have started — the earlier behaviour dropped the overflowing words in silence.
A single pasted word is left to the browser.

Clicking a fill button also blanks the passphrase field, since the three keys the buttons stand for are at the blank passphrase and a leftover passphrase would derive something else.
The two paste paths do not, although a paste can carry a published mnemonic just as easily.

### Verify test vectors

The button runs all four documented vectors of `main.md` through the page's own path — `validateMnemonic24`, then `bip39Seed`, then `nacl.sign.keyPair.fromSeed` — and compares each public key with the documented hex.
It reports OK with the count, or FAIL naming each vector that missed and what it produced.

It exists because the documented hex is a claim nothing else in the page enforces: without it, a regression in the derivation path would drift away from the published values in silence.
Each fixture carries its own passphrase, and the self-test deliberately ignores whatever is typed in the passphrase field, so its result depends on the code and not on the current UI state.
Secret material derived inside the self-test is zeroed before it touches the DOM.

## Screen 2: signing workspace

Top to bottom: the test-key banner when it fires, the fingerprint, the Export Public Key and Clear & Lock buttons, the public-key QR box when it is shown, a horizontal rule, then the message area, the "Sign as a file" checkbox, the namespace field, Sign, and the signature QR box when it is shown.
The rule is the division: identity above it, signing below.

The message area is a `textarea`, which is what makes the newline rules of `main.md` matter here: what is signed is its value as UTF-8.

Export Public Key renders the OpenSSH public-key line as a QR and prints the same line below it.
Sign renders the armored SSHSIG block as a QR and prints the same block below it, for copy-paste.

Clear & Lock wipes the key material, empties the fingerprint, the QR images, the payload texts, the message, the seed fields and the passphrase field, clears the test-key banner and the self-test line, re-ticks "Sign as a file", sets the namespace back to `file`, hides the passphrase again, and returns to Screen 1.

## The textarea normalizes line endings, so a CRLF file cannot be signed here

HTML defines a textarea's value with CR and CRLF already turned into LF, before any script can read it.
So the page cannot sign bytes that contain a CR.
A verifier holding a CRLF original has bytes the signer never saw, and `ssh-keygen` rejects a message that looks identical on screen.
The hint under the signature QR says the mechanism — "line endings become LF" — but does not spell out either consequence.
The module can sign those bytes; when the two must agree, give both the same LF-only bytes.

## QR codes

Payloads are the OpenSSH text formats verbatim — the public-key line, the armored SSHSIG block — with no JSON wrapper, so what a camera reads is exactly the file `ssh-keygen` expects.
Error correction level M, with the smallest QR type the payload fits, rendered as a data URL at 4 px per module inside a 16 px margin, the 4-module quiet zone the QR standard asks for.
The margin argument of the generator is pixels, not modules; an earlier `4` gave a margin under one module, which a scanner may not tolerate.
That gives about 180 px for the public-key line (type 5, 37 modules) and about 308 px for the signature block (type 13, 69 modules).
The module size is 4 px and not 5 because a 375 px phone leaves 319 px after the page and box padding, and 5 px with the quiet zone gives 385 px; a CSS downscale would instead break the integer module size the pixelated rendering relies on.
The intent was a QR comfortable to scan from about 20 cm, which has never been tried.

The signature QR does not carry the message.
Arbitrary message text could blow past QR capacity at any reasonable error-correction level, and a second "message" QR would double the verifier's scanning surface.
The verifier must already hold the exact message bytes, out of band; the hint under the QR says that, and repeats the newline rules.

## Key material and the DOM

No key material goes into the DOM: not into a hidden input, not into a data attribute.
The secret key, the public key and the Ed25519 seed live in top-level variables of a classic script — not on `window`, not in the DOM, but shared across the page's script blocks, which is how the word list reaches the application code.

The 32-byte seed variable is zeroed and dropped immediately after `fromSeed` has copied it, rather than waiting for Clear & Lock.
That removes one copy of two, not the seed: an Ed25519 secret key is the seed followed by the public key, so the first 32 bytes of the secret key are that same seed, and they live until Clear & Lock like the rest of it.
The mnemonic fields and the passphrase field are cleared when Screen 2 opens, since together they fully derive the key and would otherwise sit in the DOM for the whole session.
They are not cleared earlier: the derivation has no catch, so an early wipe followed by a throw would leave the user on Screen 1 with 24 blank fields and no error, and clearing at the start would also blank the fields for the 100 to 500 ms of "Deriving…", which reads as data loss.

Clear & Lock calls `fill(0)` on the key buffers.
That is best-effort and the code says so: the JavaScript garbage collector may have copied a buffer internally, and nothing in the language can reach those copies.

The key survives several Sign clicks in one session.
Screen 2 has separate Sign and Clear & Lock buttons for exactly that reason: re-deriving per signature would force 24 words to be retyped for every document, and it would buy nothing, because the seed and the key sit in memory either way until the lock.

## Inlined library provenance

The two inlined library blocks carry the SHA-256 of the script body they contain, plus a one-line recipe to reproduce it from the upstream npm package — `npm pack tweetnacl@1.0.3` and `npm pack qrcode-generator@2.0.4`, then `shasum -a 256` on the extracted file.
Without the hashes an auditor reading only this file could do no better than believe a version string.

Two details the block headers state and an auditor needs.
The tweetnacl body hashes to the upstream file exactly.
The qrcode-generator body does not, because its CommonJS wrapper was replaced with `window.qrcode = qrcode;`, so its header carries two hashes: the upstream one, which the `npm pack` recipe reproduces, and the inlined body's own, which nothing outside this file can.

The BIP39 word list is inlined the same way but carries no hash and no recipe, only the name of the package it came from.

## Code layout

The library blocks — tweetnacl, the QR generator, the BIP39 word list — sit at the top in marked sections, separate from the application logic below.
The cryptographic pipeline is commented step by step, so a reader can follow mnemonic to seed to keypair to signature.
The CSS is minimal, dark, and framework-free, which is easier on the eyes in a low-light signing session.

## Checked only here

These are the requirements only the page can be tested against.

- The page opens from a local `file://` URL with airplane mode on and works.
- Clear & Lock really clears: after the click, the old fingerprint is no longer in the DOM.
- Pasting a 24-word phrase into any field leaves no stale word from an earlier vector.
  A shorter paste is a splice and deliberately leaves the other fields as they were.
- The Verify test vectors button reports OK for all four documented vectors.
- The test-key banner appears above the fingerprint after deriving from a published mnemonic.
- Under `file://` the page registers no service worker, while under `https:` it registers one.
  Both halves are the check: the gate is the protocol and `navigator.serviceWorker` is present either way, so a run that registers nothing proves nothing on its own.

`../test/` holds probes that drive the page in jsdom and cover several of these, but it is not a suite: most scripts print what they find for a person to read rather than passing or failing, and running them needs `npm install` and, for the ones that call `ssh-keygen`, OpenSSH on the PATH.
`sw_gate.js` and `test_purejs.js` are the exceptions on both counts — they report through their exit code, and they need nothing installed.
Nothing here is needed to use, host or audit the page.

What they reach: `verify_as_file.js` hands the page's own output to the real `ssh-keygen -Y verify` in both signing modes, and `verify_sshsig.js` does the same in file mode with the bare text and a flipped byte as the negative cases; `verify_fp.js` compares the fingerprints of the three blank-passphrase vectors with `ssh-keygen -lf`; `review_sshsig_crosscheck.js` checks the page's block against what `ssh-keygen -Y sign` produces byte for byte, what a CRLF paste actually signs, and whether the seed or the secret key lands in the DOM after signing; `review_lock_check.js` looks for the public key, the fingerprint and a signature line left in the DOM after the lock; `qr_size.js` measures the QR version a long message produces; `timing.js` measures the pure-JS PBKDF2; `test_purejs.js` checks reference copies of SHA-256, HMAC-SHA512 and PBKDF2 against Node's `crypto`, and `verify.js` re-derives the three blank-passphrase public keys with it; neither of those two loads the page.
`sw_gate.js` runs the page's own script blocks in Node's `vm` against a small DOM stub, once under each protocol, and fails unless `https:` registers exactly one worker and `file://` registers none.
It avoids jsdom on purpose: a check of the offline promise should run where the page runs, on a machine that cannot `npm install`.

Which of the manual checks have actually been run is not recorded anywhere.

## Not verified

**iOS.** The page has never run on the iOS device it was written for.
The `file://` route is closed there: the Files app opens a local `.html` in QuickLook, which renders the page but runs no JavaScript, and Safari has stopped being a registered handler for local `.html` files somewhere around iOS 14.
The first answer to that was a third-party browser — Edge, iCab, Documents — and it was never tried.
The Home Screen web app above replaced that answer, and it has not been tried on a device either.
Nothing published — this document, the README, anything else — may claim iOS works.

**Scanning.** No QR code produced by this page has ever been read by a phone camera.
