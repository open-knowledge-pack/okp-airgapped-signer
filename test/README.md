# test/

Optional.
Nothing here is needed to use, host or audit the signer; `js-okp-signer/index.html` stands on its own.

Most of these scripts load `js-okp-signer/index.html` in jsdom and drive it the way a user would: pick a test vector, derive, sign, lock.
Most print what they find for a human to read; they are probes, not a pass/fail suite.
`test_purejs.js` and `verify.js` check reference implementations of the primitives against Node's `crypto`, without the page.
`sw_gate.js` runs the page's own script blocks in Node's `vm` under each protocol and fails unless `file://` registers no service worker while `https:` registers one.
It and `test_purejs.js` are the two scripts here that report through their exit code and need nothing installed.
`stale_signature.js` does too: it signs, then checks that every refused, failed or edited next Sign leaves no block of the first on screen.
`last_word.js` does the same for "Find word 24": it checks the 8 candidates against a second implementation and drives the button.
`spectre_mode.js` also reports through its exit code, but needs jsdom: it checks the Spectre input mode against spectre-web-fork's word vectors and drives it to a signature.
The `verify_*` and `review_sshsig_crosscheck` scripts hand the signature to `ssh-keygen -Y verify`, so they need OpenSSH on the PATH.

```
cd test
node sw_gate.js      # no dependencies

npm install
node verify_fp.js
```
