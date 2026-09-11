# test/

Optional.
Nothing here is needed to use, host or audit the signer; `js-okp-signer/index.html` stands on its own.

Most of these scripts load `js-okp-signer/index.html` in jsdom and drive it the way a user would: pick a test vector, derive, sign, lock.
Most print what they find for a human to read; they are probes, not a pass/fail suite.
`test_purejs.js` and `verify.js` check reference implementations of the primitives against Node's `crypto`, without the page.
`sw_gate.js` runs the page's own script blocks in Node's `vm` under each protocol and fails unless `file://` registers no service worker while `https:` registers one.
It and `test_purejs.js` are the two scripts here that report through their exit code and need nothing installed.
The `verify_*` and `review_sshsig_crosscheck` scripts hand the signature to `ssh-keygen -Y verify`, so they need OpenSSH on the PATH.

```
cd test
node sw_gate.js      # no dependencies

npm install
node verify_fp.js
```
