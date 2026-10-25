# CLAUDE.md

## `VERSION` in `js-okp-signer/sw.js` follows the files it caches

`VERSION` carries the hash of the files in `FILES`.
After a change to one of them,
run `nu toolkit.nu sw-version` before the commit.
`nu toolkit.nu check` fails while the hash does not match.

Without a new `VERSION`, an installed app keeps the old page:
the worker answers from its cache,
and the browser refetches only `sw.js`.
The page shows the version that the device holds, in the "offline copy" line.
After a deploy, the first visit installs the new cache,
and the second visit shows the new page.
