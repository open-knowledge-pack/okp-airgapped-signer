# CLAUDE.md

## `VERSION` in `js-okp-signer/sw.js` follows the files it caches

`VERSION` carries the hash of the files in `FILES`.
Do not change `VERSION` while the work on a branch goes on.
Before the branch lands on `master`,
run `nu toolkit.nu sw-version` once,
and commit `sw.js` as the last commit of the branch.
Why: a branch holds several changes to the page,
and a `VERSION` in each commit only conflicts at each rebase.
`nu toolkit.nu check` fails while the hash does not match;
the export runs it and refuses a tip without the new `VERSION`.

Without a new `VERSION`, an installed app keeps the old page:
the worker answers from its cache,
and the browser refetches only `sw.js`.
The page shows the version that the device holds, in the "offline copy" line.
After a deploy, the first visit installs the new cache,
and the second visit shows the new page.
