'use strict';

// The page must register no service worker when it is opened as a local file.
// That promise is a single condition in index.html — `location.protocol ===
// 'https:'` — and nothing else in the repository holds it.
//
// Why no jsdom, unlike the other probes here: this one has to run where the
// page runs, on a machine with nothing installed. `npm install` is exactly
// what an air-gapped machine cannot do, and a check of the offline promise
// that needs the network to run would be checking it in the wrong place.
//
// So the page's scripts are run in Node's own vm, against a DOM stub small
// enough to read. The stub is not the page and cannot prove much on its own;
// what makes the result mean something is that the same harness is run twice.
// Under `https:` the page must register, under `file://` it must not. A stub
// too poor to reach the end of the script fails the first run, so a pass on
// the second cannot come from a script that never got there.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PAGE = path.join(__dirname, '..', 'js-okp-signer', 'index.html');
const html = fs.readFileSync(PAGE, 'utf8');
// Anchored to whole lines: the page's provenance comment mentions a
// `<script>...</script>` pair in a sentence, and an unanchored match would
// pick that text up as a script body.
const scripts = [...html.matchAll(/^<script>$([\s\S]*?)^<\/script>$/gm)].map((m) => m[1]);

// If this ever stops finding the block under test, the probe must stop too:
// a page whose scripts were not extracted registers nothing, which would read
// as a pass.
const gated = scripts.filter((s) => s.includes('serviceWorker.register('));
if (gated.length !== 1) {
  throw new Error(`expected exactly one script block registering a worker, found ${gated.length} in ${scripts.length} blocks`);
}

function element() {
  const el = {
    className: '', textContent: '', value: '', type: '', id: '',
    autocomplete: '', spellcheck: false, checked: false,
    dataset: {}, style: {}, parentNode: null, children: [],
    classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
    setAttribute() {}, removeAttribute() {}, addEventListener() {}, focus() {},
    appendChild(child) { child.parentNode = el; el.children.push(child); return child; },
    querySelector: () => null, querySelectorAll: () => [],
  };
  return el;
}

// Returns the arguments every serviceWorker.register() call was made with.
function registrationsUnder(protocol) {
  const registered = [];
  const byId = new Map();
  const worker = { active: { postMessage() {} } };

  const ctx = {
    console,
    setTimeout, TextEncoder, btoa,
    location: { protocol },
    document: {
      getElementById(id) {
        if (!byId.has(id)) byId.set(id, element());
        return byId.get(id);
      },
      createElement: element,
      addEventListener() {},
    },
    navigator: {
      // Present under both protocols, as it is in a real browser: the page's
      // gate is the protocol, not this property, and a stub that hid it here
      // would pass the file:// run for the wrong reason.
      serviceWorker: {
        register(url) { registered.push(url); return Promise.resolve(worker); },
        ready: Promise.resolve(worker),
        addEventListener() {},
      },
    },
  };
  ctx.window = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);

  // No try/catch: a script that throws is a broken stub or a broken page, and
  // either one must stop this probe rather than be reported as "no register".
  for (const source of scripts) vm.runInContext(source, ctx);
  return registered;
}

const hosted = registrationsUnder('https:');
const local = registrationsUnder('file:');

const ok = hosted.length === 1 && local.length === 0;
console.log(`https: registered ${hosted.length} worker(s): ${JSON.stringify(hosted)}`);
console.log(`file:  registered ${local.length} worker(s): ${JSON.stringify(local)}`);
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
