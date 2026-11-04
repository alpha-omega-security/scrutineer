const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const script = fs.readFileSync('static/app.js', 'utf8');
const html = fs.readFileSync(0, 'utf8');

const nav = html.match(/<div class="tabs[^"]*" id="repo-tabs">\s*<nav role="tablist"[^>]*>([\s\S]*?)<\/nav>/);
assert.ok(nav, 'rendered repository tablist');
const link = html.match(/<a href="\/repositories\/\d+(#[^"]+)"[^>]*>View in Findings<\/a>/);
assert.ok(link, 'rendered View in Findings link');

function element(attrs) {
  return {
    attrs,
    getAttribute: name => (name in attrs ? attrs[name] : null),
    setAttribute: (name, value) => { attrs[name] = String(value); },
    hasAttribute: name => name in attrs,
    get id() { return attrs.id || ''; },
    get hidden() { return 'hidden' in attrs; },
    set hidden(v) { if (v) attrs.hidden = ''; else delete attrs.hidden; },
    closest: () => null,
  };
}

const byId = {};
const tablist = element({role: 'tablist'});
tablist.parentIsTabs = true;
const tabs = [...nav[1].matchAll(/<button type="button" role="tab" id="([^"]+)" aria-controls="([^"]+)" aria-selected="([^"]+)">/g)]
  .map(m => element({role: 'tab', id: m[1], 'aria-controls': m[2], 'aria-selected': m[3]}));
for (const t of tabs) {
  t.closest = sel => (sel === '[role="tablist"]' ? tablist : null);
  byId[t.id] = t;
}
tablist.querySelectorAll = sel => (sel === '[role="tab"]' ? tabs : []);
tablist.querySelector = sel => (sel === '[role="tab"][aria-selected="true"]' ? tabs.find(t => t.attrs['aria-selected'] === 'true') || null : null);
for (const m of html.matchAll(/<div role="tabpanel" id="([^"]+)"[^>]*?( hidden)?>/g)) {
  const attrs = {role: 'tabpanel', id: m[1]};
  if (m[2]) attrs.hidden = '';
  byId[m[1]] = element(attrs);
}

const listeners = {document: {}, window: {}};
const on = target => (type, fn) => { (listeners[target][type] ||= []).push(fn); };
const fire = (target, type, event) => (listeners[target][type] || []).forEach(fn => fn(event || {}));
const location = {hash: ''};
const document = {
  readyState: 'complete',
  body: {addEventListener: () => {}},
  getElementById: id => byId[id] || null,
  querySelector: () => null,
  querySelectorAll: sel => {
    if (sel === '.tabs > [role="tablist"]:not([data-default-tab])') return tablist.hasAttribute('data-default-tab') ? [] : [tablist];
    if (sel === '[role="tablist"][data-default-tab]') return tablist.hasAttribute('data-default-tab') ? [tablist] : [];
    return [];
  },
  addEventListener: on('document'),
};
const window = {addEventListener: on('window'), innerWidth: 1280};
const history = {replaceState: (s, t, url) => { location.hash = url; }};
const context = {
  document, window, location, history,
  setInterval: () => 0, setTimeout: () => 0, requestAnimationFrame: () => 0,
  MutationObserver: function () { this.observe = () => {}; },
  CustomEvent: function (type, init) { this.type = type; this.detail = init && init.detail; },
};
vm.runInNewContext(script, context, {timeout: 1000});

const selected = () => tabs.filter(t => t.attrs['aria-selected'] === 'true').map(t => t.id);
const shown = () => tabs.filter(t => !byId[t.attrs['aria-controls']].hidden).map(t => t.id);
const target = link[1].slice(1);

assert.deepEqual(selected(), ['rt1'], 'Summary is selected on load');

// Following a same-page fragment link sets the hash and fires hashchange.
fire('document', 'click', {target: element({})});
location.hash = link[1];
fire('window', 'hashchange');
assert.deepEqual(selected(), [target], 'View in Findings selects the Findings tab');
assert.deepEqual(shown(), [target], 'View in Findings shows only the Findings panel');

location.hash = '';
fire('window', 'hashchange');
assert.deepEqual(selected(), ['rt1'], 'Back to the bare URL selects Summary again');
assert.deepEqual(shown(), ['rt1'], 'Back to the bare URL shows only the Summary panel');
