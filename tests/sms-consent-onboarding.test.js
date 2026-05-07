'use strict';
/**
 * Sandbox tests for the locked SMS-consent onboarding step.
 *
 * Verifies:
 *   - SMS consent step is auto-appended to every onboarding package
 *   - The step is always last and always locked
 *   - Idempotent — re-running ensure does not duplicate
 *   - Existing customizations are preserved (other steps unchanged)
 *   - Locked step cannot be moved, removed, or reordered through
 *     moveHRStep / removeHRStep
 *
 * Run with: node --test --test-concurrency=1 tests/sms-consent-onboarding.test.js
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const html = fs.readFileSync(path.join(__dirname, '..', 'managemystaffing.html'), 'utf8');
const blocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/g) || [];
const mainBlock = blocks.reduce((a, b) => a.length > b.length ? a : b);
const mainScript = mainBlock.replace(/^<script[^>]*>/, '').replace(/<\/script>$/, '');

function buildSandbox() {
  const _store = {};
  const fakeEl = () => ({
    style:{}, classList:{ add(){}, remove(){}, toggle(){}, contains:()=>false },
    setAttribute(){}, removeAttribute(){}, getAttribute:()=>null,
    appendChild(){}, removeChild(){}, querySelector:()=>null, querySelectorAll:()=>[],
    addEventListener(){}, removeEventListener(){}, click(){}, focus(){}, blur(){},
    innerHTML:'', textContent:'', value:'', checked:false, disabled:false,
    children:[], parentNode:null, dataset:{}, remove(){},
  });
  const wrapTimer = (fn) => (...args) => { const t = fn(...args); if (t && t.unref) t.unref(); return t; };
  const ctx = {
    document: {
      getElementById: () => fakeEl(),
      querySelector: () => fakeEl(),
      querySelectorAll: () => [],
      createElement: () => fakeEl(),
      body: fakeEl(), head: fakeEl(),
      addEventListener: () => {},
      documentElement: { setAttribute(){}, style:{} },
      cookie: '',
    },
    localStorage: {
      getItem: k => (k in _store ? _store[k] : null),
      setItem: (k, v) => { _store[k] = String(v); },
      removeItem: k => { delete _store[k]; },
    },
    location: { protocol:'http:', hostname:'sandbox', href:'http://sandbox/', pathname:'/' },
    setTimeout: wrapTimer(setTimeout), clearTimeout,
    setInterval: wrapTimer(setInterval), clearInterval,
    confirm: () => true, alert: () => {}, prompt: () => null,
    crypto: { getRandomValues: arr => { for (let i=0;i<arr.length;i++) arr[i]=0; return arr; } },
    fetch: async () => ({ ok:false, json: async () => ({}) }),
    URL: { createObjectURL: () => 'blob:s', revokeObjectURL(){} },
    URLSearchParams: globalThis.URLSearchParams,
    TextEncoder: globalThis.TextEncoder, TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob, btoa: globalThis.btoa,
    Headers: globalThis.Headers, Request: globalThis.Request, Response: globalThis.Response,
    console,
    Blob: function(){ this.size=0; },
    navigator: { userAgent:'sandbox' },
    history: { pushState(){}, replaceState(){} },
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    cancelAnimationFrame: clearTimeout,
    performance: { now: () => Date.now() },
  };
  ctx.window = ctx; ctx.globalThis = ctx; ctx.self = ctx;
  return vm.createContext(ctx);
}

const sandbox = buildSandbox();
vm.runInContext(mainScript, sandbox, { filename: 'managemystaffing.inline.js' });
const App = sandbox.App;

App.persistData = () => {};
App.renderMain = () => {};
App.renderHRMain = () => {};
App.showToast = () => {};

// ── Tests ──────────────────────────────────────────────────────────────────

test('seed onboarding packages have SMS consent as final locked step', () => {
  // Top-level consts are not on the sandbox global; evaluate inside vm
  const tx = vm.runInContext("SEED_HR_ONBOARDING.co_skyblue.TX", sandbox);
  const ok = vm.runInContext("SEED_HR_ONBOARDING.co_skyblue.OK", sandbox);
  const txLast = tx.steps[tx.steps.length - 1];
  const okLast = ok.steps[ok.steps.length - 1];
  assert.equal(txLast.id, '__sms_consent__');
  assert.equal(txLast.type, 'sms_consent');
  assert.equal(txLast.locked, true);
  assert.equal(okLast.id, '__sms_consent__');
  assert.equal(okLast.type, 'sms_consent');
  assert.equal(okLast.locked, true);
});

test('SMS_CONSENT_STEP_ID and SMS_CONSENT_STEP constants are defined', () => {
  assert.equal(vm.runInContext('SMS_CONSENT_STEP_ID', sandbox), '__sms_consent__');
  assert.equal(typeof vm.runInContext('SMS_CONSENT_STEP', sandbox), 'object');
  assert.equal(vm.runInContext('SMS_CONSENT_STEP.locked', sandbox), true);
  assert.equal(vm.runInContext('SMS_CONSENT_STEP.type', sandbox), 'sms_consent');
});

test('_ensureSmsConsentStep appends step to packages missing it', () => {
  const pkg = { name:'Custom', steps:[
    { id:'a1', type:'form', title:'Application' },
    { id:'a2', type:'form', title:'I-9' },
  ]};
  App._ensureSmsConsentStep(pkg);
  assert.equal(pkg.steps.length, 3);
  assert.equal(pkg.steps[2].id, '__sms_consent__');
  assert.equal(pkg.steps[2].locked, true);
});

test('_ensureSmsConsentStep is idempotent (does not duplicate)', () => {
  const pkg = { name:'Custom', steps:[
    { id:'a1', type:'form', title:'Application' },
    { id:'__sms_consent__', type:'sms_consent', title:'SMS Consent', locked:true },
  ]};
  App._ensureSmsConsentStep(pkg);
  App._ensureSmsConsentStep(pkg);
  App._ensureSmsConsentStep(pkg);
  assert.equal(pkg.steps.length, 2);  // didn't duplicate
  assert.equal(pkg.steps[1].id, '__sms_consent__');
});

test('_ensureSmsConsentStep moves consent step to end if it got reordered', () => {
  const pkg = { name:'Custom', steps:[
    { id:'__sms_consent__', type:'sms_consent', title:'SMS Consent', locked:true },
    { id:'a1', type:'form', title:'Application' },
    { id:'a2', type:'form', title:'I-9' },
  ]};
  App._ensureSmsConsentStep(pkg);
  assert.equal(pkg.steps.length, 3);
  assert.equal(pkg.steps[2].id, '__sms_consent__');  // moved to end
  assert.equal(pkg.steps[0].id, 'a1');
});

test('_ensureSmsConsentStep restores locked flag if customer cleared it', () => {
  const pkg = { name:'Custom', steps:[
    { id:'__sms_consent__', type:'sms_consent', title:'SMS Consent', locked:false },
  ]};
  App._ensureSmsConsentStep(pkg);
  assert.equal(pkg.steps[0].locked, true);
  assert.equal(pkg.steps[0].required, true);
});

test('moveHRStep refuses to move a locked step', () => {
  // Set up state with custom package
  App.S.user = { id:'u', role:'superadmin' };
  App.S.activeCompanyId = 'co_test';
  App.S.hrOnboarding = {
    co_test: {
      TX: { name:'Test', steps:[
        { id:'a1', type:'form', title:'A' },
        { id:'a2', type:'form', title:'B' },
        { id:'__sms_consent__', type:'sms_consent', title:'SMS', locked:true, required:true },
      ]}
    }
  };
  // Try to move locked step up
  let warned = false;
  const origToast = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn') warned = true; };
  App.moveHRStep('TX', 2, -1);  // try to move SMS consent up
  App.showToast = origToast;
  // Step 2 is still SMS consent
  assert.equal(App.S.hrOnboarding.co_test.TX.steps[2].id, '__sms_consent__');
  assert.equal(warned, true);
});

test('moveHRStep refuses to move a regular step into a locked slot', () => {
  // Try to move step idx 1 down into locked slot at idx 2
  let warned = false;
  const origToast = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn') warned = true; };
  App.moveHRStep('TX', 1, 1);
  App.showToast = origToast;
  // Order should be unchanged
  const steps = App.S.hrOnboarding.co_test.TX.steps;
  assert.equal(steps[1].id, 'a2');
  assert.equal(steps[2].id, '__sms_consent__');
  assert.equal(warned, true);
});

test('removeHRStep refuses to delete a locked step', () => {
  let warned = false;
  const origToast = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn') warned = true; };
  App.removeHRStep('TX', 2);  // try to remove SMS consent
  App.showToast = origToast;
  const steps = App.S.hrOnboarding.co_test.TX.steps;
  assert.equal(steps.length, 3);  // still there
  assert.equal(steps[2].id, '__sms_consent__');
  assert.equal(warned, true);
});

test('removeHRStep DOES delete an unlocked step', () => {
  // Confirm the abort guard isn't blanket-blocking removeHRStep
  App.removeHRStep('TX', 0);  // remove 'a1' (unlocked)
  const steps = App.S.hrOnboarding.co_test.TX.steps;
  assert.equal(steps.length, 2);
  assert.equal(steps[0].id, 'a2');
  assert.equal(steps[1].id, '__sms_consent__');
});

test('moveHRStep DOES move regular steps among unlocked slots', () => {
  // Add a third unlocked step, then move it
  App.S.hrOnboarding.co_test.TX.steps.unshift({ id:'a0', type:'form', title:'Zero' });
  // Steps: [a0, a2, __sms_consent__]
  App.moveHRStep('TX', 0, 1);  // a0 → a2 swap
  const steps = App.S.hrOnboarding.co_test.TX.steps;
  assert.equal(steps[0].id, 'a2');
  assert.equal(steps[1].id, 'a0');
  assert.equal(steps[2].id, '__sms_consent__');  // still locked at end
});
