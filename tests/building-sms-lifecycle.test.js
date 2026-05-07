'use strict';
/**
 * Sandbox test for the building → Azure SMS-number lifecycle.
 *
 * Covers the client-side glue that gets a local SMS number assigned to a
 * facility when it's created and released when the facility is deactivated.
 * The actual ACS provisioning is server-side and stubbed via fetch.
 *
 * Verifies:
 *   - _zipToAreaCode maps known ZIPs to area codes
 *   - _autoProvisionBuildingSMS POSTs to /api/buildings/:id/provision-sms
 *     with the right shape and writes smsFromPhone into state on success
 *   - deactivateBuilding releases the SMS number AND marks inactive
 *   - if the SMS release fails, the building stays active (no dangling number)
 *   - reactivateBuilding clears the inactive flag and re-provisions
 *   - _sendSMS includes buildingId in the payload so the server picks the
 *     right FROM number
 *
 * Run with: node --test --test-concurrency=1 tests/building-sms-lifecycle.test.js
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

function buildSandbox(opts) {
  const _store = {};
  const localStorage = {
    getItem: k => (k in _store ? _store[k] : null),
    setItem: (k, v) => { _store[k] = String(v); },
    removeItem: k => { delete _store[k]; },
  };
  const fakeEl = () => ({
    style:{}, classList:{ add(){}, remove(){}, toggle(){}, contains:()=>false },
    setAttribute(){}, removeAttribute(){}, getAttribute:()=>null,
    appendChild(){}, removeChild(){}, querySelector:()=>null, querySelectorAll:()=>[],
    addEventListener(){}, removeEventListener(){}, click(){}, focus(){}, blur(){},
    innerHTML:'', textContent:'', value:'', checked:false, disabled:false,
    children:[], parentNode:null, dataset:{}, remove(){},
  });
  const document = {
    getElementById: () => fakeEl(),
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: () => fakeEl(),
    body: { appendChild(){}, removeChild(){} }, head: fakeEl(),
    addEventListener: () => {},
    documentElement: { setAttribute(){}, style:{} },
    cookie: '',
  };
  const fetchLog = [];
  const fetchHandler = opts && opts.fetchHandler;
  // Wrap setTimeout/setInterval so timers from the script's init code (auth
  // ping, notification polling, etc.) don't keep the test runner's event
  // loop alive past the actual test work.
  const wrapTimer = (fn) => (...args) => {
    const t = fn(...args);
    if (t && t.unref) t.unref();
    return t;
  };
  const ctx = {
    document, localStorage,
    // Important: hostname:'sandbox-app' so IS_SERVER_MODE in the script is true
    location: { protocol:'http:', hostname:'sandbox-app', href:'http://sandbox-app/', pathname:'/' },
    setTimeout: wrapTimer(setTimeout), clearTimeout,
    setInterval: wrapTimer(setInterval), clearInterval,
    confirm: () => true, alert: () => {}, prompt: () => '405',  // for areaCode prompt
    crypto: { getRandomValues: arr => { for (let i=0;i<arr.length;i++) arr[i]=0; return arr; } },
    fetch: async (url, opt) => {
      const entry = { url, opts: opt || {} };
      try { entry.body = opt && opt.body ? JSON.parse(opt.body) : null; } catch (_) {}
      fetchLog.push(entry);
      if (fetchHandler) return fetchHandler(url, opt, entry);
      return { ok:false, status:0, json: async () => ({}) };
    },
    URL: { createObjectURL: () => 'blob:s', revokeObjectURL(){} },
    URLSearchParams: globalThis.URLSearchParams || function(){ return { get:()=>null, set(){}, toString:()=>'' }; },
    TextEncoder: globalThis.TextEncoder, TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob, btoa: globalThis.btoa,
    // Required by the script's fetch interceptor IIFE — without these the
    // wrapper throws synchronously inside `new Headers(...)` and every
    // /api/* call is silently swallowed by the calling function's catch.
    Headers: globalThis.Headers,
    Request: globalThis.Request,
    Response: globalThis.Response,
    console,
    Blob: function(){ this.size=0; },
    navigator: { userAgent:'sandbox' },
    history: { pushState(){}, replaceState(){} },
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    cancelAnimationFrame: clearTimeout,
    performance: { now: () => Date.now() },
    _fetchLog: fetchLog,
  };
  ctx.window = ctx; ctx.globalThis = ctx; ctx.self = ctx;
  return { sandbox: vm.createContext(ctx), fetchLog };
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('_zipToAreaCode maps known prefixes', () => {
  const { sandbox } = buildSandbox();
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  // Texas: ZIP 75201 → 750 → 214 (Dallas)
  assert.equal(App._zipToAreaCode('75201'), '214');
  // Iowa: ZIP 50314 → 503 → 641
  assert.equal(App._zipToAreaCode('50314'), '641');
  // Oklahoma: ZIP 73044 → 730 → 405
  assert.equal(App._zipToAreaCode('73044'), '405');
  // Unknown ZIP returns null
  assert.equal(App._zipToAreaCode('99999'), null);
  assert.equal(App._zipToAreaCode(''), null);
});

test('_autoProvisionBuildingSMS POSTs to /api/buildings/:id/provision-sms with correct shape', async () => {
  const { sandbox, fetchLog } = buildSandbox({
    fetchHandler: async (url) => {
      if (url.includes('/provision-sms')) {
        return { ok: true, status: 200, json: async () => ({
          phoneNumber: '+12145550123', smsFromPhoneSid: 'sid_test_001',
        }) };
      }
      if (url.includes('/api/data')) {
        return { ok: true, status: 200, json: async () => ({}), headers: { get: () => null } };
      }
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.persistData = () => {}; App.renderMain = () => {}; App.renderSidebar = () => {};
  App.showToast = () => {}; App.render = () => {};

  App.S.user = { id:'u', role:'superadmin', buildingId:'b1' };
  App.S.buildings = [{ id:'b_new', name:'Test Facility', zip:'75201', state:'TX' }];

  fetchLog.length = 0;
  await App._autoProvisionBuildingSMS('b_new');

  // Should have hit the provision endpoint exactly once + /api/data refresh
  const prov = fetchLog.find(e => e.url.includes('/provision-sms'));
  assert.ok(prov, 'should call /provision-sms');
  assert.equal(prov.opts.method, 'POST');
  assert.equal(prov.body.autoProvision, true);
  assert.equal(prov.body.areaCode, '214', 'derived 214 from ZIP 75201');
  assert.equal(prov.body.source, 'azure-acs');
  assert.equal(prov.body.purpose, 'building-create');
});

test('deactivateBuilding marks inactive AND calls release endpoint', async () => {
  const releaseCalls = [];
  const { sandbox, fetchLog } = buildSandbox({
    fetchHandler: async (url, opt) => {
      if (url.includes('/provision-sms') && opt?.method === 'DELETE') {
        releaseCalls.push(url);
        return { ok: true, status: 200, json: async () => ({ released: true }) };
      }
      if (url.includes('/api/data')) {
        return { ok: true, json: async () => ({}), headers: { get: () => null } };
      }
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.persistData = () => {}; App.renderMain = () => {}; App.render = () => {};
  App.showToast = () => {};

  App.S.user = { id:'u', role:'superadmin' };
  App.S.buildings = [{
    id:'b_active', name:'Sunrise SNF', state:'TX', zip:'75201',
    smsFromPhone: '+12145550123', smsFromPhoneSid:'sid_001',
    inactive: false,
  }];
  App.S.employees = [];

  await App.deactivateBuilding('b_active');

  const b = App.S.buildings.find(x => x.id === 'b_active');
  assert.equal(b.inactive, true,         'should be marked inactive');
  assert.ok(b.deactivatedAt,             'should record deactivatedAt');
  assert.equal(b.smsFromPhone, undefined, 'smsFromPhone should be cleared');
  assert.equal(b.smsFromPhoneSid, undefined, 'sid should be cleared');
  assert.equal(releaseCalls.length, 1,   'should call release endpoint exactly once');
  assert.ok(releaseCalls[0].includes('/api/buildings/b_active/provision-sms'));
});

test('deactivateBuilding aborts when SMS release fails', async () => {
  const { sandbox } = buildSandbox({
    fetchHandler: async (url, opt) => {
      if (url.includes('/provision-sms') && opt?.method === 'DELETE') {
        return { ok: false, status: 500, json: async () => ({ error: 'ACS error' }) };
      }
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.persistData = () => {}; App.renderMain = () => {}; App.render = () => {};
  App.showToast = () => {};

  App.S.user = { id:'u', role:'superadmin' };
  App.S.buildings = [{ id:'b_x', name:'X', smsFromPhone:'+12145550000', inactive:false }];
  App.S.employees = [];

  await App.deactivateBuilding('b_x');
  const b = App.S.buildings.find(x => x.id === 'b_x');
  assert.equal(b.inactive, false, 'should remain active when release failed');
  assert.equal(b.smsFromPhone, '+12145550000', 'number should still be on the building');
});

test('deactivateBuilding skips SMS release if no number was provisioned', async () => {
  const calls = [];
  const { sandbox } = buildSandbox({
    fetchHandler: async (url, opt) => {
      calls.push({ url, method: opt?.method });
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.persistData = () => {}; App.renderMain = () => {}; App.render = () => {};
  App.showToast = () => {};

  App.S.user = { id:'u', role:'superadmin' };
  App.S.buildings = [{ id:'b_nosms', name:'NoSms', inactive:false }]; // no smsFromPhone
  App.S.employees = [];

  await App.deactivateBuilding('b_nosms');
  const b = App.S.buildings.find(x => x.id === 'b_nosms');
  assert.equal(b.inactive, true);
  // No release call should have been issued
  assert.equal(calls.filter(c => c.method === 'DELETE').length, 0);
});

test('reactivateBuilding clears inactive flag and triggers re-provision', async () => {
  const fetchedUrls = [];
  const { sandbox } = buildSandbox({
    fetchHandler: async (url, opt) => {
      fetchedUrls.push({ url, method: opt?.method, body: opt?.body });
      if (url.includes('/provision-sms') && opt?.method === 'POST') {
        return { ok: true, status: 200, json: async () => ({ phoneNumber: '+12145550999' }) };
      }
      if (url.includes('/api/data')) {
        return { ok: true, json: async () => ({}), headers: { get: () => null } };
      }
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.persistData = () => {}; App.renderMain = () => {}; App.render = () => {};
  App.showToast = () => {};

  App.S.user = { id:'u', role:'superadmin' };
  App.S.buildings = [{
    id:'b_old', name:'Old', state:'TX', zip:'75201',
    inactive:true, deactivatedAt:'2026-01-01T00:00:00Z',
  }];

  await App.reactivateBuilding('b_old');

  const b = App.S.buildings.find(x => x.id === 'b_old');
  assert.equal(b.inactive, false);
  assert.equal(b.deactivatedAt, undefined);

  const provCall = fetchedUrls.find(c => c.url.includes('/provision-sms') && c.method === 'POST');
  assert.ok(provCall, 'should fire a re-provision POST');
});

test('_sendSMS includes buildingId in request body', async () => {
  const { sandbox, fetchLog } = buildSandbox({
    fetchHandler: async (url) => {
      if (url === '/api/sms') return { ok: true, status: 200, json: async () => ({}) };
      return { ok: false, json: async () => ({}) };
    },
  });
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.showToast = () => {};
  App.S.activeBuildingId = 'b_caller';
  App.S.user = { id:'u', role:'admin', buildingId:'b_user' };

  // 1) Default building = activeBuildingId
  fetchLog.length = 0;
  await App._sendSMS('+15555550100', 'Hello');
  const call1 = fetchLog.find(e => e.url === '/api/sms');
  assert.ok(call1);
  assert.equal(call1.body.buildingId, 'b_caller');
  assert.equal(call1.body.to, '+15555550100');
  assert.equal(call1.body.message, 'Hello');

  // 2) Explicit override via opts.buildingId
  fetchLog.length = 0;
  await App._sendSMS('+15555550100', 'Hi', { buildingId: 'b_override' });
  const call2 = fetchLog.find(e => e.url === '/api/sms');
  assert.equal(call2.body.buildingId, 'b_override');

  // 3) When no active building, falls back to user.buildingId
  App.S.activeBuildingId = null;
  fetchLog.length = 0;
  await App._sendSMS('+15555550100', 'Yo');
  const call3 = fetchLog.find(e => e.url === '/api/sms');
  assert.equal(call3.body.buildingId, 'b_user');
});

test('_autoProvisionBuildingSMS is a no-op in local/file mode', async () => {
  // Build a sandbox where IS_SERVER_MODE evaluates to false (file:// scheme)
  const { sandbox, fetchLog } = buildSandbox();
  // Override location BEFORE script runs: file:// + empty hostname → IS_SERVER_MODE=false
  sandbox.location.protocol = 'file:';
  sandbox.location.hostname = '';
  vm.runInContext(mainScript, sandbox, { filename: 'inline.js' });
  const App = sandbox.App;
  App.showToast = () => {};

  App.S.user = { id:'u', role:'superadmin' };
  App.S.buildings = [{ id:'b1', name:'B1', zip:'75201' }];

  fetchLog.length = 0;
  await App._autoProvisionBuildingSMS('b1');
  // Should not have hit the provisioning endpoint at all
  const prov = fetchLog.find(e => e.url.includes('/provision-sms'));
  assert.equal(prov, undefined, 'no provision call in local mode');
});
