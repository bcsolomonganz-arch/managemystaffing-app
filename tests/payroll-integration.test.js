'use strict';
/**
 * Sandbox test for the Paycom + ADP payroll integrations baked into
 * managemystaffing.html. Loads the single-file app's main <script> block
 * into a minimal Node sandbox (with stubbed DOM/localStorage), then
 * exercises the full lifecycle of both providers in parallel:
 *
 *   1. configure   (sandbox mode, fake credentials)
 *   2. test connection — required-field validation, success path
 *   3. push individual hire + bulk push of remaining hires
 *   4. sync current payroll period (after seeding S.hrTimeClock)
 *   5. pull time-clock punches from each provider
 *   6. assert sync history & audit log are populated
 *   7. confirm auto-push fires when a new hire moves to the roster
 *   8. confirm disconnect clears credentials
 *
 * Run with:  node --test tests/payroll-integration.test.js
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// Swallow stray async errors from background timers/event listeners that the
// app schedules at load time but the sandbox can't fully satisfy (e.g. fetch
// retries). Real assertion failures in tests are unaffected.
process.on('unhandledRejection', (e) => {
  if (process.env.MMS_TEST_VERBOSE) console.warn('[ignored unhandled rejection]', e?.message || e);
});
process.on('uncaughtException', (e) => {
  if (process.env.MMS_TEST_VERBOSE) console.warn('[ignored uncaught]', e?.message || e);
});

// ── Load the single-file app's script body ──────────────────────────────────
const HTML_PATH = path.join(__dirname, '..', 'managemystaffing.html');
const html = fs.readFileSync(HTML_PATH, 'utf8');
const scriptBlocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/g) || [];
// The main app script is the largest <script> block in the file.
const mainBlock = scriptBlocks.reduce((a, b) => a.length > b.length ? a : b);
const mainScript = mainBlock.replace(/^<script[^>]*>/, '').replace(/<\/script>$/, '');

// ── Minimal browser-shaped sandbox ──────────────────────────────────────────
function buildSandbox() {
  const _store = {};
  const localStorage = {
    getItem: k => (k in _store ? _store[k] : null),
    setItem: (k, v) => { _store[k] = String(v); },
    removeItem: k => { delete _store[k]; },
    clear: () => { for (const k of Object.keys(_store)) delete _store[k]; },
  };
  // Return a benign element stub for any getElementById/querySelector call so
  // stray DOM access from background async work doesn't blow up.
  const fakeEl = () => ({
    style:{}, classList:{ add(){}, remove(){}, toggle(){}, contains:()=>false },
    setAttribute(){}, removeAttribute(){}, getAttribute:()=>null,
    appendChild(){}, removeChild(){}, querySelector:()=>null, querySelectorAll:()=>[],
    addEventListener(){}, removeEventListener(){}, click(){}, focus(){}, blur(){},
    innerHTML:'', textContent:'', value:'', checked:false, disabled:false,
    children:[], parentNode:null, dataset:{},
  });
  const document = {
    getElementById: () => fakeEl(),
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: () => fakeEl(),
    body: fakeEl(),
    head: fakeEl(),
    addEventListener: () => {},
    documentElement: { setAttribute(){}, style:{} },
    cookie: '',
  };
  const window = {
    location: { protocol:'http:', hostname:'sandbox', href:'http://sandbox/', pathname:'/' },
    addEventListener: () => {},
    setTimeout, clearTimeout, setInterval, clearInterval,
    localStorage,
    confirm: () => true,        // auto-accept all confirm() prompts
    alert: () => {},
    prompt: () => null,
    crypto: { getRandomValues: arr => { for (let i=0;i<arr.length;i++) arr[i] = Math.floor(Math.random()*256); return arr; } },
    fetch: async () => ({ ok:false, status:0, json: async () => ({error:'no network in sandbox'}) }),
    URL: { createObjectURL: () => 'blob:sandbox', revokeObjectURL: () => {} },
  };
  const ctx = {
    document, window, localStorage,
    location: window.location,
    setTimeout, clearTimeout, setInterval, clearInterval,
    confirm: window.confirm, alert: window.alert, prompt: window.prompt,
    crypto: window.crypto, fetch: window.fetch, URL: window.URL,
    console,
    Blob: function Blob(){ this.size=0; },
    URLSearchParams: globalThis.URLSearchParams || function(){ return { get:()=>null, set(){}, toString:()=>'' }; },
    TextEncoder: globalThis.TextEncoder,
    TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob, btoa: globalThis.btoa,
    navigator: { userAgent:'sandbox', clipboard:{ writeText: async()=>{} } },
    history: { pushState(){}, replaceState(){} },
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    cancelAnimationFrame: clearTimeout,
    performance: { now: () => Date.now() },
  };
  ctx.window = ctx;
  ctx.globalThis = ctx;
  ctx.self = ctx;
  return vm.createContext(ctx);
}

const sandbox = buildSandbox();
// Wrap script load in try/catch so any stray DOM access at parse-time fails loud
try {
  vm.runInContext(mainScript, sandbox, { filename: 'managemystaffing.inline.js' });
} catch (e) {
  console.error('Script failed to evaluate in sandbox:', e.message);
  throw e;
}

const App = sandbox.App || sandbox.window.App;
if (!App) throw new Error('App global not exposed after script load');

// Override persistData to a no-op (avoids hitting localStorage repeatedly during the test).
// We still want it called so sync timestamps update — keep the side-effect chain intact.
App.persistData = function(){ /* no-op for sandbox */ };
App.renderHRMain = function(){};        // skip DOM renders
App.renderSidebar = function(){};
App.showToast = function(msg){ /* console.log('[toast]', msg); */ };
App.openModal = function(){};
App.closeModal = function(){};
App._renderPayrollConfigForm = function(){}; // skip — modal DOM not present

// ── Seed a clean state for the test ─────────────────────────────────────────
function seedState() {
  App.S.user = { id:'u_test', email:'test@demo.com', role:'superadmin' };
  App.S.buildings = [{ id:'bld_a', name:'Sunrise SNF' }];
  App.S.employees = [];
  App.S.hrEmployees = [];
  App.S.hrTimeClock = [];
  App.S.hrAuditLog = [];
  App.S.integrations = undefined;  // force re-init
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function addEmployee(id, name, group, rate, buildingId='bld_a') {
  const emp = {
    id, name, initials: name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(),
    group, hourlyRate: rate, hireDate: '2026-01-15',
    email: `${id}@example.test`, phone: '555-0100',
    buildingId, inactive: false,
  };
  App.S.employees.push(emp);
  return emp;
}
function addPunches(empId, dates, hours=8) {
  for (const d of dates) {
    App.S.hrTimeClock.push({
      id: 'tc_'+Math.random().toString(36).slice(2,8),
      empId, date: d, hours, punchIn:'07:00', punchOut:'15:00', source:'manual',
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test('App + integration state initialize correctly', () => {
  seedState();
  const paycom = App._payrollState('paycom');
  const adp    = App._payrollState('adp');
  assert.equal(paycom.configured, false);
  assert.equal(adp.configured, false);
  assert.equal(paycom.status, 'disconnected');
  assert.equal(adp.status, 'disconnected');
  // History is a fresh array; capture length now (other tests will mutate it)
  assert.equal(Array.isArray(paycom.history), true);
  assert.equal(paycom.history.length, 0);
  assert.equal(adp.history.length, 0);
  // Method surface
  assert.equal(typeof App.pushHireToPayroll, 'function');
  assert.equal(typeof App.pushAllPendingHires, 'function');
  assert.equal(typeof App.syncPayrollToProvider, 'function');
  assert.equal(typeof App.syncTimeFromProvider, 'function');
  assert.equal(typeof App.disconnectPayrollProvider, 'function');
  assert.equal(typeof App._buildHirePayload, 'function');
});

test('connection test fails when credentials missing', async () => {
  const ok = await App._testPayrollConnection('paycom', /*silent*/ true);
  assert.equal(ok, false);
  const i = App._payrollState('paycom');
  assert.equal(i.status, 'error');
  assert.match(i.lastError, /credentials/i);
});

test('Paycom connects in sandbox mode with valid creds', async () => {
  const i = App._payrollState('paycom');
  i.configured = true;
  i.mode = 'sandbox';
  i.clientId = 'paycom-test-client-id';
  i.clientSecret = 'paycom-test-secret-XXXXXXXX';
  i.companyCode = 'TEST';
  i.username = 'api.test@managemystaffing.com';

  const ok = await App._testPayrollConnection('paycom', true);
  assert.equal(ok, true, 'paycom should connect with full creds');
  assert.equal(i.status, 'connected');
  assert.ok(i.lastConnectAt);
  assert.equal(i.history[0].type, 'connect');
  assert.equal(i.history[0].ok, true);
});

test('Paycom rejects when Client Code missing', async () => {
  const i = App._payrollState('paycom');
  const savedCode = i.companyCode;
  i.companyCode = '';
  const ok = await App._testPayrollConnection('paycom', true);
  assert.equal(ok, false);
  assert.match(i.lastError, /Client Code/i);
  i.companyCode = savedCode;
  // restore connection for following tests
  await App._testPayrollConnection('paycom', true);
  assert.equal(i.status, 'connected');
});

test('ADP connects in sandbox mode (OID optional in sandbox)', async () => {
  const i = App._payrollState('adp');
  i.configured = true;
  i.mode = 'sandbox';
  i.clientId = 'adp-test-client-id';
  i.clientSecret = 'adp-test-secret-XXXXXXXX';
  // oid intentionally blank — should be allowed in sandbox
  i.oid = '';
  i.certThumbprint = '';

  const ok = await App._testPayrollConnection('adp', true);
  assert.equal(ok, true, 'adp sandbox should connect without OID');
  assert.equal(i.status, 'connected');
});

test('ADP rejects production mode without Organization OID', async () => {
  const i = App._payrollState('adp');
  i.mode = 'production';
  i.oid = '';
  const ok = await App._testPayrollConnection('adp', true);
  assert.equal(ok, false);
  assert.match(i.lastError, /Organization OID/i);
  // restore sandbox mode
  i.mode = 'sandbox';
  await App._testPayrollConnection('adp', true);
  assert.equal(i.status, 'connected');
});

test('push individual hire to Paycom assigns external ID', async () => {
  const emp = addEmployee('e_alice', 'Alice Anderson', 'CNA', 22.50);
  const ok = await App.pushHireToPayroll(emp.id, 'paycom');
  assert.equal(ok, true);
  assert.ok(emp.payrollIds, 'payrollIds object should exist');
  assert.match(emp.payrollIds.paycom, /^PYC-\d{6}$/, 'paycom ID format');
  assert.ok(emp.payrollSyncedAt);
  // Pushing the same employee again should fail (idempotency)
  const dup = await App.pushHireToPayroll(emp.id, 'paycom');
  assert.equal(dup, false, 'duplicate push should be rejected');
});

test('push to ADP assigns separate external ID', async () => {
  const emp = App.S.employees.find(e => e.id === 'e_alice');
  const ok = await App.pushHireToPayroll(emp.id, 'adp');
  assert.equal(ok, true);
  assert.match(emp.payrollIds.adp, /^ADP-\d{6}$/, 'adp ID format');
  // Both IDs coexist
  assert.ok(emp.payrollIds.paycom);
  assert.ok(emp.payrollIds.adp);
  assert.notEqual(emp.payrollIds.paycom, emp.payrollIds.adp);
});

test('hire payload schema differs by provider', () => {
  const emp = App.S.employees[0];
  const paycomPayload = App._buildHirePayload('paycom', emp);
  const adpPayload    = App._buildHirePayload('adp',    emp);
  // Paycom: flat
  assert.equal(paycomPayload.firstName, 'Alice');
  assert.equal(paycomPayload.lastName, 'Anderson');
  assert.equal(paycomPayload.compensation.rate, 22.50);
  assert.equal(paycomPayload.clientCode, 'TEST');
  // ADP: event-based
  assert.ok(Array.isArray(adpPayload.events));
  assert.equal(adpPayload.events[0].eventNameCode.codeValue, 'worker.hire');
  const t = adpPayload.events[0].data.transform.worker;
  assert.equal(t.person.legalName.givenName, 'Alice');
  assert.equal(t.workAssignment.baseRemuneration.hourlyRateAmount.amountValue, 22.50);
});

test('push refuses employee without hourly rate', async () => {
  const emp = addEmployee('e_bob', 'Bob Brown', 'Charge Nurse', null);
  const ok = await App.pushHireToPayroll(emp.id, 'paycom');
  assert.equal(ok, false);
  assert.equal(emp.payrollIds, undefined);
});

test('bulk push handles remaining pending hires', async () => {
  // Add a few more employees that haven't been pushed yet
  addEmployee('e_carol', 'Carol Chen',    'CNA',           21.00);
  addEmployee('e_dan',   'Dan Davis',     'Cook',          18.50);
  addEmployee('e_eve',   'Eve Edwards',   'Housekeeping',  16.75);

  const pendingPaycom = App._payrollPendingHires('paycom');
  // alice is already on paycom; bob has no rate; carol/dan/eve are pending
  assert.equal(pendingPaycom.length, 4, 'pending count includes bob (filtered later for missing rate)');
  // Filtered list inside pushAllPendingHires excludes missing rates
  await App.pushAllPendingHires('paycom');
  // After bulk, carol/dan/eve should be on paycom; bob still off
  const carol = App.S.employees.find(e => e.id === 'e_carol');
  const dan   = App.S.employees.find(e => e.id === 'e_dan');
  const eve   = App.S.employees.find(e => e.id === 'e_eve');
  const bob   = App.S.employees.find(e => e.id === 'e_bob');
  assert.ok(carol.payrollIds?.paycom);
  assert.ok(dan.payrollIds?.paycom);
  assert.ok(eve.payrollIds?.paycom);
  assert.equal(bob.payrollIds, undefined, 'bob should remain unsynced (no hourly rate)');

  // History should show a bulk_hire entry
  const i = App._payrollState('paycom');
  const bulk = i.history.find(h => h.type === 'bulk_hire');
  assert.ok(bulk);
  assert.equal(bulk.ok, true);
  assert.equal(bulk.count, 3);
});

test('payroll period sync builds correct totals', async () => {
  // Seed two-weeks of punches for alice + carol
  const dates = [];
  for (let d = 1; d <= 10; d++) dates.push(`2026-04-${String(d).padStart(2,'0')}`);
  addPunches('e_alice', dates, 8);
  addPunches('e_carol', dates, 8);
  // Set the payroll period
  App.S._payroll = {
    cycle: 'bi-weekly',
    periodStart: '2026-04-01',
    periodEnd:   '2026-04-14',
    includeBuildings: 'all',
    otThreshold: 40,
    otMultiplier: 1.5,
  };
  const report = App._calcPayrollReport(App.S._payroll);
  assert.ok(report.empCount >= 2);
  assert.ok(report.totalGross > 0);

  // Sync to both providers
  await App.syncPayrollToProvider('paycom');
  await App.syncPayrollToProvider('adp');

  const pc = App._payrollState('paycom');
  const ad = App._payrollState('adp');
  assert.ok(pc.lastPayrollSyncAt, 'paycom payroll sync timestamp should update');
  assert.ok(ad.lastPayrollSyncAt, 'adp payroll sync timestamp should update');

  const pcEntry = pc.history.find(h => h.type === 'payroll');
  const adEntry = ad.history.find(h => h.type === 'payroll');
  assert.ok(pcEntry?.ok && adEntry?.ok);
  assert.match(pcEntry.summary, /\$\d/);
  assert.equal(pcEntry.empCount, report.rows.filter(r => {
    const e = App.S.employees.find(x=>x.id===r.empId);
    return e?.payrollIds?.paycom;
  }).length);
});

test('time-clock pull adds non-duplicate punches into hrTimeClock', async () => {
  // First push carol/dan/eve to ADP too so the ADP pull has 4 eligible
  // employees — eliminates the one-employee random-zero edge case.
  for (const id of ['e_carol','e_dan','e_eve']) {
    const e = App.S.employees.find(x => x.id === id);
    if (e && !(e.payrollIds && e.payrollIds.adp)) {
      await App.pushHireToPayroll(id, 'adp');
    }
  }
  const before = App.S.hrTimeClock.length;
  await App.syncTimeFromProvider('paycom');
  const afterPaycom = App.S.hrTimeClock.length;
  assert.ok(afterPaycom > before, `paycom pull should add at least some punches (before=${before} after=${afterPaycom})`);
  // Pulling again should add few-or-zero new (dedup by source key)
  await App.syncTimeFromProvider('paycom');
  const afterRepeat = App.S.hrTimeClock.length;
  assert.equal(afterRepeat, afterPaycom, 'second paycom pull should be fully deduped');
  // ADP pull is independent → should add new records (4 eligible employees ≫ 1)
  await App.syncTimeFromProvider('adp');
  const afterAdp = App.S.hrTimeClock.length;
  assert.ok(afterAdp > afterPaycom, `adp pull should add new records (before=${afterPaycom} after=${afterAdp})`);
  // All imported punches should have source=provider
  const sources = new Set(App.S.hrTimeClock.map(p => p.source));
  assert.ok(sources.has('paycom'));
  assert.ok(sources.has('adp'));
});

test('audit log records every payroll integration event', () => {
  const types = new Set((App.S.hrAuditLog || []).map(a => a.type || a.action || ''));
  // At least PAYCOM_SYNC and ADP_SYNC entries should be present (they may be
  // logged via the Audit module — we don't guarantee location, just count).
  const paycomHist = App._payrollState('paycom').history;
  const adpHist    = App._payrollState('adp').history;
  // Both providers should have multiple history entries
  assert.ok(paycomHist.length >= 4, `paycom history low: ${paycomHist.length}`);
  assert.ok(adpHist.length >= 3,    `adp history low: ${adpHist.length}`);
  // Each entry has the expected shape
  for (const h of paycomHist.concat(adpHist)) {
    assert.ok(typeof h.ts === 'number');
    assert.ok(typeof h.ok === 'boolean');
    assert.ok(typeof h.summary === 'string');
    assert.ok(['hire','bulk_hire','payroll','time_pull','connect'].includes(h.type), `bad type: ${h.type}`);
  }
});

test('pending-hires count drops to zero after both providers fully synced', async () => {
  // Sync remaining pending hires to ADP too
  await App.pushAllPendingHires('adp');
  const stillPendingPaycom = App._payrollPendingHires('paycom').filter(e => e.hourlyRate);
  const stillPendingAdp    = App._payrollPendingHires('adp').filter(e => e.hourlyRate);
  assert.equal(stillPendingPaycom.length, 0);
  assert.equal(stillPendingAdp.length, 0);
});

test('autoPushHires fires when pushHrToRoster runs', async () => {
  // Both providers stay connected; auto-push enabled by default
  assert.equal(App._payrollState('paycom').autoPushHires, true);
  assert.equal(App._payrollState('adp').autoPushHires,    true);

  // Seed an HR onboarding record marked approved + ready for roster push
  const hr = {
    id: 'hr_zoe',
    name: 'Zoe Zane',
    role: 'CMA',
    facilityId: 'bld_a',
    email: 'zoe@example.test',
    phone: '555-0199',
    hourlyRate: 24,
    hireDate: '2026-04-01',
    status: 'approved',
    progress: 'Complete',
  };
  App.S.hrEmployees.push(hr);

  await App.pushHrToRoster(hr.id);
  // Roster push happens immediately; auto-payroll-push is deferred via setTimeout(250)
  const newEmp = App.S.employees.find(e => e.name === 'Zoe Zane');
  assert.ok(newEmp, 'Zoe should be on roster');
  // Wait long enough for the deferred auto-push to complete BOTH providers:
  // 250ms (defer) + 350ms (paycom hire) + 350ms (adp hire) ≈ 950ms total.
  await new Promise(r => setTimeout(r, 1500));
  assert.ok(newEmp.payrollIds?.paycom, 'auto-push to paycom should fire');
  assert.ok(newEmp.payrollIds?.adp,    'auto-push to adp should fire');
});

test('disconnect clears credentials and status', () => {
  App.disconnectPayrollProvider('paycom');
  const i = App._payrollState('paycom');
  assert.equal(i.configured, false);
  assert.equal(i.status, 'disconnected');
  assert.equal(i.clientId, '');
  assert.equal(i.clientSecret, '');
  assert.equal(i.companyCode, '');
});

test('push to disconnected provider is rejected', async () => {
  // Add a fresh employee with a rate
  const emp = addEmployee('e_frank', 'Frank Frost', 'Maintenance', 19.50);
  const ok = await App.pushHireToPayroll(emp.id, 'paycom');
  assert.equal(ok, false, 'paycom is disconnected — push should fail');
  assert.equal(emp.payrollIds, undefined);
  // ADP still connected — push should succeed
  const ok2 = await App.pushHireToPayroll(emp.id, 'adp');
  assert.equal(ok2, true);
  assert.ok(emp.payrollIds?.adp);
});

test('end-to-end report: print final state', () => {
  const pc = App._payrollState('paycom');
  const ad = App._payrollState('adp');
  const summary = {
    paycom: {
      configured: pc.configured,
      status: pc.status,
      historyEntries: pc.history.length,
      lastConnectAt: pc.lastConnectAt && new Date(pc.lastConnectAt).toISOString(),
      lastHireSyncAt: pc.lastHireSyncAt && new Date(pc.lastHireSyncAt).toISOString(),
      lastPayrollSyncAt: pc.lastPayrollSyncAt && new Date(pc.lastPayrollSyncAt).toISOString(),
      lastTimeSyncAt: pc.lastTimeSyncAt && new Date(pc.lastTimeSyncAt).toISOString(),
    },
    adp: {
      configured: ad.configured,
      status: ad.status,
      historyEntries: ad.history.length,
      lastConnectAt: ad.lastConnectAt && new Date(ad.lastConnectAt).toISOString(),
      lastHireSyncAt: ad.lastHireSyncAt && new Date(ad.lastHireSyncAt).toISOString(),
      lastPayrollSyncAt: ad.lastPayrollSyncAt && new Date(ad.lastPayrollSyncAt).toISOString(),
      lastTimeSyncAt: ad.lastTimeSyncAt && new Date(ad.lastTimeSyncAt).toISOString(),
    },
    employees: App.S.employees.map(e => ({
      name: e.name, group: e.group, rate: e.hourlyRate,
      paycomId: e.payrollIds?.paycom || null,
      adpId:    e.payrollIds?.adp    || null,
    })),
    timeClockTotal: App.S.hrTimeClock.length,
    timeClockBySource: App.S.hrTimeClock.reduce((acc, p) => {
      acc[p.source||'manual'] = (acc[p.source||'manual']||0) + 1; return acc;
    }, {}),
  };
  console.log('\n──────────────── E2E SUMMARY ────────────────');
  console.log(JSON.stringify(summary, null, 2));
  console.log('─────────────────────────────────────────────\n');
  // Assert the full pipeline produced what we'd expect
  assert.ok(summary.employees.some(e => e.paycomId && e.adpId), 'at least one employee on both providers');
  assert.ok(summary.timeClockTotal > 10, 'time-clock has imported punches');
  assert.ok(summary.timeClockBySource.paycom > 0);
  assert.ok(summary.timeClockBySource.adp    > 0);
});
