'use strict';
/**
 * Sandbox test for two fixes:
 *   1. Calendar defaults to the CURRENT month/year (was hardcoded April 2026)
 *   2. saveAssignShift extends a 14-day rotation through the next 365 days
 *      and persists a schedulePatterns rule that auto-extends when the user
 *      navigates the calendar past the horizon.
 *
 * Run with:  node --test --test-concurrency=1 tests/rotation-calendar.test.js
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
  const localStorage = {
    getItem: k => (k in _store ? _store[k] : null),
    setItem: (k, v) => { _store[k] = String(v); },
    removeItem: k => { delete _store[k]; },
    clear: () => { for (const k of Object.keys(_store)) delete _store[k]; },
  };
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
    body: fakeEl(), head: fakeEl(),
    addEventListener: () => {},
    documentElement: { setAttribute(){}, style:{} },
    cookie: '',
  };
  const ctx = {
    document, localStorage,
    location: { protocol:'http:', hostname:'sandbox', href:'http://sandbox/', pathname:'/' },
    setTimeout, clearTimeout, setInterval, clearInterval,
    confirm: () => true, alert: () => {}, prompt: () => null,
    crypto: { getRandomValues: arr => { for (let i=0;i<arr.length;i++) arr[i]=Math.floor(Math.random()*256); return arr; } },
    fetch: async () => ({ ok:false, json: async () => ({}) }),
    URL: { createObjectURL: () => 'blob:s', revokeObjectURL(){} },
    URLSearchParams: globalThis.URLSearchParams || function(){ return { get:()=>null, set(){}, toString:()=>'' }; },
    TextEncoder: globalThis.TextEncoder, TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob, btoa: globalThis.btoa,
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
if (!App) throw new Error('App not exposed');

// Stub side effects
App.persistData = () => {};
App.renderMain = () => {};
App.renderHRMain = () => {};
App.renderSidebar = () => {};
App.showToast = () => {};
App.openModal = () => {};
App.closeModal = () => {};
App.updateMonthLabel = () => {};

// ── Tests ──────────────────────────────────────────────────────────────────

test('calendar defaults to current month/year on init', () => {
  // Re-seed integrations to a known clean state
  const now = new Date();
  assert.equal(App.S.viewYear,  now.getFullYear(),
    `viewYear should default to ${now.getFullYear()}, got ${App.S.viewYear}`);
  assert.equal(App.S.viewMonth, now.getMonth(),
    `viewMonth should default to ${now.getMonth()} (${now.toLocaleString('en-US',{month:'long'})}), got ${App.S.viewMonth}`);
});

test('goToToday() resets to current month', () => {
  // Move calendar away first
  App.S.viewMonth = 0;  // January
  App.S.viewYear  = 2020;
  App.goToToday();
  const now = new Date();
  assert.equal(App.S.viewYear,  now.getFullYear());
  assert.equal(App.S.viewMonth, now.getMonth());
});

test('saveAssignShift extends a Wed/Thu rotation through 365+ days', () => {
  // Set up a clean roster + employee
  App.S.user = { id:'u_test', email:'test@demo.com', role:'superadmin', buildingId:'b1' };
  App.S.buildings = [{ id:'b1', name:'Test SNF' }];
  App.S.employees = [{
    id:'e_z', name:'Zeke Zane', initials:'ZZ',
    group:'CNA', hourlyRate:21.5, hireDate:'2026-01-15',
    buildingId:'b1', inactive:false,
  }];
  App.S.shifts = [];
  App.S.schedulePatterns = [];

  // Find the cycle position for Wed and Thu starting from "today".
  // Use the App's TODAY constant (UTC) so picker math matches the app's
  // save loop. Computing pickerStart from local Date() can drift by a day
  // depending on local timezone vs UTC at the moment the test runs.
  const todayStr = new Date().toISOString().slice(0,10);
  const todayUTC = new Date(todayStr + 'T12:00:00Z');
  const utcDow = todayUTC.getUTCDay() || 7;  // 1..7 (Mon=1)
  const mondayUTC = new Date(todayUTC);
  mondayUTC.setUTCDate(todayUTC.getUTCDate() - (utcDow - 1));
  const pickerStart = mondayUTC.toISOString().slice(0,10);

  // Selected days: position 2 (Wed W1), 3 (Thu W1), 9 (Wed W2), 10 (Thu W2)
  // → with mirror, this gives EVERY week Wed+Thu.
  App.S._assignShiftState = {
    empId: 'e_z',
    group: 'CNA',
    buildingId: 'b1',
    shiftType: 'Day',
    dates: [pickerStart],   // day 1 of cycle
    selectedDays: [2, 3, 9, 10],
  };

  App.saveAssignShift();

  // Expectations:
  // - shifts assigned over 365 days × 2 days/week ≈ 100+ shifts
  // - all assigned to e_z, all CNA Day at b1
  const zShifts = App.S.shifts.filter(s => s.employeeId === 'e_z');
  assert.ok(zShifts.length > 90, `expected >90 rotation shifts, got ${zShifts.length}`);
  assert.ok(zShifts.length < 200, `expected <200 (sanity), got ${zShifts.length}`);
  for (const s of zShifts) {
    assert.equal(s.group, 'CNA');
    assert.equal(s.type, 'Day');
    assert.equal(s.buildingId, 'b1');
  }
  // All shift dates fall on Wed or Thu (dow 3 or 4)
  for (const s of zShifts) {
    const dow = new Date(s.date + 'T12:00:00Z').getUTCDay();
    assert.ok(dow === 3 || dow === 4,
      `shift on ${s.date} fell on day-of-week ${dow}, expected Wed(3) or Thu(4)`);
  }
  // Earliest and latest dates span at least 11 months
  const earliest = zShifts.map(s => s.date).sort()[0];
  const latest   = zShifts.map(s => s.date).sort().slice(-1)[0];
  const spanDays = Math.round((new Date(latest) - new Date(earliest)) / 86400000);
  assert.ok(spanDays >= 330, `rotation span ${spanDays} days < 330 (expected ~365)`);

  // schedulePatterns has the rule for auto-extension
  assert.equal(App.S.schedulePatterns.length, 1);
  const pat = App.S.schedulePatterns[0];
  assert.equal(pat.empId, 'e_z');
  // Use explicit element checks (deepEqual reporter races mutations across tests)
  assert.equal(pat.selectedDays.length, 4);
  assert.equal(pat.selectedDays[0], 2);
  assert.equal(pat.selectedDays[1], 3);
  assert.equal(pat.selectedDays[2], 9);
  assert.equal(pat.selectedDays[3], 10);
  assert.equal(pat.cycleLen, 14);
  assert.ok(pat.lastExtendedTo, 'lastExtendedTo should be set');
});

test('_extendRotationsThrough adds shifts when navigating past horizon', () => {
  // Simulate user navigating the calendar 14 months into the future
  const before = App.S.shifts.filter(s => s.employeeId === 'e_z').length;
  const future = new Date();
  future.setMonth(future.getMonth() + 14);
  const added = App._extendRotationsThrough(future.getFullYear(), future.getMonth());
  assert.ok(added > 0, 'should extend at least some shifts past current horizon');
  const after = App.S.shifts.filter(s => s.employeeId === 'e_z').length;
  assert.ok(after > before, `shifts after extension (${after}) should exceed before (${before})`);
  // Calling again at the same target is idempotent
  const addedAgain = App._extendRotationsThrough(future.getFullYear(), future.getMonth());
  assert.equal(addedAgain, 0, 'second extend at same target should add nothing');
});

test('navMonth advances calendar AND auto-extends rotation', () => {
  const startYear  = App.S.viewYear;
  const startMonth = App.S.viewMonth;
  // Jump 18 months forward, one month at a time
  for (let i = 0; i < 18; i++) App.navMonth(1);
  // Calendar should be exactly 18 months ahead
  const expectedTotal = startYear * 12 + startMonth + 18;
  const actualTotal   = App.S.viewYear * 12 + App.S.viewMonth;
  assert.equal(actualTotal, expectedTotal, 'navMonth should advance calendar by exactly 18 months');

  // Rotation should now extend through that month
  const pat = App.S.schedulePatterns[0];
  const lastEndYear  = parseInt(pat.lastExtendedTo.slice(0,4), 10);
  const lastEndMonth = parseInt(pat.lastExtendedTo.slice(5,7), 10) - 1;
  const lastEndTotal = lastEndYear * 12 + lastEndMonth;
  assert.ok(lastEndTotal >= expectedTotal,
    `rotation extended to ${pat.lastExtendedTo} should cover viewMonth ${App.S.viewYear}-${String(App.S.viewMonth+1).padStart(2,'0')}`);
});

test('rotation only assigns Wed + Thu in newly extended weeks', () => {
  const allZShifts = App.S.shifts.filter(s => s.employeeId === 'e_z');
  for (const s of allZShifts) {
    const dow = new Date(s.date + 'T12:00:00Z').getUTCDay();
    assert.ok(dow === 3 || dow === 4,
      `shift on ${s.date} (dow ${dow}) violates Wed/Thu rotation`);
  }
});

test('extending a rotation does not duplicate existing assignments', () => {
  const beforeDates = App.S.shifts.filter(s => s.employeeId === 'e_z').map(s => s.date);
  const beforeUnique = new Set(beforeDates).size;
  assert.equal(beforeDates.length, beforeUnique, 'no duplicate dates per employee');
  // Run extension again to trigger idempotency
  App.navMonth(0);
  const afterDates = App.S.shifts.filter(s => s.employeeId === 'e_z').map(s => s.date);
  const afterUnique = new Set(afterDates).size;
  assert.equal(afterDates.length, afterUnique, 'still no duplicates after re-extend');
  assert.equal(afterDates.length, beforeDates.length, 'idempotent re-extend adds nothing');
});

test('summary report: shift count by month over 18+ months', () => {
  const zShifts = App.S.shifts.filter(s => s.employeeId === 'e_z');
  const byMonth = {};
  for (const s of zShifts) {
    const key = s.date.slice(0,7);
    byMonth[key] = (byMonth[key] || 0) + 1;
  }
  const months = Object.keys(byMonth).sort();
  console.log('\n──── ROTATION COVERAGE ────');
  for (const m of months) console.log(`  ${m}: ${byMonth[m]} shifts`);
  console.log(`  total months: ${months.length}, total shifts: ${zShifts.length}`);
  console.log('───────────────────────────\n');
  assert.ok(months.length >= 16, `should cover at least 16 months, got ${months.length}`);
  // Most "full" months should have 8-10 shifts (4-5 weeks × Wed+Thu)
  const fullMonths = months.filter(m => byMonth[m] >= 7);
  assert.ok(fullMonths.length >= 12, `${fullMonths.length} months with ≥7 shifts (expected ≥12)`);
});
