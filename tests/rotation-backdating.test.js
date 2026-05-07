'use strict';
/**
 * Sandbox test for two follow-up fixes:
 *   1. setCycleStartDate accepts back-dated cycle starts (rotation already
 *      in progress) and computes cycleAnchorIdx so presets shift correctly.
 *   2. saveAddShifts persists an "open" pattern + auto-extends through the
 *      calendar horizon (matches saveAssignShift behavior).
 *
 * Run with: node --test --test-concurrency=1 tests/rotation-backdating.test.js
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

App.persistData = () => {};
App.renderMain = () => {};
App.renderHRMain = () => {};
App.renderSidebar = () => {};
App.showToast = () => {};
App.openModal = () => {};
App.closeModal = () => {};
App.updateMonthLabel = () => {};
App._renderAddShiftsBody = () => {};
App._renderAssignShiftBody = () => {};

// Helper: build a 14-day visible window starting from Monday of `today`'s week.
function buildVisibleDates(today) {
  const startD = new Date(today + 'T12:00:00');
  const dow = startD.getDay();
  startD.setDate(startD.getDate() - (dow === 0 ? 6 : dow - 1));
  const dates = [];
  for (let i = 0; i < 14; i++) {
    const d = new Date(startD);
    d.setDate(d.getDate() + i);
    dates.push(d.toISOString().slice(0, 10));
  }
  return dates;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('setCycleStartDate with same-day start gives anchor 0', () => {
  const today = new Date();
  const todayStr = today.toISOString().slice(0,10);
  const dates = buildVisibleDates(todayStr);
  App.S._assignShiftState = {
    empId: null, group: 'CNA', buildingId: 'b1', shiftType: 'Day',
    selectedDays: [], cycleAnchorIdx: 0, mirrorWeeks: true,
    dates, cycleStartDate: dates[0], view: 'assign',
  };
  App.setCycleStartDate('assign', dates[0]);
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 0);
  assert.equal(App.S._assignShiftState.cycleStartDate, dates[0]);
});

test('setCycleStartDate back-dated 7 days gives anchor 7', () => {
  const dates = App.S._assignShiftState.dates;
  // 7 days BEFORE visible[0]
  const back = new Date(dates[0] + 'T12:00:00');
  back.setDate(back.getDate() - 7);
  const backStr = back.toISOString().slice(0,10);
  App.setCycleStartDate('assign', backStr);
  assert.equal(App.S._assignShiftState.cycleStartDate, backStr);
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 7,
    `anchor should be 7 when cycle started 7 days before visible[0]`);
});

test('setCycleStartDate back-dated 14 days gives anchor 0 (full cycle)', () => {
  const dates = App.S._assignShiftState.dates;
  const back = new Date(dates[0] + 'T12:00:00');
  back.setDate(back.getDate() - 14);
  App.setCycleStartDate('assign', back.toISOString().slice(0,10));
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 0,
    `anchor should be 0 when cycle started exactly one cycle (14 days) ago`);
});

test('setCycleStartDate forward-dated 3 days gives anchor 3', () => {
  const dates = App.S._assignShiftState.dates;
  const fwd = new Date(dates[0] + 'T12:00:00');
  fwd.setDate(fwd.getDate() + 3);
  App.setCycleStartDate('assign', fwd.toISOString().slice(0,10));
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 3);
});

test('Pitman preset with anchor=7 shifts to back-dated rotation', () => {
  // Reset to back-dated 7 days
  const dates = App.S._assignShiftState.dates;
  const back = new Date(dates[0] + 'T12:00:00');
  back.setDate(back.getDate() - 7);
  App.setCycleStartDate('assign', back.toISOString().slice(0,10));
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 7);

  // Pick the Pitman preset
  App._selectPreset('assign', 'pitman');
  // Pitman default = [0,1,4,5,6, 9,10,11]; with anchor 7, each shifted by 7 mod 14:
  //   [7, 8, 11, 12, 13, 2, 3, 4]
  const expected = [7, 8, 11, 12, 13, 2, 3, 4];
  const actual = App.S._assignShiftState.selectedDays.slice().sort((a,b)=>a-b);
  const expSort = expected.slice().sort((a,b)=>a-b);
  assert.equal(actual.length, expSort.length);
  for (let i = 0; i < expSort.length; i++) {
    assert.equal(actual[i], expSort[i],
      `Pitman shifted by 7: position ${i} → expected ${expSort[i]}, got ${actual[i]}`);
  }
});

test('Pitman preset with anchor=0 (no back-dating) maps to base [0,1,4,5,6,9,10,11]', () => {
  const dates = App.S._assignShiftState.dates;
  App.setCycleStartDate('assign', dates[0]);
  App._selectPreset('assign', 'pitman');
  const actual = App.S._assignShiftState.selectedDays.slice().sort((a,b)=>a-b);
  assert.equal(actual.length, 8);
  assert.equal(actual[0], 0);
  assert.equal(actual[1], 1);
  assert.equal(actual[2], 4);
  assert.equal(actual[3], 5);
  assert.equal(actual[4], 6);
  assert.equal(actual[5], 9);
  assert.equal(actual[6], 10);
  assert.equal(actual[7], 11);
});

test('saveAddShifts persists an open-rotation pattern + 365-day horizon', () => {
  // Set up a clean state
  App.S.user = { id:'u_test', role:'superadmin', buildingId:'b1' };
  App.S.activeBuildingId = 'b1';
  App.S.buildings = [{ id:'b1', name:'Test SNF' }];
  App.S.shifts = [];
  App.S.schedulePatterns = [];
  App.S.shiftTemplates = [];
  App.S.selectedGroup = 'CNA';

  const today = new Date().toISOString().slice(0,10);
  const dates = buildVisibleDates(today);
  App.S._addShiftState = {
    group: 'CNA', buildingId: 'b1',
    shiftType: 'Day', slots: 2,
    selectedDays: [2, 3, 9, 10],   // Wed/Thu both weeks
    dates,
    cycleAnchorIdx: 0,
    cycleStartDate: dates[0],
    mirrorWeeks: true,
    customName:'', customStart:'7:00 AM', customEnd:'3:00 PM',
    editingBuiltinType:null,
  };

  App.saveAddShifts();

  // Should add shifts through 365 days
  const cnaShifts = App.S.shifts.filter(s => s.group === 'CNA' && s.type === 'Day');
  assert.ok(cnaShifts.length > 180, `expected >180 shifts (2 slots × ~104 days), got ${cnaShifts.length}`);
  // All open
  for (const s of cnaShifts) assert.equal(s.status, 'open');
  // All Wed or Thu
  for (const s of cnaShifts) {
    const dow = new Date(s.date + 'T12:00:00').getDay();
    assert.ok(dow === 3 || dow === 4, `${s.date} fell on dow ${dow}`);
  }
  // Should have persisted a pattern rule of kind 'open'
  assert.equal(App.S.schedulePatterns.length, 1);
  const pat = App.S.schedulePatterns[0];
  assert.equal(pat.kind, 'open');
  assert.equal(pat.empId, null);
  assert.equal(pat.slots, 2);
  assert.equal(pat.cycleLen, 14);
  assert.ok(pat.lastExtendedTo);
});

test('open-rotation auto-extends when calendar navigates past horizon', () => {
  const before = App.S.shifts.length;
  // Navigate calendar 14 months forward
  const future = new Date();
  future.setMonth(future.getMonth() + 14);
  const added = App._extendRotationsThrough(future.getFullYear(), future.getMonth());
  assert.ok(added > 0, `expected open-pattern to extend forward (added ${added})`);
  const after = App.S.shifts.length;
  assert.ok(after > before);
  // All extended shifts are also open
  const newShifts = App.S.shifts.slice(before);
  for (const s of newShifts) assert.equal(s.status, 'open');
  // Idempotent
  const addedAgain = App._extendRotationsThrough(future.getFullYear(), future.getMonth());
  assert.equal(addedAgain, 0);
});

test('back-dated rotation: assign shift carries the shifted Pitman through future weeks', () => {
  // New scenario: today is Wed; rotation started 7 days earlier (last Wed).
  // Employee joining today should pick up where the rotation is — i.e. they
  // should follow shifted Pitman.
  App.S.employees = [{
    id:'e_p', name:'Pia Pitman', initials:'PP',
    group:'CNA', hourlyRate:23, hireDate:'2026-01-01',
    buildingId:'b1', inactive:false,
  }];
  App.S.shifts = [];
  App.S.schedulePatterns = [];

  const today = new Date().toISOString().slice(0,10);
  const dates = buildVisibleDates(today);
  // Cycle started 7 days before this visible Monday
  const back = new Date(dates[0] + 'T12:00:00');
  back.setDate(back.getDate() - 7);
  const backStr = back.toISOString().slice(0,10);

  App.S._assignShiftState = {
    empId: 'e_p', group: 'CNA', buildingId: 'b1', shiftType: 'Day',
    selectedDays: [],
    cycleAnchorIdx: 0,
    cycleStartDate: dates[0],
    mirrorWeeks: true,
    dates,
    view: 'assign',
  };
  App.setCycleStartDate('assign', backStr);
  assert.equal(App.S._assignShiftState.cycleAnchorIdx, 7);

  App._selectPreset('assign', 'pitman');
  // Now pia should work positions [7,8,11,12,13,2,3,4] in the visible grid.
  const sd = App.S._assignShiftState.selectedDays.slice().sort((a,b)=>a-b);
  const exp = [2,3,4,7,8,11,12,13];
  assert.equal(sd.length, exp.length);
  for (let i = 0; i < exp.length; i++) {
    assert.equal(sd[i], exp[i], `position ${i}: expected ${exp[i]}, got ${sd[i]}`);
  }

  App.saveAssignShift();
  const piaShifts = App.S.shifts.filter(s => s.employeeId === 'e_p');
  assert.ok(piaShifts.length > 100, `expected >100 Pitman shifts over a year, got ${piaShifts.length}`);

  // The first 14-day window should contain Pitman shifts on every selected
  // position whose corresponding date is at or after TODAY (saveAssignShift
  // doesn't backfill past dates). Compute the expected count dynamically so
  // the test is stable as the system date marches forward.
  const expectedSelectedDays = [2,3,4,7,8,11,12,13];
  const todayStr = new Date().toISOString().slice(0,10);
  const expectedFirstCycleCount = expectedSelectedDays
    .filter(pos => dates[pos] >= todayStr).length;
  const firstCycle = piaShifts.filter(s => s.date >= dates[0] && s.date <= dates[13]);
  assert.equal(firstCycle.length, expectedFirstCycleCount,
    `first 14-day window should have ${expectedFirstCycleCount} Pitman shifts (positions ≥ today), got ${firstCycle.length}`);

  // Persisted rule has cycleStartDate = back-dated date
  assert.equal(App.S.schedulePatterns.length, 1);
  assert.equal(App.S.schedulePatterns[0].cycleStartDate, backStr);
});

test('summary report: back-dated rotation coverage', () => {
  const piaShifts = App.S.shifts.filter(s => s.employeeId === 'e_p');
  const byMonth = {};
  for (const s of piaShifts) {
    const k = s.date.slice(0,7);
    byMonth[k] = (byMonth[k] || 0) + 1;
  }
  const months = Object.keys(byMonth).sort();
  console.log('\n──── BACK-DATED PITMAN COVERAGE ────');
  for (const m of months) console.log(`  ${m}: ${byMonth[m]} shifts`);
  console.log(`  total: ${piaShifts.length} shifts across ${months.length} months`);
  console.log('────────────────────────────────────\n');
  assert.ok(months.length >= 11, `should cover at least 11 months, got ${months.length}`);
  // Most full months should have 16-18 shifts (8 per cycle × ~2 cycles)
  const fullMonths = months.filter(m => byMonth[m] >= 14);
  assert.ok(fullMonths.length >= 8, `${fullMonths.length} full months (≥14 shifts), expected ≥8`);
});
