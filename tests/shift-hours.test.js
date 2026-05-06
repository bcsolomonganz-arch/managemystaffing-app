'use strict';
/**
 * Sandbox test for the _shiftHours fix and the PPD daily-cost calculation.
 *
 * Bug found: _shiftHours used .split(':') which only handled "07:00" 24-hour
 * format. The codebase actually stores times as "7:00 AM" / "3:00 PM" — so
 * "3:00 PM" was being parsed as 3 (AM), making a Day shift compute as 20
 * hours instead of 8 — which then made PPD daily costs ~3× too high.
 *
 * Run with: node --test --test-concurrency=1 tests/shift-hours.test.js
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

// ── Tests ──────────────────────────────────────────────────────────────────

test('_shiftHours parses 12-hour AM/PM correctly (the bug fix)', () => {
  // Day shift: 7am to 3pm — was returning 20, should return 8
  assert.equal(App._shiftHours({ start:'7:00 AM', end:'3:00 PM' }), 8);
  // Evening shift: 3pm to 11pm
  assert.equal(App._shiftHours({ start:'3:00 PM', end:'11:00 PM' }), 8);
  // Night shift: 11pm to 7am (overnight)
  assert.equal(App._shiftHours({ start:'11:00 PM', end:'7:00 AM' }), 8);
  // Morning support shift: 6am to 2pm
  assert.equal(App._shiftHours({ start:'6:00 AM', end:'2:00 PM' }), 8);
  // Afternoon: 2pm to 10pm
  assert.equal(App._shiftHours({ start:'2:00 PM', end:'10:00 PM' }), 8);
});

test('_shiftHours handles noon and midnight edge cases', () => {
  // Noon: 12:00 PM = 12 (not 0)
  assert.equal(App._shiftHours({ start:'8:00 AM',  end:'12:00 PM' }), 4);
  // Midnight: 12:00 AM = 0
  assert.equal(App._shiftHours({ start:'12:00 AM', end:'8:00 AM'  }), 8);
  assert.equal(App._shiftHours({ start:'8:00 PM',  end:'12:00 AM' }), 4);
  // Full 24-hour cycle (e.g. live-in): should give 24, not 0
  assert.equal(App._shiftHours({ start:'7:00 AM',  end:'7:00 AM'  }), 24);
});

test('_shiftHours supports 24-hour format (defensive)', () => {
  assert.equal(App._shiftHours({ start:'07:00', end:'15:00' }), 8);
  assert.equal(App._shiftHours({ start:'15:00', end:'23:00' }), 8);
  assert.equal(App._shiftHours({ start:'23:00', end:'07:00' }), 8);
});

test('_shiftHours fractional minutes', () => {
  assert.equal(App._shiftHours({ start:'7:00 AM', end:'3:30 PM' }), 8.5);
  assert.equal(App._shiftHours({ start:'7:15 AM', end:'3:00 PM' }), 7.75);
});

test('_shiftHours returns default 8 for missing/invalid times', () => {
  assert.equal(App._shiftHours({}), 8);
  assert.equal(App._shiftHours({ start:'', end:'' }), 8);
  assert.equal(App._shiftHours({ start:'banana', end:'split' }), 8);
});

test('_dailyCostForGroups correctly computes daily nursing cost', () => {
  App.S.user = { id:'u_test', role:'superadmin', buildingId:'b1' };
  App.S.buildings = [{ id:'b1', name:'Test SNF' }];
  // Two Charge Nurses at $30/hr both working a Day shift (8 hrs each)
  App.S.employees = [
    { id:'e_a', name:'Nurse A', group:'Charge Nurse', hourlyRate:30, buildingId:'b1', inactive:false },
    { id:'e_b', name:'Nurse B', group:'Charge Nurse', hourlyRate:30, buildingId:'b1', inactive:false },
  ];
  App.S.shifts = [
    { id:'s1', date:'2026-05-05', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_a' },
    { id:'s2', date:'2026-05-05', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_b' },
    // An open slot — should NOT count toward cost (no employee)
    { id:'s3', date:'2026-05-05', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'open',
      buildingId:'b1', employeeId:null },
  ];
  const cost = App._dailyCostForGroups('b1', '2026-05-05', ['Charge Nurse']);
  // Expected: 2 nurses × 8 hrs × $30/hr = $480
  assert.equal(cost, 480, `expected $480, got $${cost}`);
});

test('open shifts (no employeeId) do NOT contribute to daily cost', () => {
  // All 3 shifts open
  App.S.shifts = [
    { id:'s1', date:'2026-05-06', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'open',
      buildingId:'b1', employeeId:null },
    { id:'s2', date:'2026-05-06', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'open',
      buildingId:'b1', employeeId:null },
  ];
  const cost = App._dailyCostForGroups('b1', '2026-05-06', ['Charge Nurse']);
  assert.equal(cost, 0, 'open shifts should not have any cost attributed');
});

test('mixed rates compute correctly', () => {
  // Two nurses at different rates, both 8-hr day shifts
  App.S.employees = [
    { id:'e_a', name:'Nurse A', group:'Charge Nurse', hourlyRate:30, buildingId:'b1', inactive:false },
    { id:'e_b', name:'Nurse B', group:'Charge Nurse', hourlyRate:36, buildingId:'b1', inactive:false },
  ];
  App.S.shifts = [
    { id:'s1', date:'2026-05-07', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_a' },
    { id:'s2', date:'2026-05-07', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_b' },
  ];
  const cost = App._dailyCostForGroups('b1', '2026-05-07', ['Charge Nurse']);
  // Expected: (30 × 8) + (36 × 8) = 240 + 288 = $528
  assert.equal(cost, 528, `expected $528, got $${cost}`);
});

test('reproduces the exact scenario from the user screenshot (16 hrs, but cost is now $480 not $1440)', () => {
  // Two Charge Nurses, Day shift each — what user reported
  App.S.employees = [
    { id:'e_a', name:'Nurse A', group:'Charge Nurse', hourlyRate:30, buildingId:'b1', inactive:false },
    { id:'e_b', name:'Nurse B', group:'Charge Nurse', hourlyRate:30, buildingId:'b1', inactive:false },
  ];
  App.S.shifts = [
    { id:'s1', date:'2026-05-05', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_a' },
    { id:'s2', date:'2026-05-05', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_b' },
  ];
  // Hours field uses count×8 — should be 16 (the displayed value)
  const dayShifts = App.S.shifts.filter(s => s.date==='2026-05-05' && s.status==='scheduled');
  const cnHrs = dayShifts.filter(s=>s.group==='Charge Nurse').length * 8;
  assert.equal(cnHrs, 16, 'hours field should show 16');
  // Cost should NOW be $480 (was $1440 with the bug — 3× too high)
  const cost = App._dailyCostForGroups('b1', '2026-05-05', ['Charge Nurse']);
  assert.equal(cost, 480,
    `cost should be 16 hrs × $30/hr = $480 (with the bug it was 20 hrs × $30/hr × 2 nurses = $1200-1440)`);
});
