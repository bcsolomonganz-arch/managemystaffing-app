'use strict';
/**
 * Sandbox test for salaried-employee support.
 *
 * Verifies:
 *   - _isSalaried + _empAnnualSalary work correctly
 *   - _empDailyRate(salaried) = annualSalary / 365
 *   - _dailyCostForGroups includes salaried employees every day, regardless
 *     of whether they're scheduled
 *   - _otPremiumOver skips salaried employees (no OT under FLSA exemption)
 *   - _ppdMetricsForDay daily-cost includes salaried portion
 *   - _buildHirePayload uses 'salary'/'annualRateAmount' for salaried hires
 *   - empCardSwitchPayType toggles payType correctly
 *   - empCardSaveRate writes annualSalary for salaried, hourlyRate for hourly
 *
 * Run with: node --test --test-concurrency=1 tests/salaried-employee.test.js
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
  const fakeEl = (tag) => ({
    tagName:(tag||'div').toUpperCase(), id:'', className:'', innerHTML:'',
    style:{}, classList:{ add(){}, remove(){}, toggle(){}, contains:()=>false },
    setAttribute(){}, removeAttribute(){}, getAttribute:()=>null,
    appendChild(){}, removeChild(){}, querySelector:()=>null, querySelectorAll:()=>[],
    addEventListener(){}, removeEventListener(){}, click(){}, focus(){}, blur(){},
    textContent:'', value:'', checked:false, disabled:false,
    children:[], parentNode:null, dataset:{}, remove(){},
  });
  const inserted = [];
  const body = {
    style:{}, appendChild(el){ inserted.push(el); el.parentNode = body; },
    removeChild(el){ const i = inserted.indexOf(el); if(i>=0) inserted.splice(i,1); },
  };
  const document = {
    getElementById(id) {
      const found = inserted.find(e => e.id === id);
      if (found) { found.remove = () => body.removeChild(found); return found; }
      return fakeEl();
    },
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: (tag) => fakeEl(tag),
    body, head: fakeEl(),
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
  return { sandbox: vm.createContext(ctx), inserted };
}

const { sandbox, inserted } = buildSandbox();
vm.runInContext(mainScript, sandbox, { filename: 'managemystaffing.inline.js' });
const App = sandbox.App;

App.persistData = () => {};
App.renderMain = () => {};
App.renderHRMain = () => {};
App.renderSidebar = () => {};
App.showToast = () => {};
App.openModal = () => {};
App.closeModal = () => {};

App.S.user = { id:'u_test', role:'superadmin', buildingId:'b1' };
App.S.buildings = [{ id:'b1', name:'Test SNF' }];

// ── _isSalaried + _empAnnualSalary ─────────────────────────────────────────

test('_isSalaried returns true only when payType=salaried AND annualSalary > 0', () => {
  assert.equal(App._isSalaried({ payType:'salaried', annualSalary: 65000 }), true);
  assert.equal(App._isSalaried({ payType:'salaried', annualSalary: 0     }), false);
  assert.equal(App._isSalaried({ payType:'salaried' }), false, 'no annualSalary set');
  assert.equal(App._isSalaried({ payType:'hourly',   annualSalary: 65000 }), false, 'payType wrong');
  assert.equal(App._isSalaried({ payType:'hourly',   hourlyRate: 25      }), false);
  assert.equal(App._isSalaried(null), false);
  assert.equal(App._isSalaried({}),   false, 'default is hourly');
});

test('_empAnnualSalary returns the salary value or 0', () => {
  assert.equal(App._empAnnualSalary({ annualSalary: 80000 }), 80000);
  assert.equal(App._empAnnualSalary({}), 0);
  assert.equal(App._empAnnualSalary(null), 0);
  assert.equal(App._empAnnualSalary({ annualSalary: '50000' }), 50000, 'string parses');
});

// ── _empDailyRate / _empHourlyRate equivalence ─────────────────────────────

test('_empDailyRate(salaried) = annualSalary / 365', () => {
  const emp = { payType:'salaried', annualSalary: 73000 };
  assert.equal(App._empDailyRate(emp), 73000 / 365);
  assert.equal(App._empDailyRate(emp).toFixed(2), '200.00');
});

test('_empHourlyRate(salaried) returns annualSalary / 2080 (FYI/OT-display only)', () => {
  const emp = { payType:'salaried', annualSalary: 104000 };
  // 104000 / 2080 = $50/hr equivalent
  assert.equal(App._empHourlyRate(emp), 50);
});

test('_empHourlyRate(hourly) still works as before', () => {
  assert.equal(App._empHourlyRate({ hourlyRate: 22.5 }), 22.5);
  assert.equal(App._empHourlyRate({ hourlyRate: '30' }), 30);
});

// ── _dailyCostForGroups: salaried employees count every day ────────────────

test('salaried employee contributes salary/365 to daily cost EVERY day, even with no shifts', () => {
  App.S.employees = [{
    id:'e_don', name:'Director Of Nursing',
    group:'Nurse Management', buildingId:'b1', inactive:false,
    payType:'salaried', annualSalary: 109500,   // exactly $300/day at /365
  }];
  App.S.shifts = []; // no shifts at all
  // Random Tuesday
  const cost = App._dailyCostForGroups('b1', '2026-05-12', ['Nurse Management']);
  assert.ok(Math.abs(cost - 300) < 0.001, `expected ~$300, got ${cost}`);
});

test('salaried employee daily cost is the SAME every day of the week (7-day spread)', () => {
  App.S.employees = [{
    id:'e_don', group:'Nurse Management', buildingId:'b1', inactive:false,
    payType:'salaried', annualSalary: 73000, name:'DON',
  }];
  App.S.shifts = [];
  const monday    = App._dailyCostForGroups('b1', '2026-05-11', ['Nurse Management']);
  const wednesday = App._dailyCostForGroups('b1', '2026-05-13', ['Nurse Management']);
  const saturday  = App._dailyCostForGroups('b1', '2026-05-16', ['Nurse Management']);
  const sunday    = App._dailyCostForGroups('b1', '2026-05-17', ['Nurse Management']);
  assert.equal(monday, wednesday);
  assert.equal(monday, saturday);
  assert.equal(monday, sunday);
});

test('salaried + hourly mix: both contribute, no double-counting', () => {
  App.S.employees = [
    // Salaried DON: $109,500/yr → $300/day
    { id:'e_don', name:'DON', group:'Nurse Management', buildingId:'b1', inactive:false,
      payType:'salaried', annualSalary: 109500 },
    // Hourly Charge Nurse: $30/hr × 8 hrs = $240/day when scheduled
    { id:'e_cn', name:'Charge Nurse 1', group:'Charge Nurse', buildingId:'b1', inactive:false,
      payType:'hourly', hourlyRate: 30 },
  ];
  App.S.shifts = [
    { id:'s1', date:'2026-05-12', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_cn' },
  ];
  // Cost for both groups together
  const cost = App._dailyCostForGroups('b1', '2026-05-12', ['Nurse Management','Charge Nurse']);
  assert.ok(Math.abs(cost - (300 + 240)) < 0.001, `expected $540, got ${cost}`);
});

test('inactive salaried employee does NOT contribute to daily cost', () => {
  App.S.employees = [{
    id:'e_don', group:'Nurse Management', buildingId:'b1', inactive:true,
    payType:'salaried', annualSalary: 109500, name:'DON',
  }];
  App.S.shifts = [];
  const cost = App._dailyCostForGroups('b1', '2026-05-12', ['Nurse Management']);
  assert.equal(cost, 0);
});

test('salaried employee in DIFFERENT building does not affect b1 cost', () => {
  App.S.buildings = [{ id:'b1', name:'Test A' }, { id:'b2', name:'Test B' }];
  App.S.employees = [{
    id:'e_don', group:'Nurse Management', buildingId:'b2', inactive:false,
    payType:'salaried', annualSalary: 109500, name:'DON',
  }];
  App.S.shifts = [];
  const costA = App._dailyCostForGroups('b1', '2026-05-12', ['Nurse Management']);
  const costB = App._dailyCostForGroups('b2', '2026-05-12', ['Nurse Management']);
  assert.equal(costA, 0);
  assert.ok(Math.abs(costB - 300) < 0.001);
  // restore for following tests
  App.S.buildings = [{ id:'b1', name:'Test SNF' }];
});

// ── OT premium: salaried skipped ────────────────────────────────────────────

test('_otPremiumOver does NOT charge OT for salaried employees who work > 40 hrs', () => {
  App.S.employees = [
    { id:'e_sal', name:'Salaried Manager', group:'Nurse Management', buildingId:'b1', inactive:false,
      payType:'salaried', annualSalary: 109500 },
  ];
  // 60 scheduled hours that week
  App.S.shifts = [];
  const dates = ['2026-05-11','2026-05-12','2026-05-13','2026-05-14','2026-05-15','2026-05-16'];
  for (const d of dates) {
    App.S.shifts.push({
      id:'s_'+d, date:d, group:'Nurse Management', type:'Day',
      start:'7:00 AM', end:'5:00 PM',  // 10-hour shift × 6 days = 60 hrs
      status:'scheduled', buildingId:'b1', employeeId:'e_sal',
    });
  }
  const otPremium = App._otPremiumOver('b1', '2026-05-11', '2026-05-17');
  assert.equal(otPremium, 0, 'salaried emp should accrue ZERO OT premium');
});

test('_otPremiumOver still charges OT for hourly employees > 40 hrs/wk', () => {
  App.S.employees = [
    { id:'e_h', name:'Hourly Worker', group:'CNA', buildingId:'b1', inactive:false,
      payType:'hourly', hourlyRate: 20 },
  ];
  App.S.shifts = [];
  // 50 scheduled hours that week (10 hrs OT)
  for (let i = 0; i < 5; i++) {
    const d = `2026-05-${String(11+i).padStart(2,'0')}`;
    App.S.shifts.push({
      id:'s_'+i, date:d, group:'CNA', type:'Day',
      start:'7:00 AM', end:'5:00 PM',  // 10 hrs × 5 days = 50 hrs
      status:'scheduled', buildingId:'b1', employeeId:'e_h',
    });
  }
  const otPremium = App._otPremiumOver('b1', '2026-05-11', '2026-05-17');
  // 10 OT hrs × $20/hr × 0.5 (premium portion) = $100
  assert.ok(Math.abs(otPremium - 100) < 0.01,
    `expected $100 OT premium, got $${otPremium}`);
});

// ── Hire payload: salary fields populate correctly ─────────────────────────

test('Paycom hire payload uses payFrequency=salary + rate=annualSalary for salaried', () => {
  const emp = {
    id:'e_sal2', name:'Salaried Senior', group:'Office', buildingId:'b1',
    payType:'salaried', annualSalary: 85000, hireDate:'2026-01-15',
    email:'sal@example.test', phone:'555-0100',
  };
  // Set up paycom config
  App._payrollState('paycom').companyCode = 'TEST';
  const payload = App._buildHirePayload('paycom', emp);
  assert.equal(payload.compensation.payFrequency, 'salary');
  assert.equal(payload.compensation.rate, 85000);
});

test('Paycom hire payload still uses payFrequency=hourly for hourly emps', () => {
  const emp = {
    id:'e_h2', name:'Hourly H', group:'CNA', buildingId:'b1',
    payType:'hourly', hourlyRate: 22, hireDate:'2026-01-15',
  };
  const payload = App._buildHirePayload('paycom', emp);
  assert.equal(payload.compensation.payFrequency, 'hourly');
  assert.equal(payload.compensation.rate, 22);
});

test('ADP hire payload uses annualRateAmount for salaried', () => {
  const emp = {
    id:'e_sal3', name:'Sally Salaried', group:'Office', buildingId:'b1',
    payType:'salaried', annualSalary: 92000, hireDate:'2026-01-15',
  };
  const payload = App._buildHirePayload('adp', emp);
  const remun = payload.events[0].data.transform.worker.workAssignment.baseRemuneration;
  assert.ok(remun.annualRateAmount, 'should have annualRateAmount');
  assert.equal(remun.annualRateAmount.amountValue, 92000);
  assert.equal(remun.payCycleCode.codeValue, 'salary');
  assert.equal(remun.hourlyRateAmount, undefined, 'hourlyRateAmount should be omitted');
});

test('ADP hire payload still uses hourlyRateAmount for hourly', () => {
  const emp = {
    id:'e_h3', name:'Henry Hourly', group:'CNA', buildingId:'b1',
    payType:'hourly', hourlyRate: 24.5,
  };
  const payload = App._buildHirePayload('adp', emp);
  const remun = payload.events[0].data.transform.worker.workAssignment.baseRemuneration;
  assert.ok(remun.hourlyRateAmount);
  assert.equal(remun.hourlyRateAmount.amountValue, 24.5);
  assert.equal(remun.payCycleCode.codeValue, 'hourly');
  assert.equal(remun.annualRateAmount, undefined);
});

// ── Hire push validation accepts salaried ──────────────────────────────────

test('pushHireToPayroll accepts a salaried employee with annualSalary set', async () => {
  // Need paycom connected
  const pcState = App._payrollState('paycom');
  pcState.configured = true;
  pcState.status = 'connected';
  pcState.mode = 'sandbox';
  pcState.clientId = 'x'; pcState.clientSecret = 'x'; pcState.companyCode = 'TEST';

  App.S.employees = [{
    id:'e_sal4', name:'Sal Saluto', group:'Office', buildingId:'b1', inactive:false,
    payType:'salaried', annualSalary: 78000, hireDate:'2026-01-01',
  }];
  const ok = await App.pushHireToPayroll('e_sal4', 'paycom');
  assert.equal(ok, true, 'salaried emp with salary set should push successfully');
  assert.ok(App.S.employees[0].payrollIds?.paycom);
});

test('pushHireToPayroll rejects salaried emp with no annualSalary', async () => {
  App.S.employees = [{
    id:'e_sal5', name:'Sal Empty', group:'Office', buildingId:'b1', inactive:false,
    payType:'salaried',  // no annualSalary
  }];
  let warned = false;
  const orig = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn' && /salary/i.test(msg)) warned = true; };
  const ok = await App.pushHireToPayroll('e_sal5', 'paycom');
  App.showToast = orig;
  assert.equal(ok, false);
  assert.equal(warned, true, 'should warn about missing annual salary');
});

// ── Inline rate edit works for both pay types ──────────────────────────────

test('empCardSaveRate writes to annualSalary when emp is salaried', () => {
  App.S.employees = [{
    id:'e_sw', name:'Switch Test', group:'Office', buildingId:'b1', inactive:false,
    payType:'salaried', annualSalary: 60000,
  }];
  // Open card so the rate-input element exists in our fakeEl router
  inserted.length = 0;
  App.openEmployeeCard('e_sw');
  // Override the input to return the new value
  const origGet = sandbox.document.getElementById;
  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_sw') return { value: '72000' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_sw');
  sandbox.document.getElementById = origGet;
  assert.equal(App.S.employees[0].annualSalary, 72000, 'annualSalary should update');
  assert.equal(App.S.employees[0].hourlyRate,   undefined, 'hourly should remain unset');
});

test('empCardSwitchPayType toggles payType + preserves the prior-mode value', () => {
  App.S.employees = [{
    id:'e_toggle', name:'Toggle', group:'Office', buildingId:'b1', inactive:false,
    payType:'hourly', hourlyRate: 40,
  }];
  inserted.length = 0;
  App.empCardSwitchPayType('e_toggle');
  assert.equal(App.S.employees[0].payType, 'salaried');
  // Old hourly rate preserved on file
  assert.equal(App.S.employees[0].hourlyRate, 40);
  // No annual salary yet → not "salaried" by _isSalaried check
  assert.equal(App._isSalaried(App.S.employees[0]), false, 'no salary set yet');
  // Switch back
  App.empCardSwitchPayType('e_toggle');
  assert.equal(App.S.employees[0].payType, 'hourly');
  assert.equal(App.S.employees[0].hourlyRate, 40, 'rate still preserved');
});

// ── PPD daily metrics include salaried ─────────────────────────────────────

test('_ppdMetricsForDay daily cost includes salaried portion', () => {
  App.S.employees = [
    { id:'e_don2', name:'DON', group:'Nurse Management', buildingId:'b1', inactive:false,
      payType:'salaried', annualSalary: 109500 },  // $300/day
    { id:'e_h4', name:'CN', group:'Charge Nurse', buildingId:'b1', inactive:false,
      payType:'hourly', hourlyRate: 35 },
  ];
  App.S.shifts = [
    { id:'s1', date:'2026-05-12', group:'Charge Nurse', type:'Day',
      start:'7:00 AM', end:'3:00 PM', status:'scheduled',
      buildingId:'b1', employeeId:'e_h4' },
  ];
  const m = App._ppdMetricsForDay('b1', '2026-05-12');
  // Expected: $300 (DON salary) + 8 hrs × $35 ($280 hourly) = $580
  assert.ok(Math.abs(m.dailyCost - 580) < 0.01,
    `expected $580 daily cost, got $${m.dailyCost}`);
});

test('summary report for salaried + hourly mixed building', () => {
  App.S.employees = [
    { id:'e_don3',  name:'DON',     group:'Nurse Management', buildingId:'b1', inactive:false,
      payType:'salaried', annualSalary: 109500 },
    { id:'e_adon3', name:'ADON',    group:'Nurse Management', buildingId:'b1', inactive:false,
      payType:'salaried', annualSalary: 73000  },
    { id:'e_cn3',   name:'CN',      group:'Charge Nurse',     buildingId:'b1', inactive:false,
      payType:'hourly',   hourlyRate: 32       },
  ];
  App.S.shifts = [];  // no shifts
  const cost = App._dailyCostForGroups('b1', '2026-05-12',
    ['Nurse Management','Charge Nurse','CNA','CMA']);
  // Expected: 109500/365 + 73000/365 = 300 + 200 = $500
  assert.ok(Math.abs(cost - 500) < 0.01,
    `expected $500 (300 + 200) salaried daily cost with no hourly shifts, got $${cost}`);
  console.log(`\n──── SALARIED COST SUMMARY ────`);
  console.log(`  DON salary $109,500 → $${(109500/365).toFixed(2)}/day`);
  console.log(`  ADON salary $73,000 → $${(73000/365).toFixed(2)}/day`);
  console.log(`  Total (no hourly shifts): $${cost.toFixed(2)}/day`);
  console.log(`──────────────────────────────\n`);
});
