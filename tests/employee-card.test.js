'use strict';
/**
 * Sandbox test for the employee card modal opened from the roster.
 *
 * Verifies:
 *   - openEmployeeCard exists and finds the employee
 *   - The modal HTML is built and inserted into the DOM
 *   - Key fields render: name, role, email, phone, hire date, hourly rate
 *   - Termination + discipline sections appear when data is present
 *   - Paycom/ADP IDs render when set
 *   - Inactive employees show "Inactive" pill and a Reactivate button
 *   - Missing fields render as a dash, not crash
 *
 * Run with: node --test --test-concurrency=1 tests/employee-card.test.js
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

// Build a sandbox where document.body really collects appendChild children.
// This lets us assert on the HTML the modal injected.
function buildSandbox() {
  const _store = {};
  const localStorage = {
    getItem: k => (k in _store ? _store[k] : null),
    setItem: (k, v) => { _store[k] = String(v); },
    removeItem: k => { delete _store[k]; },
    clear: () => { for (const k of Object.keys(_store)) delete _store[k]; },
  };
  const inserted = []; // tracks elements appended to document.body
  const fakeEl = (tag) => ({
    tagName: (tag||'div').toUpperCase(),
    id: '',
    className: '',
    innerHTML: '',
    style:{}, classList:{ add(){}, remove(){}, toggle(){}, contains:()=>false },
    setAttribute(){}, removeAttribute(){}, getAttribute:()=>null,
    appendChild(){}, removeChild(){}, querySelector:()=>null, querySelectorAll:()=>[],
    addEventListener(){}, removeEventListener(){}, click(){}, focus(){}, blur(){},
    textContent:'', value:'', checked:false, disabled:false,
    children:[], parentNode:null, dataset:{}, remove(){},
  });
  const body = {
    style: {},
    appendChild(el) { inserted.push(el); el.parentNode = body; },
    removeChild(el) {
      const i = inserted.indexOf(el);
      if (i >= 0) inserted.splice(i, 1);
    },
  };
  const document = {
    getElementById(id) {
      // Return inserted elements when queried by id (for `?.remove()` calls)
      const found = inserted.find(e => e.id === id);
      if (found) {
        found.remove = () => body.removeChild(found);
        return found;
      }
      return fakeEl();
    },
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: (tag) => fakeEl(tag),
    body,
    head: fakeEl(),
    addEventListener: () => {},
    documentElement: { setAttribute(){}, style:{} },
    cookie: '',
    _inserted: inserted,
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

// Seed
App.S.user = { id:'u_test', role:'superadmin', buildingId:'b1' };
App.S.buildings = [{ id:'b1', name:'Test SNF' }];
App.S.shifts = [];
App.S.schedulePatterns = [];

function getCardHtml() {
  const card = inserted.find(e => e.id === 'modal-employee-card');
  return card ? card.innerHTML : null;
}
function clearCard() {
  const i = inserted.findIndex(e => e.id === 'modal-employee-card');
  if (i >= 0) inserted.splice(i, 1);
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('openEmployeeCard exists as a method', () => {
  assert.equal(typeof App.openEmployeeCard, 'function');
});

test('renders the basic card with name, role, building', () => {
  App.S.employees = [{
    id:'e_alice', name:'Alice Anderson', initials:'AA',
    group:'Charge Nurse', email:'alice@example.test', phone:'555-0100',
    hireDate:'2024-03-15', dob:'1990-06-01', hourlyRate:32,
    buildingId:'b1', inactive:false,
  }];
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html, 'modal should be inserted');
  assert.ok(html.includes('Alice Anderson'), 'name should render');
  assert.ok(html.includes('Charge Nurse'),   'role should render');
  assert.ok(html.includes('Test SNF'),       'building should render');
  assert.ok(html.includes('alice@example.test'), 'email should render');
  assert.ok(html.includes('555-0100'),       'phone should render');
  assert.ok(html.includes('March 15, 2024'), 'hire date should be formatted');
  assert.ok(html.includes('$32.00'),         'hourly rate should render');
  assert.ok(html.includes('Active'),         'active pill should render');
});

test('shows tenure derived from hire date', () => {
  // hireDate=2024-03-15 + today=2026-05-06 → roughly 2 yr 1 mo
  const html = getCardHtml();
  assert.ok(/\d+ yr/.test(html), 'tenure in years should appear');
});

test('shows age derived from DOB', () => {
  const html = getCardHtml();
  // dob=1990-06-01, today around 2026 → age ~35
  assert.ok(/age \d+/.test(html), 'age computed from DOB should appear');
});

test('renders Paycom + ADP IDs when present', () => {
  App.S.employees[0].payrollIds = { paycom: 'PYC-123456', adp: 'ADP-789012' };
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('PYC-123456'), 'Paycom ID should appear');
  assert.ok(html.includes('ADP-789012'), 'ADP ID should appear');
});

test('shows termination history when present', () => {
  App.S.employees[0].terminationLog = [
    { date:'2025-01-15', reason:'voluntary', notes:'Moved out of state' },
  ];
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('Termination History'));
  assert.ok(html.includes('voluntary'));
  assert.ok(html.includes('Moved out of state'));
});

test('shows disciplinary actions when present', () => {
  App.S.employees[0].disciplineActions = [
    { date:'2025-06-10', type:'verbal warning', notes:'Late 3 times in 2 weeks' },
  ];
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('Disciplinary Actions'));
  assert.ok(html.includes('verbal warning'));
  assert.ok(html.includes('Late 3 times'));
});

test('inactive employee gets Inactive pill and Reactivate button', () => {
  App.S.employees[0].inactive = true;
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('Inactive'),        'Inactive pill should render');
  assert.ok(html.includes('Reactivate'),      'Reactivate button should appear');
  assert.ok(!html.includes('>Inactivate<'),   'Inactivate button should NOT appear for inactive emp');
  // restore
  App.S.employees[0].inactive = false;
});

test('schedule snapshot includes hours-this-week and shift count', () => {
  // Add some scheduled shifts in the current week
  const today = new Date();
  const nextWeek = new Date(today); nextWeek.setDate(today.getDate() + 7);
  App.S.shifts = [
    { id:'s1', date: today.toISOString().slice(0,10),
      group:'Charge Nurse', type:'Day', status:'scheduled',
      buildingId:'b1', employeeId:'e_alice',
      start:'7:00 AM', end:'3:00 PM' },
    { id:'s2', date: nextWeek.toISOString().slice(0,10),
      group:'Charge Nurse', type:'Day', status:'scheduled',
      buildingId:'b1', employeeId:'e_alice',
      start:'7:00 AM', end:'3:00 PM' },
  ];
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('Hours this week'));
  assert.ok(html.includes('Shifts next 30 days'));
  // Should be 2 shifts total in next 30 days
  assert.ok(/Shifts next 30 days[^>]*>[\s\S]*?>2</.test(html) || html.includes('>2<'),
    'should show shift count');
});

test('shows active rotation when schedulePatterns has entry for emp', () => {
  App.S.schedulePatterns = [{
    id:'pat1', kind:'assign', empId:'e_alice', buildingId:'b1',
    group:'Charge Nurse', shiftType:'Day', selectedDays:[2,3,9,10],
    cycleLen:14, appliedAt:'2026-04-01',
  }];
  clearCard();
  App.openEmployeeCard('e_alice');
  const html = getCardHtml();
  assert.ok(html.includes('Active rotation'));
  assert.ok(html.includes('4-day rotation'),  'should describe pattern length');
});

test('missing fields render as dash, no crash', () => {
  App.S.employees.push({
    id:'e_min', name:'Minimal Person', initials:'MP',
    group:'CNA', buildingId:'b1', inactive:false,
    // no email, phone, hireDate, dob, hourlyRate, etc.
  });
  clearCard();
  App.openEmployeeCard('e_min');
  const html = getCardHtml();
  assert.ok(html.includes('Minimal Person'), 'name should still render');
  assert.ok(html.includes('CNA'),            'role should still render');
  assert.ok(html.includes('—'),              'dashes should appear for missing fields');
});

test('empCardSaveRate updates emp.hourlyRate to a new positive value', () => {
  App.S.employees = [{
    id:'e_rate', name:'Rate Tester', initials:'RT',
    group:'CNA', buildingId:'b1', inactive:false, hourlyRate: 20,
  }];
  clearCard();
  App.openEmployeeCard('e_rate');
  // Simulate the user typing 27.50 into the input and clicking Save.
  // The input is built into the card's HTML — we override the document
  // stub to return a value when the save handler reads it.
  const origGet = sandbox.document.getElementById;
  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_rate') return { value: '27.50' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_rate');
  sandbox.document.getElementById = origGet;
  assert.equal(App.S.employees[0].hourlyRate, 27.5, 'hourlyRate should be updated');
});

test('empCardSaveRate rejects negative or non-numeric input', () => {
  App.S.employees[0].hourlyRate = 25;
  const origGet = sandbox.document.getElementById;
  let warned = false;
  const origToast = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn') warned = true; };

  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_rate') return { value: 'abc' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_rate');
  assert.equal(App.S.employees[0].hourlyRate, 25, 'rate should not change on invalid input');
  assert.equal(warned, true, 'should warn on invalid input');

  warned = false;
  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_rate') return { value: '-5' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_rate');
  assert.equal(App.S.employees[0].hourlyRate, 25, 'rate should not change on negative input');
  assert.equal(warned, true);

  warned = false;
  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_rate') return { value: '5000' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_rate');
  assert.equal(App.S.employees[0].hourlyRate, 25, 'rate should not change on absurdly high input');
  assert.equal(warned, true);

  sandbox.document.getElementById = origGet;
  App.showToast = origToast;
});

test('empCardSaveRate with blank input clears the rate', () => {
  App.S.employees[0].hourlyRate = 25;
  const origGet = sandbox.document.getElementById;
  sandbox.document.getElementById = (id) => {
    if (id === 'empcard-rate-input-e_rate') return { value: '' };
    return origGet.call(sandbox.document, id);
  };
  App.empCardSaveRate('e_rate');
  sandbox.document.getElementById = origGet;
  assert.equal(App.S.employees[0].hourlyRate, undefined, 'rate should be cleared');
});

test('unknown empId shows toast warning, no modal', () => {
  let warned = false;
  const origToast = App.showToast;
  App.showToast = (msg, type) => { if (type === 'warn') warned = true; };
  clearCard();
  App.openEmployeeCard('does-not-exist');
  App.showToast = origToast;
  assert.equal(warned, true, 'should warn for unknown employee');
  assert.equal(getCardHtml(), null, 'no modal should be inserted');
});
