'use strict';
/**
 * Sandbox test for the pinned text-blast groups (Nurses, CNAs, CMAs).
 *
 * Verifies:
 *   - _ensureTextGroups seeds the three default groups exactly once
 *   - _resolveTextGroupMembers unions autoFromGroups + manual memberIds,
 *     scoped to the active building, and respects excludedIds
 *   - addToTextGroup / removeFromTextGroup mutate state correctly
 *   - removing an auto-included member adds them to excludedIds (so they
 *     stay removed across re-renders)
 *   - re-adding an excluded member clears the exclusion
 *
 * Run with: node --test --test-concurrency=1 tests/text-groups.test.js
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
    children:[], parentNode:null, dataset:{}, remove(){},
  });
  const document = {
    getElementById: () => fakeEl(),
    querySelector: () => fakeEl(),
    querySelectorAll: () => [],
    createElement: () => fakeEl(),
    body: { appendChild(){}, removeChild(){} },
    head: fakeEl(),
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
App._renderTextGroupPanel = () => {};

// Seed
App.S.user = { id:'u_test', role:'admin', buildingId:'b1' };
App.S.buildings = [{ id:'b1', name:'Test SNF' }];
App.S.employees = [
  { id:'e_n1', name:'Nina Nurse',     initials:'NN', group:'Charge Nurse',    buildingId:'b1', inactive:false },
  { id:'e_n2', name:'Norman Nurse',   initials:'NO', group:'Nurse Management',buildingId:'b1', inactive:false },
  { id:'e_n3', name:'Nora Nurse',     initials:'NR', group:'RN',              buildingId:'b1', inactive:false },
  { id:'e_c1', name:'Carlos CNA',     initials:'CC', group:'CNA',             buildingId:'b1', inactive:false },
  { id:'e_c2', name:'Carla CNA',      initials:'CA', group:'CNA',             buildingId:'b1', inactive:false },
  { id:'e_m1', name:'Miguel CMA',     initials:'MC', group:'CMA',             buildingId:'b1', inactive:false },
  { id:'e_h1', name:'Helen Housekeep',initials:'HH', group:'Housekeeping',    buildingId:'b1', inactive:false },
  { id:'e_other', name:'Other Bldg',  initials:'OB', group:'CNA',             buildingId:'b2', inactive:false },
  { id:'e_inact', name:'Inactive Person',initials:'IP',group:'CNA',           buildingId:'b1', inactive:true },
];
App.S.textGroups = null;

// ── Tests ──────────────────────────────────────────────────────────────────

test('_ensureTextGroups seeds three pinned default groups', () => {
  App.S.textGroups = null;
  App._ensureTextGroups();
  assert.equal(App.S.textGroups.length, 3);
  const names = App.S.textGroups.map(g => g.name);
  assert.ok(names.includes('Nurses'));
  assert.ok(names.includes('CNAs'));
  assert.ok(names.includes('CMAs'));
});

test('_ensureTextGroups is idempotent (does not duplicate on re-call)', () => {
  App._ensureTextGroups();
  App._ensureTextGroups();
  App._ensureTextGroups();
  assert.equal(App.S.textGroups.length, 3);
});

test('Nurses group auto-includes Nurse Management, Charge Nurse, RN, LPN', () => {
  App._ensureTextGroups();
  const nurses = App.S.textGroups.find(g => g.name === 'Nurses');
  const memberIds = App._resolveTextGroupMembers(nurses);
  // Should include all 3 nurse seed records (Charge Nurse, Nurse Mgmt, RN)
  assert.ok(memberIds.includes('e_n1'));
  assert.ok(memberIds.includes('e_n2'));
  assert.ok(memberIds.includes('e_n3'));
  // Should NOT include CNAs/CMAs/Housekeeping
  assert.ok(!memberIds.includes('e_c1'));
  assert.ok(!memberIds.includes('e_m1'));
  assert.ok(!memberIds.includes('e_h1'));
});

test('CNAs group auto-includes only CNAs', () => {
  const cnas = App.S.textGroups.find(g => g.name === 'CNAs');
  const memberIds = App._resolveTextGroupMembers(cnas);
  assert.equal(memberIds.length, 2);  // e_c1, e_c2 (e_other is wrong building, e_inact is inactive)
  assert.ok(memberIds.includes('e_c1'));
  assert.ok(memberIds.includes('e_c2'));
});

test('CMAs group auto-includes only CMAs', () => {
  const cmas = App.S.textGroups.find(g => g.name === 'CMAs');
  const memberIds = App._resolveTextGroupMembers(cmas);
  assert.equal(memberIds.length, 1);
  assert.ok(memberIds.includes('e_m1'));
});

test('resolveTextGroupMembers excludes inactive employees', () => {
  // e_inact is a CNA but inactive — shouldn't appear
  const cnas = App.S.textGroups.find(g => g.name === 'CNAs');
  const memberIds = App._resolveTextGroupMembers(cnas);
  assert.ok(!memberIds.includes('e_inact'));
});

test('resolveTextGroupMembers excludes other-building employees', () => {
  // e_other is a CNA at b2 — shouldn't appear when active building is b1
  const cnas = App.S.textGroups.find(g => g.name === 'CNAs');
  const memberIds = App._resolveTextGroupMembers(cnas);
  assert.ok(!memberIds.includes('e_other'));
});

test('addToTextGroup adds an employee to a group', () => {
  // Add a Housekeeper to the Nurses group (manual addition)
  App.addToTextGroup('tg_nurses', 'e_h1');
  const nurses = App.S.textGroups.find(g => g.id === 'tg_nurses');
  assert.ok(nurses.memberIds.includes('e_h1'));
  // Should now resolve to include Helen
  const memberIds = App._resolveTextGroupMembers(nurses);
  assert.ok(memberIds.includes('e_h1'));
});

test('removeFromTextGroup removes auto-included member via excludedIds', () => {
  // Remove e_n1 (Charge Nurse) from Nurses group — should add to excludedIds
  App.removeFromTextGroup('tg_nurses', 'e_n1');
  const nurses = App.S.textGroups.find(g => g.id === 'tg_nurses');
  assert.ok(nurses.excludedIds.includes('e_n1'));
  const memberIds = App._resolveTextGroupMembers(nurses);
  assert.ok(!memberIds.includes('e_n1'),
    'auto-included member should disappear after removal');
  // Other auto-members still there
  assert.ok(memberIds.includes('e_n2'));
  assert.ok(memberIds.includes('e_n3'));
});

test('re-adding a previously excluded member clears exclusion', () => {
  App.addToTextGroup('tg_nurses', 'e_n1');
  const nurses = App.S.textGroups.find(g => g.id === 'tg_nurses');
  assert.ok(!nurses.excludedIds.includes('e_n1'),
    'excludedIds should no longer contain re-added member');
  const memberIds = App._resolveTextGroupMembers(nurses);
  assert.ok(memberIds.includes('e_n1'));
});

test('removeFromTextGroup with manual member fully removes them', () => {
  // e_h1 was manually added to nurses. Remove them — should be gone.
  App.removeFromTextGroup('tg_nurses', 'e_h1');
  const nurses = App.S.textGroups.find(g => g.id === 'tg_nurses');
  assert.ok(!nurses.memberIds.includes('e_h1'));
  const memberIds = App._resolveTextGroupMembers(nurses);
  assert.ok(!memberIds.includes('e_h1'));
});

test('groupLabel renames Office → Administration', () => {
  // groupLabel is a top-level const inside the bundled script, so we evaluate
  // it via the same VM context rather than reaching into the sandbox object.
  assert.equal(vm.runInContext("groupLabel('Office')",          sandbox), 'Administration');
  assert.equal(vm.runInContext("groupLabel('CNA')",             sandbox), 'CNA');
  assert.equal(vm.runInContext("groupLabel('Charge Nurse')",    sandbox), 'Charge Nurse');
  assert.equal(vm.runInContext("groupLabel('Nurse Management')",sandbox), 'Nurse Management');
});

test('summary report: pinned group counts', () => {
  // Reset to clean state
  App.S.textGroups = null;
  App._ensureTextGroups();
  const summary = {};
  for (const g of App.S.textGroups) {
    summary[g.name] = App._resolveTextGroupMembers(g).length;
  }
  console.log('\n──── PINNED TEXT GROUP COUNTS ────');
  for (const [name, n] of Object.entries(summary)) console.log(`  ${name}: ${n}`);
  console.log('──────────────────────────────────\n');
  assert.equal(summary['Nurses'], 3);
  assert.equal(summary['CNAs'],   2);
  assert.equal(summary['CMAs'],   1);
});
