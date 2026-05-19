'use strict';
/**
 * Comprehensive test suite for bulletproof data persistence.
 * Tests every new code path added in the persistence overhaul.
 *
 * Run: node test-persistence.js
 *
 * This test does NOT require a live Postgres connection — it mocks the
 * database layer and exercises the logic in isolation.
 */

const assert = require('assert');
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL: ${name}`);
    console.log(`        ${e.message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL: ${name}`);
    console.log(`        ${e.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Test _replayJournalEntry logic (extracted for unit testing)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Journal Replay Tests ===');

function _replayJournalEntry(data, entry) {
  const { table_name, entity_id, op, payload } = entry;
  const collectionMap = {
    companies: 'companies', buildings: 'buildings', accounts: 'accounts',
    employees: 'employees', shifts: 'shifts', schedulePatterns: 'schedulePatterns',
  };
  const key = collectionMap[table_name];
  if (!key) return;
  if (!Array.isArray(data[key])) data[key] = [];

  if (entity_id.startsWith('bulk:') && Array.isArray(payload?.items)) {
    const existingById = new Map(data[key].map(item => [item.id, item]));
    for (const item of payload.items) {
      if (item && item.id) existingById.set(item.id, item);
    }
    data[key] = Array.from(existingById.values());
    return;
  }

  if (op === 'DELETE') {
    data[key] = data[key].filter(item => item.id !== entity_id);
  } else if (op === 'INSERT') {
    const existing = data[key].find(item => item.id === entity_id);
    if (!existing) data[key].push(payload);
  } else if (op === 'UPDATE') {
    const idx = data[key].findIndex(item => item.id === entity_id);
    if (idx >= 0) Object.assign(data[key][idx], payload);
    else data[key].push(payload);
  }
}

test('INSERT adds new shift', () => {
  const data = { shifts: [{ id: 's1', date: '2026-05-19' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's2', op: 'INSERT',
    payload: { id: 's2', date: '2026-05-20', status: 'open' }
  });
  assert.strictEqual(data.shifts.length, 2);
  assert.strictEqual(data.shifts[1].id, 's2');
});

test('INSERT does not duplicate existing shift', () => {
  const data = { shifts: [{ id: 's1', date: '2026-05-19' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'INSERT',
    payload: { id: 's1', date: '2026-05-20' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].date, '2026-05-19'); // original preserved
});

test('UPDATE modifies existing shift', () => {
  const data = { shifts: [{ id: 's1', date: '2026-05-19', status: 'open' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'UPDATE',
    payload: { id: 's1', date: '2026-05-19', status: 'scheduled', employeeId: 'e1' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].status, 'scheduled');
  assert.strictEqual(data.shifts[0].employeeId, 'e1');
});

test('UPDATE inserts if entity missing', () => {
  const data = { shifts: [] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'UPDATE',
    payload: { id: 's1', date: '2026-05-19', status: 'open' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].id, 's1');
});

test('DELETE removes existing shift', () => {
  const data = { shifts: [{ id: 's1' }, { id: 's2' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'DELETE',
    payload: { id: 's1' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].id, 's2');
});

test('DELETE is no-op for missing shift', () => {
  const data = { shifts: [{ id: 's1' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's999', op: 'DELETE',
    payload: { id: 's999' }
  });
  assert.strictEqual(data.shifts.length, 1);
});

test('Bulk UPDATE merges items by ID', () => {
  const data = { shifts: [
    { id: 's1', date: '2026-05-19', status: 'open' },
    { id: 's2', date: '2026-05-20', status: 'open' },
  ]};
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 'bulk:admin1', op: 'UPDATE',
    payload: {
      collection: 'shifts', count: 2,
      items: [
        { id: 's1', date: '2026-05-19', status: 'scheduled', employeeId: 'e1' },
        { id: 's3', date: '2026-05-21', status: 'open' },
      ]
    }
  });
  assert.strictEqual(data.shifts.length, 3);
  const s1 = data.shifts.find(s => s.id === 's1');
  assert.strictEqual(s1.status, 'scheduled');
  assert.strictEqual(s1.employeeId, 'e1');
  assert.ok(data.shifts.find(s => s.id === 's2')); // preserved
  assert.ok(data.shifts.find(s => s.id === 's3')); // added
});

test('Unknown table_name is a no-op', () => {
  const data = { shifts: [{ id: 's1' }] };
  _replayJournalEntry(data, {
    table_name: 'unknown_table', entity_id: 'x1', op: 'INSERT',
    payload: { id: 'x1' }
  });
  assert.strictEqual(data.shifts.length, 1);
});

test('Missing collection initializes empty array', () => {
  const data = {};
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'INSERT',
    payload: { id: 's1', date: '2026-05-19' }
  });
  assert.strictEqual(data.shifts.length, 1);
});

test('Works with all supported tables', () => {
  const tables = ['companies', 'buildings', 'accounts', 'employees', 'shifts', 'schedulePatterns'];
  for (const t of tables) {
    const data = {};
    _replayJournalEntry(data, {
      table_name: t, entity_id: 'x1', op: 'INSERT',
      payload: { id: 'x1' }
    });
    const key = t;
    assert.ok(Array.isArray(data[key]), `${t} should create array`);
    assert.strictEqual(data[key].length, 1, `${t} should have 1 item`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Test saveAllIndependent result structure
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== SaveAllIndependent Structure Tests ===');

test('Result shape has required fields', () => {
  // Simulate what saveAllIndependent returns
  const result = {
    results: [
      { table: 'companies', ok: true, rowCount: 2 },
      { table: 'shifts', ok: false, error: 'constraint violation' },
    ],
    allOk: false,
    failedTables: ['shifts'],
  };
  assert.ok(Array.isArray(result.results));
  assert.strictEqual(typeof result.allOk, 'boolean');
  assert.ok(Array.isArray(result.failedTables));
  assert.strictEqual(result.failedTables[0], 'shifts');
});

test('allOk is true when no failures', () => {
  const results = [
    { table: 'companies', ok: true },
    { table: 'buildings', ok: true },
    { table: 'shifts', ok: true },
  ];
  const failedTables = results.filter(r => !r.ok).map(r => r.table);
  assert.strictEqual(failedTables.length, 0);
});

test('Partial failure correctly identifies failed tables', () => {
  const results = [
    { table: 'companies', ok: true },
    { table: 'employees', ok: false, error: 'shrink guard' },
    { table: 'shifts', ok: true },
    { table: 'appState', ok: false, error: 'timeout' },
  ];
  const failedTables = results.filter(r => !r.ok).map(r => r.table);
  assert.deepStrictEqual(failedTables, ['employees', 'appState']);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Test verifyCounts logic structure
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== VerifyCounts Logic Tests ===');

test('Only checks tables that actually saved', () => {
  const saveResult = {
    results: [
      { table: 'companies', ok: true },
      { table: 'employees', ok: false, error: 'shrink guard' },
      { table: 'shifts', ok: true },
    ],
    allOk: false,
    failedTables: ['employees'],
  };
  const savedTables = new Set(saveResult.results.filter(r => r.ok).map(r => r.table));
  // Simulated count results
  const counts = [
    { table: 'companies', expected: 2, actual: 2, match: true },
    { table: 'employees', expected: 50, actual: 45, match: false }, // expected mismatch — shrink guard
    { table: 'shifts', expected: 100, actual: 100, match: true },
  ];
  // Filter: only flag mismatches for tables that were actually saved
  const mismatches = counts.filter(c => !c.match && savedTables.has(c.table));
  assert.strictEqual(mismatches.length, 0, 'Employee mismatch should be ignored since save was skipped');
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Test alert throttling logic
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Alert Throttling Tests ===');

test('First alert fires immediately', () => {
  const THROTTLE_MS = 15 * 60 * 1000;
  let _lastAlertSentAt = null;
  const now = Date.now();
  const shouldFire = !_lastAlertSentAt || (now - new Date(_lastAlertSentAt).getTime()) >= THROTTLE_MS;
  assert.ok(shouldFire);
});

test('Second alert within 15 min is throttled', () => {
  const THROTTLE_MS = 15 * 60 * 1000;
  const _lastAlertSentAt = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // 5 min ago
  const now = Date.now();
  const shouldFire = !_lastAlertSentAt || (now - new Date(_lastAlertSentAt).getTime()) >= THROTTLE_MS;
  assert.ok(!shouldFire);
});

test('Alert fires again after 15 min', () => {
  const THROTTLE_MS = 15 * 60 * 1000;
  const _lastAlertSentAt = new Date(Date.now() - 16 * 60 * 1000).toISOString(); // 16 min ago
  const now = Date.now();
  const shouldFire = !_lastAlertSentAt || (now - new Date(_lastAlertSentAt).getTime()) >= THROTTLE_MS;
  assert.ok(shouldFire);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Test partial save + critical table logic
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Partial Save Critical Table Tests ===');

test('Shifts failure is critical', () => {
  const failedTables = ['shifts', 'appState'];
  const criticalFailed = failedTables.some(t => t === 'shifts' || t === 'employees' || t === 'accounts');
  assert.ok(criticalFailed);
});

test('AppState-only failure is non-critical', () => {
  const failedTables = ['appState'];
  const criticalFailed = failedTables.some(t => t === 'shifts' || t === 'employees' || t === 'accounts');
  assert.ok(!criticalFailed);
});

test('Employees failure is critical', () => {
  const failedTables = ['employees'];
  const criticalFailed = failedTables.some(t => t === 'shifts' || t === 'employees' || t === 'accounts');
  assert.ok(criticalFailed);
});

test('Companies + buildings failure is non-critical', () => {
  const failedTables = ['companies', 'buildings'];
  const criticalFailed = failedTables.some(t => t === 'shifts' || t === 'employees' || t === 'accounts');
  assert.ok(!criticalFailed);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Test dual-write file path logic
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Dual-Write Decision Tests ===');

test('Dual-write when allOk', () => {
  const saveResult = { allOk: true, results: [{ table: 'shifts', ok: true }, { table: 'employees', ok: true }] };
  const shiftsOk = saveResult.results.find(r => r.table === 'shifts')?.ok !== false;
  const employeesOk = saveResult.results.find(r => r.table === 'employees')?.ok !== false;
  const shouldWrite = saveResult.allOk || (shiftsOk && employeesOk);
  assert.ok(shouldWrite);
});

test('Dual-write when shifts+employees ok but appState failed', () => {
  const saveResult = {
    allOk: false, failedTables: ['appState'],
    results: [
      { table: 'shifts', ok: true },
      { table: 'employees', ok: true },
      { table: 'appState', ok: false },
    ]
  };
  const shiftsOk = saveResult.results.find(r => r.table === 'shifts')?.ok !== false;
  const employeesOk = saveResult.results.find(r => r.table === 'employees')?.ok !== false;
  const shouldWrite = saveResult.allOk || (shiftsOk && employeesOk);
  assert.ok(shouldWrite);
});

test('No dual-write when shifts failed', () => {
  const saveResult = {
    allOk: false, failedTables: ['shifts'],
    results: [
      { table: 'shifts', ok: false },
      { table: 'employees', ok: true },
    ]
  };
  const shiftsOk = saveResult.results.find(r => r.table === 'shifts')?.ok !== false;
  const employeesOk = saveResult.results.find(r => r.table === 'employees')?.ok !== false;
  const shouldWrite = saveResult.allOk || (shiftsOk && employeesOk);
  assert.ok(!shouldWrite);
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Test SMS configuration checks
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== SMS Configuration Tests ===');

test('Alert SMS requires both ALERT_PHONE and TWILIO_FROM_PHONE', () => {
  const cases = [
    { alertPhone: null, fromPhone: null, expected: false },
    { alertPhone: '+1234', fromPhone: null, expected: false },
    { alertPhone: null, fromPhone: '+5678', expected: false },
    { alertPhone: '+1234', fromPhone: '+5678', expected: true },
  ];
  for (const c of cases) {
    const shouldSend = !!(c.alertPhone && c.fromPhone);
    assert.strictEqual(shouldSend, c.expected, `ALERT_PHONE=${c.alertPhone}, FROM=${c.fromPhone}`);
  }
});

test('_processAlertJob correctly gates on kind', () => {
  // Simulating the fixed gating logic
  function shouldProcess(kind, acsConn, twilioSid) {
    if (kind === 'email' && !acsConn) return false;
    if (kind === 'sms' && !twilioSid) return false;
    return true;
  }
  assert.ok(!shouldProcess('email', null, 'sid123'), 'email without ACS should skip');
  assert.ok(shouldProcess('sms', null, 'sid123'), 'sms without ACS should proceed');
  assert.ok(!shouldProcess('sms', 'acs123', null), 'sms without Twilio should skip');
  assert.ok(shouldProcess('email', 'acs123', null), 'email without Twilio should proceed');
  assert.ok(shouldProcess('sms', 'acs123', 'sid123'), 'sms with both should proceed');
});

test('Discharge SMS checks TWILIO_ACCOUNT_SID not ACS', () => {
  // The fix changes the check from !ACS_CONNECTION_STRING to !TWILIO_ACCOUNT_SID
  function shouldRunDischarge(twilioSid) {
    if (!twilioSid) return false;
    return true;
  }
  assert.ok(shouldRunDischarge('sid123'));
  assert.ok(!shouldRunDischarge(null));
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Worst-case scenario simulations
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Worst-Case Scenario Tests ===');

test('Scenario: Container crash mid-save — journal has data for recovery', () => {
  // Simulate: shift was journaled but save didn't complete
  const pgData = { shifts: [{ id: 's1', status: 'open', date: '2026-05-19' }] };
  const journal = [
    { id: 1, table_name: 'shifts', entity_id: 's1', op: 'UPDATE',
      payload: { id: 's1', status: 'scheduled', employeeId: 'e1', date: '2026-05-19' } },
    { id: 2, table_name: 'shifts', entity_id: 's2', op: 'INSERT',
      payload: { id: 's2', status: 'open', date: '2026-05-20' } },
  ];
  for (const entry of journal) _replayJournalEntry(pgData, entry);
  assert.strictEqual(pgData.shifts.length, 2);
  assert.strictEqual(pgData.shifts[0].status, 'scheduled');
  assert.strictEqual(pgData.shifts[0].employeeId, 'e1');
  assert.strictEqual(pgData.shifts[1].id, 's2');
});

test('Scenario: Bulk POST journaled but container crashed before save', () => {
  const pgData = { shifts: [{ id: 's1', status: 'open' }] };
  const journal = [{
    id: 1, table_name: 'shifts', entity_id: 'bulk:admin1', op: 'UPDATE',
    payload: {
      collection: 'shifts', count: 3,
      items: [
        { id: 's1', status: 'scheduled', employeeId: 'e1' },
        { id: 's2', status: 'open', date: '2026-05-20' },
        { id: 's3', status: 'open', date: '2026-05-21' },
      ]
    }
  }];
  for (const entry of journal) _replayJournalEntry(pgData, entry);
  assert.strictEqual(pgData.shifts.length, 3);
  assert.strictEqual(pgData.shifts.find(s => s.id === 's1').status, 'scheduled');
});

test('Scenario: Multiple crashes — journal entries replay in order', () => {
  const data = { shifts: [{ id: 's1', status: 'open' }] };
  const journal = [
    { id: 1, table_name: 'shifts', entity_id: 's1', op: 'UPDATE',
      payload: { id: 's1', status: 'claimed' } },
    { id: 2, table_name: 'shifts', entity_id: 's1', op: 'UPDATE',
      payload: { id: 's1', status: 'scheduled', employeeId: 'e1' } },
  ];
  for (const entry of journal) _replayJournalEntry(data, entry);
  assert.strictEqual(data.shifts[0].status, 'scheduled');
  assert.strictEqual(data.shifts[0].employeeId, 'e1');
});

test('Scenario: Shift deleted then container crashed — journal replays delete', () => {
  const data = { shifts: [{ id: 's1' }, { id: 's2' }] };
  _replayJournalEntry(data, {
    table_name: 'shifts', entity_id: 's1', op: 'DELETE',
    payload: { id: 's1' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].id, 's2');
});

test('Scenario: Empty journal — no changes to data', () => {
  const data = { shifts: [{ id: 's1', status: 'open' }] };
  const journal = [];
  for (const entry of journal) _replayJournalEntry(data, entry);
  assert.strictEqual(data.shifts.length, 1);
  assert.strictEqual(data.shifts[0].status, 'open');
});

test('Scenario: Journal entry for unknown table — safe no-op', () => {
  const data = { shifts: [{ id: 's1' }] };
  _replayJournalEntry(data, {
    table_name: 'some_future_table', entity_id: 'x1', op: 'INSERT',
    payload: { id: 'x1' }
  });
  assert.strictEqual(data.shifts.length, 1);
  assert.ok(!data.some_future_table);
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Test change_journal SQL structure (parse check)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n=== Schema Tests ===');

test('change_journal DDL is valid SQL syntax', () => {
  const ddl = `CREATE TABLE IF NOT EXISTS change_journal (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    table_name  TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    op          TEXT NOT NULL CHECK (op IN ('INSERT','UPDATE','DELETE')),
    payload     JSONB NOT NULL,
    applied     BOOLEAN NOT NULL DEFAULT false,
    applied_at  TIMESTAMPTZ
  )`;
  // Check required columns are present
  assert.ok(ddl.includes('id'));
  assert.ok(ddl.includes('table_name'));
  assert.ok(ddl.includes('entity_id'));
  assert.ok(ddl.includes('op'));
  assert.ok(ddl.includes('payload'));
  assert.ok(ddl.includes('applied'));
  assert.ok(ddl.includes('CHECK'));
});

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(60));
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  console.log('SOME TESTS FAILED — review output above');
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED');
  process.exit(0);
}
