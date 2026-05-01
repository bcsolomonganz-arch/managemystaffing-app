'use strict';
//
// Unit tests for lib/punch.js — exercises the HR-Admin punch correction
// approval flow without booting Express, JWT, or any persistence layer.
//
// Run with: node --test tests/punch.test.js
//
// What we cover:
//   - classifyPunch: late / early / missed / no-out / normal cases
//   - findOrCreatePunch: dedupe by (empId, date)
//   - applyPunchEdit: hours math (incl. overnight wrap), status recompute
//   - stagePunchEdit:
//       * stages a pending edit, doesn't mutate the live punch
//       * notifies every building admin in scope (single + multi-building)
//       * supports buildingIds[] for regional admins
//   - decidePunchEdit:
//       * approve applies the edit, escalates to regional + SA, round-trips
//         a notification to the requester
//       * reject leaves the punch alone, notifies the requester with reason
//       * idempotent: cannot decide an already-decided edit
//       * 'employee no longer exists' is auto-rejected
//
const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const punch = require('../lib/punch');

// ---------- fixtures ---------------------------------------------------------

function makeFixtureData() {
  return {
    employees: [
      { id: 'e1', name: 'Anna Aide', group: 'CNA', buildingId: 'b1' },
      { id: 'e2', name: 'Ben Burns', group: 'RN',  buildingId: 'b2' },
    ],
    shifts: [
      { id: 's1', employeeId: 'e1', date: '2026-04-30', start: '07:00', end: '15:00', status: 'scheduled' },
      { id: 's2', employeeId: 'e1', date: '2026-04-29', start: '23:00', end: '07:00', status: 'scheduled' }, // overnight
    ],
    accounts: [
      // 2 admins on b1 — both should be notified for b1 edits
      { id: 'a1', email: 'admin1@b1.com', role: 'admin', buildingId: 'b1' },
      { id: 'a2', email: 'admin2@b1.com', role: 'admin', buildingId: 'b1' },
      // Admin on b2 — must NOT be notified for b1 edits
      { id: 'a3', email: 'admin@b2.com',  role: 'admin', buildingId: 'b2' },
      // Regional admin spanning b1+b2 (uses buildingIds[])
      { id: 'r1', email: 'regional@all.com', role: 'regionaladmin', buildingIds: ['b1', 'b2'] },
      // Super admin
      { id: 's1', email: 'sa@all.com',    role: 'superadmin' },
      // HR Admin requester (separate from admins)
      { id: 'h1', email: 'hr@b1.com', role: 'hradmin', buildingId: 'b1', name: 'Hannah HR' },
    ],
    hrTimeClock: [],
    pendingPunchEdits: [],
    notifications: [],
  };
}

const HR_REQUESTER = { id: 'h1', email: 'hr@b1.com', role: 'hradmin', name: 'Hannah HR' };
const ADMIN_DECIDER = { id: 'a1', email: 'admin1@b1.com', role: 'admin' };

// ---------- classifyPunch ----------------------------------------------------

describe('classifyPunch', () => {
  const emp = { id: 'e1', name: 'Anna', group: 'CNA' };
  const shifts = [
    { employeeId: 'e1', date: '2026-04-30', start: '07:00', end: '15:00', status: 'scheduled' },
  ];

  test('returns "missed" when there is no clock-in', () => {
    assert.equal(punch.classifyPunch(emp, '2026-04-30', '', '15:00', shifts), 'missed');
    assert.equal(punch.classifyPunch(emp, '2026-04-30', null, '15:00', shifts), 'missed');
  });

  test('returns "no-out" when there is a clock-in but no clock-out', () => {
    assert.equal(punch.classifyPunch(emp, '2026-04-30', '07:00', '', shifts), 'no-out');
  });

  test('returns "late" when clock-in is more than 7 minutes after scheduled start', () => {
    assert.equal(punch.classifyPunch(emp, '2026-04-30', '07:08', '15:00', shifts), 'late');
  });

  test('returns "normal" when clock-in is within the 7-minute grace', () => {
    assert.equal(punch.classifyPunch(emp, '2026-04-30', '07:07', '15:00', shifts), 'normal');
  });

  test('returns "early" when clock-in is more than 15 minutes before scheduled start', () => {
    assert.equal(punch.classifyPunch(emp, '2026-04-30', '06:44', '15:00', shifts), 'early');
  });

  test('returns "normal" when there is no scheduled shift to compare against', () => {
    assert.equal(punch.classifyPunch(emp, '2099-01-01', '07:00', '15:00', shifts), 'normal');
  });
});

// ---------- findOrCreatePunch ------------------------------------------------

describe('findOrCreatePunch', () => {
  test('creates a fresh record when one does not exist', () => {
    const data = { hrTimeClock: [] };
    const r = punch.findOrCreatePunch(data, 'e1', '2026-04-30');
    assert.equal(data.hrTimeClock.length, 1);
    assert.equal(r.empId, 'e1');
    assert.equal(r.date, '2026-04-30');
    assert.equal(r.in, '');
  });

  test('dedupes — second call for the same key returns the same object', () => {
    const data = { hrTimeClock: [] };
    const r1 = punch.findOrCreatePunch(data, 'e1', '2026-04-30');
    r1.in = '07:00';
    const r2 = punch.findOrCreatePunch(data, 'e1', '2026-04-30');
    assert.strictEqual(r1, r2);
    assert.equal(data.hrTimeClock.length, 1);
  });

  test('initializes hrTimeClock if missing', () => {
    const data = {};
    punch.findOrCreatePunch(data, 'e1', '2026-04-30');
    assert.ok(Array.isArray(data.hrTimeClock));
  });
});

// ---------- applyPunchEdit ---------------------------------------------------

describe('applyPunchEdit', () => {
  const emp = { id: 'e1', name: 'Anna', group: 'CNA', buildingId: 'b1' };

  test('computes hours correctly for a normal day shift', () => {
    const r = { empId: 'e1', date: '2026-04-30', in: '', out: '' };
    punch.applyPunchEdit(emp, r, '07:00', '15:00', { shifts: [] });
    assert.equal(r.in, '07:00');
    assert.equal(r.out, '15:00');
    assert.equal(r.hours, '8.00');
  });

  test('handles overnight shifts that cross midnight', () => {
    const r = { empId: 'e1', date: '2026-04-29', in: '', out: '' };
    punch.applyPunchEdit(emp, r, '23:00', '07:00', { shifts: [] });
    assert.equal(r.hours, '8.00');
  });

  test('clears hours if either time is missing', () => {
    const r = { empId: 'e1', date: '2026-04-30', in: '', out: '' };
    punch.applyPunchEdit(emp, r, '07:00', '', { shifts: [] });
    assert.equal(r.hours, '');
    assert.equal(r.status, 'no-out');
  });

  test('truncates time strings to HH:MM (no seconds)', () => {
    const r = { empId: 'e1', date: '2026-04-30', in: '', out: '' };
    punch.applyPunchEdit(emp, r, '07:00:45', '15:00:09', { shifts: [] });
    assert.equal(r.in, '07:00');
    assert.equal(r.out, '15:00');
  });

  test('stamps name / role / buildingId from the employee', () => {
    const r = { empId: 'e1', date: '2026-04-30', in: '', out: '' };
    punch.applyPunchEdit(emp, r, '07:00', '15:00', { shifts: [] });
    assert.equal(r.name, 'Anna');
    assert.equal(r.role, 'CNA');
    assert.equal(r.buildingId, 'b1');
  });
});

// ---------- stagePunchEdit ---------------------------------------------------

describe('stagePunchEdit', () => {
  test('creates a pending edit and does NOT mutate the live punch', () => {
    const data = makeFixtureData();
    // Seed an existing live punch to make sure it stays intact.
    data.hrTimeClock.push({ empId: 'e1', date: '2026-04-30', in: '07:05', out: '15:00', hours: '7.92', status: 'normal' });
    const before = JSON.parse(JSON.stringify(data.hrTimeClock));

    const out = punch.stagePunchEdit({
      data,
      requester: HR_REQUESTER,
      emp: data.employees[0],
      date: '2026-04-30',
      proposedIn:  '07:00',
      proposedOut: '15:00',
      note: 'Forgot to clock in on time',
    });

    assert.ok(out.editId.startsWith('pe_'));
    assert.equal(out.pendingEdit.status, 'pending');
    assert.equal(out.pendingEdit.proposed.in, '07:00');
    assert.equal(out.pendingEdit.before.in, '07:05');
    assert.equal(data.pendingPunchEdits.length, 1);
    // Live punch unchanged:
    assert.deepEqual(data.hrTimeClock, before);
  });

  test('notifies every building admin scoped to the employee\'s building', () => {
    const data = makeFixtureData();
    const out = punch.stagePunchEdit({
      data, requester: HR_REQUESTER,
      emp: data.employees[0],            // building b1
      date: '2026-04-30',
      proposedIn: '07:00', proposedOut: '15:00',
      note: '',
    });
    // 2 admins on b1, 1 on b2 → expect 2 notifications, both for b1 admins.
    assert.equal(out.notifiedAdminCount, 2);
    const recipients = data.notifications.map(n => n.toEmail).sort();
    assert.deepEqual(recipients, ['admin1@b1.com', 'admin2@b1.com']);
    for (const n of data.notifications) {
      assert.equal(n.kind, 'PUNCH_EDIT_PENDING');
      assert.equal(n.buildingId, 'b1');
      assert.equal(n.empName, 'Anna Aide');
    }
  });

  test('respects multi-building admins via buildingIds[]', () => {
    const data = makeFixtureData();
    // Promote a3 from single-building to multi-building covering b1+b2.
    const a3 = data.accounts.find(a => a.id === 'a3');
    delete a3.buildingId;
    a3.buildingIds = ['b1', 'b2'];

    punch.stagePunchEdit({
      data, requester: HR_REQUESTER,
      emp: data.employees[0],            // building b1
      date: '2026-04-30',
      proposedIn: '07:00', proposedOut: '15:00',
      note: '',
    });
    const recipients = data.notifications.map(n => n.toEmail).sort();
    // a1 + a2 (both on b1) PLUS a3 (now multi-building covering b1)
    assert.deepEqual(recipients, ['admin1@b1.com', 'admin2@b1.com', 'admin@b2.com']);
  });

  test('truncates the optional note to 500 chars', () => {
    const data = makeFixtureData();
    const big = 'X'.repeat(2000);
    const { pendingEdit } = punch.stagePunchEdit({
      data, requester: HR_REQUESTER,
      emp: data.employees[0],
      date: '2026-04-30',
      proposedIn: '07:00', proposedOut: '15:00',
      note: big,
    });
    assert.equal(pendingEdit.note.length, 500);
  });
});

// ---------- decidePunchEdit --------------------------------------------------

describe('decidePunchEdit', () => {
  function stagedFixture() {
    const data = makeFixtureData();
    data.hrTimeClock.push({ empId: 'e1', date: '2026-04-30', in: '07:05', out: '15:00', hours: '7.92', status: 'normal' });
    const out = punch.stagePunchEdit({
      data, requester: HR_REQUESTER,
      emp: data.employees[0],
      date: '2026-04-30',
      proposedIn: '07:00', proposedOut: '15:00',
      note: 'Forgot to clock in on time',
    });
    // Reset notifications array — the staging notifications shouldn't pollute
    // assertions about what decide() emits.
    data.notifications = [];
    return { data, editId: out.editId };
  }

  test('approve applies the edit to the live punch', () => {
    const { data, editId } = stagedFixture();
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'approve', decisionNote: '',
    });
    assert.equal(result.status, 'approved');
    assert.equal(result.applied, true);
    const live = data.hrTimeClock.find(p => p.empId === 'e1' && p.date === '2026-04-30');
    assert.equal(live.in, '07:00');
    assert.equal(live.out, '15:00');
    assert.equal(live.hours, '8.00');
    // event log appended
    assert.ok(Array.isArray(live.events) && live.events.length === 1);
    assert.equal(live.events[0].source, 'admin-approval-of-hradmin');
    assert.equal(live.events[0].editor, 'admin1@b1.com');
    assert.equal(live.events[0].requestedBy, 'hr@b1.com');
  });

  test('approve escalates to regional admins + super admins', () => {
    const { data, editId } = stagedFixture();
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'approve', decisionNote: '',
    });
    // 1 regional + 1 SA in the fixture
    assert.equal(result.escalatedToCount, 2);
    const escalations = data.notifications.filter(n => n.kind === 'PUNCH_EDIT_APPROVED');
    const escEmails = escalations.map(n => n.toEmail).sort();
    assert.deepEqual(escEmails, ['regional@all.com', 'sa@all.com']);
  });

  test('approve sends a round-trip notification to the HR Admin requester', () => {
    const { data, editId } = stagedFixture();
    punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'approve', decisionNote: '',
    });
    const back = data.notifications.find(n => n.kind === 'PUNCH_EDIT_APPROVED_BY_ADMIN');
    assert.ok(back, 'requester should receive a PUNCH_EDIT_APPROVED_BY_ADMIN');
    assert.equal(back.toEmail, 'hr@b1.com');
    assert.equal(back.toAccountId, 'h1');
  });

  test('reject does NOT change the live punch and notifies the requester', () => {
    const { data, editId } = stagedFixture();
    const before = JSON.parse(JSON.stringify(data.hrTimeClock));
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'reject', decisionNote: 'Already correct',
    });
    assert.equal(result.status, 'rejected');
    assert.equal(result.applied, false);
    assert.deepEqual(data.hrTimeClock, before);

    const rej = data.notifications.find(n => n.kind === 'PUNCH_EDIT_REJECTED');
    assert.ok(rej);
    assert.equal(rej.toEmail, 'hr@b1.com');
    assert.match(rej.body, /Already correct/);
  });

  test('cannot decide an already-decided edit', () => {
    const { data, editId } = stagedFixture();
    punch.decidePunchEdit({ data, decider: ADMIN_DECIDER, editId, action: 'approve' });
    const second = punch.decidePunchEdit({ data, decider: ADMIN_DECIDER, editId, action: 'approve' });
    assert.match(second.error, /Already approved/);
  });

  test('returns an error for an unknown editId', () => {
    const data = makeFixtureData();
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId: 'pe_doesnotexist', action: 'approve',
    });
    assert.match(result.error, /Pending edit not found/);
  });

  test('rejects invalid action values', () => {
    const { data, editId } = stagedFixture();
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'maybe',
    });
    assert.match(result.error, /approve\|reject/);
  });

  test('approve auto-rejects when the employee no longer exists', () => {
    const { data, editId } = stagedFixture();
    // Simulate the employee being removed between staging and decision.
    data.employees = data.employees.filter(e => e.id !== 'e1');
    const result = punch.decidePunchEdit({
      data, decider: ADMIN_DECIDER, editId, action: 'approve',
    });
    assert.equal(result.status, 'rejected');
    assert.equal(result.applied, false);
    const pe = data.pendingPunchEdits.find(p => p.id === editId);
    assert.equal(pe.status, 'rejected');
    assert.match(pe.decisionNote, /no longer exists/);
  });
});

// ---------- dmThreadId -------------------------------------------------------

describe('dmThreadId', () => {
  test('is stable regardless of argument order', () => {
    const a = punch.dmThreadId('alice', 'bob');
    const b = punch.dmThreadId('bob', 'alice');
    assert.equal(a, b);
    assert.equal(a, 'dm:alice:bob');
  });

  test('coerces non-strings consistently', () => {
    const a = punch.dmThreadId(42, 17);
    assert.equal(a, 'dm:17:42');
  });
});

// ---------- notify ----------------------------------------------------------

describe('notify', () => {
  test('inserts at the head and assigns a unique id + createdAt', () => {
    const data = { notifications: [] };
    punch.notify(data, { kind: 'X', toAccountId: 'a1', title: 'first' });
    punch.notify(data, { kind: 'X', toAccountId: 'a1', title: 'second' });
    assert.equal(data.notifications.length, 2);
    // Newest first (unshift)
    assert.equal(data.notifications[0].title, 'second');
    assert.ok(data.notifications[0].id.startsWith('n_'));
    assert.notEqual(data.notifications[0].id, data.notifications[1].id);
    assert.ok(data.notifications[0].createdAt);
    assert.equal(data.notifications[0].readAt, null);
  });

  test('caps the array at 5,000 entries', () => {
    const data = { notifications: [] };
    // Pre-fill above the cap using the same shape.
    for (let i = 0; i < 5005; i++) data.notifications.push({ id: 'n_old' + i });
    punch.notify(data, { kind: 'X', toAccountId: 'a1' });
    assert.equal(data.notifications.length, 5000);
    // The newest item is at the head.
    assert.equal(data.notifications[0].kind, 'X');
  });
});
