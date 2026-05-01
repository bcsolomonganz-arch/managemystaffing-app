'use strict';
//
// Pure helpers extracted from server.js so they can be exercised by
// node --test without booting the full Express + JWT + Postgres stack.
//
// All functions are intentionally pure-ish: they take everything they need
// as parameters (data cache, employee, shifts) and return values rather
// than mutating module-level state. The existing server passes its
// dataCache in. The audit chain, persistence, and HTTP routing layers
// stay in server.js.
//

const crypto = require('crypto');

// Punch status classifier. Cross-references the scheduled shift for this
// (empId, date) to detect late arrivals, missed clock-outs, and >15-minute
// early arrivals.
function classifyPunch(emp, date, inTime, outTime, shifts) {
  const sched = (shifts || []).find(s =>
    s.employeeId === emp.id && s.date === date && s.status === 'scheduled');
  if (!inTime) return 'missed';
  if (!outTime) return 'no-out';
  const toMin = t => { if(!t) return null; const [h,m]=String(t).trim().split(':').map(Number); return h*60+(m||0); };
  const inMin = toMin(inTime);
  const schedIn = toMin(sched?.start);
  if (schedIn != null && inMin != null && (inMin - schedIn) > 7) return 'late';
  if (schedIn != null && inMin != null && (schedIn - inMin) > 15) return 'early';
  return 'normal';
}

// Find an existing punch record for (empId, date) — punches dedupe per day.
function findOrCreatePunch(data, empId, date) {
  if (!Array.isArray(data.hrTimeClock)) data.hrTimeClock = [];
  let r = data.hrTimeClock.find(x => x.empId === empId && x.date === date);
  if (!r) {
    r = { empId, date, in: '', out: '', hours: '', status: 'normal' };
    data.hrTimeClock.push(r);
  }
  return r;
}

// Apply punch in/out edits to a record, recompute hours + status.
// Mutates `r` in place.
function applyPunchEdit(emp, r, inTime, outTime, data) {
  if (inTime  !== undefined) r.in  = String(inTime  || '').slice(0,5);
  if (outTime !== undefined) r.out = String(outTime || '').slice(0,5);
  if (r.in && r.out) {
    const [ih, im] = r.in.split(':').map(Number);
    const [oh, om] = r.out.split(':').map(Number);
    let mins = (oh*60 + (om||0)) - (ih*60 + (im||0));
    if (mins < 0) mins += 24*60;
    r.hours = (mins / 60).toFixed(2);
  } else { r.hours = ''; }
  r.status = classifyPunch(emp, emp ? r.date : null, r.in, r.out, data.shifts || []);
  r.name = emp.name; r.role = emp.group; r.buildingId = emp.buildingId;
}

// Drop a notification onto data.notifications[] for a target user/role.
function notify(data, n) {
  if (!Array.isArray(data.notifications)) data.notifications = [];
  data.notifications.unshift({
    id: 'n_' + crypto.randomBytes(6).toString('hex'),
    createdAt: new Date().toISOString(),
    readAt: null,
    ...n,
  });
  if (data.notifications.length > 5000) data.notifications.length = 5000;
}

function dmThreadId(idA, idB) {
  const [a, b] = [String(idA), String(idB)].sort();
  return 'dm:' + a + ':' + b;
}

// Stage an HR-Admin punch correction. Returns the pendingPunchEdits[] entry
// PLUS notifications to drop for every building admin in scope. Caller
// commits the entry and the notifications atomically.
//
// Pure: doesn't read process state, doesn't write the audit chain.
function stagePunchEdit({ data, requester, emp, date, proposedIn, proposedOut, note }) {
  if (!Array.isArray(data.pendingPunchEdits)) data.pendingPunchEdits = [];
  const r = findOrCreatePunch(data, emp.id, date);
  const before = { in: r.in, out: r.out };
  const proposed = {
    in:  proposedIn  !== undefined ? String(proposedIn  || '').slice(0,5) : r.in,
    out: proposedOut !== undefined ? String(proposedOut || '').slice(0,5) : r.out,
  };
  const editId = 'pe_' + crypto.randomBytes(6).toString('hex');
  const pe = {
    id: editId,
    empId: emp.id, empName: emp.name, buildingId: emp.buildingId, date,
    before, proposed,
    requestedBy: { id: requester.id, email: requester.email, name: requester.name || requester.email },
    requestedAt: new Date().toISOString(),
    note: (note || '').slice(0, 500),
    status: 'pending',
    decidedBy: null, decidedAt: null, decisionNote: null,
  };
  data.pendingPunchEdits.push(pe);

  const admins = (data.accounts || []).filter(a =>
    a.role === 'admin' && (a.buildingId === emp.buildingId
      || (Array.isArray(a.buildingIds) && a.buildingIds.includes(emp.buildingId)))
  );
  for (const ad of admins) {
    notify(data, {
      kind: 'PUNCH_EDIT_PENDING',
      toAccountId: ad.id, toEmail: ad.email,
      buildingId: emp.buildingId,
      editId, empId: emp.id, empName: emp.name, date,
      requestedBy: pe.requestedBy.email,
      title: `Punch edit pending: ${emp.name} · ${date}`,
      body: `${pe.requestedBy.name} (HR Admin) changed ${date} from ${before.in||'—'}-${before.out||'—'} to ${proposed.in||'—'}-${proposed.out||'—'}. Approve or reject.`,
    });
  }
  return { editId, pendingEdit: pe, notifiedAdminCount: admins.length };
}

// Decide a staged HR-Admin edit. action = 'approve' | 'reject'.
// Returns { status, applied, recordAfter? } and mutates `data` accordingly.
function decidePunchEdit({ data, decider, editId, action, decisionNote }) {
  const pe = (data.pendingPunchEdits || []).find(p => p.id === editId);
  if (!pe) return { error: 'Pending edit not found' };
  if (pe.status !== 'pending') return { error: `Already ${pe.status}` };
  if (!['approve','reject'].includes(action)) return { error: 'action must be approve|reject' };

  pe.status = (action === 'approve') ? 'approved' : 'rejected';
  pe.decidedBy = { id: decider.id, email: decider.email, name: decider.name || decider.email, role: decider.role };
  pe.decidedAt = new Date().toISOString();
  pe.decisionNote = (decisionNote || '').slice(0, 500);

  if (action === 'approve') {
    const emp = (data.employees || []).find(e => e.id === pe.empId);
    if (!emp) {
      pe.status = 'rejected';
      pe.decisionNote = 'Employee no longer exists; auto-rejected';
      return { status: 'rejected', applied: false };
    }
    const r = findOrCreatePunch(data, pe.empId, pe.date);
    const before = { in: r.in, out: r.out };
    applyPunchEdit(emp, r, pe.proposed.in, pe.proposed.out, data);
    if (!Array.isArray(r.events)) r.events = [];
    r.events.push({
      action: 'admin-edit', at: new Date().toISOString(),
      source: 'admin-approval-of-hradmin', editor: decider.email,
      requestedBy: pe.requestedBy.email,
      before, after: { in: r.in, out: r.out },
      note: pe.note, decisionNote: pe.decisionNote,
    });

    // Escalate notifications to regional admins + super admins.
    const escalateTo = (data.accounts || []).filter(a =>
      a.role === 'regionaladmin' || a.role === 'superadmin'
    );
    for (const ra of escalateTo) {
      notify(data, {
        kind: 'PUNCH_EDIT_APPROVED',
        toAccountId: ra.id, toEmail: ra.email,
        buildingId: pe.buildingId,
        editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
        requestedBy: pe.requestedBy.email,
        approvedBy: decider.email,
        title: `Punch edit approved: ${pe.empName} · ${pe.date}`,
        body: `${decider.email} approved an HR-Admin punch correction for ${pe.empName} on ${pe.date}: ${pe.before.in||'—'}-${pe.before.out||'—'} → ${pe.proposed.in||'—'}-${pe.proposed.out||'—'}.`,
      });
    }
    // Round-trip back to the requester.
    notify(data, {
      kind: 'PUNCH_EDIT_APPROVED_BY_ADMIN',
      toAccountId: pe.requestedBy.id, toEmail: pe.requestedBy.email,
      buildingId: pe.buildingId,
      editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
      approvedBy: decider.email,
      title: `Your punch correction was approved`,
      body: `${decider.email} approved your punch correction for ${pe.empName} on ${pe.date}.`,
    });
    return {
      status: 'approved', applied: true, recordAfter: r,
      escalatedToCount: escalateTo.length,
    };
  }

  // Reject path: notify the HR Admin so they aren't waiting forever.
  notify(data, {
    kind: 'PUNCH_EDIT_REJECTED',
    toAccountId: pe.requestedBy.id, toEmail: pe.requestedBy.email,
    buildingId: pe.buildingId,
    editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
    rejectedBy: decider.email,
    title: `Your punch correction was rejected`,
    body: `${decider.email} rejected your punch correction for ${pe.empName} on ${pe.date}.${pe.decisionNote ? ' Reason: ' + pe.decisionNote : ''}`,
  });
  return { status: 'rejected', applied: false };
}

module.exports = {
  classifyPunch,
  findOrCreatePunch,
  applyPunchEdit,
  notify,
  dmThreadId,
  stagePunchEdit,
  decidePunchEdit,
};
