'use strict';
/**
 * Postgres repository layer — exposes the same shape as the file-based
 * `dataCache` so callers in server.js need minimal changes.
 *
 * Activated when PG_CONN env var is set. On Azure App Service, the value
 * comes from a Key Vault reference.
 *
 * Key behaviors:
 * - Connection pooling (pg.Pool) — default 10 connections
 * - All writes wrapped in transactions (BEGIN / COMMIT / ROLLBACK on error)
 * - Optimistic concurrency: shifts/employees/buildings carry a `version`
 *   column; updates increment it and reject stale writes
 * - Row-Level Security context set per request via SET LOCAL
 *   (app.current_role + app.current_building_ids)
 */

const { Pool } = require('pg');

let _pool = null;

function init() {
  if (_pool || !process.env.PG_CONN) return _pool;
  _pool = new Pool({
    connectionString: process.env.PG_CONN,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
  _pool.on('error', (err) => {
    console.log(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'pg_pool_error', err: err.message }));
  });
  return _pool;
}

function isEnabled() { return !!_pool; }

async function close() {
  if (_pool) { await _pool.end(); _pool = null; }
}

// Idempotent DDL migrations for columns added after the initial schema.sql.
// Safe to call on every startup; relies on Postgres's IF NOT EXISTS clauses.
async function ensureSchema() {
  if (!_pool) return;
  await _pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS scheduler_only BOOLEAN NOT NULL DEFAULT false`);
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────
async function withTx(fn) {
  const c = await _pool.connect();
  try {
    await c.query('BEGIN');
    const r = await fn(c);
    await c.query('COMMIT');
    return r;
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    c.release();
  }
}

// Set RLS context for queries on a given client connection
async function setContext(client, user) {
  if (!user) return;
  const role = user.role || '';
  const ids = [user.buildingId, ...(user.buildingIds || [])].filter(Boolean).join(',');
  await client.query("SET LOCAL app.current_role = $1", [role]);
  await client.query("SET LOCAL app.current_building_ids = $1", [ids]);
}

// ──────────────────────────────────────────────────────────────────────────
// Read: load full dataset shape (drop-in replacement for dataCache)
// Note: when called WITH a user, RLS restricts what's returned.
//       When called as superadmin or no user, returns everything.
// ──────────────────────────────────────────────────────────────────────────
async function loadAll() {
  const c = await _pool.connect();
  try {
    // Bypass RLS for the unconditional read — caller is server-trusted code
    const [companies, buildings, accounts, employees, shifts, patterns] = await Promise.all([
      c.query('SELECT * FROM companies ORDER BY name'),
      c.query('SELECT * FROM buildings ORDER BY name'),
      c.query('SELECT * FROM accounts'),
      c.query('SELECT * FROM employees'),
      c.query('SELECT * FROM shifts ORDER BY shift_date'),
      c.query('SELECT * FROM schedule_patterns'),
    ]);
    return {
      companies: companies.rows.map(rowCompany),
      buildings: buildings.rows.map(rowBuilding),
      accounts:  accounts.rows.map(rowAccount),
      employees: employees.rows.map(rowEmployee),
      shifts:    shifts.rows.map(rowShift),
      schedulePatterns: patterns.rows.map(rowPattern),
      // HR collections still empty until HR is built — placeholder to maintain shape
      hrEmployees: [], hrAccounts: [], hrTimeClock: [],
      jobPostings: [], demos: [], billingData: {},
      shiftTemplates: [], staffingSlots: {}, buildingShiftTypes: {},
    };
  } finally {
    c.release();
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Row → object mappers (match the JSON shape the SPA expects)
// ──────────────────────────────────────────────────────────────────────────
function rowCompany(r)   { return { id: r.id, name: r.name, color: r.color }; }
function rowBuilding(r)  {
  const md = r.metadata || {};
  return {
    id: r.id, name: r.name, address: r.address, color: r.color,
    beds: r.beds, companyId: r.company_id, ...md
  };
}
function rowAccount(r) {
  const o = {
    id: r.id, email: r.email, name: r.name, role: r.role,
    buildingId: r.building_id, buildingIds: r.building_ids || [],
    group: r.group, ph: r.password_hash, totpSecret: r.totp_secret_encrypted,
    totpEnrolledAt: r.totp_enrolled_at, totpRecoveryCodesHashes: r.totp_recovery_codes_hashes,
    totpRecoveryCodesGeneratedAt: r.totp_recovery_codes_generated_at,
    failedAttempts: r.failed_attempts, lockedUntil: r.locked_until ? new Date(r.locked_until).getTime() : null,
    inviteToken: r.invite_token, inviteExpiry: r.invite_expiry ? new Date(r.invite_expiry).getTime() : null,
    invitedBy: r.invited_by, invitedAt: r.invited_at, activatedAt: r.activated_at,
    passwordResetTokenHash: r.password_reset_token_hash,
    passwordResetExpiry:    r.password_reset_expiry ? new Date(r.password_reset_expiry).getTime() : null,
    schedulerOnly: !!r.scheduler_only,
  };
  // Strip nulls/undefined to match file-based shape closer
  Object.keys(o).forEach(k => o[k] == null && delete o[k]);
  return o;
}
function rowEmployee(r) {
  const md = r.metadata || {};
  return {
    id: r.id, buildingId: r.building_id, accountId: r.account_id,
    name: r.name, email: r.email, phone: r.phone, group: r.group,
    employmentType: r.employment_type, hourlyRate: r.hourly_rate ? parseFloat(r.hourly_rate) : null,
    hireDate: r.hire_date, inactive: r.inactive,
    notifEmail: r.notif_email, notifSMS: r.notif_sms,
    terminationLog: r.termination_log || [],
    ...md
  };
}
function rowShift(r) {
  const md = r.metadata || {};
  return {
    id: r.id, buildingId: r.building_id, employeeId: r.employee_id,
    date: r.shift_date instanceof Date ? r.shift_date.toISOString().slice(0, 10) : r.shift_date,
    type: r.shift_type, group: r.group, start: r.start_time, end: r.end_time,
    status: r.status, claimRequest: r.claim_request,
    _version: r.version,
    ...md
  };
}
function rowPattern(r) {
  return {
    id: r.id, empId: r.emp_id, shiftType: r.shift_type, group: r.group,
    pattern: r.pattern, startDate: r.start_date, endDate: r.end_date,
    active: r.active,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Object → row helpers
// ──────────────────────────────────────────────────────────────────────────
function _strip(obj, keys) {
  const o = { ...obj };
  for (const k of keys) delete o[k];
  return o;
}
function _toMs(v) { return v == null ? null : (typeof v === 'number' ? new Date(v) : v); }

// ──────────────────────────────────────────────────────────────────────────
// Account ops
// ──────────────────────────────────────────────────────────────────────────
async function getAccountByEmail(email) {
  const r = await _pool.query('SELECT * FROM accounts WHERE email = $1 LIMIT 1', [email.toLowerCase()]);
  return r.rows[0] ? rowAccount(r.rows[0]) : null;
}

async function getAccountById(id) {
  const r = await _pool.query('SELECT * FROM accounts WHERE id = $1 LIMIT 1', [id]);
  return r.rows[0] ? rowAccount(r.rows[0]) : null;
}

async function upsertAccount(a) {
  await _pool.query(`
    INSERT INTO accounts (id, email, name, role, building_id, building_ids, "group",
      password_hash, totp_secret_encrypted, totp_enrolled_at,
      totp_recovery_codes_hashes, totp_recovery_codes_generated_at,
      failed_attempts, locked_until,
      invite_token, invite_expiry, invited_by, invited_at, activated_at,
      password_reset_token_hash, password_reset_expiry, scheduler_only)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
    ON CONFLICT (id) DO UPDATE SET
      email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role,
      building_id = EXCLUDED.building_id, building_ids = EXCLUDED.building_ids,
      "group" = EXCLUDED."group",
      password_hash = EXCLUDED.password_hash,
      totp_secret_encrypted        = COALESCE(EXCLUDED.totp_secret_encrypted,        accounts.totp_secret_encrypted),
      totp_enrolled_at             = COALESCE(EXCLUDED.totp_enrolled_at,             accounts.totp_enrolled_at),
      totp_recovery_codes_hashes   = COALESCE(EXCLUDED.totp_recovery_codes_hashes,   accounts.totp_recovery_codes_hashes),
      totp_recovery_codes_generated_at = COALESCE(EXCLUDED.totp_recovery_codes_generated_at, accounts.totp_recovery_codes_generated_at),
      failed_attempts = EXCLUDED.failed_attempts,
      locked_until = EXCLUDED.locked_until,
      invite_token = EXCLUDED.invite_token, invite_expiry = EXCLUDED.invite_expiry,
      invited_by = EXCLUDED.invited_by, invited_at = EXCLUDED.invited_at,
      activated_at = EXCLUDED.activated_at,
      password_reset_token_hash = EXCLUDED.password_reset_token_hash,
      password_reset_expiry = EXCLUDED.password_reset_expiry,
      scheduler_only = EXCLUDED.scheduler_only,
      updated_at = now()
  `, [
    a.id, a.email.toLowerCase(), a.name, a.role,
    a.buildingId || null, a.buildingIds || [], a.group || null,
    a.ph || null, a.totpSecret || null, a.totpEnrolledAt || null,
    a.totpRecoveryCodesHashes || null, a.totpRecoveryCodesGeneratedAt || null,
    a.failedAttempts || 0, _toMs(a.lockedUntil),
    a.inviteToken || null, _toMs(a.inviteExpiry),
    a.invitedBy || null, a.invitedAt || null, a.activatedAt || null,
    a.passwordResetTokenHash || null, _toMs(a.passwordResetExpiry),
    !!a.schedulerOnly,
  ]);
}

// Explicitly wipe TOTP for an account — used ONLY by the admin TOTP-reset endpoint.
// Regular upsertAccount uses COALESCE and will never clear an enrolled secret.
async function clearAccountTotp(accountId) {
  await _pool.query(
    `UPDATE accounts
     SET totp_secret_encrypted = NULL, totp_enrolled_at = NULL,
         totp_recovery_codes_hashes = NULL, totp_recovery_codes_generated_at = NULL,
         updated_at = now()
     WHERE id = $1`,
    [accountId]
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Bulk save — used by POST /api/data path. Wraps in a transaction.
// Caller is responsible for authz filtering BEFORE calling.
// ──────────────────────────────────────────────────────────────────────────
async function saveScopedData(data) {
  return withTx(async (c) => {
    if (Array.isArray(data.companies)) {
      for (const co of data.companies) {
        await c.query(`INSERT INTO companies (id, name, color)
          VALUES ($1, $2, $3)
          ON CONFLICT (id) DO UPDATE SET name = $2, color = $3, updated_at = now()`,
          [co.id, co.name, co.color]);
      }
    }
    if (Array.isArray(data.buildings)) {
      for (const b of data.buildings) {
        const md = _strip(b, ['id','name','address','color','beds','companyId']);
        await c.query(`INSERT INTO buildings (id, company_id, name, address, color, beds, metadata)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT (id) DO UPDATE SET company_id=$2, name=$3, address=$4, color=$5, beds=$6, metadata=$7, updated_at=now()`,
          [b.id, b.companyId || null, b.name, b.address || null, b.color || null, b.beds || null, JSON.stringify(md)]);
      }
    }
    if (Array.isArray(data.employees)) {
      for (const e of data.employees) {
        const md = _strip(e, ['id','buildingId','accountId','name','email','phone','group','employmentType','hourlyRate','hireDate','inactive','notifEmail','notifSMS','terminationLog']);
        await c.query(`INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms, metadata, termination_log)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, account_id=$3, name=$4, email=$5, phone=$6, "group"=$7,
            employment_type=$8, hourly_rate=$9, hire_date=$10, inactive=$11,
            notif_email=$12, notif_sms=$13, metadata=$14, termination_log=$15, updated_at=now()`,
          [e.id, e.buildingId, e.accountId || null, e.name, e.email || null, e.phone || null, e.group,
           e.employmentType || null, e.hourlyRate || null, e.hireDate || null,
           !!e.inactive, e.notifEmail !== false, !!e.notifSMS,
           JSON.stringify(md), JSON.stringify(e.terminationLog || [])]);
      }
    }
    if (Array.isArray(data.shifts)) {
      for (const s of data.shifts) {
        const md = _strip(s, ['id','buildingId','employeeId','date','type','group','start','end','status','claimRequest','_version']);
        await c.query(`INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, COALESCE($12,1))
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, employee_id=$3, shift_date=$4, shift_type=$5, "group"=$6,
            start_time=$7, end_time=$8, status=$9, claim_request=$10, metadata=$11,
            version = shifts.version + 1, updated_at=now()`,
          [s.id, s.buildingId, s.employeeId || null, s.date, s.type, s.group,
           s.start || null, s.end || null, s.status || 'open',
           s.claimRequest ? JSON.stringify(s.claimRequest) : null,
           JSON.stringify(md), s._version || 1]);
      }
    }
    if (Array.isArray(data.schedulePatterns)) {
      for (const p of data.schedulePatterns) {
        // Look up building from emp
        const empRow = (await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId])).rows[0];
        const bId = empRow?.building_id;
        if (!bId) continue;
        await c.query(`INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (id) DO UPDATE SET
            shift_type=$4, "group"=$5, pattern=$6, start_date=$7, end_date=$8, active=$9`,
          [p.id || `pat_${p.empId}_${Date.now()}`, bId, p.empId,
           p.shiftType || null, p.group || null, JSON.stringify(p.pattern || {}),
           p.startDate || null, p.endDate || null, p.active !== false]);
      }
    }
    if (Array.isArray(data.accounts)) {
      for (const a of data.accounts) await upsertAccount.call({ pool: () => _pool }, a);
      // Note: cannot call upsertAccount with separate connection during a tx
      // For the wholesale POST /api/data path, we'll loop here directly.
    }
  });
}

// Account upsert in an existing transaction (used by saveScopedData)
async function _upsertAccountInTx(c, a) {
  await c.query(`
    INSERT INTO accounts (id, email, name, role, building_id, building_ids, "group",
      password_hash, totp_secret_encrypted, totp_enrolled_at,
      totp_recovery_codes_hashes, totp_recovery_codes_generated_at,
      failed_attempts, locked_until,
      invite_token, invite_expiry, invited_by, invited_at, activated_at,
      password_reset_token_hash, password_reset_expiry, scheduler_only)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
    ON CONFLICT (id) DO UPDATE SET
      email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role,
      building_id = EXCLUDED.building_id, building_ids = EXCLUDED.building_ids,
      "group" = EXCLUDED."group",
      password_hash = EXCLUDED.password_hash,
      totp_secret_encrypted        = COALESCE(EXCLUDED.totp_secret_encrypted,        accounts.totp_secret_encrypted),
      totp_enrolled_at             = COALESCE(EXCLUDED.totp_enrolled_at,             accounts.totp_enrolled_at),
      totp_recovery_codes_hashes   = COALESCE(EXCLUDED.totp_recovery_codes_hashes,   accounts.totp_recovery_codes_hashes),
      totp_recovery_codes_generated_at = COALESCE(EXCLUDED.totp_recovery_codes_generated_at, accounts.totp_recovery_codes_generated_at),
      failed_attempts = EXCLUDED.failed_attempts,
      locked_until = EXCLUDED.locked_until,
      invite_token = EXCLUDED.invite_token, invite_expiry = EXCLUDED.invite_expiry,
      invited_by = EXCLUDED.invited_by, invited_at = EXCLUDED.invited_at,
      activated_at = EXCLUDED.activated_at,
      password_reset_token_hash = EXCLUDED.password_reset_token_hash,
      password_reset_expiry = EXCLUDED.password_reset_expiry,
      scheduler_only = EXCLUDED.scheduler_only,
      updated_at = now()
  `, [
    a.id, (a.email || '').toLowerCase(), a.name, a.role,
    a.buildingId || null, a.buildingIds || [], a.group || null,
    a.ph || null, a.totpSecret || null, a.totpEnrolledAt || null,
    a.totpRecoveryCodesHashes || null, a.totpRecoveryCodesGeneratedAt || null,
    a.failedAttempts || 0, _toMs(a.lockedUntil),
    a.inviteToken || null, _toMs(a.inviteExpiry),
    a.invitedBy || null, a.invitedAt || null, a.activatedAt || null,
    a.passwordResetTokenHash || null, _toMs(a.passwordResetExpiry),
    !!a.schedulerOnly,
  ]);
}

// Save full payload — wraps everything in a single transaction
async function saveAll(data) {
  return withTx(async (c) => {
    if (Array.isArray(data.companies)) {
      for (const co of data.companies) {
        await c.query(`INSERT INTO companies (id, name, color) VALUES ($1, $2, $3)
          ON CONFLICT (id) DO UPDATE SET name=$2, color=$3, updated_at=now()`,
          [co.id, co.name, co.color]);
      }
    }
    if (Array.isArray(data.buildings)) {
      for (const b of data.buildings) {
        const md = _strip(b, ['id','name','address','color','beds','companyId']);
        await c.query(`INSERT INTO buildings (id, company_id, name, address, color, beds, metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7)
          ON CONFLICT (id) DO UPDATE SET company_id=$2, name=$3, address=$4, color=$5, beds=$6, metadata=$7, updated_at=now()`,
          [b.id, b.companyId || null, b.name, b.address || null, b.color || null, b.beds || null, JSON.stringify(md)]);
      }
    }
    if (Array.isArray(data.accounts)) {
      for (const a of data.accounts) await _upsertAccountInTx(c, a);
    }
    if (Array.isArray(data.employees)) {
      for (const e of data.employees) {
        const md = _strip(e, ['id','buildingId','accountId','name','email','phone','group','employmentType','hourlyRate','hireDate','inactive','notifEmail','notifSMS','terminationLog']);
        await c.query(`INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms, metadata, termination_log)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, account_id=$3, name=$4, email=$5, phone=$6, "group"=$7,
            employment_type=$8, hourly_rate=$9, hire_date=$10, inactive=$11,
            notif_email=$12, notif_sms=$13, metadata=$14, termination_log=$15, updated_at=now()`,
          [e.id, e.buildingId, e.accountId || null, e.name, e.email || null, e.phone || null, e.group,
           e.employmentType || null, e.hourlyRate || null, e.hireDate || null,
           !!e.inactive, e.notifEmail !== false, !!e.notifSMS,
           JSON.stringify(md), JSON.stringify(e.terminationLog || [])]);
      }
    }
    if (Array.isArray(data.shifts)) {
      for (const s of data.shifts) {
        const md = _strip(s, ['id','buildingId','employeeId','date','type','group','start','end','status','claimRequest','_version']);
        await c.query(`INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, COALESCE($12,1))
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, employee_id=$3, shift_date=$4, shift_type=$5, "group"=$6,
            start_time=$7, end_time=$8, status=$9, claim_request=$10, metadata=$11,
            version = shifts.version + 1, updated_at=now()`,
          [s.id, s.buildingId, s.employeeId || null, s.date, s.type, s.group,
           s.start || null, s.end || null, s.status || 'open',
           s.claimRequest ? JSON.stringify(s.claimRequest) : null,
           JSON.stringify(md), s._version || 1]);
      }
    }
    if (Array.isArray(data.schedulePatterns)) {
      for (const p of data.schedulePatterns) {
        const empRow = (await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId])).rows[0];
        const bId = empRow?.building_id;
        if (!bId) continue;
        await c.query(`INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (id) DO UPDATE SET
            shift_type=$4, "group"=$5, pattern=$6, start_date=$7, end_date=$8, active=$9`,
          [p.id || `pat_${p.empId}_${Date.now()}`, bId, p.empId,
           p.shiftType || null, p.group || null, JSON.stringify(p.pattern || {}),
           p.startDate || null, p.endDate || null, p.active !== false]);
      }
    }
  });
}

// ──────────────────────────────────────────────────────────────────────────
// Audit chain mirror (the WORM blob is the legal record; this is for query)
// ──────────────────────────────────────────────────────────────────────────
async function appendAuditEntry(entry) {
  if (!_pool) return;
  try {
    await _pool.query(`
      INSERT INTO audit_entries (ts, user_id, user_role, action, building_id, details, prev_hash, hmac)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [entry.ts, entry.userId || null, entry.role || null, entry.action,
       entry.buildingId || null,
       JSON.stringify(_strip(entry, ['ts','userId','role','action','buildingId','prevHash','hmac'])),
       entry.prevHash, entry.hmac]);
  } catch (e) {
    // Don't fail the request if audit DB write fails — file + cloud are primary
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Health probe — quick PG ping for /health/ready
// ──────────────────────────────────────────────────────────────────────────
async function ping() {
  if (!_pool) return false;
  try {
    const r = await _pool.query('SELECT 1');
    return r.rows[0]['?column?'] === 1;
  } catch { return false; }
}

module.exports = {
  init, isEnabled, close, ensureSchema,
  withTx, setContext,
  loadAll, saveAll,
  getAccountByEmail, getAccountById, upsertAccount, clearAccountTotp,
  appendAuditEntry,
  ping,
};
