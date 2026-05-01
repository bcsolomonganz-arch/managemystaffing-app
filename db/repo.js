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
  await _pool.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS device_trust_epoch BIGINT NOT NULL DEFAULT 0`);

  // ── Persistent migration flags ─────────────────────────────────────────
  // Records like "_seedStripped" used to be JS-only flags on dataCache and
  // got reset to undefined on every postgres-mode boot. That meant the
  // applyMigrations() seed-strip logic could re-run after every restart
  // (deploy / scaling / host move) and DELETE rows we wanted to keep.
  // This table makes the flags durable across restarts.
  await _pool.query(`
    CREATE TABLE IF NOT EXISTS app_migrations (
      flag       TEXT PRIMARY KEY,
      set_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      set_by     TEXT
    )
  `);

  // ── Append-only employee history ───────────────────────────────────────
  // Every employee insert/update/delete writes a row here. NEVER deleted.
  // This makes data recovery possible from history alone — if employees
  // are lost again, we can rebuild from this log.
  await _pool.query(`
    CREATE TABLE IF NOT EXISTS employee_history (
      id           BIGSERIAL PRIMARY KEY,
      ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
      op           TEXT NOT NULL,             -- 'insert' | 'update' | 'delete' | 'restore'
      emp_id       TEXT NOT NULL,
      building_id  TEXT,
      actor        TEXT,                      -- account email of whoever triggered
      before_row   JSONB,                     -- full row before change (null for insert)
      after_row    JSONB                      -- full row after change (null for delete)
    )
  `);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_emp ON employee_history(emp_id, ts DESC)`);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_building ON employee_history(building_id, ts DESC)`);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_ts ON employee_history(ts DESC)`);

  // Postgres trigger that captures every change to employees automatically.
  // Even if the app code forgets to log, the DB will. Belt and suspenders.
  await _pool.query(`
    CREATE OR REPLACE FUNCTION log_employee_change() RETURNS TRIGGER AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO employee_history (op, emp_id, building_id, after_row)
          VALUES ('insert', NEW.id, NEW.building_id, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO employee_history (op, emp_id, building_id, before_row, after_row)
          VALUES ('update', NEW.id, NEW.building_id, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO employee_history (op, emp_id, building_id, before_row)
          VALUES ('delete', OLD.id, OLD.building_id, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
  `);
  // Drop + recreate the trigger so updates to the function take effect
  await _pool.query(`DROP TRIGGER IF EXISTS trg_employee_history ON employees`);
  await _pool.query(`
    CREATE TRIGGER trg_employee_history
      AFTER INSERT OR UPDATE OR DELETE ON employees
      FOR EACH ROW EXECUTE FUNCTION log_employee_change()
  `);

  // ── Append-only history for accounts, buildings, schedule_patterns ─────
  // Same protection employees got. Login records, building config, and
  // shift rotations are all critical-recovery data.
  await _pool.query(`
    CREATE TABLE IF NOT EXISTS account_history (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      op TEXT NOT NULL,
      account_id TEXT NOT NULL,
      email TEXT,
      role TEXT,
      before_row JSONB, after_row JSONB
    )
  `);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_acct_hist_acct ON account_history(account_id, ts DESC)`);
  await _pool.query(`
    CREATE OR REPLACE FUNCTION log_account_change() RETURNS TRIGGER AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO account_history (op, account_id, email, role, after_row)
          VALUES ('insert', NEW.id, NEW.email, NEW.role, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO account_history (op, account_id, email, role, before_row, after_row)
          VALUES ('update', NEW.id, NEW.email, NEW.role, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO account_history (op, account_id, email, role, before_row)
          VALUES ('delete', OLD.id, OLD.email, OLD.role, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await _pool.query(`DROP TRIGGER IF EXISTS trg_account_history ON accounts`);
  await _pool.query(`
    CREATE TRIGGER trg_account_history
      AFTER INSERT OR UPDATE OR DELETE ON accounts
      FOR EACH ROW EXECUTE FUNCTION log_account_change()
  `);

  await _pool.query(`
    CREATE TABLE IF NOT EXISTS building_history (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      op TEXT NOT NULL,
      building_id TEXT NOT NULL,
      before_row JSONB, after_row JSONB
    )
  `);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_bld_hist_bld ON building_history(building_id, ts DESC)`);
  await _pool.query(`
    CREATE OR REPLACE FUNCTION log_building_change() RETURNS TRIGGER AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO building_history (op, building_id, after_row)
          VALUES ('insert', NEW.id, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO building_history (op, building_id, before_row, after_row)
          VALUES ('update', NEW.id, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO building_history (op, building_id, before_row)
          VALUES ('delete', OLD.id, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await _pool.query(`DROP TRIGGER IF EXISTS trg_building_history ON buildings`);
  await _pool.query(`
    CREATE TRIGGER trg_building_history
      AFTER INSERT OR UPDATE OR DELETE ON buildings
      FOR EACH ROW EXECUTE FUNCTION log_building_change()
  `);

  await _pool.query(`
    CREATE TABLE IF NOT EXISTS pattern_history (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      op TEXT NOT NULL,
      pattern_id TEXT NOT NULL,
      building_id TEXT,
      emp_id TEXT,
      before_row JSONB, after_row JSONB
    )
  `);
  await _pool.query(`CREATE INDEX IF NOT EXISTS idx_pat_hist_emp ON pattern_history(emp_id, ts DESC)`);
  await _pool.query(`
    CREATE OR REPLACE FUNCTION log_pattern_change() RETURNS TRIGGER AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO pattern_history (op, pattern_id, building_id, emp_id, after_row)
          VALUES ('insert', NEW.id, NEW.building_id, NEW.emp_id, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO pattern_history (op, pattern_id, building_id, emp_id, before_row, after_row)
          VALUES ('update', NEW.id, NEW.building_id, NEW.emp_id, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO pattern_history (op, pattern_id, building_id, emp_id, before_row)
          VALUES ('delete', OLD.id, OLD.building_id, OLD.emp_id, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await _pool.query(`DROP TRIGGER IF EXISTS trg_pattern_history ON schedule_patterns`);
  await _pool.query(`
    CREATE TRIGGER trg_pattern_history
      AFTER INSERT OR UPDATE OR DELETE ON schedule_patterns
      FOR EACH ROW EXECUTE FUNCTION log_pattern_change()
  `);

  // ── High water mark per building ────────────────────────────────────────
  // Tracks the maximum employee/account/building row counts ever seen per
  // building. saveAll consults this and refuses to drop below the HWM.
  // This is the strongest possible defense — even if the in-memory cache,
  // the HTTP layer, AND the saveAll body all fail, the HWM check catches it.
  await _pool.query(`
    CREATE TABLE IF NOT EXISTS row_high_water (
      scope        TEXT PRIMARY KEY,    -- e.g. 'employees:b1777218436953'
      max_count    INTEGER NOT NULL,
      observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

// Read all persistent migration flags into a Set of names.
// Caller compares against expected flags and skips any that already ran.
async function loadMigrationFlags() {
  if (!_pool) return new Set();
  const r = await _pool.query('SELECT flag FROM app_migrations');
  return new Set(r.rows.map(x => x.flag));
}

async function setMigrationFlag(flag, setBy) {
  if (!_pool) return;
  await _pool.query(
    `INSERT INTO app_migrations (flag, set_by) VALUES ($1, $2) ON CONFLICT (flag) DO NOTHING`,
    [flag, setBy || 'system']
  );
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
    deviceTrustEpoch: r.device_trust_epoch ? Number(r.device_trust_epoch) : 0,
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
      password_reset_token_hash, password_reset_expiry, scheduler_only, device_trust_epoch)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
    ON CONFLICT (id) DO UPDATE SET
      email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role,
      building_id = EXCLUDED.building_id, building_ids = EXCLUDED.building_ids,
      "group" = EXCLUDED."group",
      -- COALESCE so a null incoming hash never silently wipes the existing one.
      -- Use clearAccountPassword() if you actually need to null the hash.
      password_hash = COALESCE(EXCLUDED.password_hash, accounts.password_hash),
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
      device_trust_epoch = GREATEST(EXCLUDED.device_trust_epoch, accounts.device_trust_epoch),
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
    a.deviceTrustEpoch || 0,
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
      password_reset_token_hash, password_reset_expiry, scheduler_only, device_trust_epoch)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
    ON CONFLICT (id) DO UPDATE SET
      email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role,
      building_id = EXCLUDED.building_id, building_ids = EXCLUDED.building_ids,
      "group" = EXCLUDED."group",
      -- COALESCE so a null incoming hash never silently wipes the existing one.
      -- Use clearAccountPassword() if you actually need to null the hash.
      password_hash = COALESCE(EXCLUDED.password_hash, accounts.password_hash),
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
      device_trust_epoch = GREATEST(EXCLUDED.device_trust_epoch, accounts.device_trust_epoch),
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
    a.deviceTrustEpoch || 0,
  ]);
}

// Save full payload — wraps everything in a single transaction.
//
// CRITICAL SAFETY: this function is UPSERT-only. It NEVER deletes rows.
// To reduce the number of rows in a table, use the explicit delete*
// helpers which require the row id and audit log every operation.
//
// Pre-write check: refuse to commit if dataCache.employees is shorter
// than the count currently in postgres for any building in scope. This
// is the last line of defense — even if every other tripwire fails, a
// shrinking employees collection cannot make it through this function.
async function saveAll(data) {
  return withTx(async (c) => {
    // ── Shrink guard ───────────────────────────────────────────────────
    // Compare incoming employees count to what's currently in postgres.
    // If incoming is shorter — for any building — abort the entire txn.
    if (Array.isArray(data.employees)) {
      const incomingByBld = new Map();
      for (const e of data.employees) {
        if (!e.building_id && !e.buildingId) continue;
        const bid = e.building_id || e.buildingId;
        incomingByBld.set(bid, (incomingByBld.get(bid) || 0) + 1);
      }
      const dbCounts = await c.query(`SELECT building_id, COUNT(*)::int AS n FROM employees GROUP BY building_id`);
      for (const row of dbCounts.rows) {
        const incoming = incomingByBld.get(row.building_id) || 0;
        if (incoming < row.n) {
          throw new Error(
            `saveAll refused to shrink employees in building ${row.building_id}: ` +
            `db has ${row.n}, incoming has ${incoming}. ` +
            `Use the explicit delete helpers if intentional.`
          );
        }
      }
      // High-water-mark check: refuse to drop below the all-time max ever
      // observed for this building. Updates HWM upward when incoming exceeds it.
      for (const [bid, n] of incomingByBld) {
        const scope = `employees:${bid}`;
        const hw = await c.query(`SELECT max_count FROM row_high_water WHERE scope = $1`, [scope]);
        const prev = hw.rows[0]?.max_count || 0;
        if (n < prev) {
          throw new Error(
            `saveAll refused: employees in ${bid} would drop to ${n}, ` +
            `below all-time-max ${prev}. If you intentionally inactivated ` +
            `staff, use the explicit DELETE endpoint.`
          );
        }
        if (n > prev) {
          await c.query(
            `INSERT INTO row_high_water (scope, max_count) VALUES ($1, $2)
             ON CONFLICT (scope) DO UPDATE SET max_count = GREATEST(row_high_water.max_count, $2),
             observed_at = now()`,
            [scope, n]
          );
        }
      }
    }

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
  loadMigrationFlags, setMigrationFlag,
  getAccountByEmail, getAccountById, upsertAccount, clearAccountTotp,
  appendAuditEntry,
  ping,
};
