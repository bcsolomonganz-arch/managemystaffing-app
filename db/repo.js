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
    ssl: { rejectUnauthorized: process.env.NODE_ENV === 'production' },
    max: parseInt(process.env.PG_POOL_MAX, 10) || 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
  // Set statement timeout on each new connection to prevent runaway queries
  _pool.on('connect', (client) => {
    client.query('SET statement_timeout = 30000').catch(() => {});
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
  await withTx(async (c) => {
  // Open schedule patterns (kind='open') have no employee — allow NULL emp_id.
  // building_id nullable as a safety valve; the save code always tries to set it.
  await c.query(`ALTER TABLE schedule_patterns ALTER COLUMN emp_id DROP NOT NULL`).catch(() => {});
  await c.query(`ALTER TABLE schedule_patterns ALTER COLUMN building_id DROP NOT NULL`).catch(() => {});
  await c.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS scheduler_only BOOLEAN NOT NULL DEFAULT false`);
  await c.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS device_trust_epoch BIGINT NOT NULL DEFAULT 0`);
  // Add 'hradmin' to the accounts role CHECK constraint. The original constraint
  // only allowed superadmin/admin/regionaladmin/employee. HR Admins need their own
  // role so punch corrections route through an approval workflow.
  await c.query(`
    DO $$ BEGIN
      ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_role_check;
      ALTER TABLE accounts ADD CONSTRAINT accounts_role_check
        CHECK (role IN ('superadmin','admin','regionaladmin','hradmin','employee','hrcandidate'));
    EXCEPTION WHEN OTHERS THEN NULL;
    END $$
  `);
  // Nursing license tracking. The expiry date drives a visible countdown
  // on the roster card and an automatic flag on every scheduled shift
  // where the assigned employee's license has lapsed.
  await c.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS license_number TEXT`);
  await c.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS license_expires_at DATE`);
  await c.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS license_state TEXT`);

  // ── Persistent migration flags ─────────────────────────────────────────
  await c.query(`
    CREATE TABLE IF NOT EXISTS app_migrations (
      flag       TEXT PRIMARY KEY,
      set_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      set_by     TEXT
    )
  `);

  // ── Append-only employee history ───────────────────────────────────────
  await c.query(`
    CREATE TABLE IF NOT EXISTS employee_history (
      id           BIGSERIAL PRIMARY KEY,
      ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
      op           TEXT NOT NULL,
      emp_id       TEXT NOT NULL,
      building_id  TEXT,
      actor        TEXT,
      before_row   JSONB,
      after_row    JSONB
    )
  `);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_emp ON employee_history(emp_id, ts DESC)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_building ON employee_history(building_id, ts DESC)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_emp_hist_ts ON employee_history(ts DESC)`);

  await c.query(`
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
  await c.query(`DROP TRIGGER IF EXISTS trg_employee_history ON employees`);
  await c.query(`
    CREATE TRIGGER trg_employee_history
      AFTER INSERT OR UPDATE OR DELETE ON employees
      FOR EACH ROW EXECUTE FUNCTION log_employee_change()
  `);

  // ── Append-only history for accounts, buildings, schedule_patterns ─────
  await c.query(`
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
  await c.query(`CREATE INDEX IF NOT EXISTS idx_acct_hist_acct ON account_history(account_id, ts DESC)`);
  await c.query(`
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
  await c.query(`DROP TRIGGER IF EXISTS trg_account_history ON accounts`);
  await c.query(`
    CREATE TRIGGER trg_account_history
      AFTER INSERT OR UPDATE OR DELETE ON accounts
      FOR EACH ROW EXECUTE FUNCTION log_account_change()
  `);

  await c.query(`
    CREATE TABLE IF NOT EXISTS building_history (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      op TEXT NOT NULL,
      building_id TEXT NOT NULL,
      before_row JSONB, after_row JSONB
    )
  `);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_bld_hist_bld ON building_history(building_id, ts DESC)`);
  await c.query(`
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
  await c.query(`DROP TRIGGER IF EXISTS trg_building_history ON buildings`);
  await c.query(`
    CREATE TRIGGER trg_building_history
      AFTER INSERT OR UPDATE OR DELETE ON buildings
      FOR EACH ROW EXECUTE FUNCTION log_building_change()
  `);

  // ── Append-only shift history ──────────────────────────────────────────
  await c.query(`
    CREATE TABLE IF NOT EXISTS shift_history (
      id           BIGSERIAL PRIMARY KEY,
      ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
      op           TEXT NOT NULL,
      shift_id     TEXT NOT NULL,
      building_id  TEXT,
      employee_id  TEXT,
      shift_date   DATE,
      "group"      TEXT,
      shift_type   TEXT,
      status       TEXT,
      actor        TEXT,
      before_row   JSONB,
      after_row    JSONB
    )
  `);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_shift_hist_shift ON shift_history(shift_id, ts DESC)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_shift_hist_building ON shift_history(building_id, ts DESC)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_shift_hist_date ON shift_history(shift_date, "group", shift_type)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_shift_hist_ts ON shift_history(ts DESC)`);

  await c.query(`
    CREATE OR REPLACE FUNCTION log_shift_change() RETURNS TRIGGER AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO shift_history (op, shift_id, building_id, employee_id, shift_date, "group", shift_type, status, after_row)
          VALUES ('insert', NEW.id, NEW.building_id, NEW.employee_id, NEW.shift_date, NEW."group", NEW.shift_type, NEW.status, to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO shift_history (op, shift_id, building_id, employee_id, shift_date, "group", shift_type, status, before_row, after_row)
          VALUES ('update', NEW.id, NEW.building_id, NEW.employee_id, NEW.shift_date, NEW."group", NEW.shift_type, NEW.status, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO shift_history (op, shift_id, building_id, employee_id, shift_date, "group", shift_type, status, before_row)
          VALUES ('delete', OLD.id, OLD.building_id, OLD.employee_id, OLD.shift_date, OLD."group", OLD.shift_type, OLD.status, to_jsonb(OLD));
        RETURN OLD;
      END IF;
      RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await c.query(`DROP TRIGGER IF EXISTS trg_shift_history ON shifts`);
  await c.query(`
    CREATE TRIGGER trg_shift_history
      AFTER INSERT OR UPDATE OR DELETE ON shifts
      FOR EACH ROW EXECUTE FUNCTION log_shift_change()
  `);

  await c.query(`
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
  await c.query(`CREATE INDEX IF NOT EXISTS idx_pat_hist_emp ON pattern_history(emp_id, ts DESC)`);
  await c.query(`
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
  await c.query(`DROP TRIGGER IF EXISTS trg_pattern_history ON schedule_patterns`);
  await c.query(`
    CREATE TRIGGER trg_pattern_history
      AFTER INSERT OR UPDATE OR DELETE ON schedule_patterns
      FOR EACH ROW EXECUTE FUNCTION log_pattern_change()
  `);

  // ── Index on schedule_patterns(building_id) ─────────────────────────────
  // RLS tenant filter and roster queries both filter by building_id.
  // Without this, those queries full-scan the table.
  await c.query(`CREATE INDEX IF NOT EXISTS idx_patterns_building ON schedule_patterns(building_id) WHERE active = TRUE`);

  // ── High water mark per building ────────────────────────────────────────
  await c.query(`
    CREATE TABLE IF NOT EXISTS row_high_water (
      scope        TEXT PRIMARY KEY,
      max_count    INTEGER NOT NULL,
      observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // ── app_state — JSONB blob store for collections that the SPA persists
  // via POST /api/data but that don't have dedicated tables yet.
  // Pre-fix, loadAll() returned empty placeholders for these and POST /api/data
  // dropped most of them on the way in, so anything saved through the Demo
  // Portal / Billing / shift-template / PPD-staffing UIs never reached PG.
  // Migrate the HR rows out of here once HR has dedicated RLS-scoped tables.
  await c.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      key         TEXT PRIMARY KEY,
      value       JSONB NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // ── Additional indexes for performance (Issue #16) ──────────────────────
  await c.query(`CREATE INDEX IF NOT EXISTS idx_accounts_pw_reset ON accounts(password_reset_token_hash) WHERE password_reset_token_hash IS NOT NULL`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_accounts_building_ids ON accounts USING GIN(building_ids)`);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_patterns_building ON schedule_patterns(building_id)`);

  // ── Unique constraint: no duplicate active employees per building+email (Issue #15) ──
  await c.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_building_email_unique ON employees(building_id, email) WHERE email IS NOT NULL AND inactive = FALSE`);

  // ── Change Journal — durable mutation log for crash recovery ──────────
  // Each API mutation writes a journal entry BEFORE modifying dataCache.
  // After saveAllIndependent() succeeds, entries are marked applied.
  // On startup, unapplied entries are replayed to recover mutations that
  // were journaled but lost when the container crashed before the save.
  await c.query(`
    CREATE TABLE IF NOT EXISTS change_journal (
      id          BIGSERIAL PRIMARY KEY,
      ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
      table_name  TEXT NOT NULL,
      entity_id   TEXT NOT NULL,
      op          TEXT NOT NULL CHECK (op IN ('INSERT','UPDATE','DELETE')),
      payload     JSONB NOT NULL,
      applied     BOOLEAN NOT NULL DEFAULT false,
      applied_at  TIMESTAMPTZ
    )
  `);
  await c.query(`CREATE INDEX IF NOT EXISTS idx_change_journal_unapplied ON change_journal (applied, ts) WHERE NOT applied`);
  }); // end withTx
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

// Valid roles that can be set in the RLS context
const VALID_ROLES = new Set(['superadmin', 'admin', 'regionaladmin', 'employee', 'hradmin', 'hrcandidate']);
const BUILDING_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// Set RLS context for queries on a given client connection
async function setContext(client, user) {
  if (!user) return;
  const role = user.role || '';
  if (role && !VALID_ROLES.has(role)) {
    throw new Error(`Invalid role for RLS context: ${role}`);
  }
  const rawIds = [user.buildingId, ...(user.buildingIds || [])].filter(Boolean);
  for (const id of rawIds) {
    if (!BUILDING_ID_RE.test(id)) {
      throw new Error(`Invalid building ID for RLS context: ${id}`);
    }
  }
  const ids = rawIds.join(',');
  await client.query("SET LOCAL app.current_role = $1", [role]);
  await client.query("SET LOCAL app.current_building_ids = $1", [ids]);
}

// ──────────────────────────────────────────────────────────────────────────
// Read: load full dataset shape (drop-in replacement for dataCache)
// Note: when called WITH a user, RLS restricts what's returned.
//       When called as superadmin or no user, returns everything.
// ──────────────────────────────────────────────────────────────────────────
// Collections stored as single JSONB rows in app_state. Default value type
// per key — array vs object — matches what the SPA expects on first load,
// so first-time empties don't break .filter() / .findIndex() etc.
const APP_STATE_KEYS = {
  demos:              [],
  billingData:        {},
  shiftTemplates:     [],
  staffingSlots:      {},
  buildingShiftTypes: {},
  hrOnboarding:       {},
  jobPostings:        [],
  hrEmployees:        [],
  hrAccounts:         [],
  hrTimeClock:        [],
  directMessages:     [],
  staffEvents:        [],
  prospects:          [],
  ppdDailyCensus:     [],
  contentReports:     [],
  blockedUsers:       [],
};

async function loadAppState(c) {
  const r = await c.query('SELECT key, value FROM app_state WHERE key = ANY($1)', [Object.keys(APP_STATE_KEYS)]);
  const out = {};
  for (const [k, def] of Object.entries(APP_STATE_KEYS)) out[k] = Array.isArray(def) ? [] : {};
  for (const row of r.rows) out[row.key] = row.value;
  return out;
}

async function loadAll() {
  const c = await _pool.connect();
  try {
    // Bypass RLS for the unconditional read — caller is server-trusted code
    const [companies, buildings, accounts, employees, shifts, patterns, appState] = await Promise.all([
      c.query('SELECT * FROM companies ORDER BY name'),
      c.query('SELECT * FROM buildings ORDER BY name'),
      c.query('SELECT * FROM accounts'),
      c.query('SELECT * FROM employees'),
      c.query('SELECT * FROM shifts ORDER BY shift_date'),
      c.query('SELECT * FROM schedule_patterns'),
      loadAppState(c),
    ]);
    return {
      companies: companies.rows.map(rowCompany),
      buildings: buildings.rows.map(rowBuilding),
      accounts:  accounts.rows.map(rowAccount),
      employees: employees.rows.map(rowEmployee),
      shifts:    shifts.rows.map(rowShift),
      schedulePatterns: patterns.rows.map(rowPattern),
      // app_state-backed collections — see APP_STATE_KEYS above. HR rows live
      // here as a stopgap until HR migrates to its own RLS-scoped tables.
      ...appState,
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
    hireDate: r.hire_date instanceof Date ? r.hire_date.toISOString().slice(0, 10) : r.hire_date,
    inactive: r.inactive,
    notifEmail: r.notif_email, notifSMS: r.notif_sms,
    terminationLog: r.termination_log || [],
    licenseNumber:    r.license_number    || null,
    licenseExpiresAt: r.license_expires_at instanceof Date ? r.license_expires_at.toISOString().slice(0,10) : (r.license_expires_at || null),
    licenseState:     r.license_state     || null,
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
  // The `pattern` JSONB column stores ALL metadata fields that don't have
  // their own dedicated columns (selectedDays, pickerStart, removedDates,
  // kind, cycleLen, slots, lastExtendedTo, appliedAt, etc.).  Spread it
  // back into the top-level object so the SPA sees the same shape it saved.
  const meta = (r.pattern && typeof r.pattern === 'object') ? r.pattern : {};
  return {
    ...meta,
    id: r.id, buildingId: r.building_id, empId: r.emp_id,
    shiftType: r.shift_type, group: r.group,
    startDate: r.start_date, endDate: r.end_date,
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

// Sanitize employment_type to match the DB CHECK constraint.
// Only 'fulltime', 'parttime', 'prn' are allowed; anything else → NULL.
const _VALID_EMP_TYPES = new Set(['fulltime', 'parttime', 'prn']);
function _safeEmpType(v) { return _VALID_EMP_TYPES.has(v) ? v : null; }

const MAX_METADATA_BYTES = 32 * 1024; // 32KB cap on JSONB metadata
function _validateMetadata(md, context) {
  const json = JSON.stringify(md);
  if (json.length > MAX_METADATA_BYTES) {
    throw new Error(`Metadata too large (${json.length} bytes, max ${MAX_METADATA_BYTES}) for ${context}`);
  }
  return json;
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
          [b.id, b.companyId || null, b.name, b.address || null, b.color || null, b.beds || null, _validateMetadata(md, `building:${b.id}`)]);
      }
    }
    if (Array.isArray(data.employees)) {
      for (const e of data.employees) {
        const md = _strip(e, ['id','buildingId','accountId','name','email','phone','group','employmentType','hourlyRate','hireDate','inactive','notifEmail','notifSMS','terminationLog','licenseNumber','licenseExpiresAt','licenseState']);
        await c.query(`INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms,
            metadata, termination_log,
            license_number, license_expires_at, license_state)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, account_id=$3, name=$4, email=$5, phone=$6, "group"=$7,
            employment_type=$8, hourly_rate=$9, hire_date=$10, inactive=$11,
            notif_email=$12, notif_sms=$13, metadata=$14, termination_log=$15,
            license_number = COALESCE(EXCLUDED.license_number, employees.license_number),
            license_expires_at = COALESCE(EXCLUDED.license_expires_at, employees.license_expires_at),
            license_state = COALESCE(EXCLUDED.license_state, employees.license_state),
            updated_at=now()`,
          [e.id, e.buildingId, e.accountId || null, e.name, e.email || null, e.phone || null, e.group,
           _safeEmpType(e.employmentType), e.hourlyRate || null, e.hireDate || null,
           !!e.inactive, e.notifEmail !== false, e.phone ? (e.notifSMS !== false) : !!e.notifSMS,
           _validateMetadata(md, `employee:${e.id}`), JSON.stringify(e.terminationLog || []),
           e.licenseNumber || null, e.licenseExpiresAt || null, e.licenseState || null]);
      }
    }
    if (Array.isArray(data.shifts)) {
      for (const s of data.shifts) {
        const md = _strip(s, ['id','buildingId','employeeId','date','type','group','start','end','status','claimRequest','_version']);
        const result = await c.query(`INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, COALESCE($12,1))
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, employee_id=$3, shift_date=$4, shift_type=$5, "group"=$6,
            start_time=$7, end_time=$8, status=$9, claim_request=$10, metadata=$11,
            version = shifts.version + 1, updated_at=now()
          WHERE shifts.version = $12`,
          [s.id, s.buildingId, s.employeeId || null, s.date, s.type, s.group,
           s.start || null, s.end || null, s.status || 'open',
           s.claimRequest ? JSON.stringify(s.claimRequest) : null,
           _validateMetadata(md, `shift:${s.id}`), s._version || 1]);
        // rowCount 0 on existing row means stale version (concurrency conflict)
        // rowCount 1 = either inserted or updated successfully
        if (result.rowCount === 0) {
          throw new Error(`Concurrency conflict: shift ${s.id} was modified by another request (version ${s._version})`);
        }
      }
      // DELETE orphaned shifts (scoped save — only remove shifts that
      // belong to buildings in this save scope and are no longer present)
      const scopedKeepIds = data.shifts.map(s => s.id);
      if (scopedKeepIds.length > 0) {
        // Only delete shifts whose building_id is in the incoming set
        const scopedBIds = [...new Set(data.shifts.map(s => s.buildingId).filter(Boolean))];
        if (scopedBIds.length > 0) {
          await c.query(
            'DELETE FROM shifts WHERE building_id = ANY($1::text[]) AND id != ALL($2::text[])',
            [scopedBIds, scopedKeepIds]
          );
        }
      }
    }
    if (Array.isArray(data.schedulePatterns)) {
      for (const p of data.schedulePatterns) {
        let bId = p.buildingId || null;
        if (!bId && p.empId) {
          const empRow = (await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId])).rows[0];
          bId = empRow?.building_id || null;
        }
        const meta = _strip(p, ['id','buildingId','empId','shiftType','group','startDate','endDate','active']);
        if (Object.keys(meta).length === 0 && p.id) {
          console.warn('[repo] pattern_empty_jsonb:', p.id, '— metadata fields lost, pattern will be non-functional');
        }
        await c.query(`INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, shift_type=$4, "group"=$5, pattern=$6, start_date=$7, end_date=$8, active=$9`,
          [p.id || `pat_${p.empId || 'open'}_${Date.now()}`, bId, p.empId || null,
           p.shiftType || null, p.group || null, JSON.stringify(meta),
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

// ──────────────────────────────────────────────────────────────────────────
// Independent per-table saves — each table in its own transaction.
// If one table fails, the others still commit. Returns a detailed report.
// ──────────────────────────────────────────────────────────────────────────
async function saveAllIndependent(data) {
  const results = [];
  async function _runTable(table, fn) {
    try {
      const r = await withTx(fn);
      results.push({ table, ok: true, rowCount: r || 0 });
    } catch (e) {
      console.error(`[saveAllIndependent] ${table} FAILED:`, e.message);
      results.push({ table, ok: false, error: e.message });
    }
  }

  // ── Companies ──
  if (Array.isArray(data.companies)) {
    await _runTable('companies', async (c) => {
      for (const co of data.companies) {
        await c.query(`INSERT INTO companies (id, name, color) VALUES ($1, $2, $3)
          ON CONFLICT (id) DO UPDATE SET name=$2, color=$3, updated_at=now()`,
          [co.id, co.name, co.color]);
      }
      const keepCompanyIds = data.companies.map(co => co.id);
      if (keepCompanyIds.length > 0) {
        await c.query('DELETE FROM companies WHERE id != ALL($1::text[])', [keepCompanyIds]);
      }
      return data.companies.length;
    });
  }

  // ── Buildings ──
  if (Array.isArray(data.buildings)) {
    await _runTable('buildings', async (c) => {
      for (const b of data.buildings) {
        const md = _strip(b, ['id','name','address','color','beds','companyId']);
        await c.query(`INSERT INTO buildings (id, company_id, name, address, color, beds, metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7)
          ON CONFLICT (id) DO UPDATE SET company_id=$2, name=$3, address=$4, color=$5, beds=$6, metadata=$7, updated_at=now()`,
          [b.id, b.companyId || null, b.name, b.address || null, b.color || null, b.beds || null, _validateMetadata(md, `building:${b.id}`)]);
      }
      const keepBuildingIds = data.buildings.map(b => b.id);
      if (keepBuildingIds.length > 0) {
        await c.query('DELETE FROM buildings WHERE id != ALL($1::text[])', [keepBuildingIds]);
      }
      return data.buildings.length;
    });
  }

  // ── Accounts ──
  if (Array.isArray(data.accounts)) {
    await _runTable('accounts', async (c) => {
      for (const a of data.accounts) await _upsertAccountInTx(c, a);
      const keepAccountIds = data.accounts.map(a => a.id);
      if (keepAccountIds.length > 0) {
        await c.query('DELETE FROM accounts WHERE id != ALL($1::text[])', [keepAccountIds]);
      }
      return data.accounts.length;
    });
  }

  // ── Employees (with shrink guard + HWM) ──
  if (Array.isArray(data.employees)) {
    await _runTable('employees', async (c) => {
      let _skipEmployeeSave = false;
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
          console.warn(
            `[saveAllIndependent] employee shrink guard: skipping employee save for building ${row.building_id} ` +
            `(db has ${row.n}, incoming has ${incoming}).`
          );
          _skipEmployeeSave = true;
          break;
        }
      }
      if (!_skipEmployeeSave) {
        for (const [bid, n] of incomingByBld) {
          const scope = `employees:${bid}`;
          const hw = await c.query(`SELECT max_count FROM row_high_water WHERE scope = $1 FOR UPDATE`, [scope]);
          const prev = hw.rows[0]?.max_count || 0;
          if (n < prev) {
            console.warn(
              `[saveAllIndependent] employee HWM guard: skipping employee save ` +
              `(${bid} would drop to ${n}, below HWM ${prev}).`
            );
            _skipEmployeeSave = true;
            break;
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
      if (_skipEmployeeSave) return 0;
      for (const e of data.employees) {
        const md = _strip(e, ['id','buildingId','accountId','name','email','phone','group','employmentType','hourlyRate','hireDate','inactive','notifEmail','notifSMS','terminationLog','licenseNumber','licenseExpiresAt','licenseState']);
        await c.query(`INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms,
            metadata, termination_log,
            license_number, license_expires_at, license_state)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, account_id=$3, name=$4, email=$5, phone=$6, "group"=$7,
            employment_type=$8, hourly_rate=$9, hire_date=$10, inactive=$11,
            notif_email=$12, notif_sms=$13, metadata=$14, termination_log=$15,
            license_number = COALESCE(EXCLUDED.license_number, employees.license_number),
            license_expires_at = COALESCE(EXCLUDED.license_expires_at, employees.license_expires_at),
            license_state = COALESCE(EXCLUDED.license_state, employees.license_state),
            updated_at=now()`,
          [e.id, e.buildingId, e.accountId || null, e.name, e.email || null, e.phone || null, e.group,
           _safeEmpType(e.employmentType), e.hourlyRate || null, e.hireDate || null,
           !!e.inactive, e.notifEmail !== false, e.phone ? (e.notifSMS !== false) : !!e.notifSMS,
           _validateMetadata(md, `employee:${e.id}`), JSON.stringify(e.terminationLog || []),
           e.licenseNumber || null, e.licenseExpiresAt || null, e.licenseState || null]);
      }
      return data.employees.length;
    });
  }

  // ── Shifts (with HWM guard + batch upsert) ──
  if (Array.isArray(data.shifts)) {
    await _runTable('shifts', async (c) => {
      // HWM tracking (non-blocking — doesn't prevent saves)
      const incomingByBld = new Map();
      for (const s of data.shifts) {
        const bid = s.building_id || s.buildingId;
        if (!bid) continue;
        incomingByBld.set(bid, (incomingByBld.get(bid) || 0) + 1);
      }
      for (const [bid, n] of incomingByBld) {
        const scope = `shifts:${bid}`;
        const hw = await c.query(`SELECT max_count FROM row_high_water WHERE scope = $1 FOR UPDATE`, [scope]);
        const prev = hw.rows[0]?.max_count || 0;
        if (n > prev) {
          await c.query(
            `INSERT INTO row_high_water (scope, max_count) VALUES ($1, $2)
             ON CONFLICT (scope) DO UPDATE SET max_count = GREATEST(row_high_water.max_count, $2),
             observed_at = now()`,
            [scope, n]
          );
        }
      }
      // Batch upsert
      const BATCH = 500;
      for (let i = 0; i < data.shifts.length; i += BATCH) {
        const batch = data.shifts.slice(i, i + BATCH);
        const ids = [], bIds = [], eIds = [], dates = [], types = [], groups = [];
        const starts = [], ends = [], statuses = [], claims = [], metas = [], versions = [];
        for (const s of batch) {
          const md = _strip(s, ['id','buildingId','employeeId','date','type','group','start','end','status','claimRequest','_version']);
          ids.push(s.id); bIds.push(s.buildingId); eIds.push(s.employeeId || null);
          dates.push(s.date); types.push(s.type); groups.push(s.group);
          starts.push(s.start || null); ends.push(s.end || null);
          statuses.push(s.status || 'open');
          claims.push(s.claimRequest ? JSON.stringify(s.claimRequest) : null);
          metas.push(_validateMetadata(md, `shift:${s.id}`)); versions.push(s._version || 1);
        }
        await c.query(`INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          SELECT * FROM unnest(
            $1::text[], $2::text[], $3::text[], $4::date[], $5::text[], $6::text[],
            $7::text[], $8::text[], $9::text[], $10::jsonb[], $11::jsonb[], $12::int[])
          ON CONFLICT (id) DO UPDATE SET
            building_id=EXCLUDED.building_id, employee_id=EXCLUDED.employee_id,
            shift_date=EXCLUDED.shift_date, shift_type=EXCLUDED.shift_type, "group"=EXCLUDED."group",
            start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time,
            status=EXCLUDED.status, claim_request=EXCLUDED.claim_request,
            metadata=EXCLUDED.metadata, version = shifts.version + 1, updated_at=now()`,
          [ids, bIds, eIds, dates, types, groups, starts, ends, statuses, claims, metas, versions]);
      }
      // DELETE orphaned shifts
      const keepShiftIds = data.shifts.map(s => s.id);
      if (keepShiftIds.length > 0) {
        await c.query('DELETE FROM shifts WHERE id != ALL($1::text[])', [keepShiftIds]);
      }
      return data.shifts.length;
    });
  }

  // ── Schedule Patterns ──
  if (Array.isArray(data.schedulePatterns)) {
    await _runTable('schedulePatterns', async (c) => {
      for (const p of data.schedulePatterns) {
        let bId = p.buildingId || null;
        if (!bId && p.empId) {
          const empRow = (await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId])).rows[0];
          bId = empRow?.building_id || null;
        }
        const meta = _strip(p, ['id','buildingId','empId','shiftType','group','startDate','endDate','active']);
        if (Object.keys(meta).length === 0 && p.id) {
          console.warn('[repo] pattern_empty_jsonb:', p.id, '— metadata fields lost, pattern will be non-functional');
        }
        await c.query(`INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, shift_type=$4, "group"=$5, pattern=$6, start_date=$7, end_date=$8, active=$9`,
          [p.id || `pat_${p.empId || 'open'}_${Date.now()}`, bId, p.empId || null,
           p.shiftType || null, p.group || null, JSON.stringify(meta),
           p.startDate || null, p.endDate || null, p.active !== false]);
      }
      const keepPatIds = data.schedulePatterns.filter(p => p.id).map(p => p.id);
      if (keepPatIds.length > 0) {
        await c.query('DELETE FROM schedule_patterns WHERE id != ALL($1::text[])', [keepPatIds]);
      }
      return data.schedulePatterns.length;
    });
  }

  // ── app_state blobs ──
  await _runTable('appState', async (c) => {
    const keysToWrite = Object.entries(APP_STATE_KEYS).filter(([k]) => data[k] !== undefined).map(([k]) => k);
    if (keysToWrite.length > 0) {
      await c.query(`SELECT key FROM app_state WHERE key = ANY($1) FOR UPDATE`, [keysToWrite]);
    }
    let count = 0;
    for (const [k, def] of Object.entries(APP_STATE_KEYS)) {
      if (data[k] === undefined) continue;
      const expectArray = Array.isArray(def);
      const v = expectArray
        ? (Array.isArray(data[k]) ? data[k] : [])
        : (data[k] && typeof data[k] === 'object' && !Array.isArray(data[k]) ? data[k] : {});
      await c.query(
        `INSERT INTO app_state (key, value) VALUES ($1, $2::jsonb)
         ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = now()`,
        [k, JSON.stringify(v)]
      );
      count++;
    }
    return count;
  });

  const failedTables = results.filter(r => !r.ok).map(r => r.table);
  const allOk = failedTables.length === 0;
  return { results, allOk, failedTables };
}

// ──────────────────────────────────────────────────────────────────────────
// Post-save count verification — lightweight check that data actually landed.
// ──────────────────────────────────────────────────────────────────────────
async function verifyCounts(data) {
  if (!_pool) return [];
  const checks = [];
  const tableCounts = [
    { table: 'companies',         key: 'companies',        sql: 'SELECT COUNT(*)::int AS n FROM companies' },
    { table: 'buildings',         key: 'buildings',         sql: 'SELECT COUNT(*)::int AS n FROM buildings' },
    { table: 'accounts',          key: 'accounts',          sql: 'SELECT COUNT(*)::int AS n FROM accounts' },
    { table: 'employees',         key: 'employees',         sql: 'SELECT COUNT(*)::int AS n FROM employees' },
    { table: 'shifts',            key: 'shifts',            sql: 'SELECT COUNT(*)::int AS n FROM shifts' },
    { table: 'schedule_patterns', key: 'schedulePatterns',  sql: 'SELECT COUNT(*)::int AS n FROM schedule_patterns' },
  ];
  for (const { table, key, sql } of tableCounts) {
    const arr = data[key];
    if (!Array.isArray(arr)) continue;
    try {
      const r = await _pool.query(sql);
      const actual = r.rows[0]?.n || 0;
      const expected = arr.length;
      checks.push({ table, expected, actual, match: actual === expected });
    } catch (e) {
      checks.push({ table, expected: arr.length, actual: -1, match: false, error: e.message });
    }
  }
  return checks;
}

// Legacy saveAll — retained for reference but no longer called from persistCache.
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
async function saveAllLegacy(data) {
  return withTx(async (c) => {
    // ── Employee shrink guard ────────────────────────────────────────────
    // Compare incoming employees count to what's currently in postgres.
    // If incoming is shorter — for any building — SKIP the employee upsert
    // but DO NOT abort the entire txn. Previously this guard threw, rolling
    // back the ENTIRE transaction (shifts, patterns, everything). That meant
    // a stale employee count from a scoped admin silently blocked shift
    // deletions and pattern removedDates from persisting — the #1 cause of
    // "deleted shifts reappear after container restart."
    let _skipEmployeeSave = false;
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
          console.warn(
            `[saveAll] employee shrink guard: skipping employee save for building ${row.building_id} ` +
            `(db has ${row.n}, incoming has ${incoming}). Shifts/patterns will still save.`
          );
          _skipEmployeeSave = true;
          break;
        }
      }
      // High-water-mark check: refuse to drop below the all-time max ever
      // observed for this building. Updates HWM upward when incoming exceeds it.
      if (!_skipEmployeeSave) {
        for (const [bid, n] of incomingByBld) {
          const scope = `employees:${bid}`;
          const hw = await c.query(`SELECT max_count FROM row_high_water WHERE scope = $1 FOR UPDATE`, [scope]);
          const prev = hw.rows[0]?.max_count || 0;
          if (n < prev) {
            console.warn(
              `[saveAll] employee HWM guard: skipping employee save ` +
              `(${bid} would drop to ${n}, below HWM ${prev}).`
            );
            _skipEmployeeSave = true;
            break;
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
    }

    // ── Shift HWM guard ───────────────────────────────────────────────
    // NOTE: The shift shrink guard that used to throw here was removed
    // because it blocked legitimate per-shift deletes. When DELETE
    // /api/shifts/:id splices the in-memory array and calls flushNow(),
    // saveAll sees incoming < db and threw — preventing the orphan DELETE
    // at the end from ever running. This caused shifts to resurrect on
    // container restart. The HTTP-layer anti-shrink tripwire on POST
    // /api/data (line ~7049) still protects against bulk-save data loss.
    // The orphan DELETE below (after upsert) is the authoritative cleanup.
    if (Array.isArray(data.shifts)) {
      const incomingByBld = new Map();
      for (const s of data.shifts) {
        const bid = s.building_id || s.buildingId;
        if (!bid) continue;
        incomingByBld.set(bid, (incomingByBld.get(bid) || 0) + 1);
      }
      for (const [bid, n] of incomingByBld) {
        const scope = `shifts:${bid}`;
        const hw = await c.query(`SELECT max_count FROM row_high_water WHERE scope = $1 FOR UPDATE`, [scope]);
        const prev = hw.rows[0]?.max_count || 0;
        // We allow shifts to drop below HWM (unlike employees) because
        // legitimate per-shift removes happen often (kept by HTTP-layer
        // tripwire only). HWM tracks the trend instead — exceed it and
        // we update; we don't fail on shrink.
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
      // DELETE orphaned companies no longer in the data
      const keepCompanyIds = data.companies.map(co => co.id);
      if (keepCompanyIds.length > 0) {
        await c.query('DELETE FROM companies WHERE id != ALL($1::text[])', [keepCompanyIds]);
      }
    }
    if (Array.isArray(data.buildings)) {
      for (const b of data.buildings) {
        const md = _strip(b, ['id','name','address','color','beds','companyId']);
        await c.query(`INSERT INTO buildings (id, company_id, name, address, color, beds, metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7)
          ON CONFLICT (id) DO UPDATE SET company_id=$2, name=$3, address=$4, color=$5, beds=$6, metadata=$7, updated_at=now()`,
          [b.id, b.companyId || null, b.name, b.address || null, b.color || null, b.beds || null, _validateMetadata(md, `building:${b.id}`)]);
      }
      // DELETE orphaned buildings no longer in the data
      const keepBuildingIds = data.buildings.map(b => b.id);
      if (keepBuildingIds.length > 0) {
        await c.query('DELETE FROM buildings WHERE id != ALL($1::text[])', [keepBuildingIds]);
      }
    }
    if (Array.isArray(data.accounts)) {
      for (const a of data.accounts) await _upsertAccountInTx(c, a);
      // DELETE orphaned accounts no longer in the data
      const keepAccountIds = data.accounts.map(a => a.id);
      if (keepAccountIds.length > 0) {
        await c.query('DELETE FROM accounts WHERE id != ALL($1::text[])', [keepAccountIds]);
      }
    }
    if (Array.isArray(data.employees) && !_skipEmployeeSave) {
      for (const e of data.employees) {
        const md = _strip(e, ['id','buildingId','accountId','name','email','phone','group','employmentType','hourlyRate','hireDate','inactive','notifEmail','notifSMS','terminationLog','licenseNumber','licenseExpiresAt','licenseState']);
        await c.query(`INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms,
            metadata, termination_log,
            license_number, license_expires_at, license_state)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, account_id=$3, name=$4, email=$5, phone=$6, "group"=$7,
            employment_type=$8, hourly_rate=$9, hire_date=$10, inactive=$11,
            notif_email=$12, notif_sms=$13, metadata=$14, termination_log=$15,
            license_number = COALESCE(EXCLUDED.license_number, employees.license_number),
            license_expires_at = COALESCE(EXCLUDED.license_expires_at, employees.license_expires_at),
            license_state = COALESCE(EXCLUDED.license_state, employees.license_state),
            updated_at=now()`,
          [e.id, e.buildingId, e.accountId || null, e.name, e.email || null, e.phone || null, e.group,
           _safeEmpType(e.employmentType), e.hourlyRate || null, e.hireDate || null,
           !!e.inactive, e.notifEmail !== false, e.phone ? (e.notifSMS !== false) : !!e.notifSMS,
           _validateMetadata(md, `employee:${e.id}`), JSON.stringify(e.terminationLog || []),
           e.licenseNumber || null, e.licenseExpiresAt || null, e.licenseState || null]);
      }
    }
    if (Array.isArray(data.shifts)) {
      // Batch upsert shifts using unnest — reduces ~10,000 individual queries
      // to ceil(N/500) batched queries for a ~20x speed-up.
      const BATCH = 500;
      for (let i = 0; i < data.shifts.length; i += BATCH) {
        const batch = data.shifts.slice(i, i + BATCH);
        const ids = [], bIds = [], eIds = [], dates = [], types = [], groups = [];
        const starts = [], ends = [], statuses = [], claims = [], metas = [], versions = [];
        for (const s of batch) {
          const md = _strip(s, ['id','buildingId','employeeId','date','type','group','start','end','status','claimRequest','_version']);
          ids.push(s.id); bIds.push(s.buildingId); eIds.push(s.employeeId || null);
          dates.push(s.date); types.push(s.type); groups.push(s.group);
          starts.push(s.start || null); ends.push(s.end || null);
          statuses.push(s.status || 'open');
          claims.push(s.claimRequest ? JSON.stringify(s.claimRequest) : null);
          metas.push(_validateMetadata(md, `shift:${s.id}`)); versions.push(s._version || 1);
        }
        await c.query(`INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          SELECT * FROM unnest(
            $1::text[], $2::text[], $3::text[], $4::date[], $5::text[], $6::text[],
            $7::text[], $8::text[], $9::text[], $10::jsonb[], $11::jsonb[], $12::int[])
          ON CONFLICT (id) DO UPDATE SET
            building_id=EXCLUDED.building_id, employee_id=EXCLUDED.employee_id,
            shift_date=EXCLUDED.shift_date, shift_type=EXCLUDED.shift_type, "group"=EXCLUDED."group",
            start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time,
            status=EXCLUDED.status, claim_request=EXCLUDED.claim_request,
            metadata=EXCLUDED.metadata, version = shifts.version + 1, updated_at=now()`,
          [ids, bIds, eIds, dates, types, groups, starts, ends, statuses, claims, metas, versions]);
      }
      // ── DELETE orphaned shifts that are no longer in the data ────────
      // Without this, shifts removed via DELETE /api/shifts/:id (which
      // splices the in-memory array) persist in Postgres forever because
      // saveAll only does UPSERT. On server restart, loadAll() reads them
      // back — exactly the bug where "deleted shifts come back after 30m."
      const keepShiftIds = data.shifts.map(s => s.id);
      if (keepShiftIds.length > 0) {
        await c.query('DELETE FROM shifts WHERE id != ALL($1::text[])', [keepShiftIds]);
      }
    }
    if (Array.isArray(data.schedulePatterns)) {
      for (const p of data.schedulePatterns) {
        // Resolve buildingId: use the pattern's own field first (works for
        // both open and assign patterns), fall back to employee lookup.
        let bId = p.buildingId || null;
        if (!bId && p.empId) {
          const empRow = (await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId])).rows[0];
          bId = empRow?.building_id || null;
        }
        // Store ALL metadata fields (selectedDays, pickerStart, removedDates,
        // kind, cycleLen, slots, lastExtendedTo, appliedAt, etc.) in the
        // `pattern` JSONB column. Strip out the fields that have dedicated
        // columns to avoid storing them twice.
        const meta = _strip(p, ['id','buildingId','empId','shiftType','group','startDate','endDate','active']);
        if (Object.keys(meta).length === 0 && p.id) {
          console.warn('[repo] pattern_empty_jsonb:', p.id, '— metadata fields lost, pattern will be non-functional');
        }
        await c.query(`INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (id) DO UPDATE SET
            building_id=$2, shift_type=$4, "group"=$5, pattern=$6, start_date=$7, end_date=$8, active=$9`,
          [p.id || `pat_${p.empId || 'open'}_${Date.now()}`, bId, p.empId || null,
           p.shiftType || null, p.group || null, JSON.stringify(meta),
           p.startDate || null, p.endDate || null, p.active !== false]);
      }
      // DELETE orphaned patterns no longer in the data
      const keepPatIds = data.schedulePatterns.filter(p => p.id).map(p => p.id);
      if (keepPatIds.length > 0) {
        await c.query('DELETE FROM schedule_patterns WHERE id != ALL($1::text[])', [keepPatIds]);
      }
    }

    // ── app_state blobs (demos, billingData, shiftTemplates, etc.) ───────
    // Only write keys present on `data` so a partial save doesn't blow away
    // a collection we weren't given. Default-typing matters: for a key whose
    // expected shape is an object, an array sneaking in (or vice versa)
    // would corrupt the SPA's reads later, so coerce to the expected type.
    //
    // Lock rows first (SELECT ... FOR UPDATE) so a concurrent saveAll on
    // a different request can't read-then-overwrite the same key in a
    // last-write-wins race. The lock is held until COMMIT inside withTx.
    const keysToWrite = Object.entries(APP_STATE_KEYS).filter(([k]) => data[k] !== undefined).map(([k]) => k);
    if (keysToWrite.length > 0) {
      await c.query(`SELECT key FROM app_state WHERE key = ANY($1) FOR UPDATE`, [keysToWrite]);
    }
    for (const [k, def] of Object.entries(APP_STATE_KEYS)) {
      if (data[k] === undefined) continue;
      const expectArray = Array.isArray(def);
      const v = expectArray
        ? (Array.isArray(data[k]) ? data[k] : [])
        : (data[k] && typeof data[k] === 'object' && !Array.isArray(data[k]) ? data[k] : {});
      await c.query(
        `INSERT INTO app_state (key, value) VALUES ($1, $2::jsonb)
         ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = now()`,
        [k, JSON.stringify(v)]
      );
    }
  });
}

// ──────────────────────────────────────────────────────────────────────────
// Change Journal — durable mutation log written before in-memory changes.
// Each mutation is a single INSERT (autocommit), no transaction needed.
// Survives container crashes between debounced saves.
// ──────────────────────────────────────────────────────────────────────────
async function appendJournal(tableName, entityId, op, payload) {
  if (!_pool) return null;
  try {
    const r = await _pool.query(
      `INSERT INTO change_journal (table_name, entity_id, op, payload)
       VALUES ($1, $2, $3, $4::jsonb) RETURNING id`,
      [tableName, entityId, op, JSON.stringify(payload)]
    );
    return r.rows[0]?.id || null;
  } catch (e) {
    console.error('[repo] journal_append_failed:', e.message);
    return null;
  }
}

async function markJournalApplied(ids) {
  if (!_pool || !ids || ids.length === 0) return;
  try {
    await _pool.query(
      `UPDATE change_journal SET applied = true, applied_at = now() WHERE id = ANY($1::bigint[])`,
      [ids]
    );
  } catch (e) {
    console.error('[repo] journal_mark_applied_failed:', e.message);
  }
}

async function loadUnappliedJournal() {
  if (!_pool) return [];
  try {
    const r = await _pool.query(
      `SELECT id, ts, table_name, entity_id, op, payload FROM change_journal
       WHERE applied = false ORDER BY ts ASC`
    );
    return r.rows;
  } catch (e) {
    console.error('[repo] journal_load_unapplied_failed:', e.message);
    return [];
  }
}

async function pruneJournal(olderThanDays = 7) {
  if (!_pool) return 0;
  try {
    const r = await _pool.query(
      `DELETE FROM change_journal WHERE applied = true AND ts < now() - $1::int * interval '1 day'`,
      [olderThanDays]
    );
    return r.rowCount || 0;
  } catch (e) {
    console.error('[repo] journal_prune_failed:', e.message);
    return 0;
  }
}

async function countUnappliedJournal() {
  if (!_pool) return 0;
  try {
    const r = await _pool.query(`SELECT COUNT(*)::int AS n FROM change_journal WHERE applied = false`);
    return r.rows[0]?.n || 0;
  } catch (e) {
    return 0;
  }
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
    console.error('[repo] audit_db_write_failed:', e.message);
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
  loadAll, saveAllIndependent, saveAll: saveAllIndependent, saveAllLegacy,
  verifyCounts,
  appendJournal, markJournalApplied, loadUnappliedJournal, pruneJournal, countUnappliedJournal,
  loadMigrationFlags, setMigrationFlag,
  getAccountByEmail, getAccountById, upsertAccount, clearAccountTotp,
  appendAuditEntry,
  ping,
};
