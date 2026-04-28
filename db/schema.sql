-- ManageMyStaffing — Postgres schema with Row-Level Security
-- HIPAA §164.312 + §164.502 compliant tenant isolation
-- Run order: this file once at database creation time.

-- Connect: psql "host=mms-pg-248457.postgres.database.azure.com user=mmsadmin dbname=mms sslmode=require"

CREATE EXTENSION IF NOT EXISTS pgcrypto;       -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS citext;         -- case-insensitive email

-- ──────────────────────────────────────────────────────────────────────────
-- Companies (top-level tenant) — multiple buildings can belong to one company
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS companies (
  id          TEXT PRIMARY KEY,                    -- co_skyblue, co_xxx
  name        TEXT NOT NULL,
  color       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS buildings (
  id          TEXT PRIMARY KEY,                    -- b1, sunrise-snf, etc.
  company_id  TEXT REFERENCES companies(id) ON DELETE SET NULL,
  name        TEXT NOT NULL,
  address     TEXT,
  color       TEXT CHECK (color ~ '^#[0-9a-fA-F]{3,8}$' OR color IS NULL),
  beds        INTEGER,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_buildings_company ON buildings(company_id);

-- ──────────────────────────────────────────────────────────────────────────
-- Accounts (auth + profile)
-- Per-account encryption: bcrypt for password, otplib secret for TOTP
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS accounts (
  id                              TEXT PRIMARY KEY,        -- prefer UUIDs in new code
  email                           CITEXT UNIQUE NOT NULL,  -- case-insensitive
  name                            TEXT NOT NULL,
  role                            TEXT NOT NULL CHECK (role IN ('superadmin','admin','regionaladmin','employee')),
  building_id                     TEXT REFERENCES buildings(id) ON DELETE SET NULL,
  building_ids                    TEXT[] NOT NULL DEFAULT '{}',   -- multi-building access
  "group"                         TEXT,
  password_hash                   TEXT,                          -- bcrypt
  totp_secret_encrypted           TEXT,                          -- envelope-encrypted with KMS
  totp_enrolled_at                TIMESTAMPTZ,
  totp_recovery_codes_hashes      TEXT[],                        -- bcrypt of each
  totp_recovery_codes_generated_at TIMESTAMPTZ,
  failed_attempts                 INTEGER NOT NULL DEFAULT 0,
  locked_until                    TIMESTAMPTZ,
  invite_token                    TEXT,
  invite_expiry                   TIMESTAMPTZ,
  invited_by                      TEXT,
  invited_at                      TIMESTAMPTZ,
  activated_at                    TIMESTAMPTZ,
  password_reset_token_hash       TEXT,
  password_reset_expiry           TIMESTAMPTZ,
  scheduler_only                  BOOLEAN NOT NULL DEFAULT false,  -- true = admin sees schedule only, no $ data
  created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_accounts_building ON accounts(building_id);
CREATE INDEX IF NOT EXISTS idx_accounts_invite_token ON accounts(invite_token) WHERE invite_token IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────
-- Employees (staff roster) — separate from accounts (employees may not have login)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS employees (
  id              TEXT PRIMARY KEY,
  building_id     TEXT NOT NULL REFERENCES buildings(id) ON DELETE CASCADE,
  account_id      TEXT REFERENCES accounts(id) ON DELETE SET NULL,    -- linked if employee has login
  name            TEXT NOT NULL,
  email           CITEXT,
  phone           TEXT,
  "group"         TEXT NOT NULL,             -- CNA, RN, LPN, Charge Nurse, etc.
  employment_type TEXT CHECK (employment_type IN ('fulltime','parttime','prn') OR employment_type IS NULL),
  hourly_rate     NUMERIC(10,2),
  hire_date       DATE,
  inactive        BOOLEAN NOT NULL DEFAULT FALSE,
  notif_email     BOOLEAN NOT NULL DEFAULT TRUE,
  notif_sms       BOOLEAN NOT NULL DEFAULT FALSE,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  termination_log JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_employees_building ON employees(building_id);
CREATE INDEX IF NOT EXISTS idx_employees_active ON employees(building_id) WHERE inactive = FALSE;
CREATE INDEX IF NOT EXISTS idx_employees_email ON employees(email) WHERE email IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────
-- Shifts
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shifts (
  id            TEXT PRIMARY KEY,
  building_id   TEXT NOT NULL REFERENCES buildings(id) ON DELETE CASCADE,
  employee_id   TEXT REFERENCES employees(id) ON DELETE SET NULL,
  shift_date    DATE NOT NULL,
  shift_type    TEXT NOT NULL,            -- Day, Evening, Night, etc.
  "group"       TEXT NOT NULL,
  start_time    TEXT,                      -- '07:00'
  end_time      TEXT,                      -- '15:00'
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','scheduled','cancelled')),
  claim_request JSONB,                     -- {empId, empName, requestedAt}
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  version       INTEGER NOT NULL DEFAULT 1, -- optimistic concurrency
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_shifts_building_date ON shifts(building_id, shift_date);
CREATE INDEX IF NOT EXISTS idx_shifts_employee_date ON shifts(employee_id, shift_date);
CREATE INDEX IF NOT EXISTS idx_shifts_status ON shifts(building_id, status, shift_date) WHERE status = 'open';

-- ──────────────────────────────────────────────────────────────────────────
-- Schedule patterns (rotations)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schedule_patterns (
  id          TEXT PRIMARY KEY,
  building_id TEXT NOT NULL REFERENCES buildings(id) ON DELETE CASCADE,
  emp_id      TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  shift_type  TEXT,
  "group"     TEXT,
  pattern     JSONB NOT NULL DEFAULT '{}'::jsonb,    -- e.g., {days: [1,2,3], weeks: [1,3]}
  start_date  DATE,
  end_date    DATE,
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_patterns_emp ON schedule_patterns(emp_id) WHERE active = TRUE;

-- ──────────────────────────────────────────────────────────────────────────
-- Audit log mirror (primary copy is in WORM Azure Storage)
-- This table is for fast querying; immutable storage is the legal record.
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_entries (
  id           BIGSERIAL PRIMARY KEY,
  ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id      TEXT,
  user_role    TEXT,
  action       TEXT NOT NULL,
  building_id  TEXT,
  details      JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash    CHAR(64),
  hmac         CHAR(64) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_entries(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_entries(user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_building ON audit_entries(building_id, ts DESC);

-- ──────────────────────────────────────────────────────────────────────────
-- Row-Level Security (HIPAA tenant isolation)
-- The application sets `app.current_building_ids` per request; RLS filters rows.
-- ──────────────────────────────────────────────────────────────────────────
ALTER TABLE buildings           ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts            ENABLE ROW LEVEL SECURITY;
ALTER TABLE employees           ENABLE ROW LEVEL SECURITY;
ALTER TABLE shifts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE schedule_patterns   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entries       ENABLE ROW LEVEL SECURITY;

-- Helper: get current user's building IDs from session var
CREATE OR REPLACE FUNCTION current_building_ids() RETURNS TEXT[] AS $$
  SELECT string_to_array(coalesce(current_setting('app.current_building_ids', true), ''), ',');
$$ LANGUAGE SQL STABLE;

CREATE OR REPLACE FUNCTION current_role_name() RETURNS TEXT AS $$
  SELECT coalesce(current_setting('app.current_role', true), '');
$$ LANGUAGE SQL STABLE;

-- Superadmin bypasses RLS
CREATE POLICY p_buildings_sa  ON buildings  FOR ALL USING (current_role_name() = 'superadmin') WITH CHECK (current_role_name() = 'superadmin');
CREATE POLICY p_buildings_tenant ON buildings FOR ALL
  USING (id = ANY(current_building_ids()))
  WITH CHECK (id = ANY(current_building_ids()));

CREATE POLICY p_employees_sa  ON employees  FOR ALL USING (current_role_name() = 'superadmin') WITH CHECK (current_role_name() = 'superadmin');
CREATE POLICY p_employees_tenant ON employees FOR ALL
  USING (building_id = ANY(current_building_ids()))
  WITH CHECK (building_id = ANY(current_building_ids()));

CREATE POLICY p_shifts_sa     ON shifts     FOR ALL USING (current_role_name() = 'superadmin') WITH CHECK (current_role_name() = 'superadmin');
CREATE POLICY p_shifts_tenant ON shifts FOR ALL
  USING (building_id = ANY(current_building_ids()))
  WITH CHECK (building_id = ANY(current_building_ids()));

CREATE POLICY p_patterns_sa   ON schedule_patterns FOR ALL USING (current_role_name() = 'superadmin') WITH CHECK (current_role_name() = 'superadmin');
CREATE POLICY p_patterns_tenant ON schedule_patterns FOR ALL
  USING (building_id = ANY(current_building_ids()))
  WITH CHECK (building_id = ANY(current_building_ids()));

CREATE POLICY p_accounts_sa   ON accounts FOR ALL USING (current_role_name() = 'superadmin') WITH CHECK (current_role_name() = 'superadmin');
CREATE POLICY p_accounts_tenant ON accounts FOR ALL
  USING (
    building_id = ANY(current_building_ids())
    OR building_ids && current_building_ids()
  )
  WITH CHECK (
    building_id = ANY(current_building_ids())
    OR building_ids && current_building_ids()
  );

CREATE POLICY p_audit_sa      ON audit_entries FOR ALL USING (current_role_name() = 'superadmin');
CREATE POLICY p_audit_tenant  ON audit_entries FOR SELECT
  USING (building_id IS NULL OR building_id = ANY(current_building_ids()));

-- ──────────────────────────────────────────────────────────────────────────
-- updated_at triggers
-- ──────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql;

CREATE TRIGGER companies_updated  BEFORE UPDATE ON companies  FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
CREATE TRIGGER buildings_updated  BEFORE UPDATE ON buildings  FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
CREATE TRIGGER accounts_updated   BEFORE UPDATE ON accounts   FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
CREATE TRIGGER employees_updated  BEFORE UPDATE ON employees  FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
CREATE TRIGGER shifts_updated     BEFORE UPDATE ON shifts     FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
