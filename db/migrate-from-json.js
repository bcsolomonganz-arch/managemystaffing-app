'use strict';
/**
 * One-time migration: encrypted JSON file → Postgres
 *
 * Usage:
 *   DATA_FILE=/path/to/mms-data.json \
 *   DATA_ENCRYPTION_KEY=<hex32> \
 *   PG_CONN="postgres://user:pass@host:5432/mms?sslmode=require" \
 *   node db/migrate-from-json.js
 *
 * Idempotent: ON CONFLICT DO NOTHING for inserts. Re-running won't duplicate.
 */
require('dotenv').config({ path: process.env.MMS_SECURE_DIR
  ? require('path').join(process.env.MMS_SECURE_DIR, '.env')
  : (process.platform === 'win32' ? 'C:\\ProgramData\\ManageMyStaffing\\.env' : '/var/lib/mms/.env') });

const fs     = require('fs');
const crypto = require('crypto');
const { Client } = require('pg');

const DATA_FILE = process.env.DATA_FILE;
const KEY       = process.env.DATA_ENCRYPTION_KEY;
const PG_CONN   = process.env.PG_CONN || process.env.DATABASE_URL;

if (!DATA_FILE || !KEY || !PG_CONN) {
  console.error('Required: DATA_FILE, DATA_ENCRYPTION_KEY, PG_CONN');
  process.exit(1);
}

function decrypt(blob, key) {
  const iv  = Buffer.from(blob.iv, 'hex');
  const tag = Buffer.from(blob.authTag, 'hex');
  const dec = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
  dec.setAuthTag(tag);
  return JSON.parse(Buffer.concat([dec.update(Buffer.from(blob.data, 'hex')), dec.final()]).toString());
}

(async () => {
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  const data = decrypt(JSON.parse(raw), KEY);

  const c = new Client({ connectionString: PG_CONN, ssl: { rejectUnauthorized: false } });
  await c.connect();

  // Use a transaction so partial failures roll back
  await c.query('BEGIN');
  try {
    // Companies
    for (const co of (data.companies || [])) {
      await c.query(
        'INSERT INTO companies (id, name, color) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING',
        [co.id, co.name, co.color]
      );
    }

    // Buildings
    for (const b of (data.buildings || [])) {
      const { id, name, address, color, beds, companyId, ...rest } = b;
      await c.query(
        `INSERT INTO buildings (id, company_id, name, address, color, beds, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
        [id, companyId || null, name, address, color, beds || null, JSON.stringify(rest || {})]
      );
    }

    // Accounts
    for (const a of (data.accounts || [])) {
      await c.query(
        `INSERT INTO accounts
           (id, email, name, role, building_id, building_ids, "group",
            password_hash, totp_secret_encrypted, totp_enrolled_at,
            totp_recovery_codes_hashes, totp_recovery_codes_generated_at,
            failed_attempts, locked_until,
            invite_token, invite_expiry, invited_by, invited_at, activated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
         ON CONFLICT (id) DO NOTHING`,
        [
          a.id, a.email, a.name, a.role, a.buildingId || null, a.buildingIds || [], a.group || null,
          a.ph || null, a.totpSecret || null, a.totpEnrolledAt || null,
          a.totpRecoveryCodesHashes || null, a.totpRecoveryCodesGeneratedAt || null,
          a.failedAttempts || 0, a.lockedUntil ? new Date(a.lockedUntil) : null,
          a.inviteToken || null, a.inviteExpiry ? new Date(a.inviteExpiry) : null,
          a.invitedBy || null, a.invitedAt || null, a.activatedAt || null,
        ]
      );
    }

    // Employees
    for (const e of (data.employees || [])) {
      const { id, buildingId, accountId, name, email, phone, group, employmentType,
              hourlyRate, hireDate, inactive, notifEmail, notifSMS, terminationLog,
              ...rest } = e;
      await c.query(
        `INSERT INTO employees
           (id, building_id, account_id, name, email, phone, "group", employment_type,
            hourly_rate, hire_date, inactive, notif_email, notif_sms, metadata, termination_log)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (id) DO NOTHING`,
        [
          id, buildingId, accountId || null, name, email || null, phone || null,
          group, employmentType || null, hourlyRate || null, hireDate || null,
          !!inactive, notifEmail !== false, !!notifSMS,
          JSON.stringify(rest || {}), JSON.stringify(terminationLog || []),
        ]
      );
    }

    // Shifts
    for (const s of (data.shifts || [])) {
      const { id, buildingId, employeeId, date, type, group, start, end, status,
              claimRequest, ...rest } = s;
      await c.query(
        `INSERT INTO shifts
           (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (id) DO NOTHING`,
        [
          id, buildingId, employeeId || null, date, type, group,
          start || null, end || null, status || 'open',
          claimRequest ? JSON.stringify(claimRequest) : null,
          JSON.stringify(rest || {}),
        ]
      );
    }

    // Schedule patterns
    for (const p of (data.schedulePatterns || [])) {
      // Resolve building_id from employee record
      const { rows } = await c.query('SELECT building_id FROM employees WHERE id = $1', [p.empId]);
      const bId = rows[0]?.building_id;
      if (!bId) continue;
      await c.query(
        `INSERT INTO schedule_patterns
           (id, building_id, emp_id, shift_type, "group", pattern, start_date, end_date, active)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO NOTHING`,
        [
          p.id || `pat_${p.empId}_${Date.now()}`, bId, p.empId,
          p.shiftType || null, p.group || null, JSON.stringify(p.pattern || {}),
          p.startDate || null, p.endDate || null, p.active !== false,
        ]
      );
    }

    await c.query('COMMIT');
    console.log('Migration complete:');
    console.log(`  companies:           ${(data.companies || []).length}`);
    console.log(`  buildings:           ${(data.buildings || []).length}`);
    console.log(`  accounts:            ${(data.accounts || []).length}`);
    console.log(`  employees:           ${(data.employees || []).length}`);
    console.log(`  shifts:              ${(data.shifts || []).length}`);
    console.log(`  schedule_patterns:   ${(data.schedulePatterns || []).length}`);
  } catch (e) {
    await c.query('ROLLBACK');
    console.error('Migration failed (rolled back):', e.message);
    process.exit(1);
  } finally {
    await c.end();
  }
})();
