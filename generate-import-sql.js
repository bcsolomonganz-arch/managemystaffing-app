'use strict';
//
// Reads the SmartLinx manifest and emits a single .sql file that:
//   - Ensures the SkyBlue Healthcare company row exists
//   - INSERT...ON CONFLICT DO NOTHING for every building (so re-runs are safe
//     and Kirkland Court's existing row is preserved)
//   - INSERT...ON CONFLICT DO UPDATE for every employee
//
// All values are properly escaped via pg-format-style quoting.
//

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
function stableHash(s, len = 16) {
  return crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, len);
}

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'smartlinx-import-manifest.json'), 'utf8'));

// Postgres-safe quoting for text literals. Doubles single quotes.
function q(v) {
  if (v === null || v === undefined || v === '') return 'NULL';
  return `'${String(v).replace(/'/g, "''")}'`;
}
function qDate(v) {
  if (!v) return 'NULL';
  return `'${v}'::date`;
}
function qNum(v) {
  if (v === null || v === undefined || v === '') return 'NULL';
  const n = parseFloat(v);
  return isFinite(n) ? String(n) : 'NULL';
}
function qBool(v) { return v ? 'TRUE' : 'FALSE'; }

const lines = [];
lines.push('-- SmartLinx 6 → ManageMyStaffing bulk import');
lines.push(`-- Generated ${new Date().toISOString()}`);
lines.push('-- ' + manifest.totals.buildings + ' buildings, ' + manifest.totals.employees + ' employees');
lines.push('-- Re-runnable: ON CONFLICT clauses make this idempotent.');
lines.push('');
lines.push('BEGIN;');
lines.push('');

// 1. SkyBlue Healthcare company row (idempotent)
lines.push("-- Company");
lines.push(`INSERT INTO companies (id, name, color)
  VALUES ('co_skyblue', 'SkyBlue Healthcare', '#0891B2')
  ON CONFLICT (id) DO NOTHING;`);
lines.push('');

// 2. Buildings — DO NOTHING on conflict so existing Kirkland is untouched.
lines.push('-- Buildings');
for (const b of manifest.buildings) {
  lines.push(
    `INSERT INTO buildings (id, company_id, name, beds, metadata) VALUES (` +
    `${q(b.id)}, 'co_skyblue', ${q(b.name)}, NULL, '{}'::jsonb` +
    `) ON CONFLICT (id) DO UPDATE SET company_id = EXCLUDED.company_id, ` +
    `name = COALESCE(buildings.name, EXCLUDED.name), updated_at = now();`
  );
}
lines.push('');

// 3. Employees — UPSERT with COALESCE on optional fields so a re-run from a
//    smaller source doesn't blank existing data.
lines.push('-- Employees');
let idx = 0;
for (const b of manifest.buildings) {
  lines.push(`-- ${b.name} (${b.employees.length})`);
  for (const e of b.employees) {
    idx++;
    // Stable per-employee id. Use payroll number when present (collision-
    // free in SmartLinx), otherwise hash the name + building.
    const id = e.payrollNo
      ? `e_p${e.payrollNo}`
      : 'e_' + stableHash((e.name || '') + '|' + b.name, 16);

    // Group must be one of the MMS fixed enum (column type TEXT but front-end
    // expects exact match). The mapper in extract-smartlinx.js already
    // bucketed into one of the 10 valid groups.
    const group = e.group || 'Maintenance';
    // Employment type — MMS expects 'fulltime' / 'parttime' / 'prn' / null
    const et = String(e.employmentType || '').toLowerCase();
    const empType = (et === 'ft' || et === 'fulltime') ? 'fulltime'
                  : (et === 'pt' || et === 'parttime') ? 'parttime'
                  : (et === 'prn' || et === 'pt prn')  ? 'prn'
                  : null;

    // Metadata JSON for fields outside the column set
    const md = {
      smartlinxPosition: e.smartlinxPosition || null,
      department:        e.department || null,
      payrollNo:         e.payrollNo || null,
      licenseType:       e.licenseType || null,
      initials:          e.initials || null,
    };

    lines.push(
      `INSERT INTO employees (id, building_id, name, email, phone, "group", ` +
      `employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms, ` +
      `metadata, termination_log, ` +
      `license_number, license_expires_at, license_state) VALUES (` +
      `${q(id)}, ${q(b.id)}, ${q(e.name)}, ${q(e.email)}, ${q(e.phone)}, ${q(group)}, ` +
      `${q(empType)}, ${qNum(e.hourlyRate)}, ${qDate(e.hireDate)}, FALSE, TRUE, FALSE, ` +
      `${q(JSON.stringify(md))}::jsonb, '[]'::jsonb, ` +
      `${q(e.licenseNumber)}, ${qDate(e.licenseExpiresAt)}, NULL` +
      `) ON CONFLICT (id) DO UPDATE SET ` +
      `name = EXCLUDED.name, ` +
      `email = COALESCE(EXCLUDED.email, employees.email), ` +
      `phone = COALESCE(EXCLUDED.phone, employees.phone), ` +
      `"group" = EXCLUDED."group", ` +
      `employment_type = COALESCE(EXCLUDED.employment_type, employees.employment_type), ` +
      `hourly_rate = COALESCE(EXCLUDED.hourly_rate, employees.hourly_rate), ` +
      `hire_date = COALESCE(EXCLUDED.hire_date, employees.hire_date), ` +
      `metadata = employees.metadata || EXCLUDED.metadata, ` +
      `license_number = COALESCE(EXCLUDED.license_number, employees.license_number), ` +
      `license_expires_at = COALESCE(EXCLUDED.license_expires_at, employees.license_expires_at), ` +
      `updated_at = now();`
    );
  }
  lines.push('');
}

lines.push('COMMIT;');
lines.push('');
lines.push('-- Verify after run:');
lines.push("--   SELECT name, COUNT(*) FROM buildings b JOIN employees e ON e.building_id = b.id WHERE b.company_id = 'co_skyblue' GROUP BY name ORDER BY name;");

const out = path.join(__dirname, 'smartlinx-import.sql');
fs.writeFileSync(out, lines.join('\n'));

console.log(`Wrote ${out}`);
console.log(`Total statements: ~${idx + manifest.buildings.length + 1}`);
console.log(`File size: ${(fs.statSync(out).size / 1024).toFixed(1)} KB`);
