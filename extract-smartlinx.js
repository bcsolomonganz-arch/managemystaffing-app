'use strict';
//
// One-off extractor that merges 4 SmartLinx 6 exports into a single JSON
// manifest of buildings + employees, ready to POST into ManageMyStaffing.
//
// Filtering rules from the operator:
//   - Skip rows where Center === 'Agency' (these are agency staffers, not employees)
//   - Skip Brookshire, Giddings, Floresville buildings (inactive)
//   - Skip rows that don't have a Center at all
//
// Field policy:
//   - SSN, DL, insurance — never extracted (the source files don't expose them)
//   - Empty fields are kept as null. Roster shows red star where data missing.
//
// Output: ./smartlinx-import-manifest.json
//

const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');
const XLSX = require('xlsx');

function stableHash(s, len = 16) {
  return crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, len);
}

const DOWNLOADS = 'C:/Users/bcsol/Downloads';
const FILES = {
  basic:    `${DOWNLOADS}/Basic Information_05_01_2026.xlsx`,
  contact:  `${DOWNLOADS}/Contact List_05_01_2026.xlsx`,
  payroll:  `${DOWNLOADS}/Payroll Data_05_01_2026.xlsx`,
  licenses: `${DOWNLOADS}/Licenses_05_01_2026.xlsx`,
};

const SKIP_BUILDINGS = new Set([
  'brookshire residence',
  'giddings residence',
  'floresville residence',
  'agency',
]);

// Building-name normalizations applied during merge. SmartLinx has the same
// facility under slight name variants — we collapse them to one canonical
// name. Kirkland Court already exists in MMS (id b1777218436953) so the
// canonical match is the same string the live db uses.
const NAME_CANONICALIZE = {
  'plainview healthcare':          'Plainview Healthcare Center',
  'plainview healthcare center':   'Plainview Healthcare Center',
  'kirkland court':                'Kirkland Court',
};
function canonicalBuildingName(raw) {
  const k = String(raw || '').trim().toLowerCase();
  return NAME_CANONICALIZE[k] || raw;
}

// Buildings that already exist in production MMS — reuse the existing id
// instead of generating a new one. Lookup by canonical name.
const EXISTING_BUILDINGS = {
  'Kirkland Court': 'b1777218436953',
};

// SmartLinx position → MMS group bucket. The 10 MMS groups are fixed
// (see managemystaffing.html GROUPS const). Anything we don't recognize
// falls into 'Maintenance' as a catch-all so the row still shows up
// somewhere — operator can re-bucket via Edit later.
function mapPosition(rawPos) {
  const p = String(rawPos || '').trim().toLowerCase();
  if (!p) return { group: 'Maintenance', smartlinxPosition: '' };
  // Director of Nursing / Administrator / Manager → Nurse Management
  if (/director of nursing|don\b|adon|administrator|nursing manager|director of rehab|director of clinical/.test(p))
    return { group: 'Nurse Management', smartlinxPosition: rawPos };
  // RN / LPN → Charge Nurse (MMS treats LPN/RN both as Charge Nurse)
  if (/\brn\b|registered nurse|\blpn\b|licensed practical|licensed vocational|charge nurse/.test(p))
    return { group: 'Charge Nurse', smartlinxPosition: rawPos };
  // CMA / Med Aide
  if (/\bcma\b|med aide|medication aide|medication tech/.test(p))
    return { group: 'CMA', smartlinxPosition: rawPos };
  // CNA / Nurse Aide
  if (/\bcna\b|nurse aide|nurse assistant|certified nursing/.test(p))
    return { group: 'CNA', smartlinxPosition: rawPos };
  // Dietary
  if (/cook|chef/.test(p))
    return { group: 'Cook', smartlinxPosition: rawPos };
  if (/dietary|dietician|diet aide|nutrition/.test(p))
    return { group: 'Dietary Aid', smartlinxPosition: rawPos };
  // Housekeeping / Laundry
  if (/housekeep/.test(p))
    return { group: 'Housekeeping', smartlinxPosition: rawPos };
  if (/laundry/.test(p))
    return { group: 'Laundry', smartlinxPosition: rawPos };
  // Maintenance
  if (/maintenance|janitor|grounds/.test(p))
    return { group: 'Maintenance', smartlinxPosition: rawPos };
  // Marketing / Activities / Social Services
  if (/marketing|activit|community|recreation|social|admissions/.test(p))
    return { group: 'Marketing', smartlinxPosition: rawPos };
  // Everything else — keep but bucket as Maintenance and preserve original.
  return { group: 'Maintenance', smartlinxPosition: rawPos };
}

function readSheet(file) {
  const wb = XLSX.readFile(file);
  return XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { defval: '' });
}

function excelDateToISO(serial) {
  if (!serial) return null;
  if (typeof serial === 'string') {
    // Already a string — pass through if it looks date-ish
    if (/^\d{4}-\d{2}-\d{2}/.test(serial)) return serial.slice(0, 10);
    return null;
  }
  if (typeof serial !== 'number') return null;
  // Excel epoch is 1899-12-30 (Windows compat with the 1900 leap-year bug)
  const epoch = new Date(Date.UTC(1899, 11, 30));
  const ms = epoch.getTime() + serial * 86400000;
  return new Date(ms).toISOString().slice(0, 10);
}

function cleanPhone(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (!s || s.includes('___')) return null;        // SmartLinx empty placeholder
  return s;
}

function cleanEmail(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toLowerCase();
  if (!s || !s.includes('@')) return null;
  return s;
}

function cleanRate(raw) {
  if (!raw && raw !== 0) return null;
  const n = parseFloat(raw);
  if (!isFinite(n) || n <= 0) return null;
  return n;
}

function key(row) {
  // Prefer payroll number when available; fall back to name. SmartLinx
  // sometimes lists the same name across multiple rows (different positions
  // at different facilities) — payroll number disambiguates.
  const p = String(row['Payroll No.'] || '').trim();
  if (p) return 'p:' + p;
  return 'n:' + String(row['Name'] || row['Employee Name'] || '').trim().toLowerCase();
}

// ── load & index all four sheets ────────────────────────────────────────────
const basic    = readSheet(FILES.basic);
const contact  = readSheet(FILES.contact);
const payroll  = readSheet(FILES.payroll);
const licenses = readSheet(FILES.licenses);

const contactByKey  = new Map(contact.map(r  => [key(r), r]));
const payrollByKey  = new Map(payroll.map(r  => [key(r), r]));
const licenseByKey  = new Map(licenses.map(r => [key(r), r]));

// ── walk basic-info as the source of truth, merge in extras ────────────────
const buildings = new Map();      // name → { name, employees: [] }
const skippedAgency   = [];
const skippedInactive = [];
const skippedNoCenter = [];
let withLicense = 0;
let withRate    = 0;
let withPhone   = 0;
let withEmail   = 0;

for (const b of basic) {
  const center = String(b.Center || '').trim();
  if (!center) { skippedNoCenter.push(b.Name); continue; }
  const centerLow = center.toLowerCase();
  if (centerLow === 'agency') { skippedAgency.push(b.Name); continue; }
  if (SKIP_BUILDINGS.has(centerLow)) { skippedInactive.push({ name: b.Name, center }); continue; }

  const k = key(b);
  const c = contactByKey.get(k)  || {};
  const p = payrollByKey.get(k)  || {};
  const l = licenseByKey.get(k);          // may be undefined

  const phone   = cleanPhone(c['Phone']) || cleanPhone(c['Mobile']) || cleanPhone(c['Alt. Phone']) || null;
  const email   = cleanEmail(c['Primary Email']) || cleanEmail(c['Alt. Email']) || null;
  const rate    = cleanRate(p['Pay Rate']);
  const hireISO = excelDateToISO(b['Date Hired']);
  const mapped  = mapPosition(b.Position);

  // Employee name comes "Last, First" — flip to "First Last"
  const rawName = String(b.Name || '').trim();
  let display = rawName;
  if (rawName.includes(',')) {
    const [last, first] = rawName.split(',').map(s => s.trim());
    display = `${first} ${last}`.trim();
  }

  const initials = display.split(/\s+/).map(w => (w[0] || '').toUpperCase()).join('').slice(0, 2);

  const employee = {
    name: display,
    initials,
    payrollNo:    String(b['Payroll No.'] || '').trim() || null,
    smartlinxPosition: mapped.smartlinxPosition,
    group:        mapped.group,
    department:   String(b.Department || '').trim() || null,
    employmentType: String(b['Emp Type'] || '').trim().toLowerCase() || null,
    phone, email,
    hourlyRate:   rate,
    hireDate:     hireISO,
    licenseNumber:    l ? (String(l['License Number'] || '').trim() || null) : null,
    licenseExpiresAt: l ? excelDateToISO(l['License Expiration Date'])        : null,
    licenseType:      l ? (String(l['License Type']   || '').trim() || null) : null,
  };

  if (employee.licenseNumber) withLicense++;
  if (employee.hourlyRate)    withRate++;
  if (employee.phone)         withPhone++;
  if (employee.email)         withEmail++;

  // Apply name canonicalization (merges Plainview x2 and matches Kirkland)
  const canonName = canonicalBuildingName(center);

  let bld = buildings.get(canonName);
  if (!bld) {
    bld = { name: canonName, employees: [] };
    buildings.set(canonName, bld);
  }
  bld.employees.push(employee);
}

// ── build the manifest ──────────────────────────────────────────────────────
const manifest = {
  generatedAt: new Date().toISOString(),
  source: 'SmartLinx 6 export 2026-05-01',
  filteringRules: [
    'skipped Center=Agency',
    'skipped Brookshire/Giddings/Floresville (inactive)',
    'skipped rows with no Center',
  ],
  totals: {
    buildings: buildings.size,
    employees: [...buildings.values()].reduce((s, b) => s + b.employees.length, 0),
    skippedAgency: skippedAgency.length,
    skippedInactive: skippedInactive.length,
    skippedNoCenter: skippedNoCenter.length,
    fields: {
      withLicense, withRate, withPhone, withEmail,
    },
  },
  buildings: [...buildings.values()]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(b => ({
      ...b,
      // Stable building id: existing prod id when known, otherwise a
      // deterministic hash of the canonical name so re-runs produce the
      // same id (idempotent imports).
      id: EXISTING_BUILDINGS[b.name]
        || ('b_' + stableHash(b.name, 14)),
      isExisting: !!EXISTING_BUILDINGS[b.name],
    })),
};

const out = path.join(__dirname, 'smartlinx-import-manifest.json');
fs.writeFileSync(out, JSON.stringify(manifest, null, 2));

console.log(`Wrote ${out}`);
console.log('');
console.log(`Buildings:  ${manifest.totals.buildings}`);
console.log(`Employees:  ${manifest.totals.employees}`);
console.log(`  with phone:   ${manifest.totals.fields.withPhone}`);
console.log(`  with email:   ${manifest.totals.fields.withEmail}`);
console.log(`  with rate:    ${manifest.totals.fields.withRate}`);
console.log(`  with license: ${manifest.totals.fields.withLicense}`);
console.log('');
console.log(`Skipped:`);
console.log(`  agency:    ${manifest.totals.skippedAgency}`);
console.log(`  inactive:  ${manifest.totals.skippedInactive}`);
console.log(`  no center: ${manifest.totals.skippedNoCenter}`);
console.log('');
console.log('Buildings to create (employee count):');
for (const b of manifest.buildings) {
  console.log(`  ${b.employees.length.toString().padStart(4)}  ${b.name}`);
}
