#!/usr/bin/env node
'use strict';
/*
 * inspect-data-dir.js — list and probe every candidate data file on disk
 *
 * Goal: find data-file-shaped artifacts (current, backups, tmp files,
 * snapshots from older retention windows) that the in-app snapshot
 * endpoint may not surface. Useful when the live mms-data.json has
 * been wiped and we need to know what's recoverable from disk.
 *
 * Usage (run on the server via Kudu console):
 *   node bin/inspect-data-dir.js
 *
 * Output: a table of every file in the secure dir and the backup dir,
 * with size, mtime, and (for files we can decrypt) the row counts
 * for buildings/employees/shifts/companies.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const IS_AZURE = !!process.env.WEBSITE_INSTANCE_ID;
const SECURE_DIR = IS_AZURE
  ? '/home/data'
  : (process.env.MMS_SECURE_DIR || (process.platform === 'win32' ? 'C:\\ProgramData\\ManageMyStaffing' : '/var/lib/mms'));
const SECURE_ENV = path.join(SECURE_DIR, '.env');
if (fs.existsSync(SECURE_ENV)) {
  require('dotenv').config({ path: SECURE_ENV });
} else {
  require('dotenv').config();
}

const DATA_FILE  = process.env.DATA_FILE  || path.join(SECURE_DIR, 'mms-data.json');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DATA_FILE), 'mms-backups');
const DATA_KEY   = process.env.DATA_ENCRYPTION_KEY;

function tryDecrypt(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw || raw[0] !== '{') return { error: 'not JSON' };
    const obj = JSON.parse(raw);
    if (obj.iv && obj.data && obj.authTag) {
      // Encrypted snapshot/data file
      if (!DATA_KEY) return { encrypted: true, error: 'no DATA_ENCRYPTION_KEY' };
      const key = Buffer.from(DATA_KEY, 'hex');
      const iv  = Buffer.from(obj.iv, 'hex');
      const tag = Buffer.from(obj.authTag, 'hex');
      const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
      dec.setAuthTag(tag);
      const out = Buffer.concat([dec.update(Buffer.from(obj.data, 'hex')), dec.final()]);
      const data = JSON.parse(out.toString());
      return {
        encrypted: true,
        buildings: (data.buildings || []).length,
        employees: (data.employees || []).length,
        shifts:    (data.shifts    || []).length,
        accounts:  (data.accounts  || []).length,
        companies: (data.companies || []).length,
        firstBuildingNames: (data.buildings || []).slice(0, 8).map(b => b.name),
      };
    }
    // Plaintext (legacy / .bak)
    return {
      encrypted: false,
      buildings: (obj.buildings || []).length,
      employees: (obj.employees || []).length,
      shifts:    (obj.shifts    || []).length,
      accounts:  (obj.accounts  || []).length,
      companies: (obj.companies || []).length,
      firstBuildingNames: (obj.buildings || []).slice(0, 8).map(b => b.name),
    };
  } catch (e) {
    return { error: e.message };
  }
}

function scan(dir) {
  if (!fs.existsSync(dir)) {
    console.log('  (directory does not exist)');
    return;
  }
  const items = fs.readdirSync(dir);
  if (!items.length) {
    console.log('  (empty)');
    return;
  }
  for (const name of items) {
    const fp = path.join(dir, name);
    let st;
    try { st = fs.statSync(fp); } catch (e) { console.log(`  ${name}  [stat failed: ${e.message}]`); continue; }
    if (st.isDirectory()) {
      console.log(`  📂 ${name}/  (${st.mtime.toISOString()})`);
      continue;
    }
    const sizeKB = (st.size / 1024).toFixed(1);
    const mtime  = st.mtime.toISOString();
    process.stdout.write(`  📄 ${name}  ${sizeKB} KB  ${mtime}`);
    if (/\.json(\.tmp|\.bak)?$/.test(name)) {
      const probe = tryDecrypt(fp);
      const counts = probe.error
        ? `  ❌ ${probe.error}`
        : `  → bld=${probe.buildings} emp=${probe.employees} sft=${probe.shifts} acc=${probe.accounts}` +
          (probe.firstBuildingNames?.length ? `  [${probe.firstBuildingNames.join(', ')}]` : '');
      process.stdout.write(counts);
    }
    process.stdout.write('\n');
  }
}

console.log('=== ManageMyStaffing — data directory inspection ===');
console.log('IS_AZURE:        ', IS_AZURE);
console.log('SECURE_DIR:      ', SECURE_DIR);
console.log('DATA_FILE:       ', DATA_FILE);
console.log('BACKUP_DIR:      ', BACKUP_DIR);
console.log('DATA_KEY set:    ', !!DATA_KEY);
console.log('');
console.log(`📁 ${SECURE_DIR}`);
scan(SECURE_DIR);
console.log('');
console.log(`📁 ${BACKUP_DIR}`);
scan(BACKUP_DIR);

// Also probe /home for any other mc-* / mms-* artifacts mentioned in
// project memory (mc-data.json, mc-backups/) — those would be a
// different app's data but worth listing in case files got cross-pollinated.
console.log('');
console.log('📁 /home (only listing mc-* / mms-* / *backup* / *.bak entries)');
try {
  const home = '/home';
  if (fs.existsSync(home)) {
    const items = fs.readdirSync(home).filter(n => /^(mc-|mms-)|(backup)|\.bak$/i.test(n));
    if (!items.length) console.log('  (no matches)');
    for (const name of items) {
      const fp = path.join(home, name);
      try {
        const st = fs.statSync(fp);
        console.log(`  📄 ${name}  ${(st.size/1024).toFixed(1)} KB  ${st.mtime.toISOString()}${st.isDirectory()?'  (dir)':''}`);
      } catch (e) {
        console.log(`  📄 ${name}  [${e.message}]`);
      }
    }
  } else {
    console.log('  (no /home directory on this OS)');
  }
} catch (e) {
  console.log('  (error: ' + e.message + ')');
}
