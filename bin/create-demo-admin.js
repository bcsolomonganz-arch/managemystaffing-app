#!/usr/bin/env node
'use strict';
/*
 * create-demo-admin.js — provision (or refresh) a demo admin account
 *
 * Use case: the owner needs a real, fully-functioning admin login they can
 * share for product demos, partner walkthroughs, or QA. Demo mode in the
 * client (demo@demo.com) is browser-local and doesn't persist across
 * sessions; this creates a real account on the server that:
 *
 *   • is scoped to a single building (default: Kirkland Court)
 *   • has admin role (not super-admin) so the demo viewer sees the
 *     building-admin experience, not platform-overview
 *   • has a known password — admin can hand the credentials to a
 *     prospect and have them log in immediately
 *
 * Idempotent: if an account with the demo email already exists, this
 * UPDATES its password + name + buildingId rather than creating a
 * duplicate. So "rotate the demo password" is just a re-run with a
 * new --password.
 *
 * Usage:
 *   node bin/create-demo-admin.js \
 *     --email=demo-kirkland@managemystaffing.com \
 *     --name="Kirkland Demo Admin" \
 *     --password=<choose a strong one> \
 *     --building=b1777218436953     # Kirkland Court id (run with no
 *                                   # --building to see a list)
 *
 * Run on the Azure App Service via Kudu console / SSH.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Mirror server.js env loading
const IS_AZURE = !!process.env.WEBSITE_INSTANCE_ID;
const SECURE_DIR = IS_AZURE
  ? '/home/data'
  : (process.env.MMS_SECURE_DIR || (process.platform === 'win32' ? 'C:\\ProgramData\\ManageMyStaffing' : '/var/lib/mms'));
const SECURE_ENV = path.join(SECURE_DIR, '.env');
if (fs.existsSync(SECURE_ENV)) require('dotenv').config({ path: SECURE_ENV });
else require('dotenv').config();

function getArg(name) {
  const flag = '--' + name + '=';
  const hit = process.argv.find(a => a.startsWith(flag));
  return hit ? hit.slice(flag.length) : null;
}
const email      = (getArg('email') || 'demo-kirkland@managemystaffing.com').trim().toLowerCase();
const name       = (getArg('name')  || 'Kirkland Demo Admin').trim();
const password   = getArg('password');
const buildingId = (getArg('building') || '').trim();
const role       = 'admin';     // never superadmin for a demo account

if (!password) {
  console.error('--password is required (pick something strong; the credentials will be shareable)');
  process.exit(2);
}

// Data store helpers
const useDB = !!process.env.PG_CONN;
let dbRepo;
if (useDB) {
  dbRepo = require('../db/repo');
  dbRepo.init();
}

const DATA_FILE = process.env.DATA_FILE || path.join(SECURE_DIR, 'mms-data.json');
const DATA_KEY  = process.env.DATA_ENCRYPTION_KEY;

async function decryptFile() {
  if (!DATA_KEY) throw new Error('DATA_ENCRYPTION_KEY env var not set');
  const raw = JSON.parse(await fs.promises.readFile(DATA_FILE, 'utf8'));
  const key = Buffer.from(DATA_KEY, 'hex');
  const iv  = Buffer.from(raw.iv, 'hex');
  const tag = Buffer.from(raw.authTag, 'hex');
  const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
  dec.setAuthTag(tag);
  const out = Buffer.concat([dec.update(Buffer.from(raw.data, 'hex')), dec.final()]);
  return JSON.parse(out.toString());
}

async function loadAll() {
  if (useDB) {
    const buildings = await dbRepo.getAllBuildings();
    const accounts  = await dbRepo.getAllAccounts();
    return { buildings, accounts };
  }
  const data = await decryptFile();
  return { buildings: data.buildings || [], accounts: data.accounts || [] };
}

async function findBuilding(buildings, idOrName) {
  if (!idOrName) return null;
  return buildings.find(b => b.id === idOrName || (b.name||'').toLowerCase() === idOrName.toLowerCase()) || null;
}

(async () => {
  console.log(`[create-demo-admin] data store: ${useDB ? 'Postgres' : 'encrypted file'}`);
  const { buildings, accounts } = await loadAll();

  if (!buildingId) {
    console.log('No --building specified. Available buildings:');
    for (const b of buildings) console.log(`  ${b.id}\t${b.name}`);
    console.log('\nRe-run with --building=<id>');
    process.exit(2);
  }

  const building = await findBuilding(buildings, buildingId);
  if (!building) {
    console.error(`[create-demo-admin] No building found matching ${buildingId}`);
    process.exit(1);
  }

  let acct = accounts.find(a => (a.email || '').toLowerCase() === email);
  const ph = await bcrypt.hash(password, 12);
  const nowIso = new Date().toISOString();
  if (acct) {
    // Refresh in place — don't change the id (preserves audit history)
    acct.name        = name;
    acct.role        = role;
    acct.buildingId  = building.id;
    acct.buildingIds = [building.id];
    acct.ph          = ph;
    acct.activatedAt = acct.activatedAt || nowIso;
    delete acct.passwordResetTokenHash;
    delete acct.passwordResetExpiry;
    delete acct.lockedUntil;
    delete acct.failedAttempts;
    console.log(`[create-demo-admin] Updated existing account ${acct.id} (${email})`);
  } else {
    acct = {
      id:          'acc_demo_' + Date.now(),
      name, email,
      role,
      buildingId:  building.id,
      buildingIds: [building.id],
      ph,
      schedulerOnly: false,
      activatedAt: nowIso,
      invitedBy:   'create-demo-admin.js',
      invitedAt:   nowIso,
    };
    console.log(`[create-demo-admin] Created new account ${acct.id} (${email})`);
  }

  if (useDB) {
    await dbRepo.upsertAccount(acct);
    await dbRepo.close();
  } else {
    const data = await decryptFile();
    data.accounts = data.accounts || [];
    const idx = data.accounts.findIndex(a => a.id === acct.id);
    if (idx >= 0) data.accounts[idx] = acct;
    else data.accounts.push(acct);
    const key = Buffer.from(DATA_KEY, 'hex');
    const iv  = crypto.randomBytes(12);
    const cip = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct  = Buffer.concat([cip.update(JSON.stringify(data)), cip.final()]);
    const tag = cip.getAuthTag();
    const wrapped = { iv: iv.toString('hex'), data: ct.toString('hex'), authTag: tag.toString('hex') };
    const tmp = DATA_FILE + '.tmp';
    await fs.promises.writeFile(tmp, JSON.stringify(wrapped));
    await fs.promises.rename(tmp, DATA_FILE);
  }

  const APP_URL = process.env.APP_URL || 'https://managemystaffing.com';
  console.log('');
  console.log('  ┌─ Demo admin ready ─────────────────────────────────────────');
  console.log(`  │  URL:        ${APP_URL}/`);
  console.log(`  │  Email:      ${email}`);
  console.log(`  │  Password:   ${password}`);
  console.log(`  │  Building:   ${building.name}  (${building.id})`);
  console.log(`  │  Role:       ${role}`);
  console.log('  └────────────────────────────────────────────────────────────');
  console.log('');
  console.log('  Share these credentials with whoever is doing the demo. To');
  console.log('  rotate the password later, re-run this script with a new');
  console.log('  --password — it will update in place.');
  console.log('');
})().catch(err => {
  console.error('[create-demo-admin] Failed:', err.message);
  console.error(err.stack);
  process.exit(1);
});
