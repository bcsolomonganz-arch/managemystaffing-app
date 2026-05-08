#!/usr/bin/env node
'use strict';
/*
 * admin-rescue.js — emergency admin account recovery
 *
 * Use cases this solves:
 *   1. Super admin email points to a mailbox that doesn't actually exist,
 *      so the password-reset email goes nowhere.
 *   2. Forgot password and the reset email never arrives.
 *   3. Need to change the super admin's email to a different working address.
 *
 * What it does (two modes, pick one with --mode):
 *
 *   --mode=link
 *      Generates a fresh password-reset token (1-hour TTL, identical to
 *      what /api/auth/password-reset/request creates), stores its bcrypt
 *      hash on the account, and prints the reset URL to stdout.
 *      No email is sent. Copy the URL into your browser, set a new
 *      password, sign in.
 *
 *   --mode=email
 *      Updates the account's email address to a new value, then exits.
 *      After this you can use the regular "Send password reset link"
 *      button on the website's login page — it'll go to the new address.
 *
 * Usage (run on the server, via Azure App Service Kudu console / SSH):
 *
 *   node bin/admin-rescue.js --mode=link  --email=solomong@managemystaffing.com
 *   node bin/admin-rescue.js --mode=email --email=solomong@managemystaffing.com --new-email=solomonganz@managecensus.com
 *
 * SECURITY:
 *   This script reads/writes the live data store directly. It can only
 *   be run by an operator with file-system access to the server, who
 *   already has at least as much access as this script grants. Don't
 *   share the printed reset URL with anyone — it's a single-use token
 *   that bypasses 2FA setup if 2FA hasn't been enrolled yet.
 *
 *   No special env var or token is required. The script's authority
 *   comes from running on the server.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// ── Mirror server.js env loading: look in the secure dir first ────────────
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

// ── Argv parsing ──────────────────────────────────────────────────────────
function getArg(name) {
  const flag = '--' + name + '=';
  const hit = process.argv.find(a => a.startsWith(flag));
  return hit ? hit.slice(flag.length) : null;
}
const mode      = (getArg('mode') || 'link').toLowerCase();
const email     = (getArg('email') || '').trim().toLowerCase();
const newEmail  = (getArg('new-email') || '').trim().toLowerCase();
const APP_URL   = process.env.APP_URL || 'https://managemystaffing.com';

if (!email) {
  console.error('Usage:');
  console.error('  node bin/admin-rescue.js --mode=link  --email=<email>');
  console.error('  node bin/admin-rescue.js --mode=email --email=<old> --new-email=<new>');
  process.exit(2);
}
if (!['link', 'email'].includes(mode)) {
  console.error(`Unknown --mode: ${mode}. Use 'link' or 'email'.`);
  process.exit(2);
}
if (mode === 'email' && !newEmail) {
  console.error('--mode=email requires --new-email=<address>');
  process.exit(2);
}

// ── Data store helpers (handles both Postgres and encrypted-file modes) ───
const useDB = !!process.env.PG_CONN;
let dbRepo;
if (useDB) {
  dbRepo = require('../db/repo');
  dbRepo.init();
}

const DATA_FILE = process.env.DATA_FILE || path.join(SECURE_DIR, 'mms-data.json');
const DATA_KEY = process.env.DATA_ENCRYPTION_KEY;

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
async function encryptFile(obj) {
  const key = Buffer.from(DATA_KEY, 'hex');
  const iv  = crypto.randomBytes(12);
  const cip = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct  = Buffer.concat([cip.update(JSON.stringify(obj)), cip.final()]);
  const tag = cip.getAuthTag();
  const wrapped = { iv: iv.toString('hex'), data: ct.toString('hex'), authTag: tag.toString('hex') };
  // Atomic write: tmp + rename
  const tmp = DATA_FILE + '.tmp';
  await fs.promises.writeFile(tmp, JSON.stringify(wrapped));
  await fs.promises.rename(tmp, DATA_FILE);
}

async function findAccount(emailNorm) {
  if (useDB) {
    return dbRepo.getAccountByEmail(emailNorm);
  }
  const data = await decryptFile();
  return (data.accounts || []).find(a => (a.email || '').toLowerCase() === emailNorm) || null;
}

async function saveAccount(acct) {
  if (useDB) {
    await dbRepo.upsertAccount(acct);
    return;
  }
  const data = await decryptFile();
  data.accounts = data.accounts || [];
  const idx = data.accounts.findIndex(a => a.id === acct.id);
  if (idx >= 0) data.accounts[idx] = acct;
  else data.accounts.push(acct);
  await encryptFile(data);
}

// ── Main ──────────────────────────────────────────────────────────────────
(async () => {
  console.log(`[admin-rescue] data store: ${useDB ? 'Postgres' : 'encrypted file (' + DATA_FILE + ')'}`);
  const acct = await findAccount(email);
  if (!acct) {
    console.error(`[admin-rescue] No account found with email: ${email}`);
    process.exit(1);
  }
  console.log(`[admin-rescue] Found account: ${acct.name || '(no name)'} · id=${acct.id} · role=${acct.role}`);

  if (mode === 'email') {
    const before = acct.email;
    acct.email = newEmail;
    await saveAccount(acct);
    console.log(`[admin-rescue] Email updated: ${before} → ${newEmail}`);
    console.log(`[admin-rescue] Now go to ${APP_URL}/ and click "Send password reset link" using the new address.`);
  } else {
    // mode === 'link': generate fresh reset token + URL
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = await bcrypt.hash(rawToken, 12);
    acct.passwordResetTokenHash = tokenHash;
    acct.passwordResetExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
    await saveAccount(acct);
    const url = `${APP_URL}/?reset=${rawToken}&u=${encodeURIComponent(acct.id)}`;
    console.log('');
    console.log('  ┌─ Password-reset URL (valid 1 hour, single use) ──────────────────────────');
    console.log('  │');
    console.log('  │  ' + url);
    console.log('  │');
    console.log('  └───────────────────────────────────────────────────────────────────────────');
    console.log('');
    console.log('  Open this URL in a browser. You\'ll be prompted to set a new password.');
    console.log('  After it\'s used, the token is consumed — re-running the script generates');
    console.log('  a fresh URL.');
    console.log('');
  }

  if (useDB) await dbRepo.close();
})().catch(err => {
  console.error('[admin-rescue] Failed:', err.message);
  console.error(err.stack);
  process.exit(1);
});
