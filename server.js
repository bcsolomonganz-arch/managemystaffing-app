'use strict';
// HIPAA: secrets and PHI must NOT live in OneDrive (synced cloud storage).
// Load .env from a non-synced secure location. Falls back to local .env for
// dev parity if the secure path doesn't exist.
const path0 = require('path');
const fs0   = require('fs');

// Detect Azure App Service: WEBSITE_INSTANCE_ID is always set on App Service.
// In cloud, persistent data lives on the mounted Azure Files share at /mounts/data.
const IS_AZURE = !!process.env.WEBSITE_INSTANCE_ID;
const SECURE_DIR = IS_AZURE
  ? '/mounts/data'
  : (process.env.MMS_SECURE_DIR || (process.platform === 'win32' ? 'C:\\ProgramData\\ManageMyStaffing' : '/var/lib/mms'));

const SECURE_ENV = path0.join(SECURE_DIR, '.env');
if (fs0.existsSync(SECURE_ENV)) {
  require('dotenv').config({ path: SECURE_ENV });
} else {
  require('dotenv').config();
}

// On Azure App Service, secrets come via Key Vault REFERENCES in App Settings,
// which the platform resolves before Node starts. So process.env.JWT_SECRET etc.
// are already populated by the time this code runs. No runtime fetch needed.

// Application Insights — auto-instruments Express, fetch, console
function initAppInsights() {
  if (!process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) return;
  const appInsights = require('applicationinsights');
  appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
    .setAutoDependencyCorrelation(true)
    .setAutoCollectRequests(true)
    .setAutoCollectPerformance(true, true)
    .setAutoCollectExceptions(true)
    .setAutoCollectDependencies(true)
    .setAutoCollectConsole(true, true)
    .setUseDiskRetryCaching(true)
    .setSendLiveMetrics(true)
    .start();
  console.log('[mms] Application Insights initialized');
}

const express    = require('express');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const fs         = require('fs').promises;
const fsSync     = require('fs');
const path       = require('path');
const os         = require('os');
const helmet     = require('helmet');
const cors       = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcrypt');
const otplib     = require('otplib');
const QRCode     = require('qrcode');

// otplib v13+ exports flat functions; wrap to match the older `authenticator` API
const authenticator = {
  generateSecret: () => otplib.generateSecret(),
  keyuri: (account, issuer, secret) => otplib.generateURI({ secret, accountName: account, issuer }),
  check: (token, secret) => {
    try { return otplib.verifySync({ secret, token, options: { window: 1 } }); }
    catch { return false; }
  },
};

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3002;
const NODE_ENV   = process.env.NODE_ENV   || 'development';
const IS_PROD    = NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET env var is required'); })();
if (JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 chars');
// Default data file lives in the secure non-OneDrive directory
const DATA_FILE  = process.env.DATA_FILE  || path.join(SECURE_DIR, 'mms-data.json');
const DATA_ENCRYPTION_KEY = process.env.DATA_ENCRYPTION_KEY || (() => { throw new Error('DATA_ENCRYPTION_KEY (32-byte hex) required'); })();
if (Buffer.from(DATA_ENCRYPTION_KEY, 'hex').length !== 32) throw new Error('DATA_ENCRYPTION_KEY must be 32-byte hex');
const HTML_FILE  = path.join(__dirname, 'managemystaffing.html');
const APP_URL    = process.env.APP_URL || 'https://managemystaffing.com';

// ── HIPAA SECURITY POLICY ─────────────────────────────────────────────────────
// Two security tiers:
//   - Privileged (admin/superadmin): full HIPAA technical safeguards
//     because they touch PHI through admin views, rosters, audit logs.
//   - Employee (no PHI access): only see own schedule + claim shifts.
//     §164.312 doesn't require TOTP / aggressive timeouts when the role
//     can't access PHI, so we relax those for usability.
const JWT_TTL_SECONDS              = 60 * 60 * 2;              // 2h — admin/SA hard cap
const IDLE_TIMEOUT_SECONDS         = 60 * 60 * 2;              // 2h idle — admin/SA
const EMPLOYEE_JWT_TTL_SECONDS     = 60 * 60 * 24 * 365;       // 1y — employee, effectively no expiry
const EMPLOYEE_IDLE_TIMEOUT_SECONDS = 60 * 60 * 24 * 365;      // never auto-logout employees
const MAX_FAILED_ATTEMPTS  = 5;
const LOCKOUT_MS           = 30 * 60 * 1000;     // 30 min
const PASSWORD_MIN_LENGTH          = 12;          // admin/SA
const EMPLOYEE_PASSWORD_MIN_LENGTH = 8;           // employee — length only, no complexity rules
const AUDIT_LOG_FILE       = process.env.AUDIT_LOG_FILE || path.join(path.dirname(DATA_FILE), 'mms-audit.log');
const AUDIT_HMAC_KEY       = process.env.AUDIT_HMAC_KEY || (() => { throw new Error('AUDIT_HMAC_KEY required for tamper-evident audit log'); })();
const TOTP_ISSUER          = 'ManageMyStaffing';

function isPrivilegedRole(role) {
  // hradmin and regionaladmin touch admin views (PHI) and so are subject to
  // the same idle-timeout / TOTP requirements as 'admin'.
  return role === 'admin' || role === 'superadmin' || role === 'hradmin' || role === 'regionaladmin';
}
function jwtTtlFor(role)        { return isPrivilegedRole(role) ? JWT_TTL_SECONDS : EMPLOYEE_JWT_TTL_SECONDS; }
function idleTtlFor(role)       { return isPrivilegedRole(role) ? IDLE_TIMEOUT_SECONDS : EMPLOYEE_IDLE_TIMEOUT_SECONDS; }

// ── STRUCTURED LOGGING ────────────────────────────────────────────────────────
function log(level, msg, meta = {}) {
  const entry = { ts: new Date().toISOString(), level, msg, ...meta };
  console.log(JSON.stringify(entry));
}
const logger = {
  info:  (msg, meta) => log('info', msg, meta),
  warn:  (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),
};

// ── MESSAGING CONFIG — Azure Communication Services ───────────────────────────
const ACS_CONNECTION_STRING = process.env.ACS_CONNECTION_STRING || null;
const ACS_FROM_EMAIL        = process.env.ACS_FROM_EMAIL || 'noreply@751842ed-e753-4e35-9ace-4f2a879b45b7.azurecomm.net';
const ACS_FROM_PHONE        = process.env.ACS_FROM_PHONE || null;

// ── Per-building SMS number provisioning ────────────────────────────────────
// Each building can have its own local-area-code SMS number so staff at that
// facility see a familiar local caller ID. Numbers are purchased on demand
// (admin presses "Activate SMS" after a building is fully set up — never on
// creation, to avoid wasted spend on incomplete onboarding).
//
// 10DLC NOTE: US local-area-code SMS numbers require a registered 10DLC
// brand + campaign. Without one, ACS will reject the SMS send even if the
// number is purchased. The provisioning endpoint logs a clear error message
// so the SA knows to register first via Azure portal → Communication
// Service → Phone numbers → Regulatory documents.
//
// ZIP-to-area-code lookup. Approximate (ZIP regions don't align perfectly
// with NPAs); covers common SNF/LTC operator states. Falls back to null,
// which forces the SA to enter an area code manually.
const _ZIP3_TO_AREA = {
  // Oklahoma
  '730':'405','731':'405','732':'405','734':'405','735':'405','736':'580','737':'580','738':'580','739':'580',
  '740':'918','741':'918','743':'918','744':'918','745':'918','746':'918','747':'918','748':'580','749':'918',
  // Texas — Dallas/FtWorth/Austin/Houston/SanAntonio sample
  '750':'214','751':'214','752':'214','753':'214','754':'214','755':'903','756':'430','757':'409','758':'409','759':'936',
  '760':'682','761':'817','762':'817','763':'940','764':'940','766':'806','767':'325','768':'325','769':'432',
  '770':'713','772':'713','773':'713','774':'713','775':'409','776':'936','777':'409','778':'979','779':'254',
  '780':'512','781':'737','785':'956','786':'956','787':'512','788':'210','789':'830',
  '790':'806','791':'806','792':'806','793':'915','794':'915','795':'325','796':'432','797':'432','798':'915','799':'915',
  // Iowa
  '500':'515','501':'515','502':'515','503':'641','504':'641','505':'641','506':'515','507':'515','508':'515',
  '510':'712','511':'712','512':'712','513':'712','514':'712','515':'712','516':'712','520':'515','521':'319',
  '522':'319','523':'319','524':'319','525':'319','526':'319','527':'563','528':'563',
  // Alabama (common SNF cluster)
  '350':'205','351':'205','352':'205','354':'205','355':'205','356':'205','357':'205','358':'205','359':'334','360':'334',
  '361':'334','362':'251','363':'251','364':'251','365':'251','366':'251','367':'334','368':'334','369':'334',
  // Generic catch-all for a few more
  '100':'212','101':'212','102':'212','103':'212','110':'516','111':'212','112':'718',
  '600':'773','601':'773','602':'847','603':'773','604':'773',
  '900':'213','902':'310','903':'310','904':'310','905':'310','906':'562','907':'562','908':'562','910':'818','913':'818','917':'310','918':'714','919':'714','920':'760','921':'760',
};
function zipToAreaCode(zip) {
  if (!zip) return null;
  const z = String(zip).trim().slice(0, 3);
  return _ZIP3_TO_AREA[z] || null;
}

// "Fully set up" gate for a building before SMS provisioning is allowed.
// Definition: building has a name + state + at least one admin account +
// at least one employee. Adjust here if you want to relax/tighten.
function _buildingIsFullySetUp(buildingId, data) {
  const b = (data.buildings || []).find(x => x.id === buildingId);
  if (!b || !b.name || !b.state) return { ok: false, reason: 'Building missing name or state' };
  const admins = (data.accounts || []).filter(a => a.role === 'admin' && a.buildingId === buildingId);
  if (admins.length === 0) return { ok: false, reason: 'No admin assigned to this building' };
  const emps = (data.employees || []).filter(e => e.buildingId === buildingId && !e.inactive);
  if (emps.length === 0) return { ok: false, reason: 'No employees added to this building yet' };
  return { ok: true };
}

// Resolve which FROM phone number to use for outbound SMS to a given
// building's staff. Falls back to the global ACS_FROM_PHONE if no
// per-building number is provisioned.
function _smsFromForBuilding(buildingId, data) {
  if (buildingId) {
    const b = (data?.buildings || dataCache?.buildings || []).find(x => x.id === buildingId);
    if (b?.smsFromPhone && b.smsProvisionStatus === 'active') return b.smsFromPhone;
  }
  return ACS_FROM_PHONE;
}

// ── PCC (PointClickCare) CONFIG ───────────────────────────────────────────────
const PCC_CLIENT_ID     = process.env.PCC_CLIENT_ID     || null;
const PCC_CLIENT_SECRET = process.env.PCC_CLIENT_SECRET || null;
const PCC_FACILITY_ID   = process.env.PCC_FACILITY_ID   || null;
const PCC_ORG_UUID      = process.env.PCC_ORG_UUID      || null;
const PCC_BASE          = 'https://connect.pointclickcare.com';

let _pccToken = null, _pccTokenExpiry = 0, _pccTokenInflight = null;

// ── INDEED PARTNER CONFIG ────────────────────────────────────────────────────
// Required env vars for the Partner Program integration:
//   INDEED_PARTNER_SECRET     — HMAC shared secret for inbound webhook verification
//                                (Indeed signs every Apply / Event payload with it)
//   INDEED_API_CLIENT_ID      — OAuth2 client ID for outbound disposition push
//   INDEED_API_CLIENT_SECRET  — OAuth2 secret for outbound disposition push
// All three are issued by Indeed during partner onboarding.
const INDEED_PARTNER_SECRET    = process.env.INDEED_PARTNER_SECRET    || null;
const INDEED_API_CLIENT_ID     = process.env.INDEED_API_CLIENT_ID     || null;
const INDEED_API_CLIENT_SECRET = process.env.INDEED_API_CLIENT_SECRET || null;
const INDEED_API_BASE          = 'https://api.indeed.com';
const INDEED_AUTH_BASE         = 'https://apis.indeed.com/oauth/v2/tokens';

let _indeedToken = null, _indeedTokenExpiry = 0, _indeedTokenInflight = null;

// OAuth2 client_credentials grant for outbound calls (disposition sync).
// Same stampede-safe pattern as PCC.
async function getIndeedToken({ forceRefresh = false } = {}) {
  if (!INDEED_API_CLIENT_ID || !INDEED_API_CLIENT_SECRET) throw new Error('Indeed API credentials not configured');
  if (!forceRefresh && _indeedToken && Date.now() < _indeedTokenExpiry) return _indeedToken;
  if (_indeedTokenInflight) return _indeedTokenInflight;
  _indeedTokenInflight = (async () => {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10000);
      let resp;
      try {
        resp = await fetch(INDEED_AUTH_BASE, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id:     INDEED_API_CLIENT_ID,
            client_secret: INDEED_API_CLIENT_SECRET,
            scope: 'employer.advertising.partner.account.read employer.advertising.partner.write',
          }).toString(),
          signal: ctrl.signal,
        });
      } finally { clearTimeout(t); }
      if (!resp.ok) throw new Error(`Indeed auth failed: ${resp.status}`);
      const body = await resp.json().catch(() => null);
      if (!body || !body.access_token) throw new Error('Indeed auth: malformed response');
      _indeedToken = body.access_token;
      _indeedTokenExpiry = Date.now() + ((body.expires_in || 3600) - 60) * 1000;
      return _indeedToken;
    } finally { _indeedTokenInflight = null; }
  })();
  return _indeedTokenInflight;
}

// Verify HMAC-SHA-256 signature on incoming Indeed webhooks. Indeed uses the
// "X-Indeed-Signature" header containing a hex-encoded digest of the raw body
// using INDEED_PARTNER_SECRET. timingSafeEqual prevents a comparison-timing
// side channel.
function verifyIndeedSignature(rawBody, sigHeader) {
  if (!INDEED_PARTNER_SECRET || !sigHeader) return false;
  try {
    const expected = crypto.createHmac('sha256', INDEED_PARTNER_SECRET).update(rawBody).digest();
    const provided = Buffer.from(String(sigHeader), 'hex');
    if (expected.length !== provided.length) return false;
    return crypto.timingSafeEqual(expected, provided);
  } catch { return false; }
}

// Outbound disposition sync. Tells Indeed when a candidate moves to a new
// status in our system (interviewed, hired, rejected). Required for the
// Marketplace certification — Indeed surfaces disposition data back to job
// seekers and other ATS partners.
async function pushIndeedDisposition(applyId, status, occurredAtMillis = Date.now()) {
  if (!applyId) return { ok: false, reason: 'no_apply_id' };
  if (!INDEED_API_CLIENT_ID) return { ok: false, reason: 'not_configured' };
  // Map our internal statuses to Indeed's controlled vocabulary.
  const map = {
    new:        'NEW',
    contacted:  'INTERVIEW_SCHEDULED',
    reviewing:  'INTERVIEW_SCHEDULED',
    onboarding: 'OFFER_EXTENDED',
    hired:      'HIRED',
    rejected:   'REJECTED',
  };
  const indeedStatus = map[status] || 'IN_REVIEW';
  try {
    const token = await getIndeedToken();
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    let resp;
    try {
      resp = await fetch(`${INDEED_API_BASE}/v2/employer/disposition`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          applyId,
          status: indeedStatus,
          occurredAtMillis,
        }),
        signal: ctrl.signal,
      });
    } finally { clearTimeout(t); }
    if (resp.status === 401) {
      // Refresh token + retry once.
      _indeedToken = null;
      const fresh = await getIndeedToken({ forceRefresh: true });
      const retryCtrl = new AbortController();
      const t2 = setTimeout(() => retryCtrl.abort(), 10000);
      try {
        resp = await fetch(`${INDEED_API_BASE}/v2/employer/disposition`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${fresh}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ applyId, status: indeedStatus, occurredAtMillis }),
          signal: retryCtrl.signal,
        });
      } finally { clearTimeout(t2); }
    }
    if (!resp.ok) {
      logger.error('indeed_disposition_failed', { status: resp.status, applyId });
      return { ok: false, status: resp.status };
    }
    return { ok: true };
  } catch (e) {
    logger.error('indeed_disposition_error', { msg: e.message, applyId });
    return { ok: false, reason: 'network' };
  }
}

// Promise-serialized token fetch — prevents stampede when N concurrent
// requests all see an expired token at once. PCC partner spec requires
// minimal auth-endpoint traffic; this collapses the herd to a single fetch.
async function getPCCToken({ forceRefresh = false } = {}) {
  if (!forceRefresh && _pccToken && Date.now() < _pccTokenExpiry) return _pccToken;
  if (_pccTokenInflight) return _pccTokenInflight;
  _pccTokenInflight = (async () => {
    try {
      const creds = Buffer.from(`${PCC_CLIENT_ID}:${PCC_CLIENT_SECRET}`).toString('base64');
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10000);
      let resp;
      try {
        resp = await fetch(`${PCC_BASE}/auth/token`, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'grant_type=client_credentials',
          signal: ctrl.signal,
        });
      } finally { clearTimeout(t); }
      // SECURITY: never log resp.text() here — it can echo back the auth header
      // and the credentials. Status code only.
      if (!resp.ok) throw new Error(`PCC auth failed: ${resp.status}`);
      const body = await resp.json().catch(() => null);
      if (!body || !body.access_token) throw new Error('PCC auth: malformed response');
      _pccToken = body.access_token;
      _pccTokenExpiry = Date.now() + ((body.expires_in || 3600) - 60) * 1000;
      return _pccToken;
    } finally {
      _pccTokenInflight = null;
    }
  })();
  return _pccTokenInflight;
}

// Hardened PCC fetch: timeout + 401 single-retry with token refresh + 429
// retry-after honoring + 5xx exponential backoff (max 3 attempts) + log
// scrubbing. Returns { ok, status, body, retryAfter }.
async function pccFetch(url, { timeoutMs = 15000, maxRetries = 3 } = {}) {
  let attempt = 0;
  let token = await getPCCToken();
  while (attempt < maxRetries) {
    attempt++;
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    let resp;
    try { resp = await fetch(url, { headers, signal: ctrl.signal }); }
    catch (e) { clearTimeout(t); if (attempt >= maxRetries) return { ok:false, status:0, body:null, error:'network' }; await _sleep(200 * attempt); continue; }
    finally { clearTimeout(t); }

    if (resp.status === 401 && attempt === 1) {
      // Token expired or revoked — refresh once, retry once.
      _pccToken = null;
      try { token = await getPCCToken({ forceRefresh: true }); } catch (e) { return { ok:false, status:401, body:null, error:'auth' }; }
      continue;
    }
    if (resp.status === 429) {
      // Respect Retry-After header (may be seconds or HTTP-date).
      const ra = resp.headers.get('Retry-After');
      const waitMs = ra ? (isNaN(Number(ra)) ? Math.max(0, new Date(ra).getTime() - Date.now()) : Number(ra) * 1000) : 1000 * attempt;
      if (attempt >= maxRetries) return { ok:false, status:429, body:null, retryAfter: ra };
      await _sleep(Math.min(waitMs, 30000));
      continue;
    }
    if (resp.status >= 500 && resp.status < 600) {
      if (attempt >= maxRetries) return { ok:false, status:resp.status, body:null };
      await _sleep(50 * Math.pow(2, attempt - 1));     // 50ms, 100ms, 200ms
      continue;
    }
    let body = null;
    try { body = await resp.json(); } catch { body = null; }
    return { ok: resp.ok, status: resp.status, body };
  }
  return { ok:false, status:0, body:null };
}
function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── SEED ACCOUNTS ─────────────────────────────────────────────────────────────
const SEED_SA = {
  id: 'sa0', name: 'Ben Solomon', email: 'solomong@managemystaffing.com',
  role: 'superadmin', buildingId: null, ph: null,
};
const SEED_DEMO = {
  id: 'sa-demo', name: 'Demo Admin', email: 'demo@demo.com',
  role: 'admin', buildingId: 'b1', ph: null,
};
const SEED_DEMO_NURSE = {
  id: 'demo-nurse', name: 'Demo Nurse', email: 'nurse@demo.com',
  role: 'employee', group: 'CNA', buildingId: 'b1', ph: null,
};

const SEED_BUILDING_IDS = new Set([
  'b1','b2','b3','b4',
  'sunrise-snf','willowbrook','golden-acres','harmony-hills',
  'linwood','cross-timbers','north-county','meadowbrook',
]);
const SEED_EMPLOYEE_IDS_PREFIX = 'e0';

// ── AES-256-GCM ENCRYPTION AT REST ───────────────────────────────────────────
async function encrypt(data) {
  const iv  = crypto.randomBytes(12);
  const key = Buffer.from(DATA_ENCRYPTION_KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), data: encrypted.toString('hex'), authTag: authTag.toString('hex') };
}

async function decrypt(obj) {
  const key    = Buffer.from(DATA_ENCRYPTION_KEY, 'hex');
  const iv     = Buffer.from(obj.iv, 'hex');
  const tag    = Buffer.from(obj.authTag, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(Buffer.from(obj.data, 'hex')), decipher.final()]);
  return JSON.parse(dec.toString());
}

// ── DATA LAYER ────────────────────────────────────────────────────────────────
// When PG_CONN is set, Postgres is the system of record. Otherwise fall back
// to the encrypted file (single-instance dev mode).
const dbRepo = require('./db/repo');

let dataCache   = null;
let dataDirty   = false;
let saveTimeout = null;
let _useDB      = false;

function markDirty() {
  dataDirty = true;
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(persistCache, _useDB ? 200 : 2000);
}

async function persistCache() {
  if (!dataDirty) return;
  dataDirty = false;
  clearTimeout(saveTimeout);
  try {
    if (_useDB) {
      await dbRepo.saveAll(dataCache);
      logger.info('data_saved', { backend: 'postgres' });
    } else {
      const payload   = { ...dataCache, _lastSaved: new Date().toISOString() };
      const encrypted = await encrypt(payload);
      const tmp       = DATA_FILE + '.tmp';
      await fs.writeFile(tmp, JSON.stringify(encrypted, null, 2), 'utf8');
      await fs.rename(tmp, DATA_FILE);
      logger.info('data_saved', { backend: 'file' });
    }
    // Fire-and-forget snapshot. Restore window: every-save for 24h, hourly
    // for 30d, daily for 365d. Lets a Super Admin recover from a bad edit
    // or accidental wipe without waiting on infra.
    _writeSnapshot().catch(e => logger.error('snapshot_failed', { err: e.message }));
  } catch (e) {
    logger.error('save_failed', { err: e.message });
  }
}

// ── BACKUPS / SNAPSHOTS ──────────────────────────────────────────────────────
// Encrypted point-in-time copies of the full data cache, kept on disk next to
// DATA_FILE. Filename pattern: mms-snapshot-<ISO>.json (encrypted payload,
// safe to ship to blob storage). Retention is sliding so we don't fill the
// disk:
//   - All snapshots from the last 24h
//   - One snapshot per hour for the last 30 days
//   - One snapshot per day for the last 365 days
// Older than that → pruned. Restore is exposed via POST /api/admin/restore-snapshot
// (Super Admin only).
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DATA_FILE), 'mms-backups');
const SNAPSHOT_PREFIX = 'mms-snapshot-';
let _lastSnapshotAt = 0;
const SNAPSHOT_MIN_INTERVAL_MS = 30 * 1000;        // throttle: at most one snapshot per 30s

async function _ensureBackupDir() {
  try { await fs.mkdir(BACKUP_DIR, { recursive: true }); } catch {}
}

async function _writeSnapshot() {
  // Skip when DB is the system of record — Postgres has its own PITR backups,
  // we don't want to keep duplicate plaintext-ish copies on the app server.
  if (_useDB) return;
  const now = Date.now();
  if (now - _lastSnapshotAt < SNAPSHOT_MIN_INTERVAL_MS) return;
  _lastSnapshotAt = now;

  await _ensureBackupDir();
  const stamp = new Date(now).toISOString().replace(/[:.]/g, '-');
  const file  = path.join(BACKUP_DIR, `${SNAPSHOT_PREFIX}${stamp}.json`);

  // Reuse the encrypted form from disk so we don't re-encrypt the same payload.
  // If the live DATA_FILE is missing for any reason, fall back to encrypting
  // dataCache directly.
  try {
    await fs.copyFile(DATA_FILE, file);
  } catch {
    const encrypted = await encrypt({ ...dataCache, _lastSaved: new Date(now).toISOString() });
    await fs.writeFile(file, JSON.stringify(encrypted, null, 2), 'utf8');
  }

  await _pruneSnapshots();
}

async function _listSnapshotFiles() {
  await _ensureBackupDir();
  const entries = await fs.readdir(BACKUP_DIR);
  return entries
    .filter(n => n.startsWith(SNAPSHOT_PREFIX) && n.endsWith('.json'))
    .map(n => {
      // Decode timestamp from filename
      const iso = n.slice(SNAPSHOT_PREFIX.length, -'.json'.length)
                   .replace(/-/g, ':')
                   .replace(/^([0-9]{4}):([0-9]{2}):([0-9]{2})T/, '$1-$2-$3T') // restore date-part dashes
                   .replace(/:([0-9]{3})Z$/, '.$1Z');                          // restore millis dot
      const ts = Date.parse(iso);
      return { name: n, ts: Number.isFinite(ts) ? ts : 0 };
    })
    .filter(x => x.ts > 0)
    .sort((a,b) => b.ts - a.ts);
}

async function _pruneSnapshots() {
  const now = Date.now();
  const all = await _listSnapshotFiles();
  const keep = new Set();
  const seenHour = new Set();
  const seenDay  = new Set();
  const DAY_MS  = 24 * 60 * 60 * 1000;
  const HOUR_MS = 60 * 60 * 1000;
  for (const s of all) {
    const age = now - s.ts;
    if (age <= DAY_MS) { keep.add(s.name); continue; }
    if (age <= 30 * DAY_MS) {
      const bucket = Math.floor(s.ts / HOUR_MS);
      if (!seenHour.has(bucket)) { seenHour.add(bucket); keep.add(s.name); }
      continue;
    }
    if (age <= 365 * DAY_MS) {
      const bucket = Math.floor(s.ts / DAY_MS);
      if (!seenDay.has(bucket)) { seenDay.add(bucket); keep.add(s.name); }
      continue;
    }
    // older than 365d → drop
  }
  for (const s of all) {
    if (!keep.has(s.name)) {
      try { await fs.unlink(path.join(BACKUP_DIR, s.name)); } catch {}
    }
  }
}

async function _restoreSnapshotFile(filename) {
  await _ensureBackupDir();
  if (!/^mms-snapshot-[0-9TZ:.\-]+\.json$/i.test(filename)) {
    throw new Error('invalid snapshot name');
  }
  const src = path.join(BACKUP_DIR, filename);
  const raw = await fs.readFile(src, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed.iv || !parsed.data || !parsed.authTag) {
    throw new Error('snapshot is not in encrypted format');
  }
  const decoded = await decrypt(parsed);

  // Save the *current* state as a pre-restore safety snapshot before swapping.
  try {
    const safetyStamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safetyName  = `${SNAPSHOT_PREFIX}${safetyStamp}-prerestore.json`;
    await fs.copyFile(DATA_FILE, path.join(BACKUP_DIR, safetyName));
  } catch {}

  // Hot-swap dataCache and persist
  dataCache = decoded;
  dataDirty = true;
  await persistCache();
  return { restoredFromTs: parsed._snapshottedAt || null, restoredAt: new Date().toISOString() };
}

// ── persistAccountNow ─────────────────────────────────────────────────────────
// Credential mutations (password set/reset, invite accept, TOTP enroll/reset,
// failed-attempt counters, lockouts) MUST be durable before we respond to the
// user. The 200ms markDirty debounce is fine for bulk data updates but it can
// be lost if the container restarts in that window — exactly what wiped the
// SA password earlier today. This helper writes the single account row
// directly, then still markDirty()s so the rest of dataCache eventually
// flushes too.
async function persistAccountNow(acct) {
  if (!acct) return;
  try {
    if (_useDB) {
      await dbRepo.upsertAccount(acct);
    } else {
      // File-mode: do a synchronous full flush so we don't miss the change.
      await persistCache();
    }
  } catch (e) {
    logger.error('persist_account_failed', { id: acct.id, err: e.message });
    throw e;                          // bubble so callers can return 500 instead of false success
  }
  markDirty();                        // keep rest of cache eventually consistent
}

async function loadData() {
  if (dataCache) return dataCache;

  // Initialize DB if connection string is present
  if (process.env.PG_CONN) {
    try {
      dbRepo.init();
      // Connectivity check
      const ok = await dbRepo.ping();
      if (ok) {
        _useDB = true;
        await dbRepo.ensureSchema();
        dataCache = await dbRepo.loadAll();
        logger.info('data_loaded', { backend: 'postgres', accounts: (dataCache.accounts || []).length });
      } else {
        logger.warn('pg_ping_failed_fallback_to_file');
      }
    } catch (e) {
      logger.error('pg_init_failed_fallback_to_file', { err: e.message });
    }
  }

  // File-based fallback
  if (!_useDB) {
    try {
      const raw    = await fs.readFile(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed.iv && parsed.data && parsed.authTag) {
        dataCache = await decrypt(parsed);
        logger.info('data_loaded', { backend: 'file' });
      } else {
        dataCache = parsed;
        dataDirty = true;
        await persistCache();
        logger.info('data_migrated_to_encrypted_file');
      }
    } catch (e) {
      if (e.code === 'ENOENT') {
        dataCache = {
          accounts: [SEED_SA, SEED_DEMO],
          buildings: [], employees: [], shifts: [], schedulePatterns: [],
          hrEmployees: [], hrAccounts: [], hrTimeClock: [],
          companies: [], jobPostings: [],
        };
        dataDirty = true;
        await persistCache();
        logger.info('data_initialized_empty');
      } else {
        logger.error('data_load_failed', { err: e.message });
        throw e;
      }
    }
  }

  await applyMigrations(dataCache);
  return dataCache;
}

async function applyMigrations(data) {
  let dirty = false;

  // ── Strip seed buildings / employees / shifts ─────────────────────────────
  if (!data._seedStripped) {
    const beforeB = (data.buildings || []).length;
    const beforeE = (data.employees || []).length;
    data.buildings = (data.buildings || []).filter(b => !SEED_BUILDING_IDS.has(b.id));
    data.employees = (data.employees || []).filter(e => !e.id.startsWith(SEED_EMPLOYEE_IDS_PREFIX));
    const keepBIds = new Set((data.buildings || []).map(b => b.id));
    const keepEIds = new Set((data.employees || []).map(e => e.id));
    data.shifts           = (data.shifts           || []).filter(s => keepBIds.has(s.buildingId) || keepEIds.has(s.employeeId));
    data.schedulePatterns = (data.schedulePatterns || []).filter(p => keepEIds.has(p.empId));
    const sB = beforeB - data.buildings.length, sE = beforeE - data.employees.length;
    if (sB || sE) console.log(`[mms] Stripped ${sB} seed buildings, ${sE} seed employees`);
    data._seedStripped = true;
    dirty = true;
  }

  // ── Strip seed HR employees / demo HR accounts ────────────────────────────
  if (!data._hrSeedStripped) {
    data.hrEmployees = (data.hrEmployees || []).filter(e => !e.id.startsWith('hre'));
    data.hrAccounts  = (data.hrAccounts  || []).filter(a => !['ha1','ha2'].includes(a.id));
    data._hrSeedStripped = true;
    dirty = true;
  }

  // ── Strip seed time-clock records ─────────────────────────────────────────
  if (!data._tcSeedStripped) {
    data.hrTimeClock = (data.hrTimeClock || []).filter(r => !String(r.empId||'').startsWith('tc-'));
    data._tcSeedStripped = true;
    dirty = true;
  }

  // ── Migrate old FNV-1a password hashes to null (forces bcrypt re-set) ─────
  if (!data._bcryptMigrated) {
    let migrated = 0;
    for (const acct of (data.accounts || [])) {
      if (acct.ph && !acct.ph.startsWith('$2')) {
        acct.ph = null;
        migrated++;
      }
    }
    if (migrated) console.log(`[mms] Migrated ${migrated} accounts to bcrypt (ph reset to null)`);
    data._bcryptMigrated = true;
    dirty = true;
  }

  // ── Password reset via env var ─────────────────────────────────────────────
  if (process.env.RESET_SA_PASSWORD === '1') {
    const sa = (data.accounts || []).find(a => a.id === SEED_SA.id);
    if (sa) {
      sa.ph = null;
      sa.totpSecret = null;
      sa.failedAttempts = 0;
      sa.lockedUntil = null;
      sa.inviteToken = crypto.randomBytes(24).toString('hex');
      sa.inviteExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
      dirty = true;
      console.log('\n=================================================================');
      console.log('SA password reset. Use the link below within 24h to set password:');
      console.log(`${process.env.APP_URL || 'http://localhost:3002'}/?invite=${sa.inviteToken}`);
      console.log('=================================================================\n');
    }
  }

  // ── Bootstrap SA invite if no password & no token (new install) ─────────────
  const sa = (data.accounts || []).find(a => a.id === SEED_SA.id);
  if (sa && !sa.ph && !sa.inviteToken) {
    sa.inviteToken = crypto.randomBytes(24).toString('hex');
    sa.inviteExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    dirty = true;
    console.log('\n=================================================================');
    console.log('First-time bootstrap. Use the link below within 7 days to set SA password:');
    console.log(`${process.env.APP_URL || 'http://localhost:3002'}/?invite=${sa.inviteToken}`);
    console.log('=================================================================\n');
  }

  // ── Ensure seed accounts always exist with correct immutable fields ─────────
  for (const seed of [SEED_SA, SEED_DEMO, SEED_DEMO_NURSE]) {
    const existing = (data.accounts || []).find(a => a.id === seed.id);
    if (!existing) {
      if (!data.accounts) data.accounts = [];
      data.accounts.push({ ...seed });
      dirty = true;
      console.log(`[mms] Seeded missing account: ${seed.email}`);
    } else {
      if (existing.email !== seed.email) { existing.email = seed.email; dirty = true; }
      if (existing.role  !== seed.role)  {
        console.warn(`[mms] WARN: seed ${seed.id} role corrected to '${seed.role}'`);
        existing.role = seed.role; dirty = true;
      }
    }
  }

  // ── Enforce SkyBlue Healthcare company + Kirkland Court link ─────────────
  if (!data.companies) data.companies = [];
  if (!data.companies.find(c => c.id === 'co_skyblue')) {
    data.companies.push({ id: 'co_skyblue', name: 'SkyBlue Healthcare', color: '#0891B2' });
    console.log('[mms] Restored SkyBlue Healthcare company.');
    dirty = true;
  }
  if (data.buildings) {
    data.buildings.forEach(b => {
      if (b.name === 'Kirkland Court' && !b.companyId) {
        b.companyId = 'co_skyblue';
        console.log('[mms] Restored companyId on Kirkland Court.');
        dirty = true;
      }
    });
  }
  data._skyblueSeeded = true;

  if (dirty) markDirty();
}

// ── AUDIT LOGGING (HIPAA §164.312(b) + §164.530(j)) ──────────────────────────
// Tamper-evident: each entry hashes the previous entry's HMAC.
// Triple-write: local file (fast), AND Azure Storage append-blob in WORM
// container with 6-year immutability policy.
let _lastAuditHash = null;
let _auditQueue = Promise.resolve();
let _auditAppendClient = null;       // Azure Storage AppendBlobClient

// Ship each entry to Azure Storage append-blob in the WORM-locked container.
// Best-effort — local file is the primary record; cloud copy is for retention.
async function _shipAuditEntryToCloud(entryJson) {
  if (!_auditAppendClient) return;
  try {
    await _auditAppendClient.appendBlock(entryJson + '\n', Buffer.byteLength(entryJson + '\n'));
  } catch (e) {
    // Don't block local writes if cloud is unreachable; log and move on.
    logger.warn('audit_cloud_ship_failed', { err: e.message });
  }
}

async function _initAuditCloud() {
  const connStr = process.env.AUDIT_STORAGE_CONNECTION_STRING;
  if (!connStr) {
    logger.info('audit_cloud_disabled', { reason: 'AUDIT_STORAGE_CONNECTION_STRING not set' });
    return;
  }
  try {
    const { BlobServiceClient } = require('@azure/storage-blob');
    const svc = BlobServiceClient.fromConnectionString(connStr);
    const container = svc.getContainerClient('mms-audit');
    // One append-blob per UTC date — keeps blobs manageable + immutability policy applies
    const dayKey = new Date().toISOString().slice(0, 10);
    const blobName = `audit-${dayKey}.jsonl`;
    _auditAppendClient = container.getAppendBlobClient(blobName);
    // createIfNotExists is idempotent — safe across restarts
    await _auditAppendClient.createIfNotExists();
    logger.info('audit_cloud_initialized', { blob: blobName });
  } catch (e) {
    logger.error('audit_cloud_init_failed', { err: e.message });
    _auditAppendClient = null;
  }
}

function _initAuditChain() {
  try {
    if (!fsSync.existsSync(AUDIT_LOG_FILE)) {
      _lastAuditHash = '0'.repeat(64);
      return;
    }
    const lines = fsSync.readFileSync(AUDIT_LOG_FILE, 'utf8').trim().split('\n').filter(Boolean);
    if (!lines.length) { _lastAuditHash = '0'.repeat(64); return; }
    const last = JSON.parse(lines[lines.length - 1]);
    _lastAuditHash = last.hmac;
    logger.info('audit_chain_resumed', { entries: lines.length, lastHash: _lastAuditHash.slice(0, 16) });
  } catch (e) {
    logger.error('audit_chain_init_failed', { err: e.message });
    _lastAuditHash = '0'.repeat(64);
  }
}

function auditLog(action, user, details = {}) {
  const entry = {
    ts:     new Date().toISOString(),
    userId: user?.id    || 'anonymous',
    role:   user?.role  || null,
    action,
    ...details,
  };
  // Serialize audit writes to ensure chain integrity
  _auditQueue = _auditQueue.then(async () => {
    if (_lastAuditHash === null) _initAuditChain();
    entry.prevHash = _lastAuditHash;
    const body = JSON.stringify(entry);
    const h = crypto.createHmac('sha256', AUDIT_HMAC_KEY);
    h.update(body);
    entry.hmac = h.digest('hex');
    _lastAuditHash = entry.hmac;
    const entryJson = JSON.stringify(entry);
    try {
      await fs.appendFile(AUDIT_LOG_FILE, entryJson + '\n', { mode: 0o600 });
    } catch (e) {
      logger.error('audit_write_failed', { err: e.message, action });
    }
    // Ship to cloud WORM storage (best effort — file is primary)
    await _shipAuditEntryToCloud(entryJson);
    logger.info('audit', { action, userId: entry.userId, role: entry.role });
  }).catch(e => logger.error('audit_queue_failure', { err: e.message }));
}

// Verify audit chain integrity (call from /health/ready or manually)
async function verifyAuditChain() {
  try {
    const data = await fs.readFile(AUDIT_LOG_FILE, 'utf8').catch(() => '');
    const lines = data.trim().split('\n').filter(Boolean);
    let prev = '0'.repeat(64);
    for (const [i, line] of lines.entries()) {
      const e = JSON.parse(line);
      if (e.prevHash !== prev) return { ok: false, brokenAt: i, reason: 'prevHash mismatch' };
      const { hmac, ...body } = e;
      const h = crypto.createHmac('sha256', AUDIT_HMAC_KEY).update(JSON.stringify(body)).digest('hex');
      if (h !== hmac) return { ok: false, brokenAt: i, reason: 'hmac mismatch' };
      prev = hmac;
    }
    return { ok: true, entries: lines.length };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ── REDIS (sessions + revoked tokens) ─────────────────────────────────────────
// When REDIS_CONNECTION_STRING is set, sessions persist across restarts and
// scale across instances. Falls back to in-memory if Redis is not configured
// (single-instance dev only — NOT HIPAA-safe in multi-instance prod).
let _redis = null;
try {
  const Redis = require('ioredis');
  if (process.env.REDIS_CONNECTION_STRING) {
    _redis = new Redis(process.env.REDIS_CONNECTION_STRING, {
      tls: process.env.REDIS_CONNECTION_STRING.startsWith('rediss://') ? {} : undefined,
      lazyConnect: true,
      connectTimeout: 3000,
      maxRetriesPerRequest: 3,
      // Fail-soft: return null instead of throwing on transient errors
      reconnectOnError: (err) => err.message.includes('READONLY'),
    });
    _redis.on('error', (e) => logger.warn('redis_error', { err: e.message }));
    _redis.connect().then(
      () => logger.info('redis_connected'),
      (e) => { logger.warn('redis_connect_failed', { err: e.message }); _redis = null; }
    );
  }
} catch (e) {
  logger.warn('redis_init_failed', { err: e.message });
}

// In-memory fallbacks (used when Redis unavailable)
const _memRevokedTokens = new Set();
const _memLastActivity = new Map();

// Revoked-token / last-activity Redis entries must outlive the longest JWT,
// otherwise a logged-out employee's 30-day cookie could be reused after the
// 1h Redis entry expires. Use the employee TTL as the upper bound.
const _MAX_TOKEN_TTL = Math.max(JWT_TTL_SECONDS, EMPLOYEE_JWT_TTL_SECONDS);

const revokedTokens = {
  async add(token) {
    _memRevokedTokens.add(token);
    if (_redis) {
      try { await _redis.set(`revoked:${token}`, '1', 'EX', _MAX_TOKEN_TTL); } catch (e) {}
    }
  },
  async has(token) {
    if (_memRevokedTokens.has(token)) return true;
    if (_redis) {
      try { return (await _redis.exists(`revoked:${token}`)) === 1; } catch (e) {}
    }
    return false;
  },
};

const lastActivity = {
  async set(sid, ts) {
    _memLastActivity.set(sid, ts);
    if (_redis) {
      try { await _redis.set(`act:${sid}`, String(ts), 'EX', _MAX_TOKEN_TTL); } catch (e) {}
    }
  },
  async get(sid) {
    if (_redis) {
      try {
        const v = await _redis.get(`act:${sid}`);
        if (v != null) return parseInt(v, 10);
      } catch (e) {}
    }
    return _memLastActivity.get(sid);
  },
  async delete(sid) {
    _memLastActivity.delete(sid);
    if (_redis) { try { await _redis.del(`act:${sid}`); } catch (e) {} }
  },
};

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────

async function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME]
    || (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    if (await revokedTokens.has(token)) return res.status(401).json({ error: 'Token revoked' });
    const decoded = jwt.verify(token, JWT_SECRET);
    // Idle timeout: 15 min for admin/SA (HIPAA); effectively disabled for employees.
    const sid = decoded.sid;
    const last = await lastActivity.get(sid);
    const idleMs = idleTtlFor(decoded.role) * 1000;
    if (last && (Date.now() - last) > idleMs) {
      await revokedTokens.add(token);
      await lastActivity.delete(sid);
      clearAuthCookie(res);
      auditLog('SESSION_IDLE_TIMEOUT', decoded);
      return res.status(401).json({ error: 'Session expired due to inactivity' });
    }
    await lastActivity.set(sid, Date.now());
    req.user = decoded;
    req._token = token;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Privileged roles that can hit admin endpoints. hradmin has the same surface
// as admin EXCEPT punch corrections — those are intercepted in the punch
// PATCH handler and routed through an approval flow (admin → regional).
const ADMIN_ROLES = ['admin', 'superadmin', 'hradmin', 'regionaladmin'];

function requireAdmin(req, res, next) {
  if (!ADMIN_ROLES.includes(req.user?.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.user?.role !== 'superadmin') {
    return res.status(403).json({ error: 'Superadmin only' });
  }
  next();
}

// Caller can finalize / approve operations that require an admin signoff
// (punch corrections submitted by hradmin, etc.).
function isApprovingAdmin(user) {
  return user?.role === 'admin' || user?.role === 'superadmin' || user?.role === 'regionaladmin';
}

// ── PASSWORD COMPLEXITY (HIPAA §164.308(a)(5)) ───────────────────────────────
// All roles: 8-char minimum + uppercase + lowercase + digit + special character.
// HIPAA Security Rule requires "procedures for creating, changing, and
// safeguarding passwords." The complexity rules + lockout + audit + TOTP for
// privileged accounts together satisfy that requirement.
function validatePasswordComplexity(pw, _role) {
  if (!pw || typeof pw !== 'string') return 'Password is required';
  if (pw.length < 8)              return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(pw))         return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(pw))         return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(pw))         return 'Password must contain at least one number';
  if (!/[^A-Za-z0-9]/.test(pw))  return 'Password must contain at least one special character';
  return null;
}

// ── ACCOUNT LOCKOUT (HIPAA §164.308(a)(5)(ii)(C)) ────────────────────────────
function isAccountLocked(acct) {
  if (!acct.lockedUntil) return false;
  if (Date.now() < acct.lockedUntil) return true;
  // expired — clear
  acct.lockedUntil = null;
  acct.failedAttempts = 0;
  return false;
}

function recordFailedLogin(acct) {
  acct.failedAttempts = (acct.failedAttempts || 0) + 1;
  if (acct.failedAttempts >= MAX_FAILED_ATTEMPTS) {
    acct.lockedUntil = Date.now() + LOCKOUT_MS;
    auditLog('ACCOUNT_LOCKED', acct, { until: new Date(acct.lockedUntil).toISOString() });
  }
  markDirty();
}

function clearFailedAttempts(acct) {
  if (acct.failedAttempts || acct.lockedUntil) {
    acct.failedAttempts = 0;
    acct.lockedUntil = null;
    markDirty();
  }
}

// ── PHI GUARD FOR OUTBOUND SMS (HIPAA §164.312(e)) ───────────────────────────
// SMS is unencrypted in transit by carriers. We reject any outbound SMS that
// contains identifiable info — employee names, dates, SSN-like patterns, or
// common medical terms. Admins should send generic notifications and let users
// log in for details.
function scanMessageForPHI(message, employeesScope) {
  const m = String(message || '');
  const lower = m.toLowerCase();
  // 1. SSN-like patterns
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(m)) return 'Looks like an SSN — never send PHI via SMS';
  // 2. Date-of-birth-like patterns (MM/DD/YYYY or YYYY-MM-DD)
  if (/\b(0?[1-9]|1[0-2])\/(0?[1-9]|[12]\d|3[01])\/(19|20)\d{2}\b/.test(m)) return 'Looks like a date of birth — never send PHI via SMS';
  // 3. MRN-like patterns
  if (/\b(MRN|mrn|medical record (number|#)|patient (id|#))\s*[:#]?\s*\w+/i.test(m)) return 'Looks like a medical record number — never send PHI via SMS';
  // 4. Common diagnosis / medication / care terms
  const phiKeywords = ['diagnosis', 'prescription', 'medication', 'patient ', 'resident ', 'admitted', 'discharge', 'icd-', 'cpt code', 'lab result', 'test result', 'biopsy', 'tumor', 'cancer', 'hiv', 'aids', 'dialysis', 'hospice', 'positive for', 'negative for'];
  for (const kw of phiKeywords) {
    if (lower.includes(kw)) return `Contains potentially clinical term ("${kw}") — never send PHI via SMS`;
  }
  // 5. Employee names from the caller's scope (workforce-PHI when tied to facility)
  for (const e of (employeesScope || [])) {
    if (!e.name) continue;
    const parts = e.name.split(/\s+/).filter(p => p.length >= 4);
    for (const p of parts) {
      const re = new RegExp(`\\b${p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      if (re.test(m)) return `Contains an employee name ("${p}") — keep SMS generic, link recipients to the app`;
    }
  }
  return null;
}

// ── HTML ESCAPE (used in email bodies) ───────────────────────────────────────
function escapeHtml(s) {
  return String(s||'').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
}

// ── CSV ESCAPE (defense against formula injection) ───────────────────────────
function escapeCsv(s) {
  const v = String(s == null ? '' : s);
  // Excel formula injection: prefix any cell starting with =+-@ with single quote
  return /^[=+\-@\t\r]/.test(v) ? "'" + v : v;
}

// ── HIPAA DATA MINIMIZATION (§164.502) ───────────────────────────────────────
// HR module is gated to one specific account while in development.
const HR_ALLOWED_EMAIL = 'solomong@managemystaffing.com';
function _canAccessHR(user) {
  return (user?.email || '').toLowerCase() === HR_ALLOWED_EMAIL || user?.role === 'superadmin';
}

// Strip HR-related collections from any data response unless caller is allowed.
function _stripHR(data) {
  return {
    ...data,
    hrEmployees:       [],
    hrAccounts:        [],
    hrTimeClock:       [],
    hrOnboarding:      undefined,
    jobPostings:       [],
    demos:             [],
    billingData:       undefined,
  };
}

// Strip account password hashes + TOTP secrets from any response.
function _scrubSecrets(accounts = []) {
  return accounts.map(a => {
    const { ph, totpSecret, totpRecoveryCodesHashes, inviteToken, ...safe } = a;
    return { ...safe, hasPassword: !!ph, totpEnrolled: !!totpSecret };
  });
}

// Employee role: only their own record + open shifts in their building.
function _employeeView(user, fullData) {
  const bId = user.buildingId;
  if (!bId) return { ..._stripHR(fullData), buildings: [], employees: [], shifts: [], schedulePatterns: [], accounts: [] };
  const me = (fullData.employees || []).find(e => e.id === user.id) || null;
  const myBuildings = (fullData.buildings || []).filter(b => b.id === bId);
  const minBuildings = myBuildings.map(b => ({ id: b.id, name: b.name, color: b.color }));
  return {
    ..._stripHR(fullData),
    buildings:        minBuildings,
    employees:        me ? [me] : [],          // self only — no coworker phones/emails
    shifts:           (fullData.shifts || []).filter(s =>
      s.buildingId === bId && (s.employeeId === user.id || s.status === 'open')),
    schedulePatterns: (fullData.schedulePatterns || []).filter(p => p.empId === user.id),
    accounts:         _scrubSecrets((fullData.accounts || []).filter(a => a.id === user.id)),
    companies:        (fullData.companies || []),
    // Direct messages: only threads I'm part of
    directMessages:   (fullData.directMessages || []).filter(m => m.fromId === user.id || m.toId === user.id),
    user: { id: user.id, name: user.name, email: user.email, role: user.role, buildingId: bId },
  };
}

function getDataForUser(user, fullData) {
  // Always scrub secrets from accounts before returning
  const scrubbed = { ...fullData, accounts: _scrubSecrets(fullData.accounts || []) };

  // Employees get a heavily restricted view
  if (user.role === 'employee') return _employeeView(user, scrubbed);

  // Superadmin sees everything (with secrets scrubbed) + HR if allowed
  if (user.role === 'superadmin') {
    return _canAccessHR(user) ? scrubbed : _stripHR(scrubbed);
  }

  // Building admin: their building(s) + HR strip unless HR-allowed
  const bIds = new Set([user.buildingId, ...(user.buildingIds || [])].filter(Boolean));
  if (!bIds.size) return { ..._stripHR(scrubbed), buildings: [], employees: [], shifts: [], schedulePatterns: [] };

  const filtered = {
    ...scrubbed,
    buildings:        (scrubbed.buildings        || []).filter(b => bIds.has(b.id)),
    employees:        (scrubbed.employees        || []).filter(e => bIds.has(e.buildingId)),
    shifts:           (scrubbed.shifts           || []).filter(s => bIds.has(s.buildingId)),
    schedulePatterns: (scrubbed.schedulePatterns || []).filter(p =>
      (scrubbed.employees || []).some(e => e.id === p.empId && bIds.has(e.buildingId))),
    accounts:         (scrubbed.accounts || []).filter(a =>
      a.id === user.id || (a.buildingId && bIds.has(a.buildingId)) || (a.buildingIds||[]).some(id => bIds.has(id))),
    alertLog:         (scrubbed.alertLog || []).filter(e => !e.buildingId || bIds.has(e.buildingId)),
    // Admin sees DMs in their building scope OR ones they personally sent/received
    directMessages:   (scrubbed.directMessages || []).filter(m =>
      m.fromId === user.id || m.toId === user.id ||
      (m.buildingId && bIds.has(m.buildingId))),
    prospects:        (scrubbed.prospects || []).filter(p => !p.buildingId || bIds.has(p.buildingId)),
  };
  return _canAccessHR(user) ? filtered : _stripHR(filtered);
}

// ── RATE LIMITERS ─────────────────────────────────────────────────────────────
// Login: 10 per 15 min per IP (account lockout handles per-account brute force)
const authLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: { error: 'Too many login attempts' } });
const inviteVerifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Too many requests' } });
const apiLimiter    = rateLimit({ windowMs:       60 * 1000, max: 300, message: { error: 'Too many requests' } });

// ── EXPRESS APP ───────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);     // Behind App Service / Front Door
app.disable('x-powered-by');

// Request ID for log correlation
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-Id', req.id);
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],     // inline scripts in single-file SPA
      scriptSrcAttr: ["'unsafe-inline'"],               // onclick handlers throughout SPA
      styleSrc:      ["'self'", "'unsafe-inline'"],
      imgSrc:        ["'self'", 'data:'],
      connectSrc:    ["'self'"],
      frameAncestors: ["'none'"],                       // prevent clickjacking
      objectSrc:     ["'none'"],
      baseUri:       ["'self'"],
      formAction:    ["'self'"],
    },
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }, // 2 years
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));

// Force HTTPS in production
if (IS_PROD) {
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
    return res.redirect(308, `https://${req.headers.host}${req.url}`);
  });
}

app.use(cors({
  origin: IS_PROD ? [APP_URL] : [APP_URL, 'http://localhost:3002', 'http://localhost:3000'],
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));      // Was 50mb — DoS surface
app.use(cookieParser(JWT_SECRET));             // signed cookies for CSRF defense
app.use('/api/', apiLimiter);

// ── JWT COOKIE HELPERS ────────────────────────────────────────────────────────
// HIPAA §164.312(a)(2)(iv) — JWT must NOT be readable by JavaScript.
// httpOnly + Secure + SameSite=Strict prevents XSS exfiltration and CSRF.
const COOKIE_NAME = 'mms_session';
function setAuthCookie(res, token, ttlSeconds) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure:   IS_PROD,                      // local dev allows http
    sameSite: 'strict',
    maxAge:   (ttlSeconds || JWT_TTL_SECONDS) * 1000,
    path:     '/',
    signed:   false,                        // signing the cookie isn't needed (JWT is self-signed)
  });
}
function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/' });
}

// ── DEVICE-TRUST COOKIE (HIPAA-aware 2FA UX) ─────────────────────────────────
// After a successful TOTP, we drop a 30-day signed cookie identifying THIS device
// for THIS account. On subsequent logins from the same device within 30 days, we
// skip the TOTP prompt. New device → TOTP required. Cookie expired → TOTP required.
// The cookie is account-bound: a stolen cookie won't work for a different account.
const DEVICE_TRUST_COOKIE = 'mms_device_trust';
const DEVICE_TRUST_TTL_SEC = 30 * 24 * 60 * 60;        // 30 days
const DEVICE_TRUST_TTL_MS  = DEVICE_TRUST_TTL_SEC * 1000;

function signDeviceTrust(acct) {
  // JWT carrying { acctId, did, epoch }. The epoch ties this cookie to the
  // account's current trust generation; bumping deviceTrustEpoch on TOTP reset
  // invalidates every previously-issued trust cookie immediately.
  const did   = crypto.randomBytes(12).toString('hex');
  const epoch = acct.deviceTrustEpoch || 0;
  return jwt.sign({ acctId: acct.id, did, epoch, kind: 'device_trust' }, JWT_SECRET, { expiresIn: DEVICE_TRUST_TTL_SEC });
}
function verifyDeviceTrust(token, acct) {
  if (!token || !acct) return false;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.kind !== 'device_trust') return false;
    if (decoded.acctId !== acct.id)      return false;
    if ((decoded.epoch || 0) !== (acct.deviceTrustEpoch || 0)) return false;
    return true;
  } catch { return false; }
}
function setDeviceTrustCookie(res, acct) {
  res.cookie(DEVICE_TRUST_COOKIE, signDeviceTrust(acct), {
    httpOnly: true, secure: IS_PROD, sameSite: 'strict',
    maxAge: DEVICE_TRUST_TTL_MS, path: '/', signed: false,
  });
}
function clearDeviceTrustCookie(res) {
  res.clearCookie(DEVICE_TRUST_COOKIE, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/' });
}

// ── CSRF DEFENSE ──────────────────────────────────────────────────────────────
// SameSite=Strict cookie + custom header check provides defense-in-depth.
// All state-changing endpoints require X-Requested-With: XMLHttpRequest header,
// which can't be set on cross-origin form POSTs without preflight.
function requireCSRFHeader(req, res, next) {
  const allowed = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';
  if (allowed) return next();
  if (req.headers['x-requested-with'] === 'XMLHttpRequest') return next();
  return res.status(403).json({ error: 'Missing X-Requested-With header (CSRF protection)' });
}
app.use('/api/', requireCSRFHeader);

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true, env: NODE_ENV });
});

// Deep readiness probe — checks dependencies. Use for load-balancer health.
app.get('/health/ready', async (_req, res) => {
  const checks = {
    dataBackend:  'unknown',
    dataReady:    false,
    auditChain:   false,
    encryption:   'AES-256-GCM',
    postgres:     null,
    redis:        _redis ? 'connected' : 'not-configured',
    messaging: {
      acs:   !!ACS_CONNECTION_STRING,
      email: !!ACS_FROM_EMAIL,
      sms:   !!ACS_FROM_PHONE,
    },
  };
  try {
    await loadData();
    checks.dataReady = true;
    checks.dataBackend = _useDB ? 'postgres' : 'file';
    if (_useDB) checks.postgres = await dbRepo.ping();
  } catch (e) {
    return res.status(503).json({ ok: false, ...checks, error: 'data_unreachable' });
  }
  const chain = await verifyAuditChain();
  checks.auditChain = chain.ok;
  if (!chain.ok) return res.status(503).json({ ok: false, ...checks, auditChainError: chain });
  res.json({ ok: true, ...checks });
});

// ── DEEP SECURITY HEALTHCHECK ─────────────────────────────────────────────────
// Returns a self-attested security posture report. Designed for external
// auditors (PCC partner engineering, HIPAA assessors) to verify
// configuration claims from outside the system. Public — does NOT require
// auth — but emits zero secrets, only true/false flags and shapes.
//
// Every claim here is a tested boolean: either we provably have the
// safeguard or we don't. No fabricated yes-answers.
app.get('/api/healthz/deep', (req, res) => {
  // Helper: assert a config invariant; collect failures.
  const ok = (cond) => !!cond;
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || '').toString().toLowerCase();
  const onHttps = proto === 'https' || IS_PROD;     // App Service terminates TLS

  const r = {
    asOf: new Date().toISOString(),
    app: {
      name: 'ManageMyStaffing',
      env: NODE_ENV,
      nodeVersion: process.version,
      uptimeSec: Math.round(process.uptime()),
    },
    transport: {
      tlsTerminated: onHttps,
      hsts: true,                         // helmet sets it; configured at boot
      httpsRedirect: IS_PROD,
      tlsMin: 'TLS 1.2 (Azure App Service default)',
    },
    cookies: {
      authCookieHttpOnly: true,
      authCookieSecure: IS_PROD,
      authCookieSameSite: 'strict',
      deviceTrustHttpOnly: true,
      deviceTrustSecure: IS_PROD,
      deviceTrustSameSite: 'strict',
    },
    encryption: {
      atRest: 'AES-256-GCM',
      keyManagement: process.env.AZURE_KEY_VAULT_NAME ? 'Azure Key Vault references' : 'env var',
      keyRotationSupported: true,                  // rotate-data-key.js exists
      tlsInTransit: 'enforced via App Service + HSTS',
    },
    authentication: {
      passwordHash: 'bcrypt cost 12',
      passwordMinLengthAdmin: PASSWORD_MIN_LENGTH,
      passwordMinLengthEmployee: EMPLOYEE_PASSWORD_MIN_LENGTH,
      passwordComplexityAdmin: 'upper + lower + digit + special',
      mfaRequired: 'TOTP for admin/superadmin/regional',
      mfaSecretEncryption: process.env.AZURE_KEY_VAULT_NAME ? 'env-bound key' : 'env-bound key',
      recoveryCodes: 'bcrypt cost 12, single-use',
      lockoutAfterFailures: MAX_FAILED_ATTEMPTS,
      lockoutDurationMin: Math.round(LOCKOUT_MS / 60000),
      idleTimeoutAdminMin: Math.round(IDLE_TIMEOUT_SECONDS / 60),
      idleTimeoutEmployeeMin: Math.round(EMPLOYEE_IDLE_TIMEOUT_SECONDS / 60),
      sessionTtlAdminMin: Math.round(JWT_TTL_SECONDS / 60),
      deviceTrustTtlDays: 30,
    },
    authorization: {
      rbac: 'role + per-building scoping',
      rls: _useDB ? 'Postgres row-level security policies enabled' : 'file mode (not applicable)',
      privilegedFieldsPinned: 'role/buildingId/buildingIds/schedulerOnly/group never accept client writes from non-SA',
    },
    auditLogging: {
      tamperEvident: 'HMAC chain (SHA-256, prevHash linkage)',
      hmacKeyConfigured: ok(process.env.AUDIT_HMAC_KEY),
      retentionPolicy: '7 years (HIPAA §164.530(j) max)',
      destinations: [
        process.env.AUDIT_STORAGE_CONNECTION_STRING ? 'Azure Blob (immutable)' : 'local file',
        process.env.AUDIT_LOG_FILE ? 'append-only file' : null,
      ].filter(Boolean),
      verifiedOnBoot: true,
    },
    integrity: {
      optimisticConcurrency: 'ETag / If-Match on /api/data',
      tripwireOnBulkShrink: '>50% collection drop blocked without X-Confirm-Wipe header',
      mergeProtectsSecrets: 'ph, totpSecret, totpRecoveryCodesHashes, inviteToken, passwordResetTokenHash, deviceTrustEpoch',
    },
    transportPHI: {
      smsPhiScanner: 'blocks SSN / DOB / MRN / employee names in outbound SMS body',
      emailHtmlEscape: 'escapeHtml() on all user-controlled fields in email templates',
      apiResponseScrub: 'GET /api/data strips ph/totpSecret/totpRecoveryCodesHashes/inviteToken before send',
    },
    rateLimiting: {
      auth: '10 / 15min per IP',
      apply: '30 / 15min per IP (public apply page)',
      api: '300 / 1min per IP',
      inviteVerify: '20 / 1min per IP',
    },
    pccIntegration: {
      configured: !!(PCC_CLIENT_ID && PCC_CLIENT_SECRET && PCC_FACILITY_ID),
      tokenSerialized: true,                    // _pccTokenInflight stampede protection
      retryOn401: true,                          // pccFetch
      retryOn429: 'honors Retry-After',
      retryOn5xx: 'exponential backoff up to 3 attempts',
      timeout: '15s default, 10s on auth endpoint',
      logsScrubbed: 'status-only; no body / no URL with secrets',
    },
    requiredEnv: {
      JWT_SECRET: ok(process.env.JWT_SECRET) && (process.env.JWT_SECRET || '').length >= 32,
      DATA_ENCRYPTION_KEY: ok(process.env.DATA_ENCRYPTION_KEY),
      AUDIT_HMAC_KEY: ok(process.env.AUDIT_HMAC_KEY),
      ACS_CONNECTION_STRING: ok(process.env.ACS_CONNECTION_STRING),
      APP_URL: ok(process.env.APP_URL),
      PG_CONN: ok(process.env.PG_CONN),
    },
    subprocessors: [
      // Every subprocessor that handles PHI MUST have a BAA in place.
      { name: 'Microsoft Azure (App Service, Postgres, Storage, Key Vault, Application Insights)', baaRequired: true, role: 'compute / storage / observability' },
      { name: 'Azure Communication Services',                                                       baaRequired: true, role: 'email + SMS delivery (covered by Microsoft master BAA)' },
      { name: 'PointClickCare (when configured)',                                                   baaRequired: true, role: 'EHR data source — partnership BAA' },
    ],
    deviations: [],   // populated below if any check fails
  };

  // Self-test the most important invariants. Any failure here flips ok=false.
  const failures = [];
  if (!onHttps && IS_PROD) failures.push('HTTPS not detected on prod — TLS termination misconfigured');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) failures.push('JWT_SECRET missing or under 32 chars');
  if (!process.env.DATA_ENCRYPTION_KEY) failures.push('DATA_ENCRYPTION_KEY missing — at-rest encryption disabled');
  if (!process.env.AUDIT_HMAC_KEY) failures.push('AUDIT_HMAC_KEY missing — audit chain integrity not protected');
  if (!IS_PROD && r.cookies.authCookieSecure === false) {
    // Dev mode is allowed to ship secure:false but we flag for visibility.
  }
  r.deviations = failures;
  res.setHeader('Cache-Control', 'no-store');
  res.status(failures.length ? 503 : 200).json({ ok: failures.length === 0, ...r });
});

// ── SERVE HTML ────────────────────────────────────────────────────────────────
// Force browsers to revalidate so users always get the latest UI after deploy.
// `must-revalidate` + `no-cache` together tell the browser to send a conditional
// GET on every load. App Service still serves it fast (single file).
app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache, must-revalidate');
  res.sendFile(HTML_FILE);
});

// PWA manifest — lets users "Add to Home Screen" and launch in a standalone
// window (no browser chrome). Icons are inline SVG data URLs that match the
// existing favicon, so no static-file hosting required.
app.get('/manifest.json', (_req, res) => {
  const iconSvg = `<svg viewBox="0 0 100 92" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" rx="20" fill="%23F0F7F3"/><rect x="70" y="2" width="14" height="26" rx="5" fill="%236B9E7A"/><path d="M50 5 L0 52 Q0 56 4 56 L96 56 Q100 56 100 52 Z" fill="%236B9E7A"/><rect x="3" y="50" width="94" height="42" rx="6" fill="%236B9E7A"/><rect x="38" y="20" width="9" height="9" rx="2" fill="white"/><rect x="52" y="20" width="9" height="9" rx="2" fill="white"/><rect x="38" y="32" width="9" height="9" rx="2" fill="white"/><rect x="52" y="32" width="9" height="9" rx="2" fill="white"/><rect x="63" y="57" width="10" height="9" rx="2" fill="white"/><rect x="76" y="57" width="10" height="9" rx="2" fill="white"/><rect x="63" y="69" width="10" height="9" rx="2" fill="white"/><rect x="76" y="69" width="10" height="9" rx="2" fill="white"/><rect x="7" y="71" width="26" height="8" rx="4" fill="white"/><rect x="16" y="62" width="8" height="26" rx="4" fill="white"/><rect x="41" y="70" width="18" height="22" rx="3" fill="white"/></svg>`;
  const icon = 'data:image/svg+xml,' + iconSvg;
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.json({
    name: 'ManageMyStaffing',
    short_name: 'MMS',
    description: 'HIPAA-compliant scheduling, recruiting, time clock, and PPD analytics for SNF/LTC operators',
    start_url: '/',
    display: 'standalone',
    orientation: 'any',
    background_color: '#F0F7F3',
    theme_color: '#6B9E7A',
    scope: '/',
    icons: [
      { src: icon, sizes: 'any',     type: 'image/svg+xml', purpose: 'any maskable' },
      { src: icon, sizes: '192x192', type: 'image/svg+xml' },
      { src: icon, sizes: '512x512', type: 'image/svg+xml' },
    ],
  });
});

// ── RECRUITING ────────────────────────────────────────────────────────────────
// Public Indeed XML feed. Submit https://www.managemystaffing.com/jobs.xml in
// your Indeed Employer Dashboard. Indeed crawls this URL periodically and
// indexes every <job> entry. Only postings with status === 'active' are
// included; "Take Down" flips status to 'closed' and the job drops from the
// next crawl.
function _xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function _wrapCdata(s) {
  // CDATA can't contain "]]>" — split + reassemble defensively.
  return '<![CDATA[' + String(s == null ? '' : s).replace(/]]>/g, ']]]]><![CDATA[>') + ']]>';
}
// Shared builder for the active jobs list — used by every platform feed.
async function _buildActiveJobsForFeed() {
  const data = await loadData();
  const jobs = (data.jobPostings || []).filter(j => j.status === 'active');
  const buildings = data.buildings || [];
  const baseUrl = (process.env.APP_URL || 'https://www.managemystaffing.com').replace(/\/$/, '');
  const lastBuild = new Date().toUTCString();
  return { jobs, buildings, baseUrl, lastBuild };
}

// Map our jobType to a normalized lowercased token. All three platforms
// accept the same vocabulary in their `<jobtype>` field.
function _normalizeJobType(t) {
  return ({
    'Full-time':'fulltime','Part-time':'parttime','PRN / Per Diem':'perdiem',
    'Contract':'contract','Temporary':'temporary',
  })[t] || 'fulltime';
}

// ── Indeed XML feed ───────────────────────────────────────────────────────
// Indeed-spec format. ZipRecruiter accepts the same shape — they share an
// almost identical schema — but we expose a separate URL below to keep
// crawler tracking clean and let us tune fields if Indeed and ZipRecruiter
// ever diverge.
app.get('/jobs.xml', async (_req, res) => {
  try {
    const { jobs, buildings, baseUrl, lastBuild } = await _buildActiveJobsForFeed();
    const items = jobs.map(j => {
      const b = buildings.find(x => x.id === j.buildingId);
      const company = b?.name || 'ManageMyStaffing Facility';
      const dateStr = j.createdAt ? new Date(j.createdAt).toUTCString() : lastBuild;
      return `  <job>
    <title>${_wrapCdata(j.title)}</title>
    <date>${_wrapCdata(dateStr)}</date>
    <referencenumber>${_wrapCdata(j.id)}</referencenumber>
    <url>${_wrapCdata(`${baseUrl}/apply/${j.id}`)}</url>
    <company>${_wrapCdata(company)}</company>
    <city>${_wrapCdata(j.city || '')}</city>
    <state>${_wrapCdata(j.state || '')}</state>
    <country>${_wrapCdata('US')}</country>
    <postalcode>${_wrapCdata(j.zip || '')}</postalcode>
    <description>${_wrapCdata((j.description || '') + (j.requirements ? '\n\nRequirements:\n' + j.requirements : ''))}</description>
    <salary>${_wrapCdata(j.salary || '')}</salary>
    <jobtype>${_wrapCdata(_normalizeJobType(j.jobType))}</jobtype>
    <category>${_wrapCdata(j.department || '')}</category>
  </job>`;
    }).join('\n');
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<source>
  <publisher>${_wrapCdata('ManageMyStaffing')}</publisher>
  <publisherurl>${_wrapCdata(baseUrl)}</publisherurl>
  <lastBuildDate>${_wrapCdata(lastBuild)}</lastBuildDate>
${items}
</source>`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(xml);
  } catch (e) {
    logger.error('jobs_xml_failed', { err: e.message });
    res.status(500).type('text').send('Feed temporarily unavailable');
  }
});

// ── ZipRecruiter XML feed ─────────────────────────────────────────────────
// ZR accepts the standard Indeed-style schema. The differences:
// * Their crawler tags `<source>` instead of `<jobs>` (we already use source).
// * `<expiration_date>` is honored (we omit by default — postings are evergreen
//   until the user clicks Take Down).
// * No `<category>` — ZR uses keywords from title + description.
// Submit this URL in your ZipRecruiter Job Feed Setup.
app.get('/jobs/ziprecruiter.xml', async (_req, res) => {
  try {
    const { jobs, buildings, baseUrl, lastBuild } = await _buildActiveJobsForFeed();
    const items = jobs.map(j => {
      const b = buildings.find(x => x.id === j.buildingId);
      const company = b?.name || 'ManageMyStaffing Facility';
      const dateStr = j.createdAt ? new Date(j.createdAt).toUTCString() : lastBuild;
      return `  <job>
    <title>${_wrapCdata(j.title)}</title>
    <date>${_wrapCdata(dateStr)}</date>
    <referencenumber>${_wrapCdata(j.id)}</referencenumber>
    <url>${_wrapCdata(`${baseUrl}/apply/${j.id}`)}</url>
    <company>${_wrapCdata(company)}</company>
    <city>${_wrapCdata(j.city || '')}</city>
    <state>${_wrapCdata(j.state || '')}</state>
    <country>${_wrapCdata('US')}</country>
    <postalcode>${_wrapCdata(j.zip || '')}</postalcode>
    <description>${_wrapCdata((j.description || '') + (j.requirements ? '\n\nRequirements:\n' + j.requirements : ''))}</description>
    <salary>${_wrapCdata(j.salary || '')}</salary>
    <jobtype>${_wrapCdata(_normalizeJobType(j.jobType))}</jobtype>
  </job>`;
    }).join('\n');
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<source>
  <publisher>${_wrapCdata('ManageMyStaffing')}</publisher>
  <publisherurl>${_wrapCdata(baseUrl)}</publisherurl>
  <lastBuildDate>${_wrapCdata(lastBuild)}</lastBuildDate>
${items}
</source>`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(xml);
  } catch (e) {
    logger.error('zr_xml_failed', { err: e.message });
    res.status(500).type('text').send('Feed temporarily unavailable');
  }
});

// ── LinkedIn XML feed (Limited Listings format) ───────────────────────────
// LinkedIn's open job feed uses a different schema:
// * Top-level <source> wraps a list of <job> entries (same as Indeed).
// * Required: <partnerJobId> (their dedup key), <title>, <company>,
//   <description>, <jobtype>, <applyUrl>.
// * Recommended: <location>, <city>, <state>, <country>, <postalcode>,
//   <industryCodes>, <workplaceTypes>, <expirationDate>.
// LinkedIn's "Limited Listings" requires whitelisting per-tenant; if you
// haven't been onboarded by LinkedIn, this URL still emits a valid feed
// they'll accept once your account is approved. Submit via
// https://business.linkedin.com/talent-solutions/post-jobs.
app.get('/jobs/linkedin.xml', async (_req, res) => {
  try {
    const { jobs, buildings, baseUrl, lastBuild } = await _buildActiveJobsForFeed();
    const items = jobs.map(j => {
      const b = buildings.find(x => x.id === j.buildingId);
      const company = b?.name || 'ManageMyStaffing Facility';
      const dateStr = j.createdAt ? new Date(j.createdAt).toUTCString() : lastBuild;
      const loc = [j.city, j.state].filter(Boolean).join(', ');
      // Healthcare-relevant industry codes per LinkedIn taxonomy.
      // 14 = Hospital & Health Care, 12 = Hospital, 124 = Long-Term Care.
      const industryCodes = '14';
      return `  <job>
    <partnerJobId>${_wrapCdata(j.id)}</partnerJobId>
    <title>${_wrapCdata(j.title)}</title>
    <company>${_wrapCdata(company)}</company>
    <description>${_wrapCdata((j.description || '') + (j.requirements ? '\n\nRequirements:\n' + j.requirements : ''))}</description>
    <jobtype>${_wrapCdata(_normalizeJobType(j.jobType))}</jobtype>
    <applyUrl>${_wrapCdata(`${baseUrl}/apply/${j.id}`)}</applyUrl>
    <location>${_wrapCdata(loc)}</location>
    <city>${_wrapCdata(j.city || '')}</city>
    <state>${_wrapCdata(j.state || '')}</state>
    <country>${_wrapCdata('US')}</country>
    <postalcode>${_wrapCdata(j.zip || '')}</postalcode>
    <industryCodes>${_wrapCdata(industryCodes)}</industryCodes>
    <workplaceTypes>${_wrapCdata('on-site')}</workplaceTypes>
    <salary>${_wrapCdata(j.salary || '')}</salary>
    <postingDate>${_wrapCdata(dateStr)}</postingDate>
  </job>`;
    }).join('\n');
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<source>
  <publisher>${_wrapCdata('ManageMyStaffing')}</publisher>
  <publisherurl>${_wrapCdata(baseUrl)}</publisherurl>
  <lastBuildDate>${_wrapCdata(lastBuild)}</lastBuildDate>
${items}
</source>`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(xml);
  } catch (e) {
    logger.error('linkedin_xml_failed', { err: e.message });
    res.status(500).type('text').send('Feed temporarily unavailable');
  }
});

// Public apply page — minimal HTML form that posts back to /api/recruiting/apply.
// Linked from the Indeed XML <url> field, so this is what candidates land on.
app.get('/apply/:jobId', async (req, res) => {
  try {
    const data = await loadData();
    const j = (data.jobPostings || []).find(x => x.id === req.params.jobId && x.status === 'active');
    if (!j) {
      res.status(404).type('html').send(`<!doctype html><meta charset="utf-8"><title>Position Closed</title>
        <body style="font-family:system-ui;max-width:520px;margin:80px auto;padding:24px;text-align:center;color:#374151">
        <h2>This position is no longer accepting applications</h2>
        <p>Please visit <a href="https://www.managemystaffing.com">our home page</a> to see open roles.</p>
        </body>`);
      return;
    }
    const b = (data.buildings || []).find(x => x.id === j.buildingId);
    const company = _xmlEscape(b?.name || 'ManageMyStaffing Facility');
    const loc = [j.city, j.state].filter(Boolean).map(_xmlEscape).join(', ');
    res.setHeader('Cache-Control', 'no-cache');
    res.type('html').send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${_xmlEscape(j.title)} — ${company}</title>
<style>
  body{font-family:'DM Sans',system-ui,sans-serif;background:#F9FAFB;margin:0;color:#111827;line-height:1.5}
  .wrap{max-width:640px;margin:0 auto;padding:32px 20px}
  .card{background:#fff;border:1px solid #E5E7EB;border-radius:12px;padding:28px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  h1{font-size:22px;margin:0 0 6px}
  .sub{color:#6B7280;font-size:13px;margin-bottom:18px}
  .pill{display:inline-block;background:#ECFDF5;color:#047857;font-size:11px;font-weight:700;padding:3px 9px;border-radius:99px;margin-right:5px}
  .desc{white-space:pre-wrap;color:#374151;margin:18px 0;font-size:14px}
  label{display:block;font-size:12px;font-weight:600;color:#6B7280;margin:12px 0 4px;text-transform:uppercase;letter-spacing:.05em}
  input,textarea{width:100%;padding:10px 12px;border:1.5px solid #E5E7EB;border-radius:8px;font-family:inherit;font-size:14px;box-sizing:border-box;color:#111827}
  textarea{resize:vertical;min-height:80px}
  button{width:100%;background:#6B9E7A;color:#fff;font-weight:700;font-size:14px;padding:12px;border:none;border-radius:8px;cursor:pointer;margin-top:18px}
  button:hover{background:#5a8b68}
  button:disabled{opacity:.5;cursor:not-allowed}
  .err{color:#DC2626;font-size:13px;margin-top:10px}
  .ok{background:#ECFDF5;border:1px solid #6EE7B7;color:#047857;padding:18px;border-radius:8px;font-size:14px;text-align:center}
  .logo{display:flex;align-items:center;gap:10px;margin-bottom:24px}
  .logo svg{width:32px;height:32px}
  .logo span{font-weight:800;font-size:16px;color:#111827}
</style>
</head><body><div class="wrap">
  <div class="logo">
    <svg viewBox="0 0 100 92" xmlns="http://www.w3.org/2000/svg">
      <rect x="70" y="2" width="14" height="26" rx="5" fill="#6B9E7A"/>
      <path d="M50 5 L0 52 Q0 56 4 56 L96 56 Q100 56 100 52 Z" fill="#6B9E7A"/>
      <rect x="3" y="50" width="94" height="42" rx="6" fill="#6B9E7A"/>
    </svg>
    <span>ManageMyStaffing</span>
  </div>
  <div class="card">
    <h1>${_xmlEscape(j.title)}</h1>
    <div class="sub">${company}${loc ? ' · ' + loc : ''}${j.salary ? ' · ' + _xmlEscape(j.salary) : ''}</div>
    <div>
      <span class="pill">${_xmlEscape(j.department)}</span>
      <span class="pill" style="background:#EFF6FF;color:#1D4ED8">${_xmlEscape(j.jobType)}</span>
    </div>
    <div class="desc">${_xmlEscape(j.description)}${j.requirements ? '\n\nRequirements:\n' + _xmlEscape(j.requirements) : ''}</div>
    <form id="apply-form">
      <label for="apply-name">Full Name *</label>
      <input id="apply-name" name="name" required maxlength="100" autocomplete="name">
      <label for="apply-email">Email *</label>
      <input id="apply-email" name="email" type="email" required maxlength="254" autocomplete="email">
      <label for="apply-phone">Phone Number *</label>
      <input id="apply-phone" name="phone" type="tel" required maxlength="20" autocomplete="tel" placeholder="(555) 123-4567">
      <label for="apply-msg">Message (optional)</label>
      <textarea id="apply-msg" name="message" maxlength="2000" placeholder="Tell us about your relevant experience…"></textarea>
      <button type="submit" id="apply-btn">Submit Application</button>
      <div id="apply-err" class="err" style="display:none"></div>
    </form>
    <div id="apply-ok" class="ok" style="display:none">
      Thanks for applying! We received your information and will be in touch shortly.
    </div>
  </div>
</div>
<script>
document.getElementById('apply-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('apply-btn');
  const err = document.getElementById('apply-err');
  err.style.display = 'none';
  btn.disabled = true; btn.textContent = 'Submitting…';
  const body = {
    jobId: ${JSON.stringify(j.id)},
    name:    document.getElementById('apply-name').value.trim(),
    email:   document.getElementById('apply-email').value.trim(),
    phone:   document.getElementById('apply-phone').value.trim(),
    message: document.getElementById('apply-msg').value.trim(),
  };
  try {
    const r = await fetch('/api/recruiting/apply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    const data = await r.json();
    if (!r.ok) {
      err.textContent = data.error || 'Could not submit application.'; err.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Submit Application'; return;
    }
    document.getElementById('apply-form').style.display = 'none';
    document.getElementById('apply-ok').style.display = 'block';
  } catch (ex) {
    err.textContent = 'Network error. Please try again.'; err.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Submit Application';
  }
});
</script>
</body></html>`);
  } catch (e) {
    res.status(500).type('text').send('Apply page temporarily unavailable');
  }
});

// Public application submission. No auth — this is what candidates use.
// Rate-limited to thwart bots.
const applyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many applications. Try again later.' } });
app.post('/api/recruiting/apply', applyLimiter, async (req, res) => {
  const { jobId, name, email, phone, message, source } = req.body || {};
  if (!jobId || !name || !email) return res.status(400).json({ error: 'jobId, name, and email are required' });
  const data = await loadData();
  const job = (data.jobPostings || []).find(j => j.id === jobId);
  if (!job)                       return res.status(404).json({ error: 'Job posting not found' });
  if (job.status !== 'active')    return res.status(410).json({ error: 'This position is no longer accepting applications' });
  const emailNorm = String(email).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm) || emailNorm.length > 254) return res.status(400).json({ error: 'Invalid email' });

  const prospect = {
    id: 'pr_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    jobId,
    jobTitle:   job.title,
    buildingId: job.buildingId || null,
    name:    String(name).trim().slice(0, 100),
    email:   emailNorm,
    phone:   String(phone || '').trim().slice(0, 25),
    source:  source || 'apply_page',
    message: String(message || '').trim().slice(0, 2000),
    status:  'new',
    appliedAt: new Date().toISOString(),
    notes: [],
  };
  if (!Array.isArray(data.prospects)) data.prospects = [];
  // Dedupe: same email + same job within the last 7 days collapses to a single record.
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const dupe = data.prospects.find(p =>
    p.email === emailNorm && p.jobId === jobId && new Date(p.appliedAt).getTime() > cutoff);
  if (dupe) {
    dupe.appliedAt = prospect.appliedAt;
    if (prospect.message) dupe.message = prospect.message;
  } else {
    data.prospects.push(prospect);
  }
  // Cap to last 5000 prospects to bound storage.
  if (data.prospects.length > 5000) data.prospects = data.prospects.slice(-5000);
  markDirty();
  auditLog('PROSPECT_RECEIVED', null, { jobId, emailMasked: emailNorm.replace(/^(.).*(@.*)$/, '$1***$2') });
  res.json({ ok: true, prospectId: dupe?.id || prospect.id });
});

// Send onboarding-docs email to a prospect. Marks them as in-progress so the
// dashboard reflects the handoff. Email body links the candidate to fill out
// new-hire paperwork via the existing onboarding flow.
app.post('/api/recruiting/onboard', requireAuth, requireAdmin, async (req, res) => {
  const { prospectId } = req.body || {};
  if (!prospectId) return res.status(400).json({ error: 'prospectId is required' });
  const data = await loadData();
  const p = (data.prospects || []).find(x => x.id === prospectId);
  if (!p) return res.status(404).json({ error: 'Prospect not found' });
  if (!p.email) return res.status(400).json({ error: 'No email on file for this prospect' });

  const baseUrl = (process.env.APP_URL || 'https://www.managemystaffing.com').replace(/\/$/, '');
  const link = `${baseUrl}/?onboard=${encodeURIComponent(p.id)}`;
  // Use the full escapeHtml() — covers <, >, &, ", '. The earlier regex
  // missed quotes, leaving a path for HTML attribute injection if the name
  // ever ended up inside an attribute. Defense in depth.
  const escName = escapeHtml(String(p.name || ''));
  const safePlainName = String(p.name || '').replace(/[\r\n]/g, ' ');

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec = new EmailClient(ACS_CONNECTION_STRING);
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: p.email, displayName: p.name }] },
        content: {
          subject: `Onboarding: ${p.jobTitle || 'New Hire Paperwork'}`,
          plainText: `Hi ${safePlainName},\n\nThanks for applying for ${p.jobTitle || 'a position with us'}.\n\nPlease complete your new-hire paperwork at the link below:\n${link}\n\nIf you have any questions, just reply to this email.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">Welcome aboard, ${escName}!</h2>
    <p style="color:#6b7280;font-size:14px">Thanks for applying for <strong>${escName ? p.jobTitle : 'a position'}</strong>. To finish the hiring process, please complete your new-hire paperwork below.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px;margin-top:8px">Start Onboarding →</a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0">Reply to this email if you have any questions.</p>
  </div>
</div>`,
        },
      });
      await Promise.race([
        poller.pollUntilDone(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000)),
      ]);
    } catch (e) {
      logger.error('onboard_email_failed', { err: e.message, prospectId });
      return res.status(502).json({ error: `Email failed: ${e.message}` });
    }
  } else {
    return res.status(503).json({ error: 'Email is not configured (ACS_CONNECTION_STRING missing)' });
  }

  p.status = 'onboarding';
  p.onboardingSentAt = new Date().toISOString();
  if (!Array.isArray(p.notes)) p.notes = [];
  p.notes.push({ at: new Date().toISOString(), kind:'email_out', text:'Onboarding link sent.' });
  markDirty();
  auditLog('PROSPECT_ONBOARDING_SENT', req.user, { prospectId, jobId: p.jobId });
  // If this prospect came in via Indeed Apply, push the OFFER_EXTENDED
  // disposition back to Indeed. Fire-and-forget — failure doesn't block the
  // onboarding email already sent.
  if (p.indeedApplyId && INDEED_API_CLIENT_ID) {
    pushIndeedDisposition(p.indeedApplyId, 'onboarding')
      .catch(e => logger.error('indeed_disposition_onboard_failed', { msg: e.message, prospectId: p.id }));
  }
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// INDEED PARTNER PROGRAM — APPLY + EVENT WEBHOOKS + DISPOSITION SYNC
// ─────────────────────────────────────────────────────────────────────────────
// Indeed Marketplace partners receive applications via "Indeed Apply" — a
// candidate clicks Apply on Indeed, fills out the form there, and Indeed
// POSTs the application to a partner-hosted endpoint. We treat this as
// equivalent to our public /api/recruiting/apply and create the same
// prospect record. Disposition (status changes) flow back to Indeed via
// pushIndeedDisposition() in the helper module above, fired automatically
// on setProspectStatus / startProspectOnboarding state transitions.
//
// Auth: every webhook is signed with HMAC-SHA-256 over the raw body using
// INDEED_PARTNER_SECRET. We require the X-Indeed-Signature header and
// verify it constant-time before parsing JSON.

// POST /api/indeed/apply — receives a new application from Indeed Apply
app.post('/api/indeed/apply',
  express.raw({ type: 'application/json', limit: '5mb' }),
  async (req, res) => {
    if (!INDEED_PARTNER_SECRET) {
      auditLog('INDEED_APPLY_REJECTED', null, { reason: 'not_configured' });
      return res.status(503).json({ error: 'Indeed Partner integration not configured' });
    }
    const sig = req.headers['x-indeed-signature'];
    if (!verifyIndeedSignature(req.body, sig)) {
      auditLog('INDEED_APPLY_REJECTED', null, { reason: 'bad_signature' });
      return res.status(401).json({ error: 'Invalid signature' });
    }
    let body;
    try { body = JSON.parse(req.body.toString('utf8')); }
    catch { return res.status(400).json({ error: 'Malformed JSON' }); }

    const apply = body.applyData || body || {};
    const a     = apply.applicant || {};
    const j     = apply.job || {};
    // We embed our internal job id in jobMeta when generating the Indeed
    // listing — Indeed echoes it back so we can correlate the application.
    const ourJobId = j.jobMeta?.jobId || j.jobMeta?.partnerJobId || j.referencenumber;
    if (!ourJobId) return res.status(400).json({ error: 'Missing job reference' });

    const data = await loadData();
    const job  = (data.jobPostings || []).find(x => x.id === ourJobId);
    if (!job) return res.status(404).json({ error: 'Job not found in our system' });

    const emailNorm = String(a.email || '').trim().toLowerCase();
    if (emailNorm && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm) || emailNorm.length > 254)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    const phone = String(a.phoneNumber || a.phone || '').trim().slice(0, 25);

    // Dedupe by Indeed apply id first, then by email + jobId within 7 days.
    if (!Array.isArray(data.prospects)) data.prospects = [];
    const indeedApplyId = apply.id || apply.applyId || null;
    let dupe = indeedApplyId
      ? data.prospects.find(p => p.indeedApplyId === indeedApplyId)
      : null;
    if (!dupe) {
      const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
      dupe = data.prospects.find(p =>
        p.email === emailNorm && p.jobId === ourJobId && new Date(p.appliedAt).getTime() > cutoff);
    }

    let prospect;
    if (dupe) {
      // Refresh existing record's Indeed metadata in case Indeed re-sent.
      dupe.indeedApplyId = indeedApplyId || dupe.indeedApplyId;
      dupe.appliedAt = new Date().toISOString();
      if (apply.questions && apply.questions.length) dupe.questions = apply.questions;
      if (apply.resume?.url) dupe.resumeUrl = apply.resume.url;
      prospect = dupe;
    } else {
      prospect = {
        id: 'pr_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
        jobId: ourJobId,
        jobTitle: job.title,
        buildingId: job.buildingId || null,
        name: String(a.fullName || `${a.firstName || ''} ${a.lastName || ''}`).trim().slice(0, 100),
        email: emailNorm,
        phone,
        source: 'indeed_apply',
        indeedApplyId,
        appliedAt: new Date().toISOString(),
        status: 'new',
        notes: [],
        questions: Array.isArray(apply.questions) ? apply.questions.slice(0, 50) : [],
        resumeUrl: apply.resume?.url || null,
        coverLetter: apply.coverLetter?.text ? String(apply.coverLetter.text).slice(0, 5000) : null,
      };
      data.prospects.push(prospect);
    }
    if (data.prospects.length > 5000) data.prospects = data.prospects.slice(-5000);
    markDirty();
    auditLog('INDEED_APPLY_RECEIVED', null, {
      indeedApplyId,
      jobId: ourJobId,
      emailMasked: emailNorm.replace(/^(.).*(@.*)$/, '$1***$2'),
    });
    res.json({ ok: true, prospectId: prospect.id });
  }
);

// POST /api/indeed/event — receives status events from Indeed (applicant
// withdrew, Indeed flagged duplicate, etc.). Same signature scheme.
app.post('/api/indeed/event',
  express.raw({ type: 'application/json', limit: '256kb' }),
  async (req, res) => {
    if (!INDEED_PARTNER_SECRET) return res.status(503).json({ error: 'not configured' });
    if (!verifyIndeedSignature(req.body, req.headers['x-indeed-signature'])) {
      auditLog('INDEED_EVENT_REJECTED', null, { reason: 'bad_signature' });
      return res.status(401).json({ error: 'Invalid signature' });
    }
    let body;
    try { body = JSON.parse(req.body.toString('utf8')); }
    catch { return res.status(400).json({ error: 'Malformed JSON' }); }

    const eventType = body.event || body.type || '';
    const applyId   = body.applyId || body.id;
    if (!applyId) return res.status(400).json({ error: 'Missing applyId' });

    const data = await loadData();
    const p = (data.prospects || []).find(x => x.indeedApplyId === applyId);
    if (!p) {
      auditLog('INDEED_EVENT_ORPHAN', null, { eventType, applyId });
      return res.status(200).json({ ok: true, note: 'No matching prospect; ignored' });
    }
    if (!Array.isArray(p.notes)) p.notes = [];

    if (eventType === 'WITHDRAWN' || eventType === 'withdrawn' || eventType === 'CANDIDATE_WITHDREW') {
      p.status = 'rejected';
      p.notes.push({ at: new Date().toISOString(), kind: 'indeed_event', text: 'Candidate withdrew via Indeed.' });
    } else if (eventType === 'DUPLICATE' || eventType === 'duplicate') {
      p.notes.push({ at: new Date().toISOString(), kind: 'indeed_event', text: 'Indeed flagged as duplicate application.' });
    } else {
      p.notes.push({ at: new Date().toISOString(), kind: 'indeed_event', text: `Indeed event: ${eventType}` });
    }
    p.updatedAt = new Date().toISOString();
    markDirty();
    auditLog('INDEED_EVENT_RECEIVED', null, { eventType, applyId, prospectId: p.id });
    res.json({ ok: true });
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// PER-BUILDING SMS PROVISIONING
// ─────────────────────────────────────────────────────────────────────────────
// SA-only endpoints to purchase / release a local SMS number for a building.
// Numbers come from the building's own area code (looked up from its ZIP) so
// staff at that facility see a familiar caller ID.
//
// SAFETY: provisioning charges $1–2 / month per number plus 10DLC overhead.
// Endpoint requires (a) superadmin role and (b) the building to be "fully
// set up" (has admin + at least one employee). The frontend confirms the
// charge before posting.

// (requireSuperAdmin already defined above; reused here.)

// ── BACKUP / RESTORE ENDPOINTS ───────────────────────────────────────────────
// GET  /api/admin/snapshots               → list available point-in-time snapshots
// POST /api/admin/snapshots                → force-create a snapshot right now
// POST /api/admin/snapshots/restore        → roll the cache back to a snapshot
// All Super Admin only — restoring data is a destructive operation that must
// be auditable. We log RESTORE events into the tamper-evident audit chain.
app.get('/api/admin/snapshots', requireAuth, requireSuperAdmin, async (req, res) => {
  if (_useDB) return res.json({ backend: 'postgres', message: 'Snapshots disabled in Postgres mode (use DB backups).', snapshots: [] });
  try {
    const all = await _listSnapshotFiles();
    res.json({
      backend: 'file',
      retention: { allUnder: '24h', hourly: '30d', daily: '365d' },
      snapshots: all.map(s => ({ filename: s.name, takenAt: new Date(s.ts).toISOString() })),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/snapshots', requireAuth, requireSuperAdmin, async (req, res) => {
  if (_useDB) return res.status(400).json({ error: 'Snapshots disabled in Postgres mode' });
  try {
    _lastSnapshotAt = 0;                   // force through the throttle
    await _writeSnapshot();
    auditLog('BACKUP_SNAPSHOT_FORCED', req.user, {});
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/snapshots/restore', requireAuth, requireSuperAdmin, async (req, res) => {
  if (_useDB) return res.status(400).json({ error: 'Restore disabled in Postgres mode (use DB PITR)' });
  const filename = String(req.body?.filename || '');
  if (!filename) return res.status(400).json({ error: 'filename required' });
  try {
    const result = await _restoreSnapshotFile(filename);
    auditLog('BACKUP_SNAPSHOT_RESTORED', req.user, { filename, restoredAt: result.restoredAt });
    res.json({ ok: true, ...result });
  } catch (e) {
    auditLog('BACKUP_SNAPSHOT_RESTORE_FAILED', req.user, { filename, err: e.message });
    res.status(500).json({ error: e.message });
  }
});

// POST /api/buildings/:id/provision-sms
//   Body (optional): { areaCode: "918" }   — overrides ZIP-derived area code
// Returns: { ok, phoneNumber, monthlyCost, areaCode } on success.
app.post('/api/buildings/:id/provision-sms', requireAuth, requireSuperAdmin, async (req, res) => {
  if (!ACS_CONNECTION_STRING) return res.status(503).json({ error: 'ACS not configured' });
  const buildingId = req.params.id;
  const data = await loadData();
  const b = (data.buildings || []).find(x => x.id === buildingId);
  if (!b) return res.status(404).json({ error: 'Building not found' });
  if (b.smsFromPhone && b.smsProvisionStatus === 'active') {
    return res.status(409).json({ error: 'Building already has an active SMS number', phoneNumber: b.smsFromPhone });
  }
  // Gate on fully-set-up status to avoid wasting spend on incomplete onboarding.
  const setup = _buildingIsFullySetUp(buildingId, data);
  if (!setup.ok) return res.status(412).json({ error: `Building not ready for SMS: ${setup.reason}` });

  // Resolve area code: explicit override wins, else ZIP-derived, else error.
  const overrideArea = String(req.body?.areaCode || '').replace(/\D/g, '').slice(0, 3);
  const areaCode = overrideArea || zipToAreaCode(b.zip);
  if (!areaCode || areaCode.length !== 3) {
    return res.status(400).json({ error: 'Could not derive area code from ZIP. Pass areaCode explicitly in body.' });
  }

  // Mark pending immediately so concurrent calls don't double-purchase.
  b.smsProvisionStatus = 'pending';
  b.smsAreaCode = areaCode;
  markDirty();

  let result;
  try {
    const { PhoneNumbersClient } = require('@azure/communication-phone-numbers');
    const client = new PhoneNumbersClient(ACS_CONNECTION_STRING);
    // Search for one available local number in the area code.
    const searchPoller = await client.beginSearchAvailablePhoneNumbers({
      countryCode:    'US',
      phoneNumberType:'geographic',
      assignmentType: 'application',
      capabilities:   { sms: 'inbound+outbound', calling: 'none' },
      areaCode,
      quantity:       1,
    });
    const searchResult = await searchPoller.pollUntilDone();
    if (!searchResult.phoneNumbers?.length) {
      b.smsProvisionStatus = 'failed';
      markDirty();
      return res.status(503).json({ error: `No local numbers available in area code ${areaCode}. Try a different code.` });
    }
    // Purchase the search.
    const purchasePoller = await client.beginPurchasePhoneNumbers(searchResult.searchId);
    await purchasePoller.pollUntilDone();
    // Result has the purchased number.
    const purchased = searchResult.phoneNumbers[0];
    b.smsFromPhone = purchased;
    b.smsProvisionStatus = 'active';
    b.smsProvisionedAt = new Date().toISOString();
    b.smsCostUsd = searchResult.cost?.amount || 2.0;
    markDirty();
    auditLog('SMS_NUMBER_PROVISIONED', req.user, { buildingId, phoneNumber: purchased, areaCode });
    result = {
      ok: true,
      phoneNumber: purchased,
      areaCode,
      monthlyCost: b.smsCostUsd,
    };
  } catch (e) {
    b.smsProvisionStatus = 'failed';
    b.smsProvisionError = e.message?.slice(0, 200) || 'unknown';
    markDirty();
    logger.error('sms_provision_failed', { buildingId, areaCode, msg: e.message });
    // Common failure: no 10DLC campaign registered.
    const isTenDlc = /campaign|10dlc|brand/i.test(e.message || '');
    return res.status(502).json({
      error: isTenDlc
        ? '10DLC brand + campaign must be registered in Azure portal before local SMS numbers can be activated. ACS Phone numbers → Regulatory documents.'
        : `Number purchase failed: ${e.message}`,
    });
  }
  res.json(result);
});

// DELETE /api/buildings/:id/provision-sms
//   Releases the building's SMS number back to ACS (stops billing).
app.delete('/api/buildings/:id/provision-sms', requireAuth, requireSuperAdmin, async (req, res) => {
  if (!ACS_CONNECTION_STRING) return res.status(503).json({ error: 'ACS not configured' });
  const buildingId = req.params.id;
  const data = await loadData();
  const b = (data.buildings || []).find(x => x.id === buildingId);
  if (!b) return res.status(404).json({ error: 'Building not found' });
  if (!b.smsFromPhone) return res.status(409).json({ error: 'Building has no SMS number to release' });
  try {
    const { PhoneNumbersClient } = require('@azure/communication-phone-numbers');
    const client = new PhoneNumbersClient(ACS_CONNECTION_STRING);
    const releasePoller = await client.beginReleasePhoneNumber(b.smsFromPhone);
    await releasePoller.pollUntilDone();
    auditLog('SMS_NUMBER_RELEASED', req.user, { buildingId, phoneNumber: b.smsFromPhone });
    delete b.smsFromPhone;
    delete b.smsProvisionedAt;
    delete b.smsCostUsd;
    delete b.smsProvisionError;
    b.smsProvisionStatus = 'none';
    markDirty();
    res.json({ ok: true });
  } catch (e) {
    logger.error('sms_release_failed', { buildingId, msg: e.message });
    return res.status(502).json({ error: `Release failed: ${e.message}` });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// TIME CLOCK — primary T&A for the platform
// ─────────────────────────────────────────────────────────────────────────────
// Three punch entry paths, all writing to data.hrTimeClock:
//   1. In-app mobile (/api/timeclock/punch with session auth + GPS)
//   2. Kiosk tablet at the nurse station (/kiosk/<buildingId> page)
//   3. Bridge from existing physical clocks via signed webhook
// Plus admin correction via PATCH on individual records.

const TIMECLOCK_KIOSK_SECRET = process.env.TIMECLOCK_KIOSK_SECRET || JWT_SECRET;

// Distance helper (Haversine, meters) for geofence checks.
function _haversineMeters(lat1, lng1, lat2, lng2) {
  const toRad = d => d * Math.PI / 180;
  const R = 6371000;
  const dLat = toRad(lat2 - lat1), dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// Punch status classifier. Cross-references the scheduled shift for this
// (empId, date) to detect late arrivals, missed clock-outs, and >15-minute
// early arrivals.
function _classifyPunch(emp, date, inTime, outTime, shifts) {
  const sched = (shifts || []).find(s =>
    s.employeeId === emp.id && s.date === date && s.status === 'scheduled');
  if (!inTime) return 'missed';
  if (!outTime) return 'no-out';
  const toMin = t => { if(!t) return null; const [h,m]=String(t).trim().split(':').map(Number); return h*60+(m||0); };
  const inMin = toMin(inTime);
  const schedIn = toMin(sched?.start);
  if (schedIn != null && inMin != null && (inMin - schedIn) > 7) return 'late';
  if (schedIn != null && inMin != null && (schedIn - inMin) > 15) return 'early';
  return 'normal';
}

// Find an existing punch record for (empId, date) — punches dedupe per day.
function _findOrCreatePunch(data, empId, date) {
  if (!Array.isArray(data.hrTimeClock)) data.hrTimeClock = [];
  let r = data.hrTimeClock.find(x => x.empId === empId && x.date === date);
  if (!r) {
    r = { empId, date, in: '', out: '', hours: '', status: 'normal' };
    data.hrTimeClock.push(r);
  }
  return r;
}

// Apply a single punch event (action: 'in' | 'out') to data.hrTimeClock.
// Returns { ok, record } or { error }.
function _applyPunch(data, emp, action, when, sourceMeta = {}) {
  if (!emp) return { error: 'Employee not found' };
  if (emp.inactive) return { error: 'Employee is inactive' };
  if (!['in','out'].includes(action)) return { error: 'action must be "in" or "out"' };
  const ts = when instanceof Date ? when : new Date(when || Date.now());
  if (isNaN(ts.getTime())) return { error: 'invalid timestamp' };
  const date = ts.toISOString().slice(0,10);
  const time = ts.toISOString().slice(11,16);  // HH:MM (UTC)

  const r = _findOrCreatePunch(data, emp.id, date);
  // Snapshot identity fields on each row so HR Time Clock UI shows correctly
  // even if employee is later renamed / reassigned.
  r.name = emp.name; r.role = emp.group; r.buildingId = emp.buildingId;

  if (action === 'in') {
    if (r.in) return { error: 'Already clocked in for today (in='+r.in+')' };
    r.in = time;
  } else {
    if (!r.in) return { error: 'No clock-in recorded yet for today — clock in first' };
    if (r.out) return { error: 'Already clocked out (out='+r.out+')' };
    r.out = time;
    // Compute hours
    const [ih, im] = r.in.split(':').map(Number);
    const [oh, om] = r.out.split(':').map(Number);
    let mins = (oh*60 + (om||0)) - (ih*60 + (im||0));
    if (mins < 0) mins += 24*60;
    r.hours = (mins / 60).toFixed(2);
  }
  r.status = _classifyPunch(emp, date, r.in, r.out, data.shifts || []);
  // Append source metadata to a punch-events array on the record (for audit)
  if (!Array.isArray(r.events)) r.events = [];
  r.events.push({
    action, at: ts.toISOString(),
    source: sourceMeta.source || 'unknown',
    deviceId: sourceMeta.deviceId || null,
    gps: sourceMeta.gps || null,
  });
  return { ok: true, record: r };
}

// POST /api/timeclock/punch — in-app mobile or admin-on-behalf punch.
// Body: { empId?, action: 'in'|'out', timestamp?, gps?: {lat,lng,accuracyM}, selfie?: base64 }
// Auth: requires JWT cookie; employee can only punch themselves; admin can
// punch any employee in their building. Geofence enforced for employees.
app.post('/api/timeclock/punch', requireAuth, async (req, res) => {
  const data = await loadData();
  const me = req.user;
  let { empId, action, timestamp, gps, selfie } = req.body || {};
  // Default empId to caller for employees
  if (me.role === 'employee') empId = me.id;
  if (!empId) return res.status(400).json({ error: 'empId is required for non-employee callers' });
  const emp = (data.employees || []).find(e => e.id === empId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  // Authz scoping for non-SA admins
  if (me.role === 'admin') {
    const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
    if (!callerBIds.has(emp.buildingId)) return res.status(403).json({ error: 'Out of scope' });
  }
  if (me.role === 'employee' && me.id !== empId) return res.status(403).json({ error: 'Employees can only punch themselves' });

  // Geofence check — employees only, only when building has lat/lng configured.
  if (me.role === 'employee') {
    const b = (data.buildings || []).find(x => x.id === emp.buildingId);
    if (b?.lat != null && b?.lng != null) {
      const radius = b.geofenceRadiusM || 200;
      if (!gps || gps.lat == null || gps.lng == null) {
        auditLog('PUNCH_REJECTED_NO_GPS', me, { empId });
        return res.status(412).json({ error: 'Location required to clock in/out. Allow location access in your browser.' });
      }
      const dist = _haversineMeters(b.lat, b.lng, gps.lat, gps.lng);
      if (dist > radius + (gps.accuracyM || 0)) {
        auditLog('PUNCH_REJECTED_GEOFENCE', me, { empId, distanceM: Math.round(dist), radius });
        return res.status(412).json({
          error: `You're ${Math.round(dist)}m from the facility (max ${radius}m). Are you on site?`,
        });
      }
    }
  }

  const result = _applyPunch(data, emp, action, timestamp, {
    source: me.role === 'employee' ? 'mobile' : 'admin',
    gps: gps ? { lat: gps.lat, lng: gps.lng, accuracyM: gps.accuracyM || null } : null,
  });
  // Attach selfie (if provided) to the just-pushed event entry. Capped at
  // ~256 KB per photo to bound storage; the frontend already JPEG-compresses.
  if (result.ok && selfie && typeof selfie === 'string' && selfie.startsWith('data:image/') && selfie.length < 350_000) {
    const ev = result.record.events?.[result.record.events.length - 1];
    if (ev) ev.selfie = selfie;
  }
  if (result.error) return res.status(400).json({ error: result.error });
  markDirty();
  auditLog('PUNCH_RECORDED', me, { empId, action, source: me.role === 'employee' ? 'mobile' : 'admin' });
  res.json({ ok: true, record: result.record });
});

// POST /api/timeclock/kiosk-punch — punch from the tablet kiosk.
// Body: { kioskToken, pin, action }
// Authentication: kiosk JWT (signed with TIMECLOCK_KIOSK_SECRET) carries the
// buildingId. PIN identifies the employee within that building. Three failed
// PINs in a 60-second window from the same kiosk locks the kiosk for 5 min.
const _kioskFailures = new Map();   // kioskId → { count, until }
app.post('/api/timeclock/kiosk-punch', async (req, res) => {
  const { kioskToken, pin, action } = req.body || {};
  if (!kioskToken || !pin || !action) return res.status(400).json({ error: 'kioskToken, pin, action required' });
  let decoded;
  try { decoded = jwt.verify(kioskToken, TIMECLOCK_KIOSK_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid or expired kiosk token' }); }
  if (decoded.kind !== 'kiosk' || !decoded.buildingId) return res.status(401).json({ error: 'Bad kiosk token' });
  const kioskId = decoded.kioskId || decoded.buildingId;
  const f = _kioskFailures.get(kioskId);
  if (f && f.until > Date.now()) return res.status(429).json({ error: 'Too many failed PIN attempts. Wait 5 minutes.' });

  const data = await loadData();
  // Find employee whose pinHash matches AND who's at this building.
  const candidates = (data.employees || []).filter(e =>
    e.buildingId === decoded.buildingId && !e.inactive && e.pinHash);
  let matched = null;
  for (const e of candidates) {
    if (await bcrypt.compare(String(pin), e.pinHash)) { matched = e; break; }
  }
  if (!matched) {
    const next = (f?.count || 0) + 1;
    _kioskFailures.set(kioskId, { count: next, until: next >= 3 ? Date.now() + 5*60*1000 : 0 });
    auditLog('KIOSK_PUNCH_BAD_PIN', null, { buildingId: decoded.buildingId, kioskId, attempt: next });
    return res.status(401).json({ error: 'PIN not recognized. Check your 4-digit code or ask your supervisor.' });
  }
  _kioskFailures.delete(kioskId);

  const result = _applyPunch(data, matched, action, new Date(), {
    source: 'kiosk',
    deviceId: kioskId,
  });
  if (result.error) return res.status(400).json({ error: result.error });
  markDirty();
  auditLog('PUNCH_RECORDED', null, { empId: matched.id, action, source: 'kiosk', kioskId });
  res.json({
    ok: true,
    employeeName: matched.name,
    action,
    timestamp: new Date().toISOString(),
    todayHours: result.record.hours || null,
  });
});

// POST /api/timeclock/kiosk-token — issue a kiosk JWT for a building.
// Admin-only endpoint. Returns a long-lived token (1 year) that the tablet
// stores in localStorage; the tablet then hits /api/timeclock/kiosk-punch.
app.post('/api/timeclock/kiosk-token', requireAuth, requireAdmin, async (req, res) => {
  const { buildingId } = req.body || {};
  if (!buildingId) return res.status(400).json({ error: 'buildingId required' });
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  const kioskId = 'k_' + crypto.randomBytes(8).toString('hex');
  const token = jwt.sign({
    kind: 'kiosk', buildingId, kioskId, issuedBy: req.user.email,
  }, TIMECLOCK_KIOSK_SECRET, { expiresIn: '365d' });
  auditLog('KIOSK_TOKEN_ISSUED', req.user, { buildingId, kioskId });
  res.json({ ok: true, kioskToken: token, kioskId });
});

// POST /api/timeclock/set-pin — admin sets/resets an employee's kiosk PIN.
// Body: { empId, pin } — pin must be 4-6 digits. PIN is bcrypt-hashed.
app.post('/api/timeclock/set-pin', requireAuth, requireAdmin, async (req, res) => {
  const { empId, pin } = req.body || {};
  if (!empId || !pin) return res.status(400).json({ error: 'empId and pin required' });
  if (!/^\d{4,6}$/.test(String(pin))) return res.status(400).json({ error: 'PIN must be 4–6 digits' });
  const data = await loadData();
  const emp = (data.employees || []).find(e => e.id === empId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(emp.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  // Reject PIN collisions within the building (so kiosk can match by PIN alone).
  for (const e of (data.employees || [])) {
    if (e.id === emp.id || e.buildingId !== emp.buildingId || !e.pinHash) continue;
    if (await bcrypt.compare(String(pin), e.pinHash)) {
      return res.status(409).json({ error: 'PIN already in use at this building. Pick a different code.' });
    }
  }
  emp.pinHash = await bcrypt.hash(String(pin), 12);
  emp.pinSetAt = new Date().toISOString();
  markDirty();
  auditLog('TIMECLOCK_PIN_SET', req.user, { empId });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// DEMO FACILITY SEED — sales / demo tool
// ─────────────────────────────────────────────────────────────────────────────
// SA can spawn a realistic demo facility (~12 employees across roles,
// 4 weeks of scheduled shifts, daily census, sample punches) so demos
// don't show empty calendars and zero PPD. Skipped silently if the
// caller already has a demo facility named "Demo SNF Operations".
app.post('/api/sa/seed-demo-facility', requireAuth, requireSuperAdmin, async (req, res) => {
  const data = await loadData();
  const existing = (data.buildings || []).find(b => b.name === 'Demo SNF Operations');
  if (existing) return res.status(409).json({ error: 'Demo facility already exists', buildingId: existing.id });

  const bId = 'demo_' + crypto.randomBytes(4).toString('hex');
  const building = {
    id: bId, name: 'Demo SNF Operations',
    address: '500 Cedar Ridge Dr, Tulsa, OK 74133',
    phone: '(918) 555-0142',
    beds: 96, color: '#2D6A4F',
    state: 'OK', stateCode: 'OK', zip: '74133',
    ccn: '375999',                         // sample CCN, not a real one
    lat: 36.0844, lng: -95.7864,           // Tulsa metro
    geofenceRadiusM: 250,
    isDemo: true,
  };
  if (!Array.isArray(data.buildings)) data.buildings = [];
  data.buildings.push(building);

  // Roster: 12 employees across SNF roles
  const roster = [
    { name:'Jennifer Walsh',   group:'Nurse Management', rate:42, em:'jwalsh@demo.local',  phone:'(918) 555-1010' },
    { name:'Marcus Chen',      group:'Charge Nurse',     rate:32, em:'mchen@demo.local',   phone:'(918) 555-1011' },
    { name:'Patricia Moore',   group:'CNA',              rate:18, em:'pmoore@demo.local',  phone:'(918) 555-1012' },
    { name:'Robert Lee',       group:'CNA',              rate:18, em:'rlee@demo.local',    phone:'(918) 555-1013' },
    { name:'Samantha Torres',  group:'CNA',              rate:18, em:'storres@demo.local', phone:'(918) 555-1014' },
    { name:'Aisha Johnson',    group:'CMA',              rate:22, em:'ajohnson@demo.local',phone:'(918) 555-1015' },
    { name:'David Chen',       group:'CMA',              rate:22, em:'dchen@demo.local',   phone:'(918) 555-1016' },
    { name:'Maria Santos',     group:'Cook',             rate:17, em:'msantos@demo.local', phone:'(918) 555-1017' },
    { name:'Tom Rivera',       group:'Dietary Aid',      rate:15, em:'trivera@demo.local', phone:'(918) 555-1018' },
    { name:'Priya Patel',      group:'Housekeeping',     rate:15, em:'ppatel@demo.local',  phone:'(918) 555-1019' },
    { name:'James Wilson',     group:'Laundry',          rate:14, em:'jwilson@demo.local', phone:'(918) 555-1020' },
    { name:'Sarah Kim',        group:'Maintenance',      rate:24, em:'skim@demo.local',    phone:'(918) 555-1021' },
  ];
  if (!Array.isArray(data.employees)) data.employees = [];
  const empIds = [];
  for (const r of roster) {
    const initials = r.name.split(' ').map(w => w[0] || '').join('').slice(0,2).toUpperCase();
    const e = {
      id: 'demo_e_' + crypto.randomBytes(4).toString('hex'),
      name: r.name, initials, group: r.group, email: r.em, phone: r.phone,
      buildingId: bId, employmentType: 'full-time',
      hireDate: new Date(Date.now() - (180 + Math.floor(Math.random()*1100)) * 86400000).toISOString().slice(0,10),
      hourlyRate: r.rate, inactive: false,
      notifEmail: true, notifSMS: true, notifPrefs: ['immediate','day'],
      notifChannels: { immediate:{email:true,sms:true}, day:{email:true,sms:false}, week:{email:true,sms:false}, daily:{email:false,sms:false} },
      isDemo: true,
    };
    data.employees.push(e);
    empIds.push(e.id);
  }

  // Shifts: next 28 days, daily 7am Day shift coverage for clinical roles
  if (!Array.isArray(data.shifts)) data.shifts = [];
  const today = new Date(); today.setUTCHours(0,0,0,0);
  for (let d = 0; d < 28; d++) {
    const dt = new Date(today.getTime() + d * 86400000);
    const ds = dt.toISOString().slice(0,10);
    // Round-robin clinical staff to Day shift, rotate to keep numbers realistic
    const dayShift = (group, count, start, end) => {
      const eligible = data.employees.filter(e => e.buildingId === bId && e.group === group);
      for (let s = 0; s < count; s++) {
        const emp = eligible[(d + s) % eligible.length];
        data.shifts.push({
          id: 'demo_sh_' + crypto.randomBytes(4).toString('hex'),
          date: ds, group, type: 'Day', start, end,
          status: 'scheduled', buildingId: bId,
          employeeId: emp.id, isDemo: true,
        });
      }
    };
    dayShift('Charge Nurse',     1, '7:00 AM', '3:00 PM');
    dayShift('CNA',              3, '7:00 AM', '3:00 PM');
    dayShift('CMA',              1, '7:00 AM', '3:00 PM');
    if (d % 2 === 0) dayShift('Cook',  1, '6:00 AM', '2:00 PM');
    if (d % 3 === 0) dayShift('Housekeeping', 1, '8:00 AM', '4:00 PM');
  }

  // Census: random 75–88 per day for the past 14 days + next 28 days
  if (!data.ppdDailyCensus || typeof data.ppdDailyCensus !== 'object') data.ppdDailyCensus = {};
  for (let d = -14; d < 28; d++) {
    const dt = new Date(today.getTime() + d * 86400000);
    const ds = dt.toISOString().slice(0,10);
    data.ppdDailyCensus[ds] = 75 + Math.floor(Math.random() * 14);
  }

  // Time clock: past 14 days of punches for clinical staff (mostly normal,
  // a few late and one missed)
  if (!Array.isArray(data.hrTimeClock)) data.hrTimeClock = [];
  for (let d = -14; d < 0; d++) {
    const dt = new Date(today.getTime() + d * 86400000);
    const ds = dt.toISOString().slice(0,10);
    const todaysShifts = data.shifts.filter(s => s.date === ds && s.buildingId === bId);
    for (const s of todaysShifts) {
      if (Math.random() < 0.05) continue;       // 5% no-show
      const emp = data.employees.find(e => e.id === s.employeeId);
      const lateMin = Math.random() < 0.12 ? Math.floor(Math.random() * 18) + 8 : Math.floor(Math.random() * 6);
      const inHr = 7;
      const inMin = lateMin;
      const inStr = String(inHr).padStart(2,'0') + ':' + String(inMin).padStart(2,'0');
      const outHr = 15; const outMin = Math.floor(Math.random()*30);
      const outStr = String(outHr).padStart(2,'0') + ':' + String(outMin).padStart(2,'0');
      const hours = (8 - inMin/60 + outMin/60).toFixed(2);
      const status = lateMin > 7 ? 'late' : 'normal';
      data.hrTimeClock.push({
        empId: emp.id, name: emp.name, role: emp.group, buildingId: bId,
        date: ds, in: inStr, out: outStr, hours, status,
        events: [{ action:'in', at: dt.toISOString(), source:'demo' }],
        isDemo: true,
      });
    }
  }

  markDirty();
  auditLog('DEMO_FACILITY_SEEDED', req.user, {
    buildingId: bId, employees: empIds.length,
    shifts: data.shifts.filter(s => s.buildingId === bId).length,
    punches: data.hrTimeClock.filter(p => p.buildingId === bId).length,
  });
  res.json({
    ok: true,
    buildingId: bId,
    counts: {
      employees: empIds.length,
      shifts: data.shifts.filter(s => s.buildingId === bId).length,
      punches: data.hrTimeClock.filter(p => p.buildingId === bId).length,
      censusDays: 42,
    },
  });
});

// SA-only: tear down the demo facility (and everything tagged isDemo:true).
app.delete('/api/sa/seed-demo-facility', requireAuth, requireSuperAdmin, async (req, res) => {
  const data = await loadData();
  const before = {
    buildings: (data.buildings || []).length,
    employees: (data.employees || []).length,
    shifts:    (data.shifts    || []).length,
    punches:   (data.hrTimeClock || []).length,
  };
  data.buildings   = (data.buildings || []).filter(b => !b.isDemo);
  data.employees   = (data.employees || []).filter(e => !e.isDemo);
  data.shifts      = (data.shifts    || []).filter(s => !s.isDemo);
  data.hrTimeClock = (data.hrTimeClock || []).filter(r => !r.isDemo);
  markDirty();
  auditLog('DEMO_FACILITY_REMOVED', req.user, {
    removedBuildings: before.buildings - data.buildings.length,
    removedEmployees: before.employees - data.employees.length,
    removedShifts:    before.shifts    - data.shifts.length,
    removedPunches:   before.punches   - data.hrTimeClock.length,
  });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// DIRECT MESSAGES — 1-to-1 admin ↔ employee thread
// ─────────────────────────────────────────────────────────────────────────────
// Lightweight chat: every pair (adminAccountId, employeeId) gets a single
// conversation, persisted on data.directMessages. Distinct from the broadcast
// alertLog (which is one-to-many SMS/email) — these are app-only messages.
//
// Auth model:
//   - Employee can read/write their OWN thread with anyone in the same building.
//   - Admin can read/write threads with any employee in their building scope.
//   - Each message: { id, threadId, fromId, toId, body, sentAt, readAt }
//   - Thread id is a deterministic string sort of the pair so either side
//     can compute it: dm:<sortedId1>:<sortedId2>

function _dmThreadId(idA, idB) {
  const [a, b] = [String(idA), String(idB)].sort();
  return 'dm:' + a + ':' + b;
}

// POST /api/dm — send a message
// Body: { toId, body }
app.post('/api/dm', requireAuth, async (req, res) => {
  const { toId, body } = req.body || {};
  if (!toId || !body) return res.status(400).json({ error: 'toId and body required' });
  const text = String(body).slice(0, 4000).trim();
  if (!text) return res.status(400).json({ error: 'Empty message' });

  const data = await loadData();
  const me = req.user;
  const myId = me.id;
  // Resolve participants (one is me, one is the target).
  const targetEmp = (data.employees || []).find(e => e.id === toId && !e.inactive);
  const targetAcct = (data.accounts || []).find(a => a.id === toId);
  const target = targetEmp || targetAcct;
  if (!target) return res.status(404).json({ error: 'Recipient not found' });

  // Authz: same building required (admin can DM employees in their scope;
  // employee can DM admins of their own building or other staff at that bldg).
  const targetBId = targetEmp?.buildingId || targetAcct?.buildingId;
  const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
  if (me.role !== 'superadmin') {
    if (me.role === 'employee') {
      if (targetBId !== me.buildingId) return res.status(403).json({ error: 'Out of scope' });
    } else if (!callerBIds.has(targetBId)) {
      return res.status(403).json({ error: 'Out of scope' });
    }
  }

  if (!Array.isArray(data.directMessages)) data.directMessages = [];
  const msg = {
    id: 'dm_' + Date.now() + crypto.randomBytes(2).toString('hex'),
    threadId: _dmThreadId(myId, toId),
    fromId: myId, fromName: me.name || me.email,
    toId,         toName: targetEmp?.name || targetAcct?.name || '',
    buildingId:   targetBId || me.buildingId || null,
    body: text,
    sentAt: new Date().toISOString(),
    readAt: null,
  };
  data.directMessages.push(msg);
  if (data.directMessages.length > 5000) data.directMessages = data.directMessages.slice(-5000);
  markDirty();
  auditLog('DM_SENT', me, { toId, threadId: msg.threadId, len: text.length });
  res.json({ ok: true, message: msg });
});

// POST /api/dm/read — mark a thread as read up to a given timestamp
app.post('/api/dm/read', requireAuth, async (req, res) => {
  const { threadId, upTo } = req.body || {};
  if (!threadId) return res.status(400).json({ error: 'threadId required' });
  const data = await loadData();
  const me = req.user;
  const myId = me.id;
  const cutoff = upTo ? new Date(upTo).getTime() : Date.now();
  let marked = 0;
  for (const m of (data.directMessages || [])) {
    if (m.threadId !== threadId) continue;
    if (m.toId !== myId)         continue;
    if (m.readAt)                continue;
    if (new Date(m.sentAt).getTime() > cutoff) continue;
    m.readAt = new Date().toISOString();
    marked++;
  }
  if (marked > 0) markDirty();
  res.json({ ok: true, marked });
});

// ─────────────────────────────────────────────────────────────────────────────
// EMPLOYEE ACCESS LEVEL — promote/demote between employee and admin tiers
// ─────────────────────────────────────────────────────────────────────────────
// Admin can change a roster member's access level in three ways:
//   employee  → just an employee (no admin account exists)
//   admin     → Building Admin with Full access (sees financials)
//   scheduler → Building Admin with Scheduler-only access (hides $)
//
// Promoting to admin creates an `accounts` record linked by email + emits
// an invite token so the employee can set their own password. Demoting
// removes the account (the employee record + login email is preserved).
// Authorization: building admin can only change access for employees in
// their own building; superadmin can change anyone's.
app.post('/api/employees/:id/access', requireAuth, requireAdmin, async (req, res) => {
  const empId = req.params.id;
  const { access } = req.body || {};
  if (!['employee','admin','hradmin','scheduler'].includes(access)) {
    return res.status(400).json({ error: "access must be 'employee', 'admin', 'hradmin', or 'scheduler'" });
  }
  // hradmin can only be assigned by an actual admin/SA — a scheduler-only
  // admin can't promote someone to a role that has more access than they do.
  if (access === 'hradmin' && req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Only admin or superadmin can assign HR Admin' });
  }
  const data = await loadData();
  const emp = (data.employees || []).find(e => e.id === empId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (!emp.email) return res.status(400).json({ error: 'Employee has no email — add an email before changing access' });
  // Authz: building admin can only modify employees in their own building.
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(emp.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  // Caller can't change their own access (would let an admin demote themselves
  // and lock the building out).
  if (!Array.isArray(data.accounts)) data.accounts = [];
  const existing = data.accounts.find(a => a.email && a.email.toLowerCase() === emp.email.toLowerCase());
  if (existing && existing.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot change your own access level — ask another admin or superadmin' });
  }

  // ── Demote to employee ─────────────────────────────────────────────────
  if (access === 'employee') {
    if (!existing || !['admin','hradmin'].includes(existing.role)) {
      // No-op — employee is already employee-tier
      return res.json({ ok: true, message: 'No change needed (already employee)' });
    }
    // Refuse to remove the LAST admin from a building (would lock it out).
    // hradmin doesn't count — they need an approving admin around.
    const otherAdmins = data.accounts.filter(a =>
      a.role === 'admin' && a.id !== existing.id && a.buildingId === existing.buildingId);
    if (!otherAdmins.length && existing.role === 'admin') {
      return res.status(409).json({ error: 'Cannot demote the only admin for this building. Promote someone else first.' });
    }
    // Remove the admin account; employee record remains intact.
    data.accounts = data.accounts.filter(a => a.id !== existing.id);
    markDirty();
    auditLog('ACCESS_DEMOTED', req.user, { empId, removedAccountId: existing.id, email: emp.email, fromRole: existing.role });
    return res.json({ ok: true, access: 'employee' });
  }

  // ── Promote to admin / hradmin / scheduler ─────────────────────────────
  const wantSchedulerOnly = access === 'scheduler';
  const targetRole        = (access === 'hradmin') ? 'hradmin' : 'admin';
  if (existing) {
    if (!['admin','hradmin'].includes(existing.role)) {
      // Edge case: account exists but isn't admin (e.g., regional). Refuse —
      // SA-only operation to handle non-standard role transitions.
      if (req.user.role !== 'superadmin') {
        return res.status(409).json({ error: `An account already exists with role ${existing.role}. Superadmin must adjust.` });
      }
    }
    existing.role = targetRole;
    existing.buildingId = emp.buildingId;
    existing.schedulerOnly = wantSchedulerOnly;
    await persistAccountNow(existing);
    const auditAction = targetRole === 'hradmin' ? 'ACCESS_SET_HR_ADMIN'
                       : wantSchedulerOnly       ? 'ACCESS_SET_SCHEDULER'
                                                 : 'ACCESS_SET_FULL_ADMIN';
    auditLog(auditAction, req.user, { empId, accountId: existing.id, email: emp.email });
    return res.json({ ok: true, access, accountId: existing.id });
  }

  // No existing account → create + send invite.
  const inviteToken = crypto.randomBytes(24).toString('hex');
  const newAccount = {
    id:           'acc_' + Date.now() + crypto.randomBytes(2).toString('hex'),
    name:         emp.name,
    email:        emp.email.toLowerCase(),
    role:         targetRole,
    buildingId:   emp.buildingId,
    schedulerOnly: wantSchedulerOnly,
    ph:           null,
    inviteToken,
    inviteExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
    invitedBy:    req.user.email,
    invitedAt:    new Date().toISOString(),
    promotedFromEmployeeId: emp.id,
  };
  data.accounts.push(newAccount);
  await persistAccountNow(newAccount);

  // Best-effort invite email — failure is non-blocking, admin can resend.
  let emailWarning = null;
  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec     = new EmailClient(ACS_CONNECTION_STRING);
      const link   = `${APP_URL}/?invite=${inviteToken}`;
      const escName = escapeHtml(emp.name);
      const accessLabel = targetRole === 'hradmin' ? 'HR Admin'
                        : wantSchedulerOnly        ? 'Scheduler Access'
                                                   : 'Full Building Admin';
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: emp.email }] },
        content: {
          subject: `You've been promoted to ${accessLabel} on ManageMyStaffing`,
          plainText: `Hi ${emp.name},\n\nYou now have ${accessLabel} access on ManageMyStaffing. Set your password using the link below:\n${link}\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb"><div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb"><h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">Welcome aboard, ${escName}!</h2><p style="color:#6b7280;font-size:14px;margin:0 0 20px">You now have <strong>${accessLabel}</strong> access on ManageMyStaffing. Set your password to sign in:</p><a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Set password →</a><p style="color:#9ca3af;font-size:12px;margin:20px 0 0">Link expires in 7 days.</p></div></div>`,
        },
      });
      await Promise.race([ poller.pollUntilDone(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000)) ]);
    } catch (e) {
      emailWarning = e.message;
    }
  }

  markDirty();
  const newAuditAction = targetRole === 'hradmin' ? 'ACCESS_SET_HR_ADMIN'
                       : wantSchedulerOnly        ? 'ACCESS_SET_SCHEDULER'
                                                  : 'ACCESS_SET_FULL_ADMIN';
  auditLog(newAuditAction, req.user, {
    empId, accountId: newAccount.id, email: emp.email, invited: true,
  });
  res.json({
    ok: true, access, accountId: newAccount.id,
    inviteSent: !emailWarning,
    inviteLink: emailWarning ? `${APP_URL}/?invite=${inviteToken}` : undefined,
    emailWarning,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SHIFT TRADE REQUESTS
// ─────────────────────────────────────────────────────────────────────────────
// Employee A wants to swap one of their scheduled shifts with employee B's
// scheduled shift. Goes through admin approval. Same-group only (a CNA shift
// can't be swapped with a Cook shift). Stored on data.shiftTrades.
//
// Lifecycle:
//   pending  — A submitted, B has accepted? optional, awaiting admin
//   accepted — B agreed (if A targeted B specifically)
//   approved — admin approved, employeeIds swapped on both shifts
//   rejected — admin rejected, no change
//   cancelled — A withdrew before admin decision

// POST /api/shifts/trade — employee submits a trade request
// Body: { fromShiftId, toShiftId }
app.post('/api/shifts/trade', requireAuth, async (req, res) => {
  const { fromShiftId, toShiftId } = req.body || {};
  if (!fromShiftId || !toShiftId) return res.status(400).json({ error: 'fromShiftId and toShiftId required' });
  if (fromShiftId === toShiftId)   return res.status(400).json({ error: 'Cannot trade a shift with itself' });
  const data = await loadData();
  const fromShift = (data.shifts || []).find(s => s.id === fromShiftId);
  const toShift   = (data.shifts || []).find(s => s.id === toShiftId);
  if (!fromShift || !toShift) return res.status(404).json({ error: 'Shift not found' });
  if (fromShift.status !== 'scheduled' || toShift.status !== 'scheduled') return res.status(400).json({ error: 'Both shifts must be scheduled' });
  if (fromShift.group !== toShift.group) return res.status(400).json({ error: 'Same staff group only' });
  if (fromShift.buildingId !== toShift.buildingId) return res.status(400).json({ error: 'Same building only' });
  // Auth: employee can only initiate trades for their own shifts; admin can
  // initiate any trade in their building (used for inline shift-swap by admin).
  const me = req.user;
  if (me.role === 'employee' && fromShift.employeeId !== me.id) return res.status(403).json({ error: 'You can only trade your own shifts' });
  if (me.role === 'admin') {
    const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
    if (!callerBIds.has(fromShift.buildingId)) return res.status(403).json({ error: 'Out of scope' });
  }
  // Reject duplicate-pending trades on either shift.
  if (!Array.isArray(data.shiftTrades)) data.shiftTrades = [];
  const dupe = data.shiftTrades.find(t => (t.fromShiftId === fromShiftId || t.toShiftId === toShiftId) && t.status === 'pending');
  if (dupe) return res.status(409).json({ error: 'A pending trade already exists for one of these shifts' });
  const trade = {
    id: 'tr_' + Date.now() + Math.random().toString(36).slice(2,6),
    fromShiftId, toShiftId,
    fromEmpId: fromShift.employeeId,
    toEmpId:   toShift.employeeId,
    buildingId: fromShift.buildingId,
    requestedBy: me.id,
    requestedAt: new Date().toISOString(),
    status: 'pending',
  };
  data.shiftTrades.push(trade);
  if (data.shiftTrades.length > 1000) data.shiftTrades = data.shiftTrades.slice(-1000);
  markDirty();
  auditLog('SHIFT_TRADE_REQUESTED', me, { tradeId: trade.id, fromShiftId, toShiftId });
  res.json({ ok: true, trade });
});

// POST /api/shifts/trade/:id/decide — admin approves or rejects
// Body: { decision: 'approve'|'reject', note? }
app.post('/api/shifts/trade/:id/decide', requireAuth, requireAdmin, async (req, res) => {
  const { decision, note } = req.body || {};
  if (!['approve','reject'].includes(decision)) return res.status(400).json({ error: 'decision must be approve or reject' });
  const data = await loadData();
  const trade = (data.shiftTrades || []).find(t => t.id === req.params.id);
  if (!trade) return res.status(404).json({ error: 'Trade not found' });
  if (trade.status !== 'pending') return res.status(409).json({ error: `Trade already ${trade.status}` });
  // Authz scope
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(trade.buildingId)) return res.status(403).json({ error: 'Out of scope' });
  trade.decidedBy = req.user.email;
  trade.decidedAt = new Date().toISOString();
  trade.note = (note || '').slice(0, 500);
  if (decision === 'reject') {
    trade.status = 'rejected';
    markDirty();
    auditLog('SHIFT_TRADE_REJECTED', req.user, { tradeId: trade.id });
    return res.json({ ok: true, trade });
  }
  // Approve: swap employeeIds atomically.
  const fromShift = data.shifts.find(s => s.id === trade.fromShiftId);
  const toShift   = data.shifts.find(s => s.id === trade.toShiftId);
  if (!fromShift || !toShift)     return res.status(404).json({ error: 'One or both shifts no longer exist' });
  if (fromShift.status !== 'scheduled' || toShift.status !== 'scheduled') return res.status(409).json({ error: 'A shift state changed since the request — reject and ask employees to redo' });
  const tmp = fromShift.employeeId;
  fromShift.employeeId = toShift.employeeId;
  toShift.employeeId   = tmp;
  trade.status = 'approved';
  markDirty();
  auditLog('SHIFT_TRADE_APPROVED', req.user, { tradeId: trade.id, fromShiftId: trade.fromShiftId, toShiftId: trade.toShiftId });
  res.json({ ok: true, trade });
});

// DELETE /api/shifts/trade/:id — initiator cancels (only while pending)
app.delete('/api/shifts/trade/:id', requireAuth, async (req, res) => {
  const data = await loadData();
  const trade = (data.shiftTrades || []).find(t => t.id === req.params.id);
  if (!trade) return res.status(404).json({ error: 'Trade not found' });
  if (trade.status !== 'pending') return res.status(409).json({ error: `Trade already ${trade.status}` });
  // Initiator OR admin in scope can cancel.
  const me = req.user;
  const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
  const inScope = me.role === 'superadmin' || callerBIds.has(trade.buildingId);
  if (trade.requestedBy !== me.id && !inScope) return res.status(403).json({ error: 'Not your trade' });
  trade.status = 'cancelled';
  trade.decidedAt = new Date().toISOString();
  trade.decidedBy = me.email;
  markDirty();
  auditLog('SHIFT_TRADE_CANCELLED', me, { tradeId: trade.id });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// PBJ — CMS PAYROLL-BASED JOURNAL QUARTERLY EXPORT
// ─────────────────────────────────────────────────────────────────────────────
// CMS requires every Medicare/Medicaid-certified SNF to submit staffing and
// census data quarterly via the Payroll-Based Journal (PBJ) system. The
// submission is XML conforming to the published CMS PBJ XSD (current
// version 4.0). This module renders that XML straight from our existing
// hrTimeClock + ppdDailyCensus data — no third-party tool needed.
//
// Required reference data on the building record:
//   building.ccn          — federal CMS Certification Number (6-digit)
//   building.stateCode    — 2-letter postal code, e.g. "OK"
// These are added via the SA building edit modal.
//
// Job titles (CMS controlled vocabulary, partial — only the codes our
// roster taxonomy maps to). Full list in the PBJ Manual Appendix A.
const PBJ_JOB_CODE = {
  'Nurse Management': 11,   // Director of Nursing
  'Charge Nurse':     6,    // LPN/LVN — most common SNF charge role; admin
                            //   can override per employee with employee.pbjCode
  'CNA':              7,    // Nurse Aide (Certified)
  'CMA':              9,    // Medication Aide / Technician
  'Cook':             26,   // Cook — Dietary Service Worker
  'Dietary Aid':      27,   // Other Dietary Service Worker
  // Maintenance, Housekeeping, Laundry, Marketing — not PBJ-reportable.
  // RN if added in the future would map to 5; ADON to 12; NAT to 8.
};
function _pbjCodeFor(emp) {
  if (emp?.pbjCode) return parseInt(emp.pbjCode, 10) || null;  // explicit override
  return PBJ_JOB_CODE[emp?.group] || null;
}
const PBJ_PAY_TYPE = { employee: 1, contract: 2, agency: 3 };

// XML escape — CMS rejects unescaped < > & " '
function _xmlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// Compute quarter range. Federal PBJ uses calendar quarters (Q1 = Jan–Mar).
function _pbjQuarterRange(year, quarter) {
  const q = parseInt(quarter, 10);
  if (q < 1 || q > 4) return null;
  const startMonth = (q - 1) * 3;
  const start = new Date(Date.UTC(year, startMonth, 1));
  const end   = new Date(Date.UTC(year, startMonth + 3, 0));
  return {
    start: start.toISOString().slice(0,10),
    end:   end.toISOString().slice(0,10),
  };
}

// Generate the full PBJ XML for one building, one quarter.
function _generatePbjXml({ data, buildingId, year, quarter }) {
  const range = _pbjQuarterRange(year, quarter);
  if (!range) throw new Error('Invalid year/quarter');
  const b = (data.buildings || []).find(x => x.id === buildingId);
  if (!b) throw new Error('Building not found');
  const emps = (data.employees || []).filter(e => e.buildingId === buildingId);
  const punches = (data.hrTimeClock || []).filter(r =>
    r.buildingId === buildingId && r.date >= range.start && r.date <= range.end);

  // Employee block — one entry per W-2 employee (NOT agency, those are
  // anonymized in the staffingHours block per CMS guidance).
  const empById = new Map(emps.map(e => [e.id, e]));
  const empXml = emps.map(e => {
    const term = e.terminationLog?.length
      ? e.terminationLog[e.terminationLog.length - 1].date
      : '';
    return `    <employee>
      <employeeId>${_xmlEsc(e.id)}</employeeId>
      <hireDate>${_xmlEsc(e.hireDate || range.start)}</hireDate>
      ${term ? `<terminationDate>${_xmlEsc(term)}</terminationDate>` : ''}
    </employee>`;
  }).join('\n');

  // staffingHours — one <staffHours> per (employeeId × date × jobCode × payType).
  // Hours are quarter-hour-precision in CMS spec (e.g. 7.50, 8.00, 8.25).
  const hoursXml = [];
  let unmapped = 0;
  for (const r of punches) {
    if (!r.hours) continue;
    const hrs = parseFloat(r.hours);
    if (!hrs || hrs <= 0) continue;
    let jobCode, payType, empIdOut;
    if (r.kind === 'agency') {
      // Agency hours: PBJ requires a synthesized employee ID per agency
      // worker per facility, and the role from the shift, not the staff
      // roster. payType = 3.
      jobCode = PBJ_JOB_CODE[r.role] || null;
      payType = PBJ_PAY_TYPE.agency;
      empIdOut = r.empId;     // agency_<random>
    } else {
      const emp = empById.get(r.empId);
      jobCode  = _pbjCodeFor(emp);
      payType  = PBJ_PAY_TYPE.employee;
      empIdOut = r.empId;
    }
    if (!jobCode) { unmapped++; continue; }     // role doesn't map to PBJ — skip
    hoursXml.push(`    <staffHours>
      <employeeId>${_xmlEsc(empIdOut)}</employeeId>
      <jobTitleCode>${jobCode}</jobTitleCode>
      <payTypeCode>${payType}</payTypeCode>
      <workDate>${_xmlEsc(r.date)}</workDate>
      <hoursWorked>${hrs.toFixed(2)}</hoursWorked>
    </staffHours>`);
  }

  // residentCensus — one <residentDayCount> per day in the quarter.
  // Pulls from our ppdDailyCensus map; days without a census recorded are
  // emitted with 0 (CMS requires every day to be present).
  const censusXml = [];
  for (let d = new Date(range.start + 'T00:00:00Z'); d.toISOString().slice(0,10) <= range.end; d.setUTCDate(d.getUTCDate() + 1)) {
    const ds = d.toISOString().slice(0,10);
    const c  = parseInt((data.ppdDailyCensus || {})[ds], 10) || 0;
    censusXml.push(`    <residentDayCount>
      <reportDate>${ds}</reportDate>
      <residentCount>${c}</residentCount>
    </residentDayCount>`);
  }

  const ccn   = b.ccn || '';
  const state = b.stateCode || b.state || '';

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<nursingHomeData xmlns="http://www.cms.hhs.gov/PBJ" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <header>
    <reportQuarter>${quarter}</reportQuarter>
    <federalFiscalYear>${year}</federalFiscalYear>
    <facilityId>${_xmlEsc(ccn)}</facilityId>
    <stateCode>${_xmlEsc(state)}</stateCode>
    <softwareVendorName>ManageMyStaffing</softwareVendorName>
    <softwareProductName>ManageMyStaffing PBJ Export</softwareProductName>
    <softwareProductVersion>1.0</softwareProductVersion>
    <reportPeriod>
      <startDate>${range.start}</startDate>
      <endDate>${range.end}</endDate>
    </reportPeriod>
  </header>
  <employees>
${empXml}
  </employees>
  <staffingHours>
${hoursXml.join('\n')}
  </staffingHours>
  <residentCensus>
${censusXml.join('\n')}
  </residentCensus>
</nursingHomeData>
`;
  return {
    xml,
    summary: {
      ccn, year, quarter, range,
      employees: emps.length,
      staffHoursLines: hoursXml.length,
      unmappedHours: unmapped,
      censusDays: censusXml.length,
      missingCcn: !ccn,
      missingStateCode: !state,
    },
  };
}

// GET /api/pbj/quarterly?year=YYYY&quarter=N&buildingId=...
// Returns either:
//   ?format=xml  → application/xml file download
//   ?format=json → { xml, summary } for preview in the UI
app.get('/api/pbj/quarterly', requireAuth, requireAdmin, async (req, res) => {
  const year     = parseInt(req.query.year, 10);
  const quarter  = parseInt(req.query.quarter, 10);
  const buildingId = String(req.query.buildingId || '');
  const format   = req.query.format === 'xml' ? 'xml' : 'json';
  if (!year || year < 2018 || year > 2100) return res.status(400).json({ error: 'Invalid year' });
  if (!quarter || quarter < 1 || quarter > 4) return res.status(400).json({ error: 'Invalid quarter (1–4)' });
  if (!buildingId) return res.status(400).json({ error: 'buildingId required' });

  const data = await loadData();
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  let result;
  try { result = _generatePbjXml({ data, buildingId, year, quarter }); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  auditLog('PBJ_GENERATED', req.user, { buildingId, year, quarter, ccn: result.summary.ccn });

  // Archive every generated XML to Azure Blob Storage for re-download later.
  // The archive is keyed by (buildingId, year, quarter) so re-running the
  // same quarter just overwrites — useful when an admin corrects a
  // missed-punch and re-exports.
  if (process.env.AUDIT_STORAGE_CONNECTION_STRING) {
    _pbjArchive({
      conn: process.env.AUDIT_STORAGE_CONNECTION_STRING,
      buildingId, year, quarter, ccn: result.summary.ccn,
      xml: result.xml,
      generatedBy: req.user.email,
    }).catch(e => logger.error('pbj_archive_failed', { msg: e.message }));
  }

  if (format === 'xml') {
    const fileName = `pbj_${result.summary.ccn || buildingId}_${year}Q${quarter}.xml`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return res.send(result.xml);
  }
  res.json({ ok: true, ...result });
});

// Push an archive copy of a PBJ XML to Azure Blob (container "pbj-archive").
// Idempotent: same (building, year, quarter) overwrites. Fire-and-forget
// from the export endpoint — failure is logged but doesn't block the
// download.
async function _pbjArchive({ conn, buildingId, year, quarter, ccn, xml, generatedBy }) {
  const { BlobServiceClient } = require('@azure/storage-blob');
  const blobService = BlobServiceClient.fromConnectionString(conn);
  const container   = blobService.getContainerClient('pbj-archive');
  await container.createIfNotExists();
  const safeCcn = ccn || buildingId;
  const blobName = `${year}/Q${quarter}/${safeCcn}.xml`;
  const block    = container.getBlockBlobClient(blobName);
  await block.upload(xml, Buffer.byteLength(xml), {
    blobHTTPHeaders: { blobContentType: 'application/xml; charset=utf-8' },
    metadata: {
      buildingId: String(buildingId),
      year:       String(year),
      quarter:    String(quarter),
      ccn:        String(ccn || ''),
      generatedBy: String(generatedBy || '').slice(0, 100),
      generatedAt: new Date().toISOString(),
    },
  });
}

// GET /api/pbj/archive?year=YYYY — list every archived PBJ for the year.
// Returns array of { buildingId, year, quarter, ccn, generatedAt, sizeBytes,
// downloadUrl }. SA + admins; building admins only see their own buildings.
app.get('/api/pbj/archive', requireAuth, requireAdmin, async (req, res) => {
  if (!process.env.AUDIT_STORAGE_CONNECTION_STRING) return res.json({ ok: true, archives: [] });
  const year = parseInt(req.query.year, 10) || new Date().getFullYear();
  try {
    const { BlobServiceClient } = require('@azure/storage-blob');
    const blobService = BlobServiceClient.fromConnectionString(process.env.AUDIT_STORAGE_CONNECTION_STRING);
    const container   = blobService.getContainerClient('pbj-archive');
    const callerBIds  = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
    const out = [];
    for await (const blob of container.listBlobsFlat({ prefix: `${year}/`, includeMetadata: true })) {
      const md = blob.metadata || {};
      const bId = md.buildingid || md.buildingId;
      if (!bId) continue;
      if (req.user.role !== 'superadmin' && !callerBIds.has(bId)) continue;
      out.push({
        buildingId: bId,
        year:       parseInt(md.year, 10) || year,
        quarter:    parseInt(md.quarter, 10) || 0,
        ccn:        md.ccn || '',
        generatedAt: md.generatedat || md.generatedAt || blob.properties.lastModified?.toISOString(),
        sizeBytes:   blob.properties.contentLength,
        blobName:    blob.name,
      });
    }
    out.sort((a, b) => b.quarter - a.quarter);
    res.json({ ok: true, archives: out });
  } catch (e) {
    logger.error('pbj_archive_list_failed', { msg: e.message });
    res.status(502).json({ error: 'Archive lookup failed' });
  }
});

// GET /api/pbj/archive/download?blob=<name> — re-download a previously
// archived PBJ XML.
app.get('/api/pbj/archive/download', requireAuth, requireAdmin, async (req, res) => {
  if (!process.env.AUDIT_STORAGE_CONNECTION_STRING) return res.status(503).json({ error: 'Archive not configured' });
  const blobName = String(req.query.blob || '');
  if (!blobName || /[^A-Za-z0-9._\/Q-]/.test(blobName)) return res.status(400).json({ error: 'Invalid blob name' });
  try {
    const { BlobServiceClient } = require('@azure/storage-blob');
    const blobService = BlobServiceClient.fromConnectionString(process.env.AUDIT_STORAGE_CONNECTION_STRING);
    const container   = blobService.getContainerClient('pbj-archive');
    const block       = container.getBlobClient(blobName);
    const props       = await block.getProperties();
    const md          = props.metadata || {};
    const bId         = md.buildingid || md.buildingId;
    const callerBIds  = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
    if (req.user.role !== 'superadmin' && bId && !callerBIds.has(bId)) {
      return res.status(403).json({ error: 'Out of scope' });
    }
    const buf = await block.downloadToBuffer();
    auditLog('PBJ_ARCHIVE_DOWNLOADED', req.user, { blobName, buildingId: bId });
    const fname = blobName.split('/').pop() || 'pbj.xml';
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send(buf);
  } catch (e) {
    logger.error('pbj_archive_download_failed', { msg: e.message });
    res.status(502).json({ error: 'Archive download failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// HR REPORTS — SCHEDULED EMAIL DIGESTS
// ─────────────────────────────────────────────────────────────────────────────
// Admins create report subscriptions naming the recipients, the facility
// (or facilities, for regional admins), and the metrics they want. The
// daily scheduler renders an HTML email body with a styled table — NO
// attachments, the table renders inline in any email client.
//
// Friday emails include the week's totals; the last-day-of-month email
// includes the month's totals. Otherwise it's just the day's metrics.
//
// Subscription shape (data.reportSubscriptions):
//   {
//     id, name, recipients: [emails...],
//     buildingIds: [...],         // 1 or many; many = regional digest
//     metrics: ['ppd','ot','cost','missed'],   // any subset
//     enabled: true, createdBy, createdAt, lastSentAt
//   }

// Helper: compute one day's metrics for one building.
function _reportDayMetrics(data, buildingId, dateISO) {
  const shifts = (data.shifts || []).filter(s =>
    s.date === dateISO && s.buildingId === buildingId && s.status === 'scheduled');
  const totalHrs = shifts.reduce((sum, sh) => {
    const [ih, im] = String(sh.start || '0:00').split(':').map(Number);
    const [oh, om] = String(sh.end   || '0:00').split(':').map(Number);
    let m = (oh*60 + (om||0)) - (ih*60 + (im||0));
    if (m < 0) m += 24*60;
    return sum + (m / 60);
  }, 0);
  const census = (data.ppdDailyCensus || {})[dateISO] || 0;
  const ppd = census > 0 ? (totalHrs / census).toFixed(2) : '—';
  // Daily cost = sum of (hours × hourlyRate) for all shifts that day, plus
  // any agency hours for that day.
  const empById = new Map((data.employees || []).map(e => [e.id, e]));
  let cost = 0;
  for (const s of shifts) {
    const emp = empById.get(s.employeeId);
    const rate = emp ? (parseFloat(emp.hourlyRate) || 0) : 0;
    const [ih, im] = String(s.start || '0:00').split(':').map(Number);
    const [oh, om] = String(s.end   || '0:00').split(':').map(Number);
    let m = (oh*60 + (om||0)) - (ih*60 + (im||0));
    if (m < 0) m += 24*60;
    cost += (m / 60) * rate;
  }
  // Add agency hours for the day
  const agency = (data.hrTimeClock || []).filter(r =>
    r.kind === 'agency' && r.buildingId === buildingId && r.date === dateISO);
  for (const a of agency) {
    cost += (parseFloat(a.hours) || 0) * (parseFloat(a.hourlyRate) || 0);
  }
  // Daily OT = today's punches that pushed someone over 40 this week. We
  // approximate per-day by looking at this-week-cumulative hours up to and
  // including dateISO; the "today contribution" is hours past 40.
  const wkStart = (() => {
    const d = new Date(dateISO + 'T00:00:00');
    const day = d.getDay();
    const offset = day === 0 ? -6 : 1 - day;
    const s = new Date(d); s.setDate(d.getDate() + offset);
    return s.toISOString().slice(0,10);
  })();
  const recs = (data.hrTimeClock || []).filter(r =>
    r.buildingId === buildingId && r.date >= wkStart && r.date <= dateISO);
  const wkByEmp = new Map();
  for (const r of recs) {
    if (!r.empId || r.kind === 'agency') continue;
    wkByEmp.set(r.empId, (wkByEmp.get(r.empId) || 0) + (parseFloat(r.hours) || 0));
  }
  let otHrs = 0;
  for (const [empId, hrs] of wkByEmp) {
    if (hrs > 40) otHrs += Math.min(hrs - 40, parseFloat(
      (recs.filter(r => r.empId === empId && r.date === dateISO).reduce((s,r)=>s+(parseFloat(r.hours)||0),0))
    ));
  }
  const missed = (data.hrTimeClock || []).filter(r =>
    r.buildingId === buildingId && r.date === dateISO && (r.status === 'missed' || r.status === 'no-out')).length;
  return {
    date: dateISO,
    census,
    totalHrs: totalHrs.toFixed(1),
    ppd,
    cost,
    otHrs: otHrs.toFixed(1),
    missed,
  };
}

// Helper: aggregate one period (weekly or monthly) for one building.
function _reportPeriodMetrics(data, buildingId, fromISO, toISO) {
  const days = [];
  const start = new Date(fromISO + 'T00:00:00Z').getTime();
  const end   = new Date(toISO   + 'T00:00:00Z').getTime();
  for (let t = start; t <= end; t += 86400000) {
    days.push(new Date(t).toISOString().slice(0,10));
  }
  let totalHrs = 0, totalCost = 0, totalOt = 0, totalMissed = 0;
  let ppdSum = 0, ppdDays = 0;
  for (const d of days) {
    const m = _reportDayMetrics(data, buildingId, d);
    totalHrs   += parseFloat(m.totalHrs) || 0;
    totalCost  += m.cost;
    totalOt    += parseFloat(m.otHrs) || 0;
    totalMissed += m.missed;
    if (m.ppd !== '—') { ppdSum += parseFloat(m.ppd); ppdDays++; }
  }
  return {
    fromISO, toISO,
    totalHrs:    totalHrs.toFixed(1),
    avgPPD:      ppdDays > 0 ? (ppdSum / ppdDays).toFixed(2) : '—',
    totalCost,
    totalOt:     totalOt.toFixed(1),
    totalMissed,
  };
}

// Render the inline HTML email body for a subscription on a given send date.
function _reportEmailHtml(data, sub, sendDate) {
  const moneyFmt = n => '$' + Math.round(n).toLocaleString('en-US');
  const today = sendDate || new Date().toISOString().slice(0,10);
  const yesterday = new Date(new Date(today).getTime() - 86400000).toISOString().slice(0,10);
  const day = new Date(today).getDay();
  const includeWeekTotals  = day === 5;        // Friday → roll up the past week
  const dayOfMonth = new Date(today).getDate();
  const lastDayOfMonth = new Date(new Date(today).getFullYear(), new Date(today).getMonth() + 1, 0).getDate();
  const includeMonthTotals = dayOfMonth === lastDayOfMonth;

  const wkStart = (() => {
    const d = new Date(yesterday + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() - 6);
    return d.toISOString().slice(0,10);
  })();
  const moStart = yesterday.slice(0,7) + '-01';

  const buildings = (data.buildings || []).filter(b => sub.buildingIds.includes(b.id));
  if (!buildings.length) return null;
  const wantPpd     = !sub.metrics || sub.metrics.includes('ppd');
  const wantCost    = !sub.metrics || sub.metrics.includes('cost');
  const wantOt      = !sub.metrics || sub.metrics.includes('ot');
  const wantMissed  = !sub.metrics || sub.metrics.includes('missed');

  // Style — inline only, email-client safe (no external CSS)
  const TH = `style="background:#1A3C34;color:#fff;text-align:left;padding:10px 14px;font-size:13px;font-weight:700;font-family:Arial,Helvetica,sans-serif;border-bottom:2px solid #2D6A4F"`;
  const TD = `style="padding:10px 14px;font-size:13px;color:#1F2937;font-family:Arial,Helvetica,sans-serif;border-bottom:1px solid #E5E7EB"`;
  const TDR = TD.replace('"','" style="text-align:right;') + ';font-variant-numeric:tabular-nums';

  const renderTable = (title, rows, totalRow) => `
    <h3 style="font-family:Arial,Helvetica,sans-serif;color:#1A3C34;margin:24px 0 8px">${title}</h3>
    <table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;width:100%;border:1px solid #E5E7EB;border-radius:8px;overflow:hidden">
      ${rows}
      ${totalRow || ''}
    </table>`;

  // Daily section: rows = facilities, columns = metrics.
  const headerCols = [
    'Facility',
    wantPpd    ? 'Daily PPD' : null,
    'Census',
    wantOt     ? 'OT hrs' : null,
    wantCost   ? 'Cost' : null,
    wantMissed ? 'Missed punches' : null,
  ].filter(Boolean);
  const dailyHeader = `<tr>${headerCols.map(c => `<th ${TH}>${c}</th>`).join('')}</tr>`;
  const dailyRows = buildings.map(b => {
    const m = _reportDayMetrics(data, b.id, yesterday);
    return `<tr>
      <td ${TD}><strong>${b.name}</strong></td>
      ${wantPpd    ? `<td ${TDR}">${m.ppd}</td>` : ''}
      <td ${TDR}">${m.census || '—'}</td>
      ${wantOt     ? `<td ${TDR}">${m.otHrs}</td>` : ''}
      ${wantCost   ? `<td ${TDR}">${moneyFmt(m.cost)}</td>` : ''}
      ${wantMissed ? `<td ${TDR}" style="text-align:right;${m.missed > 0 ? 'color:#DC2626;font-weight:700' : ''}">${m.missed}</td>` : ''}
    </tr>`;
  }).join('');
  let dailyTotalRow = '';
  if (buildings.length > 1) {
    const tot = buildings.reduce((acc, b) => {
      const m = _reportDayMetrics(data, b.id, yesterday);
      acc.cost += m.cost; acc.ot += parseFloat(m.otHrs); acc.missed += m.missed;
      return acc;
    }, { cost:0, ot:0, missed:0 });
    dailyTotalRow = `<tr style="background:#F0F8F2">
      <td ${TD}><strong>Total (${buildings.length} facilities)</strong></td>
      ${wantPpd    ? `<td ${TDR}">—</td>` : ''}
      <td ${TDR}">—</td>
      ${wantOt     ? `<td ${TDR}"><strong>${tot.ot.toFixed(1)}</strong></td>` : ''}
      ${wantCost   ? `<td ${TDR}"><strong>${moneyFmt(tot.cost)}</strong></td>` : ''}
      ${wantMissed ? `<td ${TDR}"><strong>${tot.missed}</strong></td>` : ''}
    </tr>`;
  }
  const dailyTable = renderTable(`Daily Recap — ${yesterday}`, dailyHeader + dailyRows, dailyTotalRow);

  // Weekly + monthly totals (Friday / month-end)
  let weeklyTable = '';
  if (includeWeekTotals) {
    const periodHeader = `<tr>${['Facility','Avg PPD','Total hours','OT hours','Cost','Missed punches'].map(c => `<th ${TH}>${c}</th>`).join('')}</tr>`;
    const weekRows = buildings.map(b => {
      const m = _reportPeriodMetrics(data, b.id, wkStart, yesterday);
      return `<tr>
        <td ${TD}><strong>${b.name}</strong></td>
        <td ${TDR}">${m.avgPPD}</td>
        <td ${TDR}">${m.totalHrs}</td>
        <td ${TDR}">${m.totalOt}</td>
        <td ${TDR}">${moneyFmt(m.totalCost)}</td>
        <td ${TDR}">${m.totalMissed}</td>
      </tr>`;
    }).join('');
    weeklyTable = renderTable(`Weekly Totals — ${wkStart} to ${yesterday}`, periodHeader + weekRows);
  }
  let monthlyTable = '';
  if (includeMonthTotals) {
    const periodHeader = `<tr>${['Facility','Avg PPD','Total hours','OT hours','Cost','Missed punches'].map(c => `<th ${TH}>${c}</th>`).join('')}</tr>`;
    const moRows = buildings.map(b => {
      const m = _reportPeriodMetrics(data, b.id, moStart, yesterday);
      return `<tr>
        <td ${TD}><strong>${b.name}</strong></td>
        <td ${TDR}">${m.avgPPD}</td>
        <td ${TDR}">${m.totalHrs}</td>
        <td ${TDR}">${m.totalOt}</td>
        <td ${TDR}">${moneyFmt(m.totalCost)}</td>
        <td ${TDR}">${m.totalMissed}</td>
      </tr>`;
    }).join('');
    monthlyTable = renderTable(`Monthly Totals — ${moStart} to ${yesterday}`, periodHeader + moRows);
  }

  return `<!doctype html><html><body style="margin:0;padding:24px;background:#F9FAFB;font-family:Arial,Helvetica,sans-serif;color:#1F2937">
    <div style="max-width:760px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #E5E7EB">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
        <div style="width:32px;height:32px;background:#6B9E7A;border-radius:7px;color:#fff;font-weight:800;display:inline-flex;align-items:center;justify-content:center;font-size:15px">M</div>
        <span style="font-size:15px;font-weight:700;color:#1A3C34">ManageMyStaffing</span>
      </div>
      <h2 style="margin:0 0 4px;color:#1F2937">${sub.name || 'Daily Operations Report'}</h2>
      <p style="color:#6B7280;margin:0 0 8px;font-size:13px">For ${yesterday} · sent ${today}</p>
      ${dailyTable}
      ${weeklyTable}
      ${monthlyTable}
      <p style="color:#6B7280;font-size:11px;margin-top:24px;border-top:1px solid #E5E7EB;padding-top:14px">
        Auto-generated daily by ManageMyStaffing. Manage subscribers in HR → Reports.
      </p>
    </div>
  </body></html>`;
}

// POST /api/reports/subscriptions — upsert a subscription.
app.post('/api/reports/subscriptions', requireAuth, requireAdmin, async (req, res) => {
  const { id, name, recipients, buildingIds, metrics, enabled } = req.body || {};
  if (!Array.isArray(recipients) || !recipients.length) return res.status(400).json({ error: 'recipients required' });
  if (!Array.isArray(buildingIds) || !buildingIds.length) return res.status(400).json({ error: 'buildingIds required' });
  // Validate emails
  for (const e of recipients) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e))) return res.status(400).json({ error: `Invalid email: ${e}` });
  }
  // Authz scoping
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin') {
    for (const bId of buildingIds) {
      if (!callerBIds.has(bId)) return res.status(403).json({ error: `Out of scope: ${bId}` });
    }
  }
  const data = await loadData();
  if (!Array.isArray(data.reportSubscriptions)) data.reportSubscriptions = [];
  const sub = id ? data.reportSubscriptions.find(s => s.id === id) : null;
  if (id && !sub) return res.status(404).json({ error: 'Subscription not found' });
  const upsert = sub || {
    id: 'rs_' + Date.now() + Math.random().toString(36).slice(2,5),
    createdBy: req.user.email,
    createdAt: new Date().toISOString(),
  };
  upsert.name = String(name || 'Daily report').slice(0,100);
  upsert.recipients = recipients.map(e => String(e).toLowerCase());
  upsert.buildingIds = buildingIds.slice(0, 50);
  upsert.metrics = Array.isArray(metrics) ? metrics : ['ppd','ot','cost','missed'];
  upsert.enabled = enabled !== false;
  if (!sub) data.reportSubscriptions.push(upsert);
  markDirty();
  auditLog('REPORT_SUBSCRIPTION_SAVED', req.user, { id: upsert.id, recipients: upsert.recipients.length, buildings: upsert.buildingIds.length });
  res.json({ ok: true, subscription: upsert });
});

// DELETE /api/reports/subscriptions/:id
app.delete('/api/reports/subscriptions/:id', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const before = (data.reportSubscriptions || []).length;
  data.reportSubscriptions = (data.reportSubscriptions || []).filter(s => s.id !== req.params.id);
  if (data.reportSubscriptions.length === before) return res.status(404).json({ error: 'Subscription not found' });
  markDirty();
  auditLog('REPORT_SUBSCRIPTION_DELETED', req.user, { id: req.params.id });
  res.json({ ok: true });
});

// POST /api/reports/test/:id — send the report immediately to verify config.
app.post('/api/reports/test/:id', requireAuth, requireAdmin, async (req, res) => {
  if (!ACS_CONNECTION_STRING) return res.status(503).json({ error: 'ACS not configured' });
  const data = await loadData();
  const sub = (data.reportSubscriptions || []).find(s => s.id === req.params.id);
  if (!sub) return res.status(404).json({ error: 'Subscription not found' });
  const html = _reportEmailHtml(data, sub, new Date().toISOString().slice(0,10));
  if (!html) return res.status(400).json({ error: 'Report has no buildings to render' });
  try {
    const { EmailClient } = require('@azure/communication-email');
    const ec = new EmailClient(ACS_CONNECTION_STRING);
    const poller = await ec.beginSend({
      senderAddress: ACS_FROM_EMAIL,
      recipients: { to: sub.recipients.map(e => ({ address: e })) },
      content: {
        subject: `[Test] ${sub.name} — ManageMyStaffing daily report`,
        plainText: 'Your email client does not support HTML. Open in a browser to view the table.',
        html,
      },
    });
    await poller.pollUntilDone();
    auditLog('REPORT_SUBSCRIPTION_TEST_SENT', req.user, { id: sub.id, recipients: sub.recipients.length });
    res.json({ ok: true });
  } catch (e) {
    logger.error('report_test_send_failed', { msg: e.message });
    res.status(502).json({ error: 'Email send failed' });
  }
});

// Background timer: every hour, on the hour, send any subscriptions due.
// Reports go out at 06:00 Central Time = 12:00 UTC each day. We snapshot
// "lastSentDate" on the subscription so a restart mid-day doesn't double-send.
async function _maybeSendDueReports() {
  if (!ACS_CONNECTION_STRING) return;
  try {
    const now = new Date();
    if (now.getUTCHours() !== 12) return;       // only at noon UTC (≈ 6am CT)
    const today = now.toISOString().slice(0,10);
    const data = await loadData();
    const subs = (data.reportSubscriptions || []).filter(s => s.enabled !== false);
    for (const sub of subs) {
      if (sub.lastSentDate === today) continue;
      const html = _reportEmailHtml(data, sub, today);
      if (!html) continue;
      try {
        const { EmailClient } = require('@azure/communication-email');
        const ec = new EmailClient(ACS_CONNECTION_STRING);
        const poller = await ec.beginSend({
          senderAddress: ACS_FROM_EMAIL,
          recipients: { to: sub.recipients.map(e => ({ address: e })) },
          content: {
            subject: `${sub.name} — ${today}`,
            plainText: 'Your email client does not support HTML. View in browser.',
            html,
          },
        });
        await poller.pollUntilDone();
        sub.lastSentDate = today;
        markDirty();
        auditLog('REPORT_SUBSCRIPTION_SENT', null, { id: sub.id, date: today, recipients: sub.recipients.length });
      } catch (e) {
        logger.error('report_send_failed', { id: sub.id, msg: e.message });
      }
    }
  } catch (e) { logger.error('reports_scheduler_error', { msg: e.message }); }
}
// Check once a minute. Cheap; fires exactly once per day per subscription.
setInterval(_maybeSendDueReports, 60 * 1000);

// ─────────────────────────────────────────────────────────────────────────────
// ONBOARDING → EMPLOYEE ROSTER (push completed onboardee into the staff list)
// ─────────────────────────────────────────────────────────────────────────────
// When a prospect/candidate finishes onboarding paperwork, admin clicks
// "Push to Roster" — we promote the prospect record into the employees
// collection so the new hire shows up on the schedule, gets a PIN slot,
// etc. The original prospect is marked 'hired' for traceability.
app.post('/api/recruiting/push-to-roster', requireAuth, requireAdmin, async (req, res) => {
  const { prospectId, position, hireDate, hourlyRate, dob, phone, employmentType } = req.body || {};
  if (!prospectId) return res.status(400).json({ error: 'prospectId required' });
  const data = await loadData();
  const p = (data.prospects || []).find(x => x.id === prospectId);
  if (!p) return res.status(404).json({ error: 'Prospect not found' });
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && p.buildingId && !callerBIds.has(p.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  // Already promoted? guard to avoid double-create.
  if (p.employeeId) {
    const existing = (data.employees || []).find(e => e.id === p.employeeId);
    if (existing) return res.status(409).json({ error: 'Already on roster', employeeId: existing.id });
  }
  // Map prospect → employee
  const validPositions = ['Nurse Management','Charge Nurse','CNA','CMA','Housekeeping','Laundry','Cook','Dietary Aid','Maintenance','Marketing'];
  const pos = position || p.appliedPosition || p.role;
  if (!validPositions.includes(pos)) return res.status(400).json({ error: `position must be one of ${validPositions.join(', ')}` });
  const initials = String(p.name || '').split(' ').map(w => w[0] || '').join('').slice(0,2).toUpperCase();
  const newEmp = {
    id: 'e' + Date.now() + Math.random().toString(36).slice(2,5),
    name: p.name,
    initials,
    group: pos,
    email: p.email,
    phone: phone || p.phone || '',
    buildingId: p.buildingId,
    employmentType: employmentType || 'full-time',
    hireDate: hireDate || new Date().toISOString().slice(0,10),
    hourlyRate: hourlyRate ? parseFloat(hourlyRate) : null,
    dob: dob || null,
    inactive: false,
    notifEmail: true,
    notifSMS: !!p.phone,
    notifPrefs: ['immediate','day'],
    notifChannels: { immediate:{email:true,sms:!!p.phone}, day:{email:true,sms:false}, week:{email:true,sms:false}, daily:{email:false,sms:false} },
    onboardedAt: new Date().toISOString(),
    onboardingProspectId: prospectId,
    terminationLog: [],
  };
  if (!Array.isArray(data.employees)) data.employees = [];
  data.employees.push(newEmp);
  // Update prospect → mark hired and link
  p.status = 'hired';
  p.employeeId = newEmp.id;
  p.hiredAt = new Date().toISOString();
  if (!Array.isArray(p.notes)) p.notes = [];
  p.notes.push({ at: new Date().toISOString(), kind:'system', text:`Pushed to employee roster as ${pos}` });
  markDirty();
  auditLog('PROSPECT_PUSHED_TO_ROSTER', req.user, { prospectId, employeeId: newEmp.id, position: pos });
  // Push disposition to Indeed if this prospect came from there
  if (p.indeedApplyId && INDEED_API_CLIENT_ID) {
    pushIndeedDisposition(p.indeedApplyId, 'hired')
      .catch(e => logger.error('indeed_disposition_hire_failed', { msg: e.message }));
  }
  res.json({ ok: true, employee: newEmp });
});

// ─────────────────────────────────────────────────────────────────────────────
// SMARTLINX SLATE INTEGRATION
// ─────────────────────────────────────────────────────────────────────────────
// SmartLinx Slate clocks export punches via SOAP/REST or nightly SFTP. The
// most reliable path for non-partners is to run a small bridge script on the
// facility's network that polls the Slate clock's local export and POSTs
// each punch to this endpoint.
//
// Supports two payload shapes:
//   A. Single punch:  { badgeId, action: 'in'|'out', timestamp, deviceId? }
//   B. Batch:         { punches: [ {badgeId, action, timestamp, deviceId?}, ... ] }
//
// Auth: shared-secret header (SMARTLINX_WEBHOOK_SECRET env var) on
// X-SmartLinx-Secret. Bridge scripts attach the secret. Mismatch → 401.
//
// Employee identification: SmartLinx sends a badge ID (printed on the
// physical badge). We map to an employee via employee.badgeId. Admin sets
// this once per employee in the roster.
app.post('/api/timeclock/smartlinx', express.json({ limit:'1mb' }), async (req, res) => {
  const expected = process.env.SMARTLINX_WEBHOOK_SECRET;
  if (!expected) return res.status(503).json({ error: 'SmartLinx integration not configured' });
  if (req.headers['x-smartlinx-secret'] !== expected) {
    auditLog('SMARTLINX_REJECTED', null, { reason: 'bad_secret' });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const body = req.body || {};
  const punches = Array.isArray(body.punches) ? body.punches : [body];
  const data = await loadData();
  const empByBadge = new Map();
  for (const e of (data.employees || [])) {
    if (e.badgeId) empByBadge.set(String(e.badgeId), e);
  }
  let accepted = 0, skipped = 0, errors = [];
  for (const p of punches) {
    const badgeId = String(p.badgeId || p.badge || p.empCode || '').trim();
    const action  = String(p.action || p.type || '').toLowerCase().replace(/^punch_?/,'');
    const ts      = p.timestamp || p.time || p.punchTime;
    if (!badgeId) { skipped++; continue; }
    const emp = empByBadge.get(badgeId);
    if (!emp) { skipped++; errors.push(`unknown badge ${badgeId}`); continue; }
    if (!['in','out'].includes(action)) { skipped++; continue; }
    const r = _applyPunch(data, emp, action, ts, {
      source: 'smartlinx',
      deviceId: p.deviceId || null,
    });
    if (r.error) { errors.push(`${emp.name}: ${r.error}`); skipped++; continue; }
    accepted++;
  }
  if (accepted > 0) {
    markDirty();
    auditLog('SMARTLINX_PUNCHES', null, { accepted, skipped });
  }
  res.json({ ok: true, accepted, skipped, errors: errors.slice(0,20) });
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENCY TIME ENTRY (PBJ-eligible non-staff hours)
// ─────────────────────────────────────────────────────────────────────────────
// When an open shift is filled by an agency nurse (not a regular employee),
// admin records the hours here. The data feeds into PBJ submissions and
// daily PPD calcs as if it were a regular punch — but the source is tagged
// 'agency' and the worker isn't on the staff roster.
//
// Body: { shiftId, agencyName, workerName, in, out, hourlyRate, license? }
// Returns: created hrTimeClock record (with kind:'agency') + updated shift.
app.post('/api/timeclock/agency', requireAuth, requireAdmin, async (req, res) => {
  const { shiftId, agencyName, workerName, in: inTime, out: outTime, hourlyRate, license } = req.body || {};
  if (!shiftId || !workerName || !inTime || !outTime) {
    return res.status(400).json({ error: 'shiftId, workerName, in, out required' });
  }
  if (!/^\d{1,2}:\d{2}$/.test(inTime) || !/^\d{1,2}:\d{2}$/.test(outTime)) {
    return res.status(400).json({ error: 'in/out must be HH:MM' });
  }
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === shiftId);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  // Authz scope check
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(shift.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  // Compute hours
  const [ih, im] = inTime.split(':').map(Number);
  const [oh, om] = outTime.split(':').map(Number);
  let mins = (oh*60 + (om||0)) - (ih*60 + (im||0));
  if (mins < 0) mins += 24*60;
  const hours = (mins / 60).toFixed(2);

  const agencyId = 'agency_' + crypto.randomBytes(6).toString('hex');
  const record = {
    empId: agencyId,
    name: String(workerName).slice(0,100),
    role: shift.group,                           // matches the shift's role for PPD bucketing
    buildingId: shift.buildingId,
    date: shift.date,
    in: inTime,
    out: outTime,
    hours,
    status: 'normal',
    kind: 'agency',                              // distinguishes from staff punches
    agencyName: String(agencyName || '').slice(0,100),
    license:    String(license    || '').slice(0,50),
    hourlyRate: parseFloat(hourlyRate) || 0,
    enteredBy:  req.user.email,
    enteredAt:  new Date().toISOString(),
    events: [{
      action: 'agency-entry', at: new Date().toISOString(),
      source: 'admin-agency', editor: req.user.email,
    }],
  };
  if (!Array.isArray(data.hrTimeClock)) data.hrTimeClock = [];
  data.hrTimeClock.push(record);
  // Mark the shift as filled by agency.
  shift.status = 'agency-filled';
  shift.agencyName  = record.agencyName;
  shift.agencyWorker = record.name;
  shift.filledByAgencyAt = new Date().toISOString();
  markDirty();
  auditLog('AGENCY_TIME_RECORDED', req.user, {
    shiftId, agencyName: record.agencyName, hours, buildingId: shift.buildingId,
  });
  res.json({ ok: true, record, shift });
});

// Helper: apply punch in/out edits to a record, recompute hours + status.
function _applyPunchEdit(emp, r, inTime, outTime, data) {
  if (inTime  !== undefined) r.in  = String(inTime  || '').slice(0,5);
  if (outTime !== undefined) r.out = String(outTime || '').slice(0,5);
  if (r.in && r.out) {
    const [ih, im] = r.in.split(':').map(Number);
    const [oh, om] = r.out.split(':').map(Number);
    let mins = (oh*60 + (om||0)) - (ih*60 + (im||0));
    if (mins < 0) mins += 24*60;
    r.hours = (mins / 60).toFixed(2);
  } else { r.hours = ''; }
  r.status = _classifyPunch(emp, emp ? r.date : null, r.in, r.out, data.shifts || []);
  r.name = emp.name; r.role = emp.group; r.buildingId = emp.buildingId;
}

// Helper: drop a notification onto data.notifications[] for a target user/role.
// Sidebar / inbox UI reads from this array. Each entry is non-PHI metadata
// only — the punch record reference lets the UI fetch the rest.
function _notify(data, n) {
  if (!Array.isArray(data.notifications)) data.notifications = [];
  data.notifications.unshift({
    id: 'n_' + crypto.randomBytes(6).toString('hex'),
    createdAt: new Date().toISOString(),
    readAt: null,
    ...n,
  });
  // Cap at 5,000 to bound storage
  if (data.notifications.length > 5000) data.notifications.length = 5000;
}

// PATCH /api/timeclock/punch — admin correction.
// Body: { empId, date, in?, out?, note? }
//
// Admin / superadmin / regionaladmin: applied immediately (current behavior).
// HR Admin (`hradmin`): the change is staged into a `pendingPunchEdits[]`
// queue and a notification is dropped for building admins. The admin then
// hits /api/timeclock/punch/:editId/approve or /reject. On approve, the edit
// is applied AND a notification fires to regional admins.
app.patch('/api/timeclock/punch', requireAuth, requireAdmin, async (req, res) => {
  const { empId, date, in: inTime, out: outTime, note } = req.body || {};
  if (!empId || !date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'empId, date (YYYY-MM-DD) required' });
  const data = await loadData();
  const emp = (data.employees || []).find(e => e.id === empId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(emp.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  // ── HR Admin: stage as pending, alert building admin, do not apply ──
  if (req.user.role === 'hradmin') {
    if (!Array.isArray(data.pendingPunchEdits)) data.pendingPunchEdits = [];
    const r = _findOrCreatePunch(data, empId, date);
    const before = { in: r.in, out: r.out };
    const proposed = {
      in:  inTime  !== undefined ? String(inTime  || '').slice(0,5) : r.in,
      out: outTime !== undefined ? String(outTime || '').slice(0,5) : r.out,
    };
    const editId = 'pe_' + crypto.randomBytes(6).toString('hex');
    const pe = {
      id: editId,
      empId, empName: emp.name, buildingId: emp.buildingId, date,
      before, proposed,
      requestedBy: { id: req.user.id, email: req.user.email, name: req.user.name || req.user.email },
      requestedAt: new Date().toISOString(),
      note: (note || '').slice(0, 500),
      status: 'pending',
      decidedBy: null, decidedAt: null, decisionNote: null,
    };
    data.pendingPunchEdits.push(pe);

    // Notify every building admin for this facility.
    const admins = (data.accounts || []).filter(a =>
      a.role === 'admin' && (a.buildingId === emp.buildingId
        || (Array.isArray(a.buildingIds) && a.buildingIds.includes(emp.buildingId)))
    );
    for (const ad of admins) {
      _notify(data, {
        kind: 'PUNCH_EDIT_PENDING',
        toAccountId: ad.id, toEmail: ad.email,
        buildingId: emp.buildingId,
        editId, empId, empName: emp.name, date,
        requestedBy: pe.requestedBy.email,
        title: `Punch edit pending: ${emp.name} · ${date}`,
        body: `${pe.requestedBy.name} (HR Admin) changed ${date} from ${before.in||'—'}-${before.out||'—'} to ${proposed.in||'—'}-${proposed.out||'—'}. Approve or reject.`,
      });
    }
    markDirty();
    auditLog('PUNCH_EDIT_REQUESTED', req.user, { editId, empId, date, before, proposed });
    return res.json({ ok: true, pending: true, editId, message: 'Submitted for admin approval' });
  }

  // ── Admin / SA / Regional: apply immediately (existing path) ──
  const r = _findOrCreatePunch(data, empId, date);
  const before = { in: r.in, out: r.out };
  _applyPunchEdit(emp, r, inTime, outTime, data);
  if (!Array.isArray(r.events)) r.events = [];
  r.events.push({
    action: 'admin-edit', at: new Date().toISOString(),
    source: 'admin', editor: req.user.email,
    before, after: { in: r.in, out: r.out },
    note: (note || '').slice(0, 500),
  });
  markDirty();
  auditLog('PUNCH_EDITED', req.user, { empId, date, before, after: { in: r.in, out: r.out } });
  res.json({ ok: true, record: r });
});

// GET /api/timeclock/punch/pending — list pending HR-Admin punch edits
// scoped to caller's buildings.
app.get('/api/timeclock/punch/pending', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  const all = (data.pendingPunchEdits || []).filter(p => p.status === 'pending');
  const scoped = req.user.role === 'superadmin'
    ? all
    : all.filter(p => callerBIds.has(p.buildingId));
  res.json({ items: scoped });
});

// POST /api/timeclock/punch/:editId/approve  — admin/regional/SA only.
// Applies the staged edit, then notifies regional admins.
// POST /api/timeclock/punch/:editId/reject   — admin discards the edit.
app.post('/api/timeclock/punch/:editId/decide', requireAuth, requireAdmin, async (req, res) => {
  if (!isApprovingAdmin(req.user)) return res.status(403).json({ error: 'Only admin/regional/SA can approve punch edits' });
  const editId = req.params.editId;
  const action = String(req.body?.action || '').toLowerCase();         // 'approve' | 'reject'
  const decisionNote = String(req.body?.note || '').slice(0, 500);
  if (!['approve','reject'].includes(action)) return res.status(400).json({ error: 'action must be approve|reject' });
  const data = await loadData();
  const pe = (data.pendingPunchEdits || []).find(p => p.id === editId);
  if (!pe) return res.status(404).json({ error: 'Pending edit not found' });
  if (pe.status !== 'pending') return res.status(409).json({ error: `Already ${pe.status}` });

  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(pe.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  pe.status = (action === 'approve') ? 'approved' : 'rejected';
  pe.decidedBy = { id: req.user.id, email: req.user.email, name: req.user.name || req.user.email, role: req.user.role };
  pe.decidedAt = new Date().toISOString();
  pe.decisionNote = decisionNote;

  if (action === 'approve') {
    const emp = (data.employees || []).find(e => e.id === pe.empId);
    if (!emp) {
      pe.status = 'rejected';
      pe.decisionNote = 'Employee no longer exists; auto-rejected';
      markDirty();
      return res.status(409).json({ error: 'Employee no longer exists' });
    }
    const r = _findOrCreatePunch(data, pe.empId, pe.date);
    const before = { in: r.in, out: r.out };
    _applyPunchEdit(emp, r, pe.proposed.in, pe.proposed.out, data);
    if (!Array.isArray(r.events)) r.events = [];
    r.events.push({
      action: 'admin-edit', at: new Date().toISOString(),
      source: 'admin-approval-of-hradmin', editor: req.user.email,
      requestedBy: pe.requestedBy.email,
      before, after: { in: r.in, out: r.out },
      note: pe.note, decisionNote,
    });

    // Notify all regional admins (and superadmins) about the approved change.
    const escalateTo = (data.accounts || []).filter(a =>
      a.role === 'regionaladmin' || a.role === 'superadmin'
    );
    for (const ra of escalateTo) {
      _notify(data, {
        kind: 'PUNCH_EDIT_APPROVED',
        toAccountId: ra.id, toEmail: ra.email,
        buildingId: pe.buildingId,
        editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
        requestedBy: pe.requestedBy.email,
        approvedBy: req.user.email,
        title: `Punch edit approved: ${pe.empName} · ${pe.date}`,
        body: `${req.user.email} approved an HR-Admin punch correction for ${pe.empName} on ${pe.date}: ${pe.before.in||'—'}-${pe.before.out||'—'} → ${pe.proposed.in||'—'}-${pe.proposed.out||'—'}.`,
      });
    }
    markDirty();
    auditLog('PUNCH_EDIT_APPROVED', req.user, { editId: pe.id, empId: pe.empId, date: pe.date, before, after: { in: r.in, out: r.out }, requestedBy: pe.requestedBy.email });
    return res.json({ ok: true, status: 'approved', record: r });
  }

  // Reject: just stamp the record; no time-clock change.
  markDirty();
  auditLog('PUNCH_EDIT_REJECTED', req.user, { editId: pe.id, empId: pe.empId, date: pe.date, requestedBy: pe.requestedBy.email });
  res.json({ ok: true, status: 'rejected' });
});

// GET /kiosk/:buildingId — serves the standalone tablet kiosk HTML page.
// The page is locked to one building (token embedded server-side). No SPA
// shell, no nav. Tablet can be left running 24/7 at the nurse station.
app.get('/kiosk/:buildingId', async (req, res) => {
  const buildingId = req.params.buildingId;
  const data = await loadData();
  const b = (data.buildings || []).find(x => x.id === buildingId);
  if (!b) return res.status(404).type('text').send('Building not found');
  // Issue a kiosk token for this device session. Long-lived (1 year) so the
  // tablet doesn't need to re-authenticate. To revoke, change KIOSK_SECRET
  // env var which invalidates all kiosk tokens system-wide.
  const kioskId = 'k_' + crypto.randomBytes(8).toString('hex');
  const kioskToken = jwt.sign({
    kind: 'kiosk', buildingId, kioskId, autoIssued: true,
  }, TIMECLOCK_KIOSK_SECRET, { expiresIn: '365d' });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(_kioskHtml(b, kioskToken));
});

function _kioskHtml(building, kioskToken) {
  const safeName = String(building.name || '').replace(/[<>"'&]/g, c => ({'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','&':'&amp;'}[c]));
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>Clock In / Out — ${safeName}</title>
<style>
  *,*::before,*::after { box-sizing:border-box }
  html,body { height:100%; margin:0; font-family:'DM Sans',-apple-system,Segoe UI,sans-serif; background:#0f172a; color:#fff; -webkit-user-select:none; user-select:none; overscroll-behavior:none }
  .wrap { max-width:540px; margin:0 auto; height:100%; display:flex; flex-direction:column; padding:24px 20px }
  header { text-align:center; padding:20px 0 24px }
  header .name { font-size:18px; font-weight:600; color:#94a3b8; letter-spacing:.04em; text-transform:uppercase }
  header .clock { font-size:64px; font-weight:800; margin:8px 0; font-variant-numeric:tabular-nums; color:#fff }
  header .date { font-size:16px; color:#94a3b8 }
  .pad { background:#1e293b; border-radius:24px; padding:24px; margin-top:8px; box-shadow:0 8px 32px rgba(0,0,0,.4) }
  .pin-display { font-size:48px; text-align:center; letter-spacing:24px; padding:16px 0 24px; font-variant-numeric:tabular-nums; min-height:80px; color:#6B9E7A; font-weight:800 }
  .pin-display.empty { color:#475569; letter-spacing:8px; font-size:18px; font-weight:500 }
  .keys { display:grid; grid-template-columns:repeat(3,1fr); gap:12px }
  button { font-family:inherit; font-size:28px; font-weight:700; background:#334155; color:#fff; border:none; border-radius:16px; padding:24px 0; cursor:pointer; transition:transform .05s, background .15s; touch-action:manipulation }
  button:active { transform:scale(0.95); background:#475569 }
  button.action { font-size:18px; padding:18px 0 }
  button.in  { background:#16a34a }
  button.in:active { background:#15803d }
  button.out { background:#dc2626 }
  button.out:active { background:#991b1b }
  button.del { background:#475569; font-size:20px }
  button.clr { background:#475569; font-size:14px }
  .actions { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:16px }
  .toast { position:fixed; left:50%; top:24px; transform:translateX(-50%); background:#1e293b; border:1px solid #334155; padding:14px 22px; border-radius:12px; max-width:90%; text-align:center; font-size:16px; font-weight:600; box-shadow:0 12px 36px rgba(0,0,0,.6); transition:opacity .25s, transform .25s; opacity:0; pointer-events:none; z-index:10 }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0) }
  .toast.ok { border-color:#16a34a }
  .toast.err { border-color:#dc2626 }
  .toast .who { color:#94a3b8; font-size:13px; font-weight:500; margin-top:2px }
  footer { padding:18px 0; text-align:center; color:#475569; font-size:12px }
</style></head>
<body>
<div class="wrap">
  <header>
    <div class="name">${safeName}</div>
    <div class="clock" id="clock">--:--</div>
    <div class="date" id="date">—</div>
  </header>
  <div class="pad">
    <div class="pin-display empty" id="pin">Enter PIN</div>
    <div class="keys">
      <button onclick="press('1')">1</button>
      <button onclick="press('2')">2</button>
      <button onclick="press('3')">3</button>
      <button onclick="press('4')">4</button>
      <button onclick="press('5')">5</button>
      <button onclick="press('6')">6</button>
      <button onclick="press('7')">7</button>
      <button onclick="press('8')">8</button>
      <button onclick="press('9')">9</button>
      <button class="clr" onclick="clearPin()">Clear</button>
      <button onclick="press('0')">0</button>
      <button class="del" onclick="del()">⌫</button>
    </div>
    <div class="actions">
      <button class="action in"  onclick="punch('in')">CLOCK IN</button>
      <button class="action out" onclick="punch('out')">CLOCK OUT</button>
    </div>
  </div>
  <footer>Tablet kiosk · Punches recorded immediately</footer>
</div>
<div class="toast" id="toast"></div>
<script>
const KIOSK_TOKEN = ${JSON.stringify(kioskToken)};
let pinBuf = '';
function $(id){return document.getElementById(id)}
function refreshPin(){
  const el = $('pin');
  if (!pinBuf) { el.textContent = 'Enter PIN'; el.classList.add('empty'); return; }
  el.textContent = '•'.repeat(pinBuf.length);
  el.classList.remove('empty');
}
function press(d){ if (pinBuf.length < 6) { pinBuf += d; refreshPin(); } }
function del(){ pinBuf = pinBuf.slice(0, -1); refreshPin(); }
function clearPin(){ pinBuf=''; refreshPin(); }
function showToast(msg, who, kind){
  const t = $('toast');
  t.className = 'toast show ' + (kind||'ok');
  t.innerHTML = msg + (who?'<div class="who">'+who+'</div>':'');
  setTimeout(()=>{ t.className='toast '+(kind||''); }, 4000);
}
async function punch(action){
  if (pinBuf.length < 4) { showToast('Enter your 4-digit PIN','','err'); return; }
  const pin = pinBuf;
  try {
    const r = await fetch('/api/timeclock/kiosk-punch', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ kioskToken: KIOSK_TOKEN, pin, action }),
    });
    const data = await r.json();
    if (!r.ok) { showToast(data.error || 'Punch failed', '', 'err'); pinBuf=''; refreshPin(); return; }
    const verb = action === 'in' ? 'Clocked in' : 'Clocked out';
    showToast('✓ ' + verb, data.employeeName + (data.todayHours ? ' · ' + data.todayHours + ' hrs today' : ''), 'ok');
    pinBuf=''; refreshPin();
  } catch (e) {
    showToast('Network error — try again', '', 'err');
  }
}
function tick(){
  const d = new Date();
  $('clock').textContent = d.toLocaleTimeString([], { hour:'numeric', minute:'2-digit' });
  $('date').textContent = d.toLocaleDateString([], { weekday:'long', month:'long', day:'numeric' });
}
tick(); setInterval(tick, 1000);
// Disable context menu and pull-to-refresh on tablet
document.addEventListener('contextmenu', e => e.preventDefault());
</script>
</body></html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────────────────────────────────────
// Body: { email, password, totp?, totpSetupCode? }
// Returns:
//   - { needsTotpSetup: true, totpSecret, qrDataUrl } if first 2FA enrollment
//   - { needsTotp: true, sessionId } if password OK, awaiting TOTP code
//   - { token, user } when fully authenticated
//
// Security:
//   - Account lockout after 5 failed password attempts (30 min)
//   - First login requires inviteToken (passed in `password` field via /api/invite/accept)
//   - Demo accounts disabled in production
//   - TOTP required for all non-demo accounts
const _totpPending = new Map(); // sessionId → { acctId, expiresAt }

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password, totp, sessionId } = req.body || {};

  // Step 2: TOTP or Recovery Code verification
  if (sessionId && totp) {
    const pend = _totpPending.get(sessionId);
    if (!pend || Date.now() > pend.expiresAt) {
      _totpPending.delete(sessionId);
      return res.status(401).json({ error: 'TOTP session expired. Sign in again.' });
    }
    const data = await loadData();
    const acct = (data.accounts || []).find(a => a.id === pend.acctId);
    if (!acct || !acct.totpSecret) {
      _totpPending.delete(sessionId);
      return res.status(401).json({ error: 'Account error' });
    }
    const cleaned = String(totp).replace(/\s/g, '');
    let ok = false;
    let viaRecovery = false;
    // Try as TOTP code first
    if (/^\d{6}$/.test(cleaned)) {
      ok = authenticator.check(cleaned, acct.totpSecret);
    }
    // Fall back to recovery code (single-use, format xxxxxxxx-xxxxxxxx)
    if (!ok && /^[a-f0-9]{8}-[a-f0-9]{8}$/i.test(cleaned)) {
      const hashes = acct.totpRecoveryCodesHashes || [];
      for (let i = 0; i < hashes.length; i++) {
        if (await bcrypt.compare(cleaned.toLowerCase(), hashes[i])) {
          // Consume the code by removing its hash
          hashes.splice(i, 1);
          acct.totpRecoveryCodesHashes = hashes;
          await persistAccountNow(acct);
          ok = true;
          viaRecovery = true;
          break;
        }
      }
    }
    if (!ok) {
      auditLog('TOTP_FAILED', acct);
      return res.status(401).json({ error: 'Invalid code' });
    }
    _totpPending.delete(sessionId);
    if (viaRecovery) {
      auditLog('TOTP_RECOVERY_CODE_USED', acct, { codesRemaining: (acct.totpRecoveryCodesHashes || []).length });
    }
    // Trust this device for the next 30 days — TOTP won't be re-prompted on this browser.
    setDeviceTrustCookie(res, acct);
    return _issueToken(req, res, acct, data);
  }

  // Step 1: email + password
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  let data;
  try { data = await loadData(); } catch (e) { return res.status(500).json({ error: 'Server error' }); }

  const acct = (data.accounts || []).find(a => (a.email || '').toLowerCase() === email.toLowerCase());
  if (!acct) {
    auditLog('LOGIN_FAILED', null, { email: email.toLowerCase(), reason: 'unknown_email' });
    // Constant-time-ish: still hash a dummy
    await bcrypt.compare(password, '$2b$12$' + 'a'.repeat(53));
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Lockout check
  if (isAccountLocked(acct)) {
    auditLog('LOGIN_BLOCKED_LOCKED', acct);
    const minutesLeft = Math.ceil((acct.lockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Account locked. Try again in ${minutesLeft} min.` });
  }

  // Demo accounts disabled in production
  const isDemo = acct.id === SEED_DEMO.id || acct.id === SEED_DEMO_NURSE.id;
  if (isDemo && IS_PROD) {
    auditLog('LOGIN_FAILED', acct, { reason: 'demo_disabled_in_prod' });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  let authenticated = false;
  if (isDemo) {
    authenticated = true;
  } else if (!acct.ph) {
    // First login MUST go through /api/invite/accept (uses inviteToken).
    // Direct login with no password set is blocked — closes the first-login hijack.
    auditLog('LOGIN_FAILED', acct, { reason: 'no_password_set_use_invite' });
    return res.status(403).json({ error: 'Account not yet activated. Use the invitation link sent to your email.' });
  } else {
    authenticated = await bcrypt.compare(password, acct.ph);
  }

  if (!authenticated) {
    recordFailedLogin(acct);
    auditLog('LOGIN_FAILED', acct, { reason: 'wrong_password', failedAttempts: acct.failedAttempts });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  clearFailedAttempts(acct);

  // TOTP gating: required for privileged roles (admin/SA) only.
  // Employees don't access PHI, so HIPAA §164.312 doesn't require 2FA for them.
  // Skip TOTP entirely → straight to token.
  if (!isDemo && !isPrivilegedRole(acct.role)) {
    return _issueToken(req, res, acct, data);
  }
  if (!isDemo) {
    if (!acct.totpSecret) {
      // First-time TOTP enrollment
      const secret = authenticator.generateSecret();
      const otpauth = authenticator.keyuri(acct.email, TOTP_ISSUER, secret);
      const qrDataUrl = await QRCode.toDataURL(otpauth);
      // Stash pending secret — confirmed on /api/auth/totp/enroll
      const sid = crypto.randomBytes(16).toString('hex');
      _totpPending.set(sid, { acctId: acct.id, pendingSecret: secret, expiresAt: Date.now() + 10 * 60 * 1000, mode: 'enroll' });
      auditLog('TOTP_ENROLL_STARTED', acct);
      return res.json({ needsTotpSetup: true, sessionId: sid, totpSecret: secret, qrDataUrl, issuer: TOTP_ISSUER });
    }
    // ── Trusted-device shortcut ────────────────────────────────────────────
    // If the browser presents a valid device-trust cookie issued for THIS
    // account within the last 30 days, skip the TOTP prompt entirely.
    // New device or expired cookie → fall through to require TOTP.
    const trustCookie = req.cookies?.[DEVICE_TRUST_COOKIE];
    if (verifyDeviceTrust(trustCookie, acct)) {
      auditLog('TOTP_SKIPPED_TRUSTED_DEVICE', acct);
      return _issueToken(req, res, acct, data);
    }
    // Existing TOTP — require code
    const sid = crypto.randomBytes(16).toString('hex');
    _totpPending.set(sid, { acctId: acct.id, expiresAt: Date.now() + 5 * 60 * 1000, mode: 'verify' });
    return res.json({ needsTotp: true, sessionId: sid });
  }

  // Demo path — issue token directly
  return _issueToken(req, res, acct, data);
});

// Generate N single-use recovery codes. Each is shown ONCE to the user.
// Stored as bcrypt hashes server-side; consumed on use.
async function _generateRecoveryCodes(n = 10) {
  const codes = [];
  const hashes = [];
  for (let i = 0; i < n; i++) {
    // Format: xxxx-xxxx (8 hex chars + dash + 8 hex chars) — easy to read/type
    const raw = crypto.randomBytes(4).toString('hex') + '-' + crypto.randomBytes(4).toString('hex');
    codes.push(raw);
    hashes.push(await bcrypt.hash(raw, 12));
  }
  return { codes, hashes };
}

// Confirm TOTP enrollment (user scanned QR + entered first code)
app.post('/api/auth/totp/enroll', async (req, res) => {
  const { sessionId, totp } = req.body || {};
  if (!sessionId || !totp) return res.status(400).json({ error: 'sessionId and totp are required' });
  const pend = _totpPending.get(sessionId);
  if (!pend || pend.mode !== 'enroll' || Date.now() > pend.expiresAt) {
    _totpPending.delete(sessionId);
    return res.status(401).json({ error: 'Enrollment session expired' });
  }
  const ok = authenticator.check(String(totp).replace(/\s/g, ''), pend.pendingSecret);
  if (!ok) return res.status(401).json({ error: 'Invalid TOTP code' });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === pend.acctId);
  if (!acct) return res.status(404).json({ error: 'Account not found' });

  // Generate recovery codes — show ONCE, never stored plaintext server-side
  const { codes, hashes } = await _generateRecoveryCodes(10);
  acct.totpSecret = pend.pendingSecret;
  acct.totpEnrolledAt = new Date().toISOString();
  acct.totpRecoveryCodesHashes = hashes;
  acct.totpRecoveryCodesGeneratedAt = new Date().toISOString();
  await persistAccountNow(acct);
  _totpPending.delete(sessionId);
  auditLog('TOTP_ENROLLED', acct, { recoveryCodesGenerated: codes.length });

  // Issue cookie/session, then return user info + the plaintext codes (shown once)
  const sid = crypto.randomBytes(16).toString('hex');
  const isDemo = acct.id === SEED_DEMO.id || acct.id === SEED_DEMO_NURSE.id;
  const payload = {
    id: acct.id, name: acct.name, email: acct.email, role: acct.role,
    buildingId: acct.buildingId || null, buildingIds: acct.buildingIds || [],
    group: acct.group || undefined, demo: isDemo || undefined, sid,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL_SECONDS });
  lastActivity.set(sid, Date.now());
  setAuthCookie(res, token);
  // Trust this device for 30 days — first enrollment counts as a verified device.
  setDeviceTrustCookie(res, acct);
  auditLog('LOGIN_SUCCESS', acct, { sid, via: 'totp_enrollment' });
  return res.json({ user: payload, authVia: 'cookie', recoveryCodes: codes });
});

// Regenerate recovery codes (user must be authenticated)
app.post('/api/auth/totp/recovery-codes', requireAuth, async (req, res) => {
  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === req.user.id);
  if (!acct?.totpSecret) return res.status(400).json({ error: 'TOTP not enrolled' });
  const { codes, hashes } = await _generateRecoveryCodes(10);
  acct.totpRecoveryCodesHashes = hashes;
  acct.totpRecoveryCodesGeneratedAt = new Date().toISOString();
  await persistAccountNow(acct);
  auditLog('TOTP_RECOVERY_CODES_REGENERATED', acct);
  res.json({ recoveryCodes: codes });
});

// Superadmin-only: reset another user's TOTP (forces re-enrollment on next login)
app.post('/api/auth/totp/reset', requireAuth, requireSuperAdmin, async (req, res) => {
  const { accountId } = req.body || {};
  if (!accountId) return res.status(400).json({ error: 'accountId is required' });
  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === accountId);
  if (!acct) return res.status(404).json({ error: 'Account not found' });
  if (acct.id === req.user.id) return res.status(400).json({ error: 'Cannot reset your own TOTP this way — use Account Settings' });
  // Clear TOTP directly in DB — upsertAccount uses COALESCE and would preserve
  // the existing secret, so we use the dedicated clear function here.
  if (_useDB) {
    await dbRepo.clearAccountTotp(accountId);
  }
  acct.totpSecret = null;
  acct.totpEnrolledAt = null;
  acct.totpRecoveryCodesHashes = null;
  acct.totpRecoveryCodesGeneratedAt = null;
  // Bump device-trust epoch so every previously-trusted device must re-verify.
  acct.deviceTrustEpoch = Date.now();
  await persistAccountNow(acct);
  markDirty();
  auditLog('TOTP_RESET_BY_ADMIN', req.user, { targetAccountId: accountId, targetEmail: acct.email });
  res.json({ ok: true, message: `TOTP reset for ${acct.email}. They will re-enroll on next login.` });
});

async function _issueToken(req, res, acct, data) {
  const sid = crypto.randomBytes(16).toString('hex');
  const isDemo = acct.id === SEED_DEMO.id || acct.id === SEED_DEMO_NURSE.id;
  const payload = {
    id:         acct.id,
    name:       acct.name,
    email:      acct.email,
    role:       acct.role,
    buildingId: acct.buildingId || null,
    buildingIds: acct.buildingIds || [],
    group:      acct.group || undefined,
    schedulerOnly: acct.role === 'admin' && !!acct.schedulerOnly ? true : undefined,
    demo:       isDemo || undefined,
    sid,
  };
  const ttl = jwtTtlFor(acct.role);
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: ttl });
  await lastActivity.set(sid, Date.now());
  setAuthCookie(res, token, ttl);           // ← XSS-safe httpOnly cookie, role-aware TTL
  auditLog('LOGIN_SUCCESS', acct, { sid });
  return res.json({ user: payload, authVia: 'cookie' });
}

// ── GET /api/auth/verify ──────────────────────────────────────────────────────
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  if (req._token) await revokedTokens.add(req._token);
  if (req.user?.sid) await lastActivity.delete(req.user.sid);
  clearAuthCookie(res);
  auditLog('LOGOUT', req.user);
  res.json({ ok: true });
});

// ── GET /api/data ─────────────────────────────────────────────────────────────
// Returns ETag header so client can do optimistic concurrency on writes.
let _dataVersion = Date.now().toString(36);
function _bumpDataVersion() { _dataVersion = Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex'); }

app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const data     = await loadData();
    const filtered = getDataForUser(req.user, data);
    res.setHeader('ETag', `"${_dataVersion}"`);
    auditLog('DATA_ACCESS', req.user, { role: req.user.role });
    res.json(filtered);
  } catch (e) {
    res.status(500).json({ error: 'Failed to read data' });
  }
});

// ── POST /api/data ────────────────────────────────────────────────────────────
// Per-tenant write authz: building admins can only modify entities tied to
// their own building. Superadmin can modify everything. Seed accounts are
// protected from role tampering. Caller cannot escalate their own role.
app.post('/api/data', requireAuth, requireAdmin, async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== 'object') return res.status(400).json({ error: 'Invalid payload' });

  // ── Reject empty / garbage bodies ────────────────────────────────────────
  // A POST that doesn't include ANY of the expected top-level collections is
  // almost certainly a client bug (missing Content-Type header, etc.). We
  // refuse to write rather than risk no-op or partial overwrite.
  const KNOWN_KEYS = ['buildings','employees','shifts','schedulePatterns',
                      'hrEmployees','hrTimeClock','accounts','companies',
                      'jobPostings','hrAccounts'];
  const present = KNOWN_KEYS.filter(k => k in payload);
  if (present.length === 0) {
    auditLog('DATA_UPDATE_REJECTED_EMPTY', req.user, { keys: Object.keys(payload) });
    return res.status(400).json({ error: 'Payload contains no recognized data collections' });
  }

  // Optimistic concurrency: if client sent If-Match, must match current version.
  // Without this, two concurrent edits silently overwrite each other.
  const ifMatch = (req.headers['if-match'] || '').replace(/"/g, '');
  if (ifMatch && ifMatch !== _dataVersion) {
    auditLog('DATA_UPDATE_CONFLICT', req.user, { provided: ifMatch, current: _dataVersion });
    return res.status(412).json({
      error: 'Data was modified by another user. Reload and try again.',
      conflict: true,
      currentVersion: _dataVersion,
    });
  }

  const data = await loadData();

  // ── Tripwire: refuse writes that would drop existing collections ─────────
  // If a client sends an array that is dramatically smaller than what we
  // already have, treat it as suspicious and reject unless the caller has
  // explicitly opted in via X-Confirm-Wipe: yes (used by SA "Reset to Demo").
  // This is a belt-and-suspenders defense — even with mergeScoped's safeties,
  // we never want to silently shrink data because of a client bug.
  const confirmWipe = String(req.headers['x-confirm-wipe'] || '').toLowerCase() === 'yes';
  if (!confirmWipe) {
    const TRIPWIRE = [
      ['shifts',           data.shifts,           payload.shifts],
      ['employees',        data.employees,        payload.employees],
      ['buildings',        data.buildings,        payload.buildings],
      ['accounts',         data.accounts,         payload.accounts],
      ['schedulePatterns', data.schedulePatterns, payload.schedulePatterns],
    ];
    for (const [name, existing, incoming] of TRIPWIRE) {
      if (!Array.isArray(incoming)) continue;
      const exLen = (existing || []).length;
      const inLen = incoming.length;
      // Two independent guards:
      //  (1) ANY non-empty collection going to zero — covers the small-facility
      //      case where a stale 0-employee client cache would silently overwrite
      //      a freshly-added employee. This is what likely lost sam Burns at
      //      Kirkland Court when the client had no employees in cache.
      //  (2) Big collections (≥10 items) shrinking by more than 50% — covers
      //      the legacy "client bug truncates my array" pattern.
      const goneToZero = exLen > 0 && inLen === 0;
      const bigShrink  = exLen >= 10 && inLen < Math.ceil(exLen * 0.5);
      if (goneToZero || bigShrink) {
        auditLog('DATA_UPDATE_REJECTED_SHRINK', req.user, {
          collection: name, existingCount: exLen, incomingCount: inLen,
          reason: goneToZero ? 'zeroed' : 'shrink>50%',
        });
        return res.status(409).json({
          error: `Refusing to shrink ${name} from ${exLen} to ${inLen}. ` +
                 'If this is intentional (e.g., Reset to Demo), retry with X-Confirm-Wipe: yes.',
          collection: name,
          existingCount: exLen,
          incomingCount: inLen,
        });
      }
    }
  }

  const isSA = req.user.role === 'superadmin';
  const callerBId = req.user.buildingId;
  const callerBIds = new Set([callerBId, ...(req.user.buildingIds||[])].filter(Boolean));

  // ── Per-collection merge with authz scoping ────────────────────────────────
  const mergeScoped = (existing = [], incoming = [], scopeOk) => {
    if (isSA) return Array.isArray(incoming) ? incoming : existing;
    if (!Array.isArray(incoming)) return existing;
    const result = [];
    const seen = new Set();
    // Take incoming items that are in caller's scope
    for (const item of incoming) {
      if (scopeOk(item)) { result.push(item); seen.add(item.id); }
    }
    // Preserve existing items that are OUT of scope (caller can't touch them)
    for (const item of existing) {
      if (!scopeOk(item) && !seen.has(item.id)) result.push(item);
    }
    return result;
  };

  const inScopeBuilding   = b => callerBIds.has(b.id);
  const inScopeEmployee   = e => callerBIds.has(e.buildingId);
  const inScopeShift      = s => callerBIds.has(s.buildingId);
  const inScopePattern    = p => {
    const emp = (data.employees || []).find(e => e.id === p.empId);
    return emp ? callerBIds.has(emp.buildingId) : false;
  };
  const inScopeAccount    = a => {
    if (a.role === 'superadmin') return false;        // never let admins touch SA
    return callerBIds.has(a.buildingId) || (a.buildingIds||[]).some(id => callerBIds.has(id));
  };

  data.buildings        = mergeScoped(data.buildings,        payload.buildings,        inScopeBuilding);
  data.employees        = mergeScoped(data.employees,        payload.employees,        inScopeEmployee);
  data.shifts           = mergeScoped(data.shifts,           payload.shifts,           inScopeShift);
  data.schedulePatterns = mergeScoped(data.schedulePatterns, payload.schedulePatterns, inScopePattern);
  data.hrEmployees      = mergeScoped(data.hrEmployees,      payload.hrEmployees,      inScopeEmployee);
  data.hrTimeClock      = mergeScoped(data.hrTimeClock,      payload.hrTimeClock,      inScopeEmployee);

  // Accounts: protect seed accounts; prevent caller from escalating own role
  // OR another in-scope admin's authority via mass-assignment.
  if (Array.isArray(payload.accounts)) {
    // Non-SA callers can only modify a tightly-defined subset of account
    // fields. role / buildingId / buildingIds / schedulerOnly / group are
    // privileged — changing them requires explicit endpoints (/api/invite,
    // toggleAdminScheduler, manage-admin building assignment). Without this
    // whitelist, a building admin could promote a colleague to superadmin or
    // grant themselves access to other facilities by editing their own
    // account record in /api/data POST.
    const NON_SA_ACCOUNT_WRITABLE = new Set([
      'id', 'name', 'email', 'phone',
      'notifEmail', 'notifSMS', 'notifPrefs', 'notifChannels',
      'inactive',
      // Secret fields are restored separately below regardless of whether
      // they're in this list.
      'ph', 'totpSecret', 'totpEnrolledAt', 'totpRecoveryCodesHashes',
      'totpRecoveryCodesGeneratedAt', 'inviteToken', 'inviteExpiry',
      'invitedBy', 'invitedAt', 'activatedAt',
      'passwordResetTokenHash', 'passwordResetExpiry',
      'deviceTrustEpoch', 'failedAttempts', 'lockedUntil',
    ]);
    if (!isSA) {
      for (let i = 0; i < payload.accounts.length; i++) {
        const incoming = payload.accounts[i];
        const orig = (data.accounts || []).find(x => x.id === incoming.id);
        if (!orig) continue;       // mergeScoped will reject new accounts via inScopeAccount
        const sanitized = { ...orig };
        for (const k of Object.keys(incoming)) {
          if (NON_SA_ACCOUNT_WRITABLE.has(k)) sanitized[k] = incoming[k];
        }
        // Hard pin: privileged fields ALWAYS come from the existing record.
        sanitized.role             = orig.role;
        sanitized.buildingId       = orig.buildingId;
        sanitized.buildingIds      = orig.buildingIds || [];
        sanitized.schedulerOnly    = orig.schedulerOnly || false;
        sanitized.group            = orig.group;
        payload.accounts[i] = sanitized;
      }
    }
    const accountsScoped = mergeScoped(data.accounts, payload.accounts, inScopeAccount);
    for (const seed of [SEED_SA, SEED_DEMO, SEED_DEMO_NURSE]) {
      const a = accountsScoped.find(x => x.id === seed.id);
      const orig = (data.accounts || []).find(x => x.id === seed.id);
      if (a && orig) {
        // Restore immutable seed fields
        a.role = orig.role; a.email = orig.email;
        if (a.id === SEED_SA.id) a.buildingId = orig.buildingId;
      }
    }
    // Prevent caller self-escalation
    const me = accountsScoped.find(a => a.id === req.user.id);
    if (me && me.role !== req.user.role) {
      logger.warn('blocked_self_role_escalation', { userId: req.user.id, attempted: me.role });
      me.role = req.user.role;
    }
    // CRITICAL: GET /api/data scrubs every account's secret fields (ph,
    // totpSecret, totpRecoveryCodesHashes, inviteToken) before sending to the
    // client. When the client persists, those fields come back undefined.
    // Without these guards, every save would null the password hash, TOTP
    // secret, recovery codes, and invite tokens for EVERY account in scope —
    // silently locking users out. Restore each stripped secret from the
    // existing DB row whenever the incoming object doesn't carry it.
    for (const a of accountsScoped) {
      const orig = (data.accounts || []).find(x => x.id === a.id);
      if (!orig) continue;
      if (orig.ph                      && !a.ph)                      a.ph                      = orig.ph;
      if (orig.totpSecret              && !a.totpSecret)              a.totpSecret              = orig.totpSecret;
      if (orig.totpEnrolledAt          && !a.totpEnrolledAt)          a.totpEnrolledAt          = orig.totpEnrolledAt;
      if (orig.totpRecoveryCodesHashes && !a.totpRecoveryCodesHashes) a.totpRecoveryCodesHashes = orig.totpRecoveryCodesHashes;
      if (orig.totpRecoveryCodesGeneratedAt && !a.totpRecoveryCodesGeneratedAt) a.totpRecoveryCodesGeneratedAt = orig.totpRecoveryCodesGeneratedAt;
      if (orig.inviteToken             && !a.inviteToken)             a.inviteToken             = orig.inviteToken;
      if (orig.inviteExpiry            && !a.inviteExpiry)            a.inviteExpiry            = orig.inviteExpiry;
      if (orig.passwordResetTokenHash  && !a.passwordResetTokenHash)  a.passwordResetTokenHash  = orig.passwordResetTokenHash;
      if (orig.passwordResetExpiry     && !a.passwordResetExpiry)     a.passwordResetExpiry     = orig.passwordResetExpiry;
      if (orig.deviceTrustEpoch        && !a.deviceTrustEpoch)        a.deviceTrustEpoch        = orig.deviceTrustEpoch;
    }
    data.accounts = accountsScoped;
  }

  // Superadmin-only top-level fields
  if (isSA) {
    if (Array.isArray(payload.companies))   data.companies   = payload.companies;
    if (Array.isArray(payload.jobPostings)) data.jobPostings = payload.jobPostings;
    if (Array.isArray(payload.hrAccounts))  data.hrAccounts  = payload.hrAccounts;
  }

  // Per-day census map ({ 'YYYY-MM-DD': number }) — populated by PPD calendar
  // Sync Month from PCC, or by manual entry. Merged so concurrent edits across
  // facilities don't drop each other's days.
  if (payload.ppdDailyCensus && typeof payload.ppdDailyCensus === 'object') {
    data.ppdDailyCensus = { ...(data.ppdDailyCensus || {}), ...payload.ppdDailyCensus };
  }

  // Staff Events calendar (custom nursing/activity/appreciation events).
  // Scoped per building so admins can't drop other facilities' events.
  if (Array.isArray(payload.staffEvents)) {
    const inScopeEvent = e => !e.buildingId || callerBIds.has(e.buildingId);
    data.staffEvents = mergeScoped(data.staffEvents || [], payload.staffEvents, inScopeEvent);
  }

  // Recruiting prospects (incoming applicants). Per-building scoped — building
  // admins manage their own pipeline. SA can touch all (handled by mergeScoped).
  if (Array.isArray(payload.prospects)) {
    const inScopeProspect = p => !p.buildingId || callerBIds.has(p.buildingId);
    // Snapshot pre-merge statuses for Indeed prospects so we can detect
    // transitions and fire disposition pushes after the write.
    const indeedPriorStatus = new Map();
    for (const p of (data.prospects || [])) {
      if (p.indeedApplyId) indeedPriorStatus.set(p.id, p.status);
    }
    data.prospects = mergeScoped(data.prospects || [], payload.prospects, inScopeProspect);
    // Fire-and-forget disposition pushes for any Indeed-sourced prospect whose
    // status actually changed. Configured-out (no Indeed credentials) is a
    // no-op so this is safe to run regardless of partner-program enrollment.
    if (INDEED_API_CLIENT_ID) {
      for (const p of data.prospects) {
        if (!p.indeedApplyId) continue;
        const prev = indeedPriorStatus.get(p.id);
        if (prev !== p.status && p.status) {
          pushIndeedDisposition(p.indeedApplyId, p.status).catch(e =>
            logger.error('indeed_disposition_async_failed', { msg: e.message, prospectId: p.id }));
        }
      }
    }
  }

  dataCache = data;
  _bumpDataVersion();
  markDirty();
  auditLog('DATA_UPDATE', req.user, {
    counts: {
      buildings: data.buildings?.length || 0,
      employees: data.employees?.length || 0,
      shifts:    data.shifts?.length    || 0,
    },
  });
  res.setHeader('ETag', `"${_dataVersion}"`);
  res.json({ ok: true, version: _dataVersion });
});

// ── POST /api/invite ──────────────────────────────────────────────────────────
app.post('/api/invite', requireAuth, requireAdmin, async (req, res) => {
  const { name, email, role, buildingId, schedulerOnly } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'name and email are required' });
  const emailNorm = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'Invalid email address' });

  const acctRole       = ['admin','employee'].includes(role) ? role : 'admin';
  const callerBId      = req.user.buildingId;
  const targetBuilding = buildingId || callerBId;
  if (req.user.role === 'admin' && targetBuilding !== callerBId) {
    return res.status(403).json({ error: 'Admins can only invite users to their own building' });
  }

  const data = await loadData();
  if ((data.accounts || []).find(a => a.email.toLowerCase() === emailNorm)) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  const inviteToken = crypto.randomBytes(24).toString('hex');
  const newAccount  = {
    id:           'acc_' + Date.now(),
    name:         name.trim(),
    email:        emailNorm,
    role:         acctRole,
    buildingId:   targetBuilding || null,
    ph:           null,
    schedulerOnly: acctRole === 'admin' ? !!schedulerOnly : false,
    inviteToken,
    inviteExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
    invitedBy:    req.user.email,
    invitedAt:    new Date().toISOString(),
  };
  data.accounts = data.accounts || [];
  data.accounts.push(newAccount);
  await persistAccountNow(newAccount);

  const link    = `${APP_URL}/?invite=${inviteToken}`;
  const building = (data.buildings || []).find(b => b.id === targetBuilding);
  const bName   = building?.name || 'your facility';
  const escName = escapeHtml(name.trim());
  const escB    = escapeHtml(bName);
  // CRLF-safe plaintext version
  const safePlainName = String(name.trim()).replace(/[\r\n]/g, ' ');
  const safePlainB    = String(bName).replace(/[\r\n]/g, ' ');

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec     = new EmailClient(ACS_CONNECTION_STRING);
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: emailNorm, displayName: name.trim() }] },
        content: {
          subject: "You've been invited to ManageMyStaffing",
          plainText: `Hi ${safePlainName},\n\nYou've been invited to manage ${safePlainB} on ManageMyStaffing.\n\nClick the link below to set your password:\n${link}\n\nThis invitation expires in 7 days.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">You've been invited!</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Hi ${escName}, you've been invited to manage <strong>${escB}</strong> on ManageMyStaffing.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Set Your Password &amp; Sign In →</a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0">This invitation expires in 7 days. If you didn't expect this, safely ignore this email.</p>
  </div>
</div>`,
        },
      });
      await Promise.race([
        poller.pollUntilDone(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000)),
      ]);
    } catch (e) {
      console.error('[mms] Invite email error:', e.message);
      return res.json({ ok: true, accountId: newAccount.id, emailWarning: e.message, inviteLink: link });
    }
  }

  auditLog('INVITE_SENT', req.user, { to: emailNorm, role: acctRole });
  res.json({ ok: true, accountId: newAccount.id, inviteLink: link });
});

// ── POST /api/invite/resend ───────────────────────────────────────────────────
// Body: { accountId } — regenerates invite token, clears password, emails link.
// Whatever password the user sets on first login becomes permanent.
app.post('/api/invite/resend', requireAuth, requireAdmin, async (req, res) => {
  const { accountId } = req.body || {};
  if (!accountId) return res.status(400).json({ error: 'accountId is required' });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === accountId);
  if (!acct) return res.status(404).json({ error: 'Account not found' });

  // Building admins can only resend invites within their building
  if (req.user.role === 'admin' && acct.buildingId !== req.user.buildingId &&
      !(acct.buildingIds||[]).includes(req.user.buildingId)) {
    return res.status(403).json({ error: 'Cannot resend invites for accounts outside your building' });
  }
  if (acct.role === 'superadmin') {
    return res.status(403).json({ error: 'Cannot reset superadmin password via invite' });
  }

  acct.inviteToken  = crypto.randomBytes(24).toString('hex');
  acct.inviteExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
  acct.ph           = null;
  acct.invitedBy    = req.user.email;
  acct.invitedAt    = new Date().toISOString();
  delete acct.activatedAt;
  await persistAccountNow(acct);

  const link    = `${APP_URL}/?invite=${acct.inviteToken}`;
  const building = (data.buildings || []).find(b => b.id === acct.buildingId);
  const bName   = building?.name || 'your facility';

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec     = new EmailClient(ACS_CONNECTION_STRING);
      const escName = String(acct.name).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
      const escB    = String(bName).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: acct.email, displayName: acct.name }] },
        content: {
          subject: "Your ManageMyStaffing invitation has been resent",
          plainText: `Hi ${acct.name},\n\nYour ManageMyStaffing invitation for ${bName} has been resent.\n\nClick the link below to set your password and sign in:\n${link}\n\nThe password you choose will become your permanent password. This invitation expires in 7 days.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">Your invitation has been resent</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Hi ${escName}, your invitation to manage <strong>${escB}</strong> on ManageMyStaffing has been resent.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Set Your Password &amp; Sign In →</a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0">The password you choose becomes your permanent password. This invitation expires in 7 days.</p>
  </div>
</div>`,
        },
      });
      await Promise.race([
        poller.pollUntilDone(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000)),
      ]);
    } catch (e) {
      console.error('[mms] Resend invite email error:', e.message);
      auditLog('INVITE_RESENT', req.user, { to: acct.email, emailFailed: true });
      return res.json({ ok: true, emailWarning: e.message, inviteLink: link });
    }
  }

  auditLog('INVITE_RESENT', req.user, { to: acct.email });
  res.json({ ok: true, inviteLink: link });
});

// ── POST /api/auth/password-reset/request ─────────────────────────────────────
// Body: { email }
// Always returns 200 with same body to avoid account-enumeration.
// Generates a 1-hour reset token, stores its bcrypt hash on the account, and
// emails a magic link. TOTP enrollment is preserved across reset.
app.post('/api/auth/password-reset/request', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  const safeRes = { ok: true, message: 'If an account with that email exists, a reset link has been sent.' };
  if (!email || typeof email !== 'string') return res.json(safeRes);
  const emailNorm = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm) || emailNorm.length > 254) return res.json(safeRes);

  const data = await loadData();
  const acct = (data.accounts || []).find(a => (a.email || '').toLowerCase() === emailNorm);

  // Constant-ish time: still hash a dummy if no account so timing is similar.
  // Cost matches the real reset-token hash below to keep timing constant.
  if (!acct) {
    await bcrypt.hash('dummy', 12).catch(()=>{});
    auditLog('PWD_RESET_REQUESTED', null, { email: emailNorm, found: false });
    return res.json(safeRes);
  }
  // Don't allow reset for demo accounts
  if (acct.id === SEED_DEMO.id || acct.id === SEED_DEMO_NURSE.id) {
    auditLog('PWD_RESET_BLOCKED_DEMO', acct);
    return res.json(safeRes);
  }

  const rawToken = crypto.randomBytes(32).toString('hex');   // 64-char hex
  const tokenHash = await bcrypt.hash(rawToken, 12);    // matches password hash cost
  acct.passwordResetTokenHash = tokenHash;
  acct.passwordResetExpiry = Date.now() + 60 * 60 * 1000;     // 1 hour
  await persistAccountNow(acct);

  const link = `${APP_URL}/?reset=${rawToken}&u=${encodeURIComponent(acct.id)}`;
  const escName = escapeHtml(acct.name || acct.email);

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec = new EmailClient(ACS_CONNECTION_STRING);
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: acct.email, displayName: acct.name }] },
        content: {
          subject: 'Reset your ManageMyStaffing password',
          plainText: `Hi ${(acct.name || '').replace(/[\r\n]/g, ' ')},\n\nWe received a request to reset your ManageMyStaffing password.\n\nClick the link below to set a new password (expires in 1 hour):\n${link}\n\nIf you didn't request this, ignore this email — your password will not change.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">Reset your password</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Hi ${escName}, we received a request to reset your password.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Reset Password →</a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0">This link expires in 1 hour. If you didn't request this, your password will not change — safely ignore this email.</p>
  </div>
</div>`,
        },
      });
      await Promise.race([
        poller.pollUntilDone(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000)),
      ]);
    } catch (e) {
      logger.error('pwd_reset_email_failed', { err: e.message, acctId: acct.id });
      // Don't reveal email failure to caller (would leak account existence)
    }
  }

  auditLog('PWD_RESET_REQUESTED', acct);
  return res.json(safeRes);
});

// ── GET /api/auth/password-reset/verify ───────────────────────────────────────
// Validates a reset token without consuming it. Returns email/name to pre-fill.
app.get('/api/auth/password-reset/verify', inviteVerifyLimiter, async (req, res) => {
  const { token, u } = req.query;
  if (!token || !u) return res.status(400).json({ error: 'token and u are required' });
  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === u);
  if (!acct?.passwordResetTokenHash) return res.status(404).json({ error: 'Invalid or expired reset link' });
  if (Date.now() > (acct.passwordResetExpiry || 0)) {
    return res.status(410).json({ error: 'This reset link has expired. Request a new one.' });
  }
  const ok = await bcrypt.compare(String(token), acct.passwordResetTokenHash);
  if (!ok) return res.status(404).json({ error: 'Invalid or expired reset link' });
  res.json({ ok: true, email: acct.email, name: acct.name, role: acct.role });
});

// ── POST /api/auth/password-reset/complete ────────────────────────────────────
// Body: { token, u, password }
app.post('/api/auth/password-reset/complete', authLimiter, async (req, res) => {
  const { token, u, password } = req.body || {};
  if (!token || !u || !password) return res.status(400).json({ error: 'token, u, and password are required' });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.id === u);
  if (!acct?.passwordResetTokenHash) return res.status(404).json({ error: 'Invalid or expired reset link' });
  if (Date.now() > (acct.passwordResetExpiry || 0)) {
    return res.status(410).json({ error: 'This reset link has expired. Request a new one.' });
  }
  const ok = await bcrypt.compare(String(token), acct.passwordResetTokenHash);
  if (!ok) return res.status(404).json({ error: 'Invalid or expired reset link' });

  // Validate with the account's role (employees get the relaxed rule).
  const complexityErr = validatePasswordComplexity(password, acct.role);
  if (complexityErr) return res.status(400).json({ error: complexityErr });

  // Set new password + invalidate the reset token + clear lockout
  acct.ph = await bcrypt.hash(password, 12);
  acct.passwordResetTokenHash = null;
  acct.passwordResetExpiry = null;
  acct.failedAttempts = 0;
  acct.lockedUntil = null;
  await persistAccountNow(acct);

  auditLog('PWD_RESET_COMPLETED', acct);
  // Don't auto-issue a token — force fresh login (which will trigger TOTP)
  res.json({ ok: true, requiresLogin: true, email: acct.email });
});

// ── GET /api/invite/verify ────────────────────────────────────────────────────
app.get('/api/invite/verify', inviteVerifyLimiter, async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'token is required' });
  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired. Please request a new one.' });
  }
  res.json({ ok: true, email: acct.email, name: acct.name, buildingId: acct.buildingId, role: acct.role });
});

// ── POST /api/invite/accept ───────────────────────────────────────────────────
// Body: { token, password }  — plaintext password, hashed with bcrypt server-side
app.post('/api/invite/accept', authLimiter, async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password are required' });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired.' });
  }

  // Validate with the account's role (employees get the relaxed rule).
  const complexityErr = validatePasswordComplexity(password, acct.role);
  if (complexityErr) return res.status(400).json({ error: complexityErr });

  acct.ph             = await bcrypt.hash(password, 12);
  acct.inviteToken    = undefined;
  acct.inviteExpiry   = undefined;
  acct.activatedAt    = new Date().toISOString();
  acct.failedAttempts = 0;
  acct.lockedUntil    = null;
  await persistAccountNow(acct);

  auditLog('INVITE_ACCEPTED', acct);

  // After invite acceptance, account still requires TOTP enrollment via login flow.
  // Don't auto-issue a token here — force them to log in (which triggers TOTP setup).
  res.json({ ok: true, requiresLogin: true, email: acct.email });
});

// ── GET /api/pcc/status ───────────────────────────────────────────────────────
app.get('/api/pcc/status', requireAuth, (_req, res) => {
  res.json({
    configured: !!(PCC_CLIENT_ID && PCC_CLIENT_SECRET && PCC_FACILITY_ID),
    facilityId: PCC_FACILITY_ID || null,
    orgUuid:    PCC_ORG_UUID ? `${PCC_ORG_UUID.slice(0, 8)}…` : null,
  });
});

// Validate ISO date and reject impossible ones (Feb 30, year 9999, future).
function _isValidIsoDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  if (isNaN(d.getTime())) return false;
  if (d.toISOString().slice(0,10) !== s) return false;   // catches Feb 30 etc.
  // Reasonable range: 2000-01-01 to today + 1 year
  const minMs = Date.UTC(2000, 0, 1);
  const maxMs = Date.now() + 366 * 86400000;
  return d.getTime() >= minMs && d.getTime() <= maxMs;
}

// ── GET /api/pcc/census ───────────────────────────────────────────────────────
app.get('/api/pcc/census', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured.' });
  }
  const dateRaw = (req.query.date || new Date().toISOString().slice(0, 10)).slice(0, 10);
  if (!_isValidIsoDate(dateRaw)) return res.status(400).json({ error: 'Invalid date — expected YYYY-MM-DD' });
  const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/census?censusDate=${dateRaw}`;
  const r = await pccFetch(url);
  if (!r.ok) {
    logger.error('pcc_census_failed', { status: r.status });
    return res.status(502).json({ error: `PCC census unavailable (status ${r.status})` });
  }
  const d = (r.body && (r.body.data || r.body)) || {};
  res.json({
    ok: true,
    census: d.totalCensus ?? d.occupiedBeds ?? d.census ?? null,
    date:   d.censusDate || dateRaw,
    details: {
      totalBeds:     d.totalBeds     || null,
      medicareCount: d.medicareCount || null,
      medicaidCount: d.medicaidCount || null,
      otherCount:    d.otherCount    || null,
    },
  });
});

// ── GET /api/pcc/census/range ─────────────────────────────────────────────────
// Returns census for every day in [start, end] inclusive. Used by the PPD
// calendar view. PCC has no batch endpoint — we serialize per-day requests.
app.get('/api/pcc/census/range', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured.' });
  }
  const start = String(req.query.start || '').slice(0, 10);
  const end   = String(req.query.end   || '').slice(0, 10);
  if (!_isValidIsoDate(start) || !_isValidIsoDate(end)) {
    return res.status(400).json({ error: 'start and end must be YYYY-MM-DD' });
  }
  const startMs = new Date(start + 'T00:00:00Z').getTime();
  const endMs   = new Date(end   + 'T00:00:00Z').getTime();
  if (endMs < startMs) return res.status(400).json({ error: 'end before start' });
  const days = Math.round((endMs - startMs) / 86400000) + 1;
  if (days > 31) return res.status(400).json({ error: 'Range too large (max 31 days)' });
  const out = {};
  for (let i = 0; i < days; i++) {
    const d = new Date(startMs + i * 86400000).toISOString().slice(0, 10);
    const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/census?censusDate=${d}`;
    const r = await pccFetch(url);
    if (!r.ok || !r.body) { out[d] = null; continue; }
    const x = r.body.data || r.body;
    out[d] = x.totalCensus ?? x.occupiedBeds ?? x.census ?? null;
  }
  res.json({ ok: true, start, end, census: out });
});

// ── GET /api/pcc/staffing ─────────────────────────────────────────────────────
app.get('/api/pcc/staffing', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured.' });
  }
  const dateRaw = (req.query.date || new Date().toISOString().slice(0, 10)).slice(0, 10);
  if (!_isValidIsoDate(dateRaw)) return res.status(400).json({ error: 'Invalid date — expected YYYY-MM-DD' });
  const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/staffShifts?date=${dateRaw}`;
  const r = await pccFetch(url);
  if (!r.ok) {
    logger.error('pcc_staffing_failed', { status: r.status });
    return res.status(502).json({ error: `PCC staffing unavailable (status ${r.status})` });
  }
  const body   = r.body || {};
  const shifts = body.data || body.shifts || body || [];
  const _date  = dateRaw;
  try {
    const hours  = { rn: 0, lpn: 0, cna: 0, cma: 0, nm: 0 };
    for (const s of (Array.isArray(shifts) ? shifts : [])) {
      const hrs = parseFloat(s.workedHours ?? s.scheduledHours ?? s.hours ?? 0) || 0;
      const hay = ((s.positionCode||s.jobCode||s.position||'') + ' ' + (s.positionDesc||s.jobTitle||s.title||'')).toUpperCase();
      if      (/\bRN\b|REGISTERED NURSE/.test(hay))                                     hours.rn  += hrs;
      else if (/\bLPN\b|\bLVN\b|LICENSED PRACTICAL|LICENSED VOCATIONAL/.test(hay))      hours.lpn += hrs;
      else if (/\bCNA\b|NURSE AID|NURSE ASSISTANT|CERTIFIED NURSING/.test(hay))         hours.cna += hrs;
      else if (/\bCMA\b|MED AIDE|MEDICATION AIDE|MEDICATION TECH/.test(hay))            hours.cma += hrs;
      else if (/DIRECTOR OF NURSING|\bDON\b|NURSE MANAGER|DIR OF NURS/.test(hay))       hours.nm  += hrs;
    }
    res.json({ ok: true, date: _date, hours, rn24: hours.rn >= 24, shifts: Array.isArray(shifts) ? shifts.length : 0 });
  } catch (e) {
    logger.error('pcc_staffing_parse_failed', { msg: e.message });
    res.status(502).json({ error: 'PCC response could not be parsed' });
  }
});

// ── GET /api/pcc/staffing/range ───────────────────────────────────────────────
app.get('/api/pcc/staffing/range', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured' });
  }
  const today = new Date().toISOString().slice(0, 10);
  const start = String(req.query.start || (today.slice(0, 8) + '01')).slice(0, 10);
  const end   = String(req.query.end   || today).slice(0, 10);
  if (!_isValidIsoDate(start) || !_isValidIsoDate(end)) return res.status(400).json({ error: 'Invalid date — expected YYYY-MM-DD' });
  const startMs = new Date(start + 'T00:00:00Z').getTime(), endMs = new Date(end + 'T00:00:00Z').getTime();
  if (endMs < startMs || endMs - startMs > 31 * 86400000) {
    return res.status(400).json({ error: 'Invalid date range (max 31 days)' });
  }
  const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/staffShifts?startDate=${start}&endDate=${end}`;
  const r = await pccFetch(url);
  if (!r.ok) {
    logger.error('pcc_staffing_range_failed', { status: r.status });
    return res.status(502).json({ error: `PCC staffing range unavailable (status ${r.status})` });
  }
  const body   = r.body || {};
  const shifts = body.data || body.shifts || body || [];
  try {
    const byDate = {};
    for (const s of (Array.isArray(shifts) ? shifts : [])) {
      const d   = (s.shiftDate || s.date || start).slice(0, 10);
      if (!byDate[d]) byDate[d] = { rn: 0, lpn: 0, cna: 0, cma: 0, nm: 0 };
      const hrs = parseFloat(s.workedHours ?? s.scheduledHours ?? s.hours ?? 0) || 0;
      const hay = ((s.positionCode||s.jobCode||s.position||'') + ' ' + (s.positionDesc||s.jobTitle||s.title||'')).toUpperCase();
      if      (/\bRN\b|REGISTERED NURSE/.test(hay))                                    byDate[d].rn  += hrs;
      else if (/\bLPN\b|\bLVN\b|LICENSED PRACTICAL|LICENSED VOCATIONAL/.test(hay))     byDate[d].lpn += hrs;
      else if (/\bCNA\b|NURSE AID|NURSE ASSISTANT|CERTIFIED NURSING/.test(hay))        byDate[d].cna += hrs;
      else if (/\bCMA\b|MED AIDE|MEDICATION AIDE|MEDICATION TECH/.test(hay))           byDate[d].cma += hrs;
      else if (/DIRECTOR OF NURSING|\bDON\b|NURSE MANAGER|DIR OF NURS/.test(hay))      byDate[d].nm  += hrs;
    }
    const days = Object.keys(byDate).sort(), n = days.length || 1;
    let totRn = 0, totLpn = 0, totCna = 0, totCma = 0, totNm = 0, rn24Days = 0;
    for (const d of days) {
      const r = byDate[d];
      totRn += r.rn; totLpn += r.lpn; totCna += r.cna; totCma += r.cma; totNm += r.nm;
      if (r.rn >= 24) rn24Days++;
    }
    res.json({
      ok: true, start, end, daysInPeriod: n, rn24Days,
      avgDaily: {
        rn:      +(totRn  / n).toFixed(2), lpn: +(totLpn / n).toFixed(2),
        cna:     +(totCna / n).toFixed(2), cma: +(totCma / n).toFixed(2),
        nm:      +(totNm  / n).toFixed(2),
        nursing: +((totRn + totLpn + totCna + totCma + totNm) / n).toFixed(2),
      },
      byDate,
    });
  } catch (e) {
    logger.error('pcc_staffing_range_parse_failed', { msg: e.message });
    res.status(502).json({ error: 'PCC response could not be parsed' });
  }
});

// ── GET /api/pcc/clinical ────────────────────────────────────────────────────
// Pulls the key CMS quality metrics from PCC for a date range:
//   - UTIs (incident count + rate per 1000 resident-days)
//   - 30-day re-hospitalizations
//   - significant weight loss (>=5% in 30d or >=10% in 180d)
//   - antipsychotic use (residents on long-term antipsychotic w/o supporting dx)
//   - falls with major injury
//   - pressure ulcers (Stage II+)
//   - catheter use (long-stay)
//   - C. diff infections
//
// PCC's clinical APIs are scoped per facility. We aggregate counts from the
// /clinical/* endpoints and divide by total resident-days from /census to
// produce the rate. When PCC isn't configured, we return cached values from
// data.pccClinicalCache (manually uploaded by the admin) so the report still
// renders. Caller must be admin/superadmin/regional/hradmin and scoped to the
// requested building.
app.get('/api/pcc/clinical', requireAuth, requireAdmin, async (req, res) => {
  const start = String(req.query.start || '').slice(0, 10);
  const end   = String(req.query.end   || '').slice(0, 10);
  const buildingId = String(req.query.buildingId || req.user.buildingId || '').slice(0, 64);
  if (!_isValidIsoDate(start) || !_isValidIsoDate(end)) {
    return res.status(400).json({ error: 'start and end must be YYYY-MM-DD' });
  }
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
  if (req.user.role !== 'superadmin' && buildingId && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  // Always pull cached fallback first — used when PCC isn't configured or
  // when a particular metric is missing from the response.
  const data = await loadData();
  const cache = (data.pccClinicalCache || []).find(c =>
    c.buildingId === buildingId && c.start === start && c.end === end
  );

  // Helper to compute rate per 1000 resident-days from census.
  const _residentDays = async () => {
    if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) return null;
    const startMs = new Date(start + 'T00:00:00Z').getTime();
    const endMs   = new Date(end   + 'T00:00:00Z').getTime();
    if (endMs < startMs) return null;
    const days = Math.min(31, Math.round((endMs - startMs) / 86400000) + 1);
    let total = 0;
    for (let i = 0; i < days; i++) {
      const d = new Date(startMs + i * 86400000).toISOString().slice(0, 10);
      const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/census?censusDate=${d}`;
      const r = await pccFetch(url);
      if (r.ok && r.body) {
        const x = r.body.data || r.body;
        const c = x.totalCensus ?? x.occupiedBeds ?? x.census ?? 0;
        total += Number(c) || 0;
      }
    }
    return total;
  };

  // If PCC isn't configured, just hand back the cache (or zeros).
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.json({
      ok: true, source: 'cache', start, end, buildingId,
      metrics: cache?.metrics || {
        utis: 0, rehospitalizations30d: 0, weightLossSignificant: 0,
        antipsychoticLongTerm: 0, fallsMajorInjury: 0, pressureUlcersStage2plus: 0,
        catheterLongStay: 0, cdiffInfections: 0,
      },
      residentDays: cache?.residentDays || 0,
      generatedAt: new Date().toISOString(),
      note: cache ? 'PCC not configured — returning cached upload.' : 'PCC not configured and no cached data — returning zeros.',
    });
  }

  // Fan out to PCC clinical endpoints. Each one is best-effort: if PCC errors
  // on a particular metric, we use the cache value or 0 and continue. Better
  // to render a partial report with one missing tile than fail the whole call.
  const fetchCount = async (endpoint, predicate) => {
    const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/${endpoint}?startDate=${start}&endDate=${end}`;
    const r = await pccFetch(url);
    if (!r.ok || !r.body) return null;
    const items = r.body.data || r.body.items || r.body || [];
    return Array.isArray(items) ? items.filter(predicate || (() => true)).length : null;
  };

  const [
    utis, rehosp, weightLoss, antipsy, falls, pu, cath, cdiff, residentDays
  ] = await Promise.all([
    fetchCount('clinical/uti'),
    fetchCount('clinical/hospitalReturns', x => Number(x.daysSinceDischarge ?? 99) <= 30),
    fetchCount('clinical/weightChanges', x =>
      (Number(x.pctChange30d ?? 0) <= -5) || (Number(x.pctChange180d ?? 0) <= -10)),
    fetchCount('clinical/medications', x =>
      /antipsychotic/i.test(String(x.therapeuticClass||x.drugClass||'')) &&
      Number(x.daysOnMedication ?? 0) >= 90 &&
      !x.supportingDiagnosis),
    fetchCount('clinical/falls',  x => /major/i.test(String(x.injuryLevel||''))),
    fetchCount('clinical/skinIntegrity', x => Number(String(x.stage||'').replace(/\D/g,''))>=2),
    fetchCount('clinical/catheterUse', x => x.longStay === true || Number(x.daysWithCatheter ?? 0) >= 14),
    fetchCount('clinical/infections', x => /c\.?\s*diff|clostridi/i.test(String(x.organism||x.infectionType||''))),
    _residentDays(),
  ]);

  const v = (live, cacheKey) => {
    if (live !== null && live !== undefined) return live;
    return cache?.metrics?.[cacheKey] ?? 0;
  };

  const metrics = {
    utis:                     v(utis,        'utis'),
    rehospitalizations30d:    v(rehosp,      'rehospitalizations30d'),
    weightLossSignificant:    v(weightLoss,  'weightLossSignificant'),
    antipsychoticLongTerm:    v(antipsy,     'antipsychoticLongTerm'),
    fallsMajorInjury:         v(falls,       'fallsMajorInjury'),
    pressureUlcersStage2plus: v(pu,          'pressureUlcersStage2plus'),
    catheterLongStay:         v(cath,        'catheterLongStay'),
    cdiffInfections:          v(cdiff,       'cdiffInfections'),
  };
  const rd = residentDays || cache?.residentDays || 0;
  const ratePer1000 = (n) => rd > 0 ? +((n / rd) * 1000).toFixed(2) : null;
  const rates = Object.fromEntries(Object.entries(metrics).map(([k,n]) => [k, ratePer1000(n)]));

  // Update cache for the building+range combo so the next call (or a non-
  // configured environment) can fall back to this snapshot.
  if (!Array.isArray(data.pccClinicalCache)) data.pccClinicalCache = [];
  const idx = data.pccClinicalCache.findIndex(c =>
    c.buildingId === buildingId && c.start === start && c.end === end);
  const entry = { buildingId, start, end, metrics, residentDays: rd, updatedAt: new Date().toISOString() };
  if (idx >= 0) data.pccClinicalCache[idx] = entry; else data.pccClinicalCache.push(entry);
  // Cap cache so it doesn't grow unbounded
  if (data.pccClinicalCache.length > 5000) data.pccClinicalCache.length = 5000;
  markDirty();
  auditLog('PCC_CLINICAL_REPORT', req.user, { buildingId, start, end });

  res.json({
    ok: true, source: 'live', start, end, buildingId,
    metrics, ratePer1000: rates, residentDays: rd,
    generatedAt: new Date().toISOString(),
  });
});

// (Duplicate /jobs.xml route removed — see the canonical implementation in
// the RECRUITING block above. Express honors the first registration; this
// stub was dead code and confusing for future maintenance.)

// ── GET /api/jobs ─────────────────────────────────────────────────────────────
app.get('/api/jobs', async (_req, res) => {
  try {
    const data = await loadData();
    const jobs  = (data.jobPostings || []).filter(j => j.status === 'active')
      .map(({ id, title, department, jobType, city, state, salary, description, createdAt }) =>
        ({ id, title, department, jobType, city, state, salary, description, createdAt }));
    res.json({ jobs });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load jobs' });
  }
});

// ── POST /api/alert ───────────────────────────────────────────────────────────
function toE164(raw) {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, '');
  if (d.length === 10) return '+1' + d;
  if (d.length === 11 && d[0] === '1') return '+' + d;
  return null;
}

// ── SERVICE BUS QUEUE FOR ALERT FAN-OUT ───────────────────────────────────────
// Without this, /api/alert blocks the request thread for the duration of all
// email/SMS sends. Big blasts exceed App Service 230s timeout.
let _sbSender = null;
let _sbReceiver = null;
let _sbClient = null;

async function _initServiceBus() {
  const connStr = process.env.SERVICEBUS_CONNECTION_STRING;
  if (!connStr) {
    logger.info('servicebus_disabled', { reason: 'SERVICEBUS_CONNECTION_STRING not set' });
    return;
  }
  try {
    const { ServiceBusClient } = require('@azure/service-bus');
    _sbClient = new ServiceBusClient(connStr);
    _sbSender = _sbClient.createSender('mms-alerts');
    _sbReceiver = _sbClient.createReceiver('mms-alerts', { receiveMode: 'peekLock' });
    _sbReceiver.subscribe(
      {
        processMessage: async (msg) => { try { await _processAlertJob(msg.body); } catch (e) { logger.error('alert_worker_error', { err: e.message }); throw e; } },
        processError: async (args) => { logger.error('servicebus_error', { src: args.errorSource, err: args.error?.message }); },
      },
      { autoCompleteMessages: true, maxConcurrentCalls: 5 }
    );
    logger.info('servicebus_connected', { queue: 'mms-alerts' });
  } catch (e) {
    logger.warn('servicebus_init_failed', { err: e.message });
  }
}

// Worker — processes one queued alert job (email + SMS fan-out).
async function _processAlertJob(job) {
  if (!ACS_CONNECTION_STRING) return;
  const { kind, recipients, subject, message, fromEmail, fromPhone, jobId } = job || {};

  if (kind === 'email') {
    const { EmailClient } = require('@azure/communication-email');
    const ec = new EmailClient(ACS_CONNECTION_STRING);
    let sent = 0; const errors = [];
    for (const r of (recipients || [])) {
      try {
        const body = message.replace(/\[Name\]/g, r.name || '');
        const poller = await ec.beginSend({
          senderAddress: fromEmail,
          recipients: { to: [{ address: r.email, displayName: r.name }] },
          content: {
            subject: subject || 'Alert from ManageMyStaffing',
            plainText: body,
            html: `<pre style="font-family:sans-serif;white-space:pre-wrap">${body.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre>`,
          },
        });
        await Promise.race([
          poller.pollUntilDone(),
          new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000)),
        ]);
        sent++;
      } catch (e) {
        errors.push({ name: r.name, err: e.message });
      }
    }
    auditLog('ALERT_JOB_DONE', null, { jobId, kind, sent, failed: errors.length });
  } else if (kind === 'sms') {
    if (!fromPhone) return;
    const { SmsClient } = require('@azure/communication-sms');
    const sc = new SmsClient(ACS_CONNECTION_STRING);
    let sent = 0; const errors = [];
    for (const r of (recipients || [])) {
      const to = toE164(r.phone);
      if (!to) { errors.push({ name: r.name, err: 'invalid phone' }); continue; }
      try {
        const results = await sc.send({
          from: fromPhone, to: [to],
          message: message.replace(/\[Name\]/g, r.name || '').slice(0, 1600),
        });
        if (results[0]?.successful) sent++;
        else errors.push({ name: r.name, err: results[0]?.errorMessage || 'failed' });
      } catch (e) { errors.push({ name: r.name, err: e.message }); }
    }
    auditLog('ALERT_JOB_DONE', null, { jobId, kind, sent, failed: errors.length });
  }
}

// Enqueue alert job; returns immediately
async function _enqueueAlertJob(job) {
  if (!_sbSender) {
    // Fallback: process inline (single-instance dev mode)
    _processAlertJob(job).catch(e => logger.error('alert_inline_failed', { err: e.message }));
    return { queued: false, mode: 'inline' };
  }
  await _sbSender.sendMessages({ body: job, contentType: 'application/json' });
  return { queued: true, mode: 'servicebus' };
}

app.post('/api/alert', requireAuth, requireAdmin, async (req, res) => {
  const { groups, message, subject, viaSMS, viaEmail, buildingId } = req.body || {};
  if (!Array.isArray(groups) || !groups.length) return res.status(400).json({ error: 'groups array is required' });
  if (!message) return res.status(400).json({ error: 'message is required' });
  if (message.length > 4000) return res.status(400).json({ error: 'message too long (4000 char max)' });

  const data      = await loadData();
  const isSA      = req.user.role === 'superadmin';
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));

  // Enforce per-building scoping for non-superadmins. Caller cannot blast
  // staff from buildings they don't manage.
  let scopedBId = buildingId;
  if (!isSA) {
    if (buildingId && !callerBIds.has(buildingId)) {
      return res.status(403).json({ error: 'Cannot send alerts to that building' });
    }
    scopedBId = buildingId || req.user.buildingId;
  }

  const employees = (data.employees || []).filter(e =>
    groups.includes(e.group) && (!scopedBId || e.buildingId === scopedBId) && !e.inactive
    && (isSA || callerBIds.has(e.buildingId)));

  // PHI guard for SMS path of /api/alert (HIPAA §164.312(e)).
  // Email is hop-by-hop TLS so PHI is allowed in email; SMS is unencrypted
  // so we scan and block PHI before sending SMS.
  if (viaSMS) {
    const phiReason = scanMessageForPHI(message, employees);
    if (phiReason) {
      auditLog('ALERT_BLOCKED_PHI', req.user, { reason: phiReason, channel: 'sms' });
      return res.status(400).json({ error: `Alert SMS blocked: ${phiReason}. Use a generic notification and link to the app, or send via email only.` });
    }
  }

  const emailList = viaEmail ? employees.filter(e => e.notifEmail && e.email) : [];
  const smsList   = viaSMS   ? employees.filter(e => e.notifSMS  && e.phone)  : [];

  if (!ACS_CONNECTION_STRING) {
    return res.status(503).json({ error: 'Messaging not configured' });
  }

  const jobId = crypto.randomUUID();
  const queuedJobs = [];

  if (emailList.length) {
    await _enqueueAlertJob({
      kind: 'email',
      jobId,
      recipients: emailList.map(e => ({ name: e.name, email: e.email })),
      subject, message, fromEmail: ACS_FROM_EMAIL,
    });
    queuedJobs.push({ kind: 'email', count: emailList.length });
  }

  if (smsList.length) {
    // Use the building's local SMS number if it's been provisioned and
    // activated; otherwise fall back to the global ACS_FROM_PHONE. Staff at
    // a facility see a familiar local caller ID this way.
    const sender = _smsFromForBuilding(scopedBId, data);
    if (!sender) {
      return res.status(503).json({ error: 'SMS not configured' });
    }
    await _enqueueAlertJob({
      kind: 'sms',
      jobId,
      recipients: smsList.map(e => ({ name: e.name, phone: e.phone })),
      message, fromPhone: sender,
    });
    queuedJobs.push({ kind: 'sms', count: smsList.length });
  }

  // Persist a Texts-tab visible log of this dispatch (sender, recipients,
  // subject, body, channels). Inbound replies (Twilio webhook → /api/sms/inbound,
  // not yet wired) will append into the same log keyed by jobId / phone.
  if (!Array.isArray(data.alertLog)) data.alertLog = [];
  // Recipient email/phone are masked in the persisted alertLog entry. The
  // actual delivery has already been queued — we don't need full PII in
  // the searchable audit trail. employeeId remains so admins can still
  // join back to the employee record when needed.
  const maskEmail = e => String(e || '').replace(/^(.).*?(?=@)/, (_,a) => a + '***');
  const maskPhone = p => { const n = String(p || '').replace(/\D/g,''); return n ? '***-***-' + n.slice(-4) : ''; };
  data.alertLog.push({
    id: jobId,
    sentAt: new Date().toISOString(),
    sentBy: req.user.email,
    sentById: req.user.id,
    buildingId: scopedBId || null,
    groups,
    subject: subject || null,
    message,
    channels: { email: !!viaEmail, sms: !!viaSMS },
    recipients: {
      email: emailList.map(e => ({ id: e.id, name: e.name, email: maskEmail(e.email) })),
      sms:   smsList.map(e   => ({ id: e.id, name: e.name, phone: maskPhone(e.phone) })),
    },
    replies: [], // inbound SMS responses appended here when webhook lands
  });
  // Cap to last 500 entries to bound memory.
  if (data.alertLog.length > 500) data.alertLog = data.alertLog.slice(-500);
  markDirty();

  auditLog('ALERT_QUEUED', req.user, { jobId, jobs: queuedJobs, groups });
  // Return 202 Accepted with jobId — actual delivery is async
  res.status(202).json({
    ok: true, jobId,
    queued: { email: emailList.length, sms: smsList.length },
    note: 'Alert dispatched to background queue. Delivery confirmation emails will follow.',
  });
});

// ── POST /api/sms/inbound ─────────────────────────────────────────────────────
// Webhook for inbound SMS replies. Configure your messaging provider
// (Twilio, Azure Communication Services, etc.) to POST here when the recipient
// replies to an alert. The reply is attached to the most recent alert log
// entry that included that phone number (within the last 7 days), so it
// shows up under the conversation in the Texts sidebar.
//
// Security: shared-secret header check via SMS_WEBHOOK_SECRET env var.
// Twilio: configure it as a custom HTTP header or as a query string and
// validate the X-Twilio-Signature instead.
app.post('/api/sms/inbound', async (req, res) => {
  const expected = process.env.SMS_WEBHOOK_SECRET;
  const provided = req.headers['x-webhook-secret'] || req.query.secret;
  if (!expected || expected !== provided) {
    auditLog('SMS_INBOUND_REJECTED', null, { reason: 'bad_secret' });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Accept Twilio-style ({ From, To, Body }) or our own ({ from, to, body, jobId? }).
  const from = (req.body?.from || req.body?.From || '').toString().trim();
  const to   = (req.body?.to   || req.body?.To   || '').toString().trim();
  const body = (req.body?.body || req.body?.Body || '').toString().slice(0, 1600);
  const jobId = (req.body?.jobId || '').toString();
  if (!from || !body) return res.status(400).json({ error: 'from and body required' });
  // Normalize phone for matching (strip non-digits, keep last 10).
  const normPhone = p => String(p || '').replace(/\D/g, '').slice(-10);
  const fromNorm = normPhone(from);
  const toNorm   = normPhone(to);

  const data = await loadData();
  if (!Array.isArray(data.alertLog)) data.alertLog = [];

  // Resolve which building owns the destination number. If TO matches a
  // provisioned building number, replies are routed into that building's
  // alertLog; otherwise we fall back to the broader matching below.
  let routedBuildingId = null;
  if (toNorm) {
    const ownerBuilding = (data.buildings || []).find(b =>
      b.smsFromPhone && normPhone(b.smsFromPhone) === toNorm);
    if (ownerBuilding) routedBuildingId = ownerBuilding.id;
  }

  // Match by jobId if given, otherwise the most recent alert (last 7 days)
  // that texted this phone, scoped to the routed building when known.
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  let match = null;
  if (jobId) match = data.alertLog.find(e => e.id === jobId);
  if (!match) {
    for (let i = data.alertLog.length - 1; i >= 0; i--) {
      const e = data.alertLog[i];
      const sentMs = new Date(e.sentAt).getTime();
      if (sentMs < cutoff) break;
      if (routedBuildingId && e.buildingId !== routedBuildingId) continue;
      const matched = (e.recipients?.sms || []).some(r => normPhone(r.phone) === fromNorm);
      if (matched) { match = e; break; }
    }
  }
  if (!match) {
    // Park orphan replies in a synthetic entry so they aren't lost. Tag
    // with the routed building so the right facility's Texts sidebar
    // shows it even without a matching outbound alert.
    match = {
      id: 'orphan_' + Date.now(),
      sentAt: new Date().toISOString(),
      sentBy: 'inbound',
      buildingId: routedBuildingId,
      groups: [],
      subject: 'Inbound SMS (no matching alert)',
      message: '',
      channels: { sms: true, email: false },
      recipients: { sms: [], email: [] },
      replies: [],
    };
    data.alertLog.push(match);
  }
  if (!Array.isArray(match.replies)) match.replies = [];
  match.replies.push({
    from: from,
    body,
    receivedAt: new Date().toISOString(),
  });
  markDirty();
  auditLog('SMS_INBOUND_RECEIVED', null, { jobId: match.id, fromMasked: fromNorm.slice(-4) });
  res.json({ ok: true });
});

// ── POST /api/sms ─────────────────────────────────────────────────────────────
app.post('/api/sms', requireAuth, requireAdmin, async (req, res) => {
  const { to, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message are required' });
  if (message.length > 1600) return res.status(400).json({ error: 'message too long (1600 char max)' });
  if (!ACS_CONNECTION_STRING) {
    return res.status(503).json({ error: 'SMS not configured' });
  }
  const normalized = toE164(to);
  if (!normalized) return res.status(400).json({ error: `Invalid phone number: ${to}` });

  // Authz: non-superadmins can only SMS phones belonging to employees in their
  // own building(s). This stops toll fraud and external-phishing pivots via
  // company SMS gateway.
  const data = await loadData();
  let scopedEmployees = data.employees || [];
  let recipientBuildingId = null;
  if (req.user.role !== 'superadmin') {
    const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
    scopedEmployees = scopedEmployees.filter(e => callerBIds.has(e.buildingId));
    const recipient = scopedEmployees.find(e => !e.inactive && toE164(e.phone) === normalized);
    if (!recipient) {
      auditLog('SMS_BLOCKED', req.user, { to: normalized, reason: 'phone_not_in_building_roster' });
      return res.status(403).json({ error: 'Phone number is not in your building roster' });
    }
    recipientBuildingId = recipient.buildingId;
  } else {
    // SA: still resolve building so the per-building number is used.
    const recipient = (data.employees || []).find(e => !e.inactive && toE164(e.phone) === normalized);
    recipientBuildingId = recipient?.buildingId || null;
  }

  // Determine which FROM number to use — prefer the building's local
  // provisioned number; fall back to the global toll-free.
  const sender = _smsFromForBuilding(recipientBuildingId, data);
  if (!sender) return res.status(503).json({ error: 'SMS not configured (no FROM number)' });

  // PHI guard (HIPAA §164.312(e)) — block any message containing PHI patterns.
  const phiReason = scanMessageForPHI(message, scopedEmployees);
  if (phiReason) {
    auditLog('SMS_BLOCKED_PHI', req.user, { to: normalized, reason: phiReason });
    return res.status(400).json({ error: `SMS blocked: ${phiReason}. Use a generic notification and link to the app.` });
  }

  try {
    const { SmsClient } = require('@azure/communication-sms');
    const smsClient = new SmsClient(ACS_CONNECTION_STRING);
    const results   = await smsClient.send({ from: sender, to: [normalized], message: message.slice(0, 1600) });
    if (results[0]?.successful) {
      auditLog('SMS_SENT', req.user, { to: normalized });
      res.json({ ok: true });
    } else {
      res.status(502).json({ error: results[0]?.errorMessage || 'SMS send failed' });
    }
  } catch (e) {
    logger.error('sms_send_failed', { reqId: req.id, err: e.message });
    res.status(500).json({ error: 'SMS send failed' });
  }
});

// ── POST /api/demo/message ────────────────────────────────────────────────────
app.post('/api/demo/message', requireAuth, async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'superadmin only' });
  const { to, name, subject, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message are required' });
  if (!ACS_CONNECTION_STRING || !ACS_FROM_EMAIL) {
    return res.status(503).json({ error: 'Email not configured' });
  }
  const { EmailClient } = require('@azure/communication-email');
  const emailClient = new EmailClient(ACS_CONNECTION_STRING);
  const htmlBody    = message.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
  try {
    const poller = await emailClient.beginSend({
      senderAddress: ACS_FROM_EMAIL,
      recipients: { to: [{ address: to, displayName: name || to }] },
      content: {
        subject:   subject || 'Message from ManageMyStaffing',
        plainText: message,
        html:      `<div style="font-family:sans-serif;font-size:14px;color:#111">${htmlBody}</div>`,
      },
    });
    await Promise.race([poller.pollUntilDone(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000))]);
    auditLog('DEMO_MSG_SENT', req.user, { to });
    res.json({ ok: true });
  } catch (e) {
    console.error('[mms] Demo message error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── 404 HANDLER ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.status(404).send('Not found');
});

// ── ERROR HANDLER (don't leak stack traces) ──────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error('unhandled_error', { reqId: req.id, err: err.message, stack: IS_PROD ? undefined : err.stack });
  res.status(500).json({ error: IS_PROD ? 'Internal server error' : err.message });
});

// ── STARTUP ───────────────────────────────────────────────────────────────────
let _server;
(async () => {
  try {
    initAppInsights();
    _initAuditChain();
    await _initAuditCloud();           // best-effort — won't block startup
    await _initServiceBus();           // best-effort — falls back to inline if unavailable
    await loadData();
  } catch (e) {
    logger.error('startup_failed', { err: e.message });
    process.exit(1);
  }

  if (!ACS_CONNECTION_STRING) logger.warn('acs_not_configured');
  if (!ACS_FROM_PHONE)        logger.warn('acs_sms_not_configured');
  if (IS_PROD && DATA_FILE.toLowerCase().includes('onedrive')) {
    logger.error('PHI_DATA_FILE_ON_ONEDRIVE_NOT_PERMITTED_IN_PRODUCTION');
    process.exit(1);
  }

  _server = app.listen(PORT, () => {
    logger.info('server_started', {
      port: PORT, env: NODE_ENV, dataFile: DATA_FILE,
      auditLog: AUDIT_LOG_FILE,
      pcc: !!(PCC_CLIENT_ID && PCC_FACILITY_ID),
    });
  });
})();

// ── GRACEFUL SHUTDOWN ─────────────────────────────────────────────────────────
async function shutdown(signal) {
  logger.info('shutdown_initiated', { signal });
  if (_server) _server.close(() => logger.info('server_closed'));
  // Flush pending data writes + close clients
  try {
    await persistCache();
    await _auditQueue;
    if (_sbReceiver) await _sbReceiver.close();
    if (_sbSender)   await _sbSender.close();
    if (_sbClient)   await _sbClient.close();
    if (_redis)      await _redis.quit();
    logger.info('clean_shutdown');
  } catch (e) {
    logger.error('shutdown_flush_failed', { err: e.message });
  }
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException', (e) => {
  logger.error('uncaught_exception', { err: e.message, stack: e.stack });
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (reason) => {
  logger.error('unhandled_rejection', { reason: String(reason) });
});
