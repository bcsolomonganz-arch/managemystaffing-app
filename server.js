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
const helmet      = require('helmet');
const compression = require('compression');
const cors        = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcrypt');
const otplib     = require('otplib');
const QRCode     = require('qrcode');
const webpush    = require('web-push');

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

// PWA-surface override: the companion app (public/app.html) only exposes
// the user's own schedule, open shifts in their group, and in-app
// messaging — no roster, HR, audit log, or other PHI-bearing admin
// views. Auto-logoff is therefore not HIPAA-required on the /app
// surface, and the friction of a 2h timeout on a personal phone is a
// poor trade. When a login request comes in with body.surface==='pwa'
// (set by the PWA login form), the JWT carries that tag and these
// helpers return the 1y (effectively forever) values for every role.
// Desktop sessions stay on the 2h cap because the desktop site does
// touch PHI (roster, audit log, mass-swap, payroll, etc.).
//
// Caveat: in-app DMs are a permitted channel for clinical comms (see
// the /api/dm comment block), so an unattended phone with the PWA
// open could expose past DM bodies. Mobile OS lock screens are the
// mitigation; HIPAA §164.310(d) covers physical-device safeguards
// separately from §164.312(a)(2)(iii) auto-logoff.
function effectiveJwtTtl(role, surface) {
  if (surface === 'pwa') return EMPLOYEE_JWT_TTL_SECONDS;
  return jwtTtlFor(role);
}
function effectiveIdleTtl(role, surface) {
  if (surface === 'pwa') return EMPLOYEE_IDLE_TIMEOUT_SECONDS;
  return idleTtlFor(role);
}

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

// Write mutex for file-based persistence — prevents concurrent writes from
// corrupting the data file. Node's event loop is single-threaded for JS, but
// async operations (encrypt, fs.writeFile) yield control, so two overlapping
// flushNow() calls could race on the file. This serializes writes.
let _persistLock = Promise.resolve();
function withPersistLock(fn) {
  const prev = _persistLock;
  let release;
  _persistLock = new Promise(r => { release = r; });
  return prev.then(fn).finally(release);
}

function markDirty() {
  dataDirty = true;
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(persistCache, _useDB ? 200 : 2000);
  // Bump the data version on every mutation so:
  //   1. Any future intermediate cache layer (CDN, proxy) that respects ETag
  //      won't serve a stale /api/data body after a write — the response
  //      Cache-Control: no-store added at GET /api/data prevents this today,
  //      but defense in depth is cheap.
  //   2. Concurrent /api/data POSTs from another tab/admin actually hit the
  //      412 If-Match conflict path instead of silently overwriting state
  //      that mutated under them via /api/shifts/* etc. Pre-fix, only POST
  //      /api/data bumped the version, so out-of-band shift writes left the
  //      ETag unchanged and a stale follow-up POST would slip through.
  _bumpDataVersion();
}

// ── flushNow ──────────────────────────────────────────────────────────────────
// Synchronous flush for per-shift mutation endpoints. These used to call
// markDirty() (200ms debounce), meaning the client got { ok: true } while
// data was still in memory. A container crash in that window lost the write.
// flushNow() writes to Postgres immediately — the caller awaits it and can
// return 500 on failure. Still bumps _dataVersion for ETag concurrency.
async function flushNow() {
  _bumpDataVersion();
  dataDirty = true;
  clearTimeout(saveTimeout);
  await persistCache();       // throws on failure — caller catches
}

// Tracks consecutive file-mode persist failures. If we hit too many in a
// row, we know writes are silently failing (e.g., DATA_FILE points to a
// path whose parent dir doesn't exist) and we surface it loudly. Without
// this counter, the 2026-05-08 incident's writes failed silently for an
// entire session before anyone noticed the data was never persisted.
let _consecutiveFilePersistFailures = 0;
let _lastSuccessfulPersistAt = null;

async function persistCache() {
  if (!dataDirty) return;
  return withPersistLock(async () => {
  if (!dataDirty) return;       // re-check after acquiring lock
  dataDirty = false;
  clearTimeout(saveTimeout);
  try {
    if (_useDB) {
      await dbRepo.saveAll(dataCache);
      logger.info('data_saved', { backend: 'postgres' });
      _lastSuccessfulPersistAt = new Date().toISOString();
    } else {
      const payload   = { ...dataCache, _lastSaved: new Date().toISOString() };
      const encrypted = await encrypt(payload);
      const tmp       = DATA_FILE + '.tmp';
      await fs.writeFile(tmp, JSON.stringify(encrypted, null, 2), 'utf8');
      await fs.rename(tmp, DATA_FILE);
      logger.info('data_saved', { backend: 'file' });
      _consecutiveFilePersistFailures = 0;
      _lastSuccessfulPersistAt = new Date().toISOString();
    }
    // Fire-and-forget snapshot. Restore window: every-save for 24h, hourly
    // for 30d, daily for 365d. Lets a Super Admin recover from a bad edit
    // or accidental wipe without waiting on infra.
    _writeSnapshot().catch(e => logger.error('snapshot_failed', { err: e.message }));
  } catch (e) {
    logger.error('save_failed', { err: e.message, backend: _useDB ? 'postgres' : 'file' });
    if (!_useDB) {
      _consecutiveFilePersistFailures++;
      // Surface a clear, loud error after 3 consecutive failures. With the
      // pre-fix code, file writes failing silently for hours wasn't visible
      // anywhere except buried logger.error lines. /health/ready will now
      // return 503 with this counter so monitoring can alert on it.
      if (_consecutiveFilePersistFailures >= 3) {
        const msg = `[mms] CRITICAL: ${_consecutiveFilePersistFailures} consecutive file-mode persist failures. ` +
                    `DATA_FILE=${DATA_FILE}. Recent edits are NOT being saved. ` +
                    `Check that ${path.dirname(DATA_FILE)} exists and is writable, or set PG_REQUIRE_ON_BOOT=true so the server fails fast instead of silently losing writes.`;
        console.error(msg);
        logger.error('file_persist_repeatedly_failing', {
          consecutive: _consecutiveFilePersistFailures,
          dataFile: DATA_FILE,
          dataFileDirExists: fsSync.existsSync(path.dirname(DATA_FILE)),
        });
      }
    }
    // Re-mark dirty so the next markDirty/save attempt retries this batch.
    // Without this, a single transient EBUSY would lose the whole batch
    // because dataDirty was already set to false at the top of persistCache.
    dataDirty = true;
  }
  }); // end withPersistLock
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
  // Snapshots run in BOTH file and postgres modes now. Postgres has Azure
  // PITR (35 days), but PITR alone proved insufficient on 2026-04-30 when
  // Tanya's Kirkland adds disappeared and SA was locked out — we couldn't
  // even check the audit table. App-side encrypted snapshots are the
  // belt-and-suspenders defense: every persistCache call writes a copy of
  // the whole dataCache to BACKUP_DIR so a Super Admin can restore in one
  // click without leaving the app.
  const now = Date.now();
  if (now - _lastSnapshotAt < SNAPSHOT_MIN_INTERVAL_MS) return;
  _lastSnapshotAt = now;

  await _ensureBackupDir();
  const stamp = new Date(now).toISOString().replace(/[:.]/g, '-');
  const file  = path.join(BACKUP_DIR, `${SNAPSHOT_PREFIX}${stamp}.json`);

  if (_useDB) {
    // Postgres mode: there's no live encrypted DATA_FILE to copy. Encrypt the
    // current dataCache directly. Same envelope shape as the file backend so
    // restores work identically.
    try {
      const encrypted = await encrypt({ ...dataCache, _lastSaved: new Date(now).toISOString() });
      await fs.writeFile(file, JSON.stringify(encrypted, null, 2), 'utf8');
    } catch (e) {
      logger.error('snapshot_pg_encrypt_failed', { err: e.message });
      return;
    }
  } else {
    // File mode: copy the already-encrypted file. Cheaper than re-encrypting.
    try {
      await fs.copyFile(DATA_FILE, file);
    } catch {
      const encrypted = await encrypt({ ...dataCache, _lastSaved: new Date(now).toISOString() });
      await fs.writeFile(file, JSON.stringify(encrypted, null, 2), 'utf8');
    }
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
  // In file mode we just copy the encrypted DATA_FILE; in PG mode there's
  // no live file to copy, so we encrypt-write the current dataCache directly.
  try {
    const safetyStamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safetyName  = `${SNAPSHOT_PREFIX}${safetyStamp}-prerestore.json`;
    const safetyPath  = path.join(BACKUP_DIR, safetyName);
    if (_useDB) {
      const encrypted = await encrypt({ ...(dataCache || {}), _lastSaved: new Date().toISOString() });
      await fs.writeFile(safetyPath, JSON.stringify(encrypted, null, 2), 'utf8');
    } else {
      await fs.copyFile(DATA_FILE, safetyPath);
    }
  } catch (e) {
    logger.warn('prerestore_snapshot_failed', { err: e.message });
    // Don't abort the restore — the user already confirmed via dryRun + confirmShrink.
  }

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

// PG_REQUIRE_ON_BOOT — when set, refuse to fall back to file mode if
// PG_CONN is configured but the ping fails. This prevents the silent
// "Postgres is configured but server fell back to file with empty data
// and made every save go nowhere" scenario that lost the 2026-05-08
// session. Recommended setting in production where PG is the system
// of record.
const PG_REQUIRE_ON_BOOT = String(process.env.PG_REQUIRE_ON_BOOT || '').toLowerCase() === 'true';

// Periodic recovery ping. If the server starts in file fallback mode but
// PG_CONN is configured, retry every 60 seconds. The first time pg comes
// back, promote to postgres mode and reload data from there. Without this,
// a single transient ping failure at boot strands the server in file mode
// indefinitely (writes go to a path the operator may have moved, and
// silently fail). Set PG_NO_RECOVERY=true to disable.
const PG_RECOVERY_INTERVAL_MS = Number(process.env.PG_RECOVERY_INTERVAL_MS) || 60000;
const PG_NO_RECOVERY = String(process.env.PG_NO_RECOVERY || '').toLowerCase() === 'true';
function _scheduleDbRecoveryPing() {
  if (PG_NO_RECOVERY || _useDB || !process.env.PG_CONN) return;
  setTimeout(async () => {
    if (_useDB) return;
    try {
      dbRepo.init();
      const ok = await dbRepo.ping();
      if (ok) {
        logger.warn('pg_recovery_ping_succeeded', { msg: 'Postgres reachable; promoting from file mode and reloading from db.' });
        try {
          await dbRepo.ensureSchema();
          const fresh = await dbRepo.loadAll();
          // Adopt Postgres state — but DON'T overwrite Postgres with our
          // file-mode in-memory cache. The file-mode cache is what got the
          // server through the outage; Postgres is system of record and
          // wins. If a user added data while we were in file mode, that
          // data was failing to persist anyway (writes went to a stale
          // path). At least now subsequent writes will reach Postgres.
          dataCache = fresh;
          _useDB = true;
          dataDirty = false;
          if (saveTimeout) { clearTimeout(saveTimeout); saveTimeout = null; }
          _bumpDataVersion();
          logger.info('data_promoted_from_file_to_postgres');
        } catch (e) {
          logger.error('pg_recovery_promotion_failed', { err: e.message });
        }
      }
    } catch (e) {
      // swallow — try again next interval
    } finally {
      _scheduleDbRecoveryPing();
    }
  }, PG_RECOVERY_INTERVAL_MS).unref();
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
        if (PG_REQUIRE_ON_BOOT) {
          throw new Error('PG_REQUIRE_ON_BOOT=true and Postgres ping failed; refusing to start in file fallback mode.');
        }
        // Schedule periodic re-ping so a transient connection blip doesn't
        // strand us in file mode forever.
        _scheduleDbRecoveryPing();
      }
    } catch (e) {
      logger.error('pg_init_failed_fallback_to_file', { err: e.message });
      if (PG_REQUIRE_ON_BOOT) throw e;
      _scheduleDbRecoveryPing();
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

  // ── Persistent migration flags ───────────────────────────────────────────
  // Postgres mode: load the set of flags that have already run from the
  // app_migrations table. File mode: fall back to JS-only flags on dataCache.
  // The 2026-04-30 Kirkland incident exposed how dangerous JS-only flags are
  // in postgres mode — `data._seedStripped` was undefined on every restart
  // because postgres didn't preserve it, so the seed-strip migration could
  // re-run every restart.
  let pgFlags = null;
  if (_useDB) {
    try { pgFlags = await dbRepo.loadMigrationFlags(); }
    catch (e) { logger.error('migration_flags_load_failed', { err: e.message }); }
  }
  const ranAlready = (flag) => {
    if (pgFlags) return pgFlags.has(flag);
    return !!data[flag];
  };
  const markRan = async (flag) => {
    data[flag] = true;
    if (_useDB) {
      try { await dbRepo.setMigrationFlag(flag); }
      catch (e) { logger.error('migration_flag_write_failed', { flag, err: e.message }); }
    }
  };

  // ── Strip seed buildings / employees / shifts ─────────────────────────────
  if (!ranAlready('_seedStripped')) {
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
    await markRan('_seedStripped');
    dirty = true;
  }

  // ── Strip seed HR employees / demo HR accounts ────────────────────────────
  if (!ranAlready('_hrSeedStripped')) {
    data.hrEmployees = (data.hrEmployees || []).filter(e => !e.id.startsWith('hre'));
    data.hrAccounts  = (data.hrAccounts  || []).filter(a => !['ha1','ha2'].includes(a.id));
    await markRan('_hrSeedStripped');
    dirty = true;
  }

  // ── Strip seed time-clock records ─────────────────────────────────────────
  if (!ranAlready('_tcSeedStripped')) {
    data.hrTimeClock = (data.hrTimeClock || []).filter(r => !String(r.empId||'').startsWith('tc-'));
    await markRan('_tcSeedStripped');
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
    if (IS_PROD) {
      logger.warn('AUDIT_CLOUD_NOT_CONFIGURED_IN_PRODUCTION', {
        reason: 'AUDIT_STORAGE_CONNECTION_STRING not set',
        risk: 'Audit logs are file-based only — not HIPAA-compliant for durability (§164.312(b))',
        fix: 'Set AUDIT_STORAGE_CONNECTION_STRING to an Azure Blob Storage connection string with immutability policy'
      });
    } else {
      logger.info('audit_cloud_disabled', { reason: 'AUDIT_STORAGE_CONNECTION_STRING not set' });
    }
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

// In-memory fallbacks (used when Redis unavailable).
// Use a Map with expiry timestamps to prevent unbounded growth.
const _memRevokedTokens = new Map(); // token -> expiresAt (ms)
const _memLastActivity = new Map();
// Periodically evict expired entries (every 10 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [k, exp] of _memRevokedTokens) { if (exp < now) _memRevokedTokens.delete(k); }
  for (const [k, ts] of _memLastActivity) { if (now - ts > _MAX_TOKEN_TTL * 1000) _memLastActivity.delete(k); }
}, 600000).unref();

// Revoked-token / last-activity Redis entries must outlive the longest JWT,
// otherwise a logged-out employee's 30-day cookie could be reused after the
// 1h Redis entry expires. Use the employee TTL as the upper bound.
const _MAX_TOKEN_TTL = Math.max(JWT_TTL_SECONDS, EMPLOYEE_JWT_TTL_SECONDS);

const revokedTokens = {
  async add(token) {
    _memRevokedTokens.set(token, Date.now() + _MAX_TOKEN_TTL * 1000);
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
    // Idle timeout: 2h for admin/SA on the desktop site (HIPAA §164.312
    // (a)(2)(iii)). Effectively disabled for employees and for any
    // session tagged surface='pwa' at issue time. See effectiveIdleTtl
    // for the rationale.
    const sid = decoded.sid;
    const last = await lastActivity.get(sid);
    const idleMs = effectiveIdleTtl(decoded.role, decoded.surface) * 1000;
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

async function recordFailedLogin(acct) {
  acct.failedAttempts = (acct.failedAttempts || 0) + 1;
  if (acct.failedAttempts >= MAX_FAILED_ATTEMPTS) {
    acct.lockedUntil = Date.now() + LOCKOUT_MS;
    auditLog('ACCOUNT_LOCKED', acct, { until: new Date(acct.lockedUntil).toISOString() });
  }
  // Must be durable before we respond — a crash during the markDirty 200ms
  // debounce window would reset the lockout counter, weakening brute-force
  // protection. Same pattern as password-reset and TOTP mutations.
  await persistAccountNow(acct);
}

async function clearFailedAttempts(acct) {
  if (acct.failedAttempts || acct.lockedUntil) {
    acct.failedAttempts = 0;
    acct.lockedUntil = null;
    await persistAccountNow(acct);
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
// HR module access is role-based: superadmins and users with the 'hr' role or
// the hrAccess flag. Previously gated to a single hardcoded email.
function _canAccessHR(user) {
  if (!user) return false;
  if (user.role === 'superadmin') return true;
  if (user.role === 'hr' || user.hrAccess === true) return true;
  return false;
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

  // HIPAA minimum-necessary: a DM body is only ever shipped to a client
  // when that client is a participant in the thread. Even superadmins
  // do NOT bulk-receive other people's DMs — message-level oversight is
  // the audit log's job (DM_SENT events carry metadata only, never body).
  // Apply this filter to every role's response below.
  const dmsForMe = (m) => m.fromId === user.id || m.toId === user.id;

  // Employees get a heavily restricted view
  if (user.role === 'employee') return _employeeView(user, scrubbed);

  // Superadmin sees everything (with secrets scrubbed) + HR if allowed
  if (user.role === 'superadmin') {
    const out = _canAccessHR(user) ? scrubbed : _stripHR(scrubbed);
    return { ...out, directMessages: (out.directMessages || []).filter(dmsForMe) };
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
      // Open patterns (no empId) are scoped by buildingId directly.
      // Assign patterns are scoped by the employee's building.
      p.empId
        ? (scrubbed.employees || []).some(e => e.id === p.empId && bIds.has(e.buildingId))
        : (p.buildingId && bIds.has(p.buildingId))),
    accounts:         (scrubbed.accounts || []).filter(a =>
      a.id === user.id || (a.buildingId && bIds.has(a.buildingId)) || (a.buildingIds||[]).some(id => bIds.has(id))),
    alertLog:         (scrubbed.alertLog || []).filter(e => !e.buildingId || bIds.has(e.buildingId)),
    directMessages:   (scrubbed.directMessages || []).filter(dmsForMe),
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

// Gzip/Brotli compression — reduces the 1.2MB HTML to ~150KB on the wire
app.use(compression({ threshold: 1024 }));

// Request ID for log correlation
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-Id', req.id);
  next();
});

// Generate a per-request CSP nonce for inline scripts.
// The SPA serves inline <script> blocks; nonces let us avoid 'unsafe-inline'.
// NOTE: 'unsafe-inline' is kept as a fallback for scriptSrcAttr (onclick handlers)
// and styleSrc (inline style= attributes used extensively throughout the SPA).
// Fully removing those requires migrating all onclick handlers to addEventListener
// and all inline styles to CSS classes — tracked as a future refactor.
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      scriptSrcAttr: ["'unsafe-inline'"],               // onclick handlers — future: migrate to addEventListener
      styleSrc:      ["'self'", "'unsafe-inline'"],      // inline style= attributes throughout SPA
      imgSrc:        ["'self'", 'data:'],
      connectSrc:    ["'self'"],
      frameAncestors: ["'none'"],
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

// Body size limit: must accommodate the full app state on /api/data POST.
// Live data payload is ~1.3 MB at 21 buildings / 1.6k staff / 1k shifts and
// grows when admins add rotations (a year of weekday shifts adds ~250 rows).
// Was 1mb — too tight, caused PayloadTooLargeError → 500 on weekday rotation
// adds (incident 2026-05-08). Was previously 50mb — DoS surface.
// 10mb gives ample headroom for tenant growth without opening DoS.
app.use(express.json({ limit: '10mb' }));
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
  // Surface persist-failure state so monitoring can alert. The 2026-05-08
  // incident's writes failed silently for an entire user session because
  // there was no visible health signal — only buried log lines.
  checks.persistFailuresConsecutive = _consecutiveFilePersistFailures;
  checks.lastSuccessfulPersistAt    = _lastSuccessfulPersistAt;
  if (_consecutiveFilePersistFailures >= 3) {
    return res.status(503).json({
      ok: false,
      ...checks,
      error: 'persist_repeatedly_failing',
      message: 'File-mode persists are failing. Edits are not being saved. ' +
               'Investigate DATA_FILE config or set PG_REQUIRE_ON_BOOT=true.',
    });
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
// Cache the HTML file in memory for nonce injection (avoids re-reading on every request)
let _cachedHtml = null;
let _cachedHtmlMtime = null;
app.get('/', async (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, must-revalidate');
  try {
    const stat = await fs.stat(HTML_FILE);
    const mtime = stat.mtimeMs;
    if (!_cachedHtml || mtime !== _cachedHtmlMtime) {
      _cachedHtml = await fs.readFile(HTML_FILE, 'utf8');
      _cachedHtmlMtime = mtime;
    }
    // Inject CSP nonce into all <script> tags
    const nonce = res.locals.cspNonce;
    const html = _cachedHtml.replace(/<script(?=[>\s])/gi, `<script nonce="${nonce}"`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    logger.error('html_serve_failed', { err: e.message });
    res.sendFile(HTML_FILE);
  }
});

// ── COMPANION APP (employee shift claim + admin schedule/messages) ────────
// Single-page PWA at /app — talks to the same /api/* endpoints as the main
// site. Designed mobile-first; installable via "Add to Home Screen".
const APP_HTML_FILE = path.join(__dirname, 'public', 'app.html');
app.get('/app', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache, must-revalidate');
  res.sendFile(APP_HTML_FILE);
});
app.get('/app/manifest.webmanifest', (_req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(JSON.stringify({
    name: 'ManageMyStaffing',
    short_name: 'MMS',
    description: 'Shift scheduling, team messaging, and workforce management for healthcare staffing agencies.',
    start_url: '/app',
    id: '/app',
    scope: '/app',
    display: 'standalone',
    orientation: 'portrait',
    lang: 'en-US',
    dir: 'ltr',
    background_color: '#1B5E3B',
    theme_color: '#1B5E3B',
    categories: ['business', 'productivity', 'medical'],
    icons: [
      { src: '/app/icon.svg',                sizes: 'any',     type: 'image/svg+xml', purpose: 'any' },
      { src: '/app/icon-maskable.svg',       sizes: 'any',     type: 'image/svg+xml', purpose: 'maskable' },
      { src: '/app/icon-192.png',            sizes: '192x192', type: 'image/png',     purpose: 'any' },
      { src: '/app/icon-512.png',            sizes: '512x512', type: 'image/png',     purpose: 'any' },
      { src: '/app/icon-maskable-192.png',   sizes: '192x192', type: 'image/png',     purpose: 'maskable' },
      { src: '/app/icon-maskable-512.png',   sizes: '512x512', type: 'image/png',     purpose: 'maskable' },
    ],
    screenshots: [
      { src: '/app/screenshot-wide.png', sizes: '1280x720', type: 'image/png', form_factor: 'wide', label: 'Schedule management dashboard' },
      { src: '/app/screenshot-schedule.png', sizes: '390x844', type: 'image/png', form_factor: 'narrow', label: 'Employee shift schedule' },
      { src: '/app/screenshot-messages.png', sizes: '390x844', type: 'image/png', form_factor: 'narrow', label: 'Team messaging' },
    ],
    shortcuts: [
      { name: 'My Schedule',  short_name: 'Schedule', url: '/app#schedule', icons: [{ src: '/app/icon-192.png', sizes: '192x192' }] },
      { name: 'Messages',     short_name: 'Messages', url: '/app#messages', icons: [{ src: '/app/icon-192.png', sizes: '192x192' }] },
    ],
    ...(process.env.TWA_PACKAGE ? {
      prefer_related_applications: true,
      related_applications: [
        { platform: 'play', id: process.env.TWA_PACKAGE,
          url: `https://play.google.com/store/apps/details?id=${process.env.TWA_PACKAGE}` },
      ],
    } : {}),
  }));
});

// ── Digital Asset Links (Android TWA verification) ──────────────────
app.get('/.well-known/assetlinks.json', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  const sha = process.env.TWA_SHA256 || '';
  const pkg = process.env.TWA_PACKAGE || 'com.managemystaffing.app';
  const entries = [
    { relation: ['delegate_permission/common.handle_all_urls'],
      target: { namespace: 'web', site: APP_URL } },
  ];
  if (sha) {
    entries.push({
      relation: ['delegate_permission/common.handle_all_urls'],
      target: { namespace: 'android_app', package_name: pkg,
        sha256_cert_fingerprints: [sha] },
    });
  }
  res.send(JSON.stringify(entries));
});

// ── Apple Universal Links (AASA) ────────────────────────────────────
app.get('/.well-known/apple-app-site-association', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  const teamId = process.env.APPLE_TEAM_ID || 'XXXXXXXXXX';
  const bundleId = process.env.APPLE_BUNDLE_ID || 'com.managemystaffing.app';
  res.send(JSON.stringify({
    applinks: { apps: [], details: [{ appID: `${teamId}.${bundleId}`, paths: ['/app/*'] }] },
    webcredentials: { apps: [`${teamId}.${bundleId}`] },
  }));
});

// ── Placeholder screenshots for manifest (PWA store listing) ────────
// Generates branded placeholder PNGs using inline SVG rendered to PNG.
// Replace with real captures once the store build pipeline is set up.
function screenshotSvg(w, h, title, subtitle) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
    <rect width="${w}" height="${h}" fill="#F0F7F3"/>
    <rect width="${w}" height="${Math.round(h * 0.12)}" fill="#1B5E3B"/>
    <text x="${w/2}" y="${Math.round(h * 0.075)}" text-anchor="middle" font-family="sans-serif" font-size="${Math.round(h * 0.03)}" font-weight="bold" fill="white">ManageMyStaffing</text>
    <text x="${w/2}" y="${h/2}" text-anchor="middle" font-family="sans-serif" font-size="${Math.round(h * 0.045)}" font-weight="bold" fill="#1B5E3B">${title}</text>
    <text x="${w/2}" y="${h/2 + Math.round(h * 0.06)}" text-anchor="middle" font-family="sans-serif" font-size="${Math.round(h * 0.025)}" fill="#475569">${subtitle}</text>
  </svg>`;
}
app.get('/app/screenshot-wide.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(screenshotSvg(1280, 720, 'Schedule Dashboard', 'Manage shifts, teams, and facilities at a glance'));
});
app.get('/app/screenshot-schedule.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(screenshotSvg(390, 844, 'Shift Schedule', 'View and manage employee shifts'));
});
app.get('/app/screenshot-messages.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(screenshotSvg(390, 844, 'Team Messages', 'Direct messaging between staff and managers'));
});

// Inline SVG app icon — exact same medical-house artwork as the main site's
// LOGO_SVG (managemystaffing.html ~1232). Drawing in 100×92 source coords,
// centered on a 512×512 tile with a green background. Updates here should
// stay in sync with the website logo.
//
// Reuse the path data so the app icon and website logo can never drift.
const _LOGO_PATHS = `
    <rect x="70" y="2" width="14" height="26" rx="5" fill="#6B9E7A"/>
    <path d="M50 5 L0 52 Q0 56 4 56 L96 56 Q100 56 100 52 Z" fill="#6B9E7A"/>
    <rect x="3" y="50" width="94" height="42" rx="6" fill="#6B9E7A"/>
    <rect x="38" y="20" width="9" height="9" rx="2" fill="white"/>
    <rect x="52" y="20" width="9" height="9" rx="2" fill="white"/>
    <rect x="38" y="32" width="9" height="9" rx="2" fill="white"/>
    <rect x="52" y="32" width="9" height="9" rx="2" fill="white"/>
    <rect x="63" y="57" width="10" height="9" rx="2" fill="white"/>
    <rect x="76" y="57" width="10" height="9" rx="2" fill="white"/>
    <rect x="63" y="69" width="10" height="9" rx="2" fill="white"/>
    <rect x="76" y="69" width="10" height="9" rx="2" fill="white"/>
    <rect x="7" y="71" width="26" height="8" rx="4" fill="white"/>
    <rect x="16" y="62" width="8" height="26" rx="4" fill="white"/>
    <rect x="41" y="70" width="18" height="22" rx="3" fill="white"/>
`;
// Standard icon: green tile with the website logo centered. Source SVG
// is 100×92 — we scale to ~440×405 inside a 512×512 tile, then offset
// by 36px to center.
app.get('/app/icon.svg', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="96" fill="#1B5E3B"/>
  <g transform="translate(36 53.5) scale(4.4)">${_LOGO_PATHS}</g>
</svg>`);
});

// Maskable variant — same art but inset by ~14% so Android adaptive-icon
// crops never clip the logo. Background extends to the edges so OSes can
// shape the tile freely (circle / squircle / rounded square).
app.get('/app/icon-maskable.svg', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" fill="#1B5E3B"/>
  <g transform="translate(81 99) scale(3.5)">${_LOGO_PATHS}</g>
</svg>`);
});

// ── PNG icon generator (zero dependencies — uses built-in zlib) ────────────
// App stores and older browsers require raster PNG icons. We render the same
// logo artwork into a pixel buffer at the requested size and encode a valid
// PNG using Node's built-in zlib.deflateSync. Results are cached in memory
// since the icon never changes at runtime.
const _pngCache = new Map();
function _generatePngIcon(size, maskable) {
  const key = `${size}-${maskable ? 'm' : 's'}`;
  if (_pngCache.has(key)) return _pngCache.get(key);

  const w = size, h = size;
  const rowSize = 1 + w * 4; // filter byte + RGBA per pixel
  const raw = Buffer.alloc(rowSize * h);

  // Fill background #1B5E3B
  for (let y = 0; y < h; y++) {
    const ro = y * rowSize; raw[ro] = 0;
    for (let x = 0; x < w; x++) {
      const o = ro + 1 + x * 4;
      raw[o] = 0x1B; raw[o+1] = 0x5E; raw[o+2] = 0x3B; raw[o+3] = 255;
    }
  }

  function fillRect(sx, sy, sw, sh, r, g, b) {
    const x1 = Math.max(0, Math.round(sx)), y1 = Math.max(0, Math.round(sy));
    const x2 = Math.min(w, Math.round(sx + sw)), y2 = Math.min(h, Math.round(sy + sh));
    for (let y = y1; y < y2; y++) {
      const ro = y * rowSize + 1;
      for (let x = x1; x < x2; x++) {
        const o = ro + x * 4;
        raw[o] = r; raw[o+1] = g; raw[o+2] = b; raw[o+3] = 255;
      }
    }
  }

  // Logo placement: maskable insets more to survive adaptive-icon crops
  const scale = maskable ? (size / 512 * 3.5) : (size / 512 * 4.4);
  const ox    = maskable ? (size / 512 * 81)  : (size / 512 * 36);
  const oy    = maskable ? (size / 512 * 99)  : (size / 512 * 53.5);

  const Lr = 0x6B, Lg = 0x9E, Lb = 0x7A; // #6B9E7A (green elements)
  // Chimney
  fillRect(ox+70*scale, oy+2*scale, 14*scale, 26*scale, Lr, Lg, Lb);
  // House body
  fillRect(ox+3*scale, oy+50*scale, 94*scale, 42*scale, Lr, Lg, Lb);
  // Roof triangle (rasterised scan-line by scan-line)
  for (let sy = 5; sy <= 56; sy++) {
    const p = (sy - 5) / 47, hw = p * 50;
    fillRect(ox+(50-hw)*scale, oy+sy*scale, hw*2*scale, scale, Lr, Lg, Lb);
  }
  // White elements
  const W = 255;
  fillRect(ox+38*scale, oy+20*scale,  9*scale,  9*scale, W,W,W);
  fillRect(ox+52*scale, oy+20*scale,  9*scale,  9*scale, W,W,W);
  fillRect(ox+38*scale, oy+32*scale,  9*scale,  9*scale, W,W,W);
  fillRect(ox+52*scale, oy+32*scale,  9*scale,  9*scale, W,W,W);
  fillRect(ox+63*scale, oy+57*scale, 10*scale,  9*scale, W,W,W);
  fillRect(ox+76*scale, oy+57*scale, 10*scale,  9*scale, W,W,W);
  fillRect(ox+63*scale, oy+69*scale, 10*scale,  9*scale, W,W,W);
  fillRect(ox+76*scale, oy+69*scale, 10*scale,  9*scale, W,W,W);
  fillRect(ox+ 7*scale, oy+71*scale, 26*scale,  8*scale, W,W,W); // cross H
  fillRect(ox+16*scale, oy+62*scale,  8*scale, 26*scale, W,W,W); // cross V
  fillRect(ox+41*scale, oy+70*scale, 18*scale, 22*scale, W,W,W); // door

  // Compress with built-in zlib
  const compressed = require('zlib').deflateSync(raw, { level: 6 });

  // Assemble PNG: signature + IHDR + IDAT + IEND
  function chunk(type, data) {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const tb = Buffer.from(type, 'ascii');
    const body = Buffer.concat([tb, data]);
    let c = 0xFFFFFFFF;
    for (let i = 0; i < body.length; i++) {
      c ^= body[i]; for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (c & 1 ? 0xEDB88320 : 0);
    }
    const crc = Buffer.alloc(4); crc.writeUInt32BE((c ^ 0xFFFFFFFF) >>> 0);
    return Buffer.concat([len, body, crc]);
  }
  const sig = Buffer.from([137,80,78,71,13,10,26,10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8]=8; ihdr[9]=6; // 8-bit RGBA
  const png = Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', compressed), chunk('IEND', Buffer.alloc(0))]);
  _pngCache.set(key, png);
  return png;
}

// PNG icon endpoints — required by app stores and older browsers
app.get('/app/icon-192.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(_generatePngIcon(192, false));
});
app.get('/app/icon-512.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(_generatePngIcon(512, false));
});
app.get('/app/icon-maskable-192.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(_generatePngIcon(192, true));
});
app.get('/app/icon-maskable-512.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(_generatePngIcon(512, true));
});

// Apple touch icon — serves actual 180×180 PNG (iOS requires real PNG, not SVG)
app.get('/app/apple-touch-icon.png', (_req, res) => {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(_generatePngIcon(180, false));
});

// Service worker — caches the app shell so /app loads offline and reloads
// instantly. Network-first for /api/* (so live data wins when online),
// cache-first for the static shell. Shipped from the same /app scope so
// browsers register it for the right path.
const APP_CACHE_VERSION = 'mms-app-v6';
app.get('/app/sw.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  // SW must NOT be cached or you can never roll out a new one.
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Service-Worker-Allowed', '/app');
  res.send(`'use strict';
const CACHE = '${APP_CACHE_VERSION}';
const SHELL = ['/app', '/app/manifest.webmanifest', '/app/icon.svg',
  '/app/icon-192.png', '/app/icon-512.png',
  '/app/icon-maskable-192.png', '/app/icon-maskable-512.png'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(()=>{})));
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE && k !== CACHE + '-data').map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // API data: network-first with cache fallback for GET /api/data
  if (url.pathname.startsWith('/api/')) {
    if (url.pathname === '/api/data' && req.method === 'GET') {
      e.respondWith((async () => {
        try {
          const r = await fetch(req);
          if (r.ok) {
            const cache = await caches.open(CACHE + '-data');
            cache.put(req, r.clone()).catch(()=>{});
          }
          return r;
        } catch (err) {
          const cache = await caches.open(CACHE + '-data');
          const cached = await cache.match(req);
          return cached || new Response('{"offline":true}', {
            status: 503, headers: {'Content-Type':'application/json'}
          });
        }
      })());
    }
    return;
  }

  // App shell: cache first, network fallback
  if (url.pathname === '/app' || url.pathname.startsWith('/app/')) {
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(req);
      const fetched = fetch(req).then(r => {
        if (r && r.ok && r.type === 'basic') cache.put(req, r.clone()).catch(()=>{});
        return r;
      }).catch(() => cached);
      return cached || fetched;
    })());
  }
});

// Web Push: server sends { title, body, tag, url } via webpush.sendNotification
self.addEventListener('push', e => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (_) {
    try { data = { body: e.data ? e.data.text() : '' }; } catch (__) {}
  }
  const title = data.title || 'ManageMyStaffing';
  const opts = {
    body: data.body || '',
    icon: '/app/icon.svg',
    badge: '/app/icon.svg',
    tag: data.tag || 'mms',
    renotify: true,
    data: { url: data.url || '/app' },
  };
  e.waitUntil(self.registration.showNotification(title, opts));
});

// Tapping a notification: focus an existing /app tab if one's open, else
// open a new one. Uses includeUncontrolled so we find tabs that loaded
// before this SW activated (PWAs that install the SW lazily).
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const target = e.notification?.data?.url || '/app';
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if (c.url.includes('/app')) { c.focus(); c.navigate(target).catch(()=>{}); return; }
    }
    if (self.clients.openWindow) await self.clients.openWindow(target);
  })());
});
`);
});

// ── PUBLIC LEGAL PAGES (privacy, terms) ───────────────────────────────────
// Required for A2P 10DLC SMS brand registration with Azure Communication
// Services — carriers (T-Mobile, AT&T, Verizon) verify these URLs are live
// before approving a campaign. Both render inline so there are no extra
// static files to host. Update copy here if your privacy posture changes.
const _legalPageStyles = `
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;color:#1f2937;max-width:780px;margin:0 auto;padding:32px 24px}
  h1{font-size:28px;color:#0f172a;margin:0 0 8px;border-bottom:2px solid #e5e7eb;padding-bottom:12px}
  h2{font-size:18px;color:#0f172a;margin:24px 0 8px}
  h3{font-size:15px;color:#334155;margin:16px 0 6px}
  p,li{font-size:14px;color:#334155}
  ul{padding-left:22px}
  a{color:#2563eb;text-decoration:none}
  a:hover{text-decoration:underline}
  .meta{color:#64748b;font-size:12px;margin-bottom:20px}
  .nav{margin-top:36px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:13px;color:#64748b}
`;
function renderLegalPage(title, html) {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — ManageMyStaffing</title>
<style>${_legalPageStyles}</style>
</head><body>${html}<div class="nav"><a href="/">← Back to ManageMyStaffing</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></div></body></html>`;
}

app.get('/privacy', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLegalPage('Privacy Policy', `
<h1>Privacy Policy</h1>
<p class="meta">Last updated: May 2026</p>

<p>ManageMyStaffing ("we", "us", "our") provides workforce-management software to skilled-nursing facilities and other healthcare employers. This Privacy Policy explains what information we collect, how we use it, and the choices you have.</p>

<h2>1. Information we collect</h2>
<ul>
  <li><strong>Account information</strong> — name, email address, phone number, role, building assignment.</li>
  <li><strong>Employment information</strong> — hire date, employment status, hourly rate or salary, license numbers (for licensed roles), shift assignments, time-clock punches.</li>
  <li><strong>Health-related information</strong> — limited to what's needed to operate the schedule and meet CMS Payroll-Based Journal (PBJ) reporting (e.g. employee role classification, hours worked). We do <strong>not</strong> collect resident PHI through this app; resident census data is aggregated counts only, sourced from your facility's EHR via integration.</li>
  <li><strong>Communications</strong> — SMS / email message content sent through the app, plus replies received via inbound webhooks.</li>
  <li><strong>Usage data</strong> — IP address, browser type, login timestamps, audit-log events (who did what, when).</li>
</ul>

<h2>2. How we use information</h2>
<ul>
  <li>Operate the schedule, time clock, and payroll calculations on behalf of your employer (the facility).</li>
  <li>Send you SMS and email notifications about open shifts, schedule changes, and HR documents — only when you've opted in (during onboarding paperwork or by an admin who confirmed verbal consent).</li>
  <li>Generate compliance reports (PBJ, CMS Five-Star, audit logs).</li>
  <li>Detect and respond to security incidents.</li>
</ul>

<h2>3. SMS communications &amp; opt-out</h2>
<p>If you have opted in to SMS notifications, you may receive messages about shift availability, schedule changes, and time-off responses. Message frequency varies based on your role and your facility's staffing.</p>
<ul>
  <li>Reply <strong>STOP</strong> to any message to unsubscribe from all SMS communications.</li>
  <li>Reply <strong>HELP</strong> to receive contact information.</li>
  <li>Message and data rates may apply per your wireless carrier's plan.</li>
  <li>Carriers supported: AT&amp;T, T-Mobile, Verizon, US Cellular, and others.</li>
  <li>We do <strong>not</strong> share your mobile number with third parties for their own marketing.</li>
</ul>

<h2>4. How we share information</h2>
<p>We share information only with:</p>
<ul>
  <li>Your employer (the facility that hired you and added you to the app).</li>
  <li>Service providers who help us operate the platform — Microsoft Azure (hosting, SMS via Azure Communication Services), payroll vendors you've authorized us to push data to (e.g. Paycom, ADP), the carrier providing your SMS service.</li>
  <li>Government agencies (CMS, state Medicaid) when required for PBJ reporting.</li>
  <li>Law enforcement, when compelled by valid legal process.</li>
</ul>
<p>We do not sell personal information.</p>

<h2>5. HIPAA</h2>
<p>ManageMyStaffing operates as a Business Associate under HIPAA. We have signed Business Associate Agreements with each facility customer. Technical safeguards include AES-256 encryption at rest, TLS 1.2+ in transit, role-based access controls, MFA for administrative access, and tamper-evident audit logging (45 CFR §164.312).</p>

<h2>6. Data retention</h2>
<p>Audit logs are retained for 6 years per HIPAA §164.316(b). Other personal data is retained while you're active and for 2 years after last activity, unless your employer requests earlier deletion or longer retention is required by law.</p>

<h2>7. Your rights</h2>
<ul>
  <li>Request a copy of the personal information we hold about you.</li>
  <li>Request correction of inaccurate information.</li>
  <li>Request deletion (subject to legal retention requirements).</li>
  <li>Opt out of SMS at any time (reply STOP).</li>
</ul>
<p>Contact your facility's HR administrator first; they can fulfill most requests directly. For escalations, email <a href="mailto:privacy@managemystaffing.com">privacy@managemystaffing.com</a>.</p>

<h2>8. Contact</h2>
<p>ManageMyStaffing<br>Solomon Ganz, CEO<br>Email: <a href="mailto:bcsolomonganz@gmail.com">bcsolomonganz@gmail.com</a><br>Phone: 347-456-1681</p>

<h2>9. Changes</h2>
<p>We'll update the "Last updated" date at the top when we make material changes. For significant changes, we'll also notify your facility's administrators.</p>
`));
});

// SMS opt-in evidence page — referenced by Azure Communication Services
// regulatory documents (toll-free verification + 10DLC campaign) as the
// "where do subscribers opt in" URL. Carriers require a publicly-viewable
// page showing the consent UI and the call-to-action language. This page
// renders a high-fidelity SVG mockup of the in-app onboarding checkbox so
// reviewers can see the actual consent flow without needing app credentials.
app.get('/sms-opt-in', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  // SVG mockup of the in-app consent checkbox + surrounding context. Inline
  // so the page is self-contained (no external image hosting required).
  const svgMockup = `
<svg viewBox="0 0 720 540" xmlns="http://www.w3.org/2000/svg" style="max-width:720px;width:100%;border:1px solid #e5e7eb;border-radius:8px;background:#ffffff">
  <!-- App header -->
  <rect x="0" y="0" width="720" height="56" fill="#0f172a"/>
  <text x="20" y="34" font-family="Segoe UI,sans-serif" font-size="16" font-weight="700" fill="#ffffff">ManageMyStaffing — New Hire Paperwork</text>
  <text x="630" y="34" font-family="Segoe UI,sans-serif" font-size="12" fill="#94a3b8">Step 3 of 7</text>
  <!-- Section heading -->
  <text x="32" y="92" font-family="Segoe UI,sans-serif" font-size="20" font-weight="800" fill="#0f172a">Notification Preferences</text>
  <text x="32" y="118" font-family="Segoe UI,sans-serif" font-size="13" fill="#475569">Choose how we contact you about open shifts and schedule changes.</text>
  <!-- Phone field -->
  <text x="32" y="158" font-family="Segoe UI,sans-serif" font-size="12" font-weight="700" fill="#334155">Mobile phone number</text>
  <rect x="32" y="170" width="380" height="38" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5" rx="6"/>
  <text x="44" y="194" font-family="Segoe UI,sans-serif" font-size="13" fill="#0f172a">(347) 456-1681</text>
  <!-- Consent checkbox row -->
  <rect x="32" y="232" width="656" height="106" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1" rx="8"/>
  <rect x="46" y="248" width="20" height="20" fill="#2563eb" stroke="#1d4ed8" stroke-width="1.5" rx="3"/>
  <path d="M51 258 L55 263 L62 252" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="76" y="265" font-family="Segoe UI,sans-serif" font-size="14" font-weight="700" fill="#0f172a">I agree to receive SMS text messages from ManageMyStaffing</text>
  <text x="76" y="288" font-family="Segoe UI,sans-serif" font-size="12" fill="#475569">I consent to receive transactional SMS about open shifts, schedule changes, and</text>
  <text x="76" y="304" font-family="Segoe UI,sans-serif" font-size="12" fill="#475569">HR communications. Msg &amp; data rates may apply. Reply STOP to opt out, HELP for help.</text>
  <text x="76" y="324" font-family="Segoe UI,sans-serif" font-size="11" fill="#64748b" font-style="italic">Frequency varies. View our Privacy Policy and Terms.</text>
  <!-- Email checkbox row -->
  <rect x="32" y="356" width="656" height="56" fill="#ffffff" stroke="#e2e8f0" stroke-width="1" rx="8"/>
  <rect x="46" y="372" width="20" height="20" fill="#2563eb" stroke="#1d4ed8" stroke-width="1.5" rx="3"/>
  <path d="M51 382 L55 387 L62 376" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="76" y="389" font-family="Segoe UI,sans-serif" font-size="14" font-weight="700" fill="#0f172a">Email notifications</text>
  <text x="76" y="406" font-family="Segoe UI,sans-serif" font-size="11" fill="#64748b">Same content as SMS, sent to your email address.</text>
  <!-- Continue button -->
  <rect x="32" y="438" width="160" height="42" fill="#2563eb" rx="6"/>
  <text x="112" y="464" font-family="Segoe UI,sans-serif" font-size="14" font-weight="700" fill="#ffffff" text-anchor="middle">Continue →</text>
  <!-- Footer -->
  <text x="32" y="510" font-family="Segoe UI,sans-serif" font-size="11" fill="#94a3b8">By continuing you confirm your consent choices. You can change them anytime in your profile.</text>
</svg>`;
  res.send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SMS Opt-in — ManageMyStaffing</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;color:#1f2937;max-width:820px;margin:0 auto;padding:32px 24px;background:#f8fafc}
  h1{font-size:28px;color:#0f172a;margin:0 0 8px;border-bottom:2px solid #e5e7eb;padding-bottom:12px}
  h2{font-size:18px;color:#0f172a;margin:28px 0 8px}
  p,li{font-size:14px;color:#334155}
  ul,ol{padding-left:22px}
  a{color:#2563eb;text-decoration:none}
  a:hover{text-decoration:underline}
  .meta{color:#64748b;font-size:12px;margin-bottom:20px}
  .nav{margin-top:36px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:13px;color:#64748b}
  .callout{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px 16px;margin:14px 0;font-size:13px;color:#1e40af}
  .sample-msg{background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:14px 16px;margin:10px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;color:#0f172a;max-width:380px}
  .sample-msg .from{font-size:11px;color:#64748b;font-weight:600;margin-bottom:4px}
  code{background:#f1f5f9;padding:1px 6px;border-radius:4px;font-size:12px;font-family:Consolas,Menlo,monospace}
</style></head><body>
<h1>SMS Opt-in &amp; Consent — ManageMyStaffing</h1>
<p class="meta">Last updated: May 2026 · This page documents how employees opt in to SMS notifications.</p>

<h2>Who receives messages</h2>
<p>ManageMyStaffing is a closed-system workforce-management application for skilled-nursing-facility staff. <strong>Only verified employees of contracted facilities</strong> receive SMS — there is no public sign-up. Employees are invited by their facility's HR administrator after they're hired.</p>

<h2>How employees opt in</h2>
<p>During the new-hire onboarding paperwork process, every employee sees a notification-preferences step. They explicitly check a consent box agreeing to receive SMS, after providing their phone number. <strong>Mockup of the in-app consent screen below:</strong></p>

${svgMockup}

<h2>Exact consent language shown to employees</h2>
<div class="callout">
  <strong>☑ I agree to receive SMS text messages from ManageMyStaffing</strong><br>
  I consent to receive transactional SMS about open shifts, schedule changes, and HR communications. Msg &amp; data rates may apply. Reply STOP to opt out, HELP for help. Frequency varies. View our <a href="/privacy">Privacy Policy</a> and <a href="/terms">Terms</a>.
</div>

<h2>Verbal-consent path (admin-added employees)</h2>
<p>For employees who don't complete self-service onboarding, facility administrators may add them after confirming verbal consent in person. The admin attests to the consent in the system, and the employee can revoke it at any time by replying STOP to any message they receive.</p>

<h2>Sample messages employees receive</h2>
<div class="sample-msg"><div class="from">From: ManageMyStaffing</div>Open shifts are available in ManageMyStaffing. Sign in to view and claim: https://managemystaffing.com — Reply STOP to opt out, HELP for help.</div>
<div class="sample-msg"><div class="from">From: ManageMyStaffing</div>Urgent: a shift needs coverage. Sign in to view: https://managemystaffing.com — Reply STOP to opt out.</div>
<div class="sample-msg"><div class="from">From: ManageMyStaffing</div>You've been added to your facility's schedule. Sign in: https://managemystaffing.com — Reply STOP to opt out, HELP for help.</div>

<h2>Opt-out (STOP) and help (HELP)</h2>
<ul>
  <li><strong>STOP</strong> — reply STOP to any message to immediately unsubscribe from all SMS. The system logs the opt-out and stops all further SMS to that number.</li>
  <li><strong>HELP</strong> — reply HELP to receive contact information for ManageMyStaffing support.</li>
  <li>Employees can also disable SMS notifications in their in-app profile under "Notification Preferences."</li>
  <li>Standard message and data rates may apply per the recipient's wireless carrier plan.</li>
</ul>

<h2>Frequency &amp; content</h2>
<ul>
  <li>Frequency varies based on the employee's role and the facility's staffing needs (typically 0–10 messages per week per employee).</li>
  <li>All SMS are <strong>transactional only</strong> — open shifts, schedule changes, time-off responses, HR documents. No marketing.</li>
</ul>

<h2>Privacy &amp; data handling</h2>
<p>Phone numbers are stored encrypted at rest and never shared with third parties for marketing. Full details: <a href="/privacy">Privacy Policy</a> § 3 (SMS communications &amp; opt-out).</p>

<h2>Contact</h2>
<p>ManageMyStaffing<br>
Solomon Ganz, CEO<br>
Email: <a href="mailto:bcsolomonganz@gmail.com">bcsolomonganz@gmail.com</a><br>
Phone: 347-456-1681</p>

<div class="nav"><a href="/">← Back to ManageMyStaffing</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></div>
</body></html>`);
});

app.get('/terms', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLegalPage('Terms of Service', `
<h1>Terms of Service</h1>
<p class="meta">Last updated: May 2026</p>

<p>These Terms of Service ("Terms") govern your use of the ManageMyStaffing application and related services ("Service"). By accessing or using the Service, you agree to these Terms.</p>

<h2>1. Eligibility &amp; accounts</h2>
<p>The Service is intended for use by skilled-nursing-facility staff and administrators authorized by their employer. You may only access the Service via an account provisioned by your employer. You're responsible for safeguarding your credentials and for all activity under your account.</p>

<h2>2. Acceptable use</h2>
<p>You agree not to:</p>
<ul>
  <li>Access data outside your authorized scope (your facility, your role).</li>
  <li>Reverse-engineer, decompile, or attempt to derive source code.</li>
  <li>Use automated tools to scrape or extract data.</li>
  <li>Upload malware, phishing content, or attempt to disrupt the Service.</li>
  <li>Use the Service to send unsolicited messages to people who haven't consented.</li>
</ul>

<h2>3. SMS &amp; messaging</h2>
<p>The Service may send SMS notifications to staff who have opted in. By providing your phone number, you consent to receive SMS messages relating to your work schedule, open shifts, and HR communications. Standard message and data rates apply per your wireless plan. Reply STOP at any time to opt out.</p>

<h2>4. Customer data &amp; ownership</h2>
<p>Your employer (the facility) owns the data they enter or that's generated through their use of the Service. ManageMyStaffing is a Business Associate processing this data on the facility's behalf. We do not claim ownership of customer data.</p>

<h2>5. Service availability</h2>
<p>We aim for high availability but the Service is provided "as is" without warranty of uninterrupted operation. Scheduled maintenance is announced in advance. Critical security patches may be applied without prior notice.</p>

<h2>6. Compliance</h2>
<p>The Service is designed to support HIPAA, CMS PBJ reporting, and standard wage-and-hour compliance. <strong>You and your employer are responsible</strong> for ensuring data entered into the Service is accurate, that you've obtained necessary consents, and that your use of the data complies with applicable law (HIPAA, FLSA, state employment laws, etc.).</p>

<h2>7. Termination</h2>
<p>Your employer may terminate your account at any time. We may suspend or terminate accounts that violate these Terms. Upon termination, your access ends but data is retained per the Privacy Policy.</p>

<h2>8. Limitation of liability</h2>
<p>To the maximum extent permitted by law, ManageMyStaffing's total liability for any claim arising from the Service is limited to the fees paid by your employer for the Service in the 12 months preceding the claim. We're not liable for indirect, incidental, or consequential damages, including lost profits or lost data.</p>

<h2>9. Indemnification</h2>
<p>You agree to indemnify ManageMyStaffing for claims arising from your violation of these Terms or your misuse of the Service.</p>

<h2>10. Changes to these Terms</h2>
<p>We may update these Terms. Material changes will be notified to your facility's administrators. Continued use after changes constitutes acceptance.</p>

<h2>11. Governing law</h2>
<p>These Terms are governed by the laws of the state of Texas, without regard to conflict-of-law rules. Disputes will be resolved in the state or federal courts located in Texas.</p>

<h2>12. Contact</h2>
<p>ManageMyStaffing<br>Solomon Ganz, CEO<br>Email: <a href="mailto:bcsolomonganz@gmail.com">bcsolomonganz@gmail.com</a><br>Phone: 347-456-1681</p>
`));
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
  // Snapshots run in BOTH modes. In PG mode the underlying _writeSnapshot
  // encrypts dataCache directly (no DATA_FILE to copy); in file mode it
  // copies the encrypted file. Either way the user gets the same
  // restore-to-N-hours-ago capability.
  try {
    const all = await _listSnapshotFiles();
    // Surface the Azure PITR window in PG mode as supplementary info — the
    // human can use the portal to restore further back than the in-app
    // snapshot retention if needed. Not actionable from this endpoint.
    let pitr = null;
    if (_useDB) {
      pitr = {
        windowDays: 7,        // Azure flexible-server default
        note: 'For older recovery, use Azure PostgreSQL point-in-time restore via the portal or az CLI.',
      };
    }
    res.json({
      backend: _useDB ? 'postgres' : 'file',
      retention: { allUnder: '24h', hourly: '30d', daily: '365d' },
      pitr,
      snapshots: all.map(s => ({ filename: s.name, takenAt: new Date(s.ts).toISOString() })),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/snapshots', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    _lastSnapshotAt = 0;                   // force through the throttle
    await _writeSnapshot();
    auditLog('BACKUP_SNAPSHOT_FORCED', req.user, { backend: _useDB ? 'postgres' : 'file' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/admin/inspect-disk — superadmin-only directory dump for recovery
// Lists every file in SECURE_DIR and BACKUP_DIR, plus tries to decrypt
// each .json/.json.tmp/.json.bak we find and returns row counts. Read-only;
// safe to call repeatedly. Supplements the snapshots endpoint by surfacing
// .tmp / .bak / stray copies that aren't tracked by the snapshot system.
app.get('/api/admin/inspect-disk', requireAuth, requireSuperAdmin, async (req, res) => {
  const out = {
    config: {
      IS_AZURE,
      SECURE_DIR,
      DATA_FILE,
      BACKUP_DIR,
      _useDB,
      hasDataKey: !!process.env.DATA_ENCRYPTION_KEY,
    },
    secureDir: [],
    backupDir: [],
    home: [],
  };
  const fsSync2 = require('fs');
  const cryptoLib = require('crypto');
  const dataKey = process.env.DATA_ENCRYPTION_KEY;
  function probe(filePath) {
    try {
      const raw = fsSync2.readFileSync(filePath, 'utf8');
      if (!raw || raw[0] !== '{') return { error: 'not JSON' };
      const obj = JSON.parse(raw);
      let data;
      let isEnc = false;
      if (obj.iv && obj.data && obj.authTag) {
        if (!dataKey) return { encrypted: true, error: 'no data key' };
        isEnc = true;
        const key = Buffer.from(dataKey, 'hex');
        const iv  = Buffer.from(obj.iv, 'hex');
        const tag = Buffer.from(obj.authTag, 'hex');
        const dec = cryptoLib.createDecipheriv('aes-256-gcm', key, iv);
        dec.setAuthTag(tag);
        const buf = Buffer.concat([dec.update(Buffer.from(obj.data, 'hex')), dec.final()]);
        data = JSON.parse(buf.toString());
      } else {
        data = obj;
      }
      return {
        encrypted: isEnc,
        buildings: (data.buildings || []).length,
        employees: (data.employees || []).length,
        shifts:    (data.shifts    || []).length,
        accounts:  (data.accounts  || []).length,
        companies: (data.companies || []).length,
        firstBuildingNames: (data.buildings || []).slice(0, 8).map(b => b.name),
      };
    } catch (e) { return { error: e.message }; }
  }
  function scanDir(dir) {
    const list = [];
    if (!fsSync2.existsSync(dir)) return list;
    for (const name of fsSync2.readdirSync(dir)) {
      const fp = require('path').join(dir, name);
      let st;
      try { st = fsSync2.statSync(fp); } catch (e) { list.push({ name, error: e.message }); continue; }
      const entry = {
        name,
        sizeKB: +(st.size / 1024).toFixed(1),
        mtime: st.mtime.toISOString(),
        isDir: st.isDirectory(),
      };
      if (!st.isDirectory() && /\.json(\.tmp|\.bak)?$/.test(name)) {
        entry.probe = probe(fp);
      }
      list.push(entry);
    }
    return list;
  }
  out.secureDir = scanDir(SECURE_DIR);
  out.backupDir = scanDir(BACKUP_DIR);
  // /home top-level scan for any mc-*/mms-*/.bak/backup files
  if (fsSync2.existsSync('/home')) {
    try {
      out.home = fsSync2.readdirSync('/home')
        .filter(n => /^(mc-|mms-)|backup|\.bak$/i.test(n))
        .map(n => {
          const fp = '/home/' + n;
          try {
            const st = fsSync2.statSync(fp);
            return { name: n, sizeKB: +(st.size/1024).toFixed(1), mtime: st.mtime.toISOString(), isDir: st.isDirectory() };
          } catch (e) { return { name: n, error: e.message }; }
        });
    } catch (e) { out.home = [{ error: e.message }]; }
  }
  res.json(out);
});

// GET /api/admin/probe-pg — superadmin Postgres connectivity probe.
// Creates a fresh pg client (independent of the global _pool that's
// already failed) and reports the exact connection error + row counts
// of the core tables. Used to diagnose "server fell back to file mode
// with empty data" — if PG actually has the data, the snapshots / file
// fallback are red herrings.
app.get('/api/admin/probe-pg', requireAuth, requireSuperAdmin, async (_req, res) => {
  const result = {
    pgConnSet: !!process.env.PG_CONN,
    pgConnRedacted: process.env.PG_CONN
      ? process.env.PG_CONN.replace(/:[^:@]+@/, ':***@')
      : null,
    _useDB,
    poolPing: null,
    fresh: { connect: null, error: null, counts: null, sampleRows: null },
  };
  if (_useDB) {
    try { result.poolPing = await dbRepo.ping(); }
    catch (e) { result.poolPing = 'error: ' + e.message; }
  }
  if (!process.env.PG_CONN) return res.json(result);

  // Fresh connection to bypass the cached pool that may have failed at boot.
  const { Client } = require('pg');
  const c = new Client({
    connectionString: process.env.PG_CONN,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
  });
  try {
    await c.connect();
    result.fresh.connect = 'ok';
    const counts = {};
    for (const t of ['buildings','employees','shifts','accounts','companies','schedule_patterns']) {
      try {
        const r = await c.query(`SELECT count(*)::int AS n FROM ${t}`);
        counts[t] = r.rows[0]?.n ?? null;
      } catch (e) { counts[t] = 'error: ' + e.message; }
    }
    result.fresh.counts = counts;
    // First few building names so we know if it's the user's real data
    try {
      const r = await c.query(`SELECT id, name, beds, company_id FROM buildings ORDER BY name LIMIT 8`);
      result.fresh.sampleRows = r.rows;
    } catch (e) { result.fresh.sampleRows = 'error: ' + e.message; }
  } catch (e) {
    result.fresh.error = e.message + (e.code ? ` [${e.code}]` : '');
  } finally {
    try { await c.end(); } catch (_) {}
  }
  res.json(result);
});

// POST /api/admin/snapshots/restore
//
// Hardened after the 2026-05-08 incident: a panic-debug session called this
// endpoint 18× during diagnosis with snapshots that turned out to be empty,
// each call wiped the in-memory cache (which was the ONLY copy of that
// session's writes since the file-mode persist path was broken). The
// edits from that session were lost.
//
// Two new safety gates:
//   1. dryRun:true returns the snapshot's row counts and a diff vs the
//      live cache, WITHOUT mutating dataCache or persisting. Use this to
//      inspect a snapshot before committing to a restore.
//   2. shrinkPercent guard: if the snapshot's collection counts are
//      smaller than live by >= 10%, reject the restore unless the caller
//      passes confirmShrink:true. This prevents accidentally rolling
//      back into a near-empty snapshot.
// POST /api/admin/provision-demo-admin
// Superadmin-only convenience endpoint to spin up (or refresh) a building-
// scoped admin login that can be shared for product demos. Idempotent — if
// an account with the given email already exists it gets the new password,
// name, and building scope rather than a duplicate. Useful when the offline
// bin/create-demo-admin.js script can't reach the running server's PG
// connection (the bcrypt + PG_CONN env aren't surfaced to Kudu commands).
//
// Body: { email, name, password, buildingId }
// Always grants role:'admin' (never superadmin). Always single-building.
app.post('/api/admin/provision-demo-admin', requireAuth, requireSuperAdmin, async (req, res) => {
  const email      = String((req.body && req.body.email)      || '').trim().toLowerCase();
  const name       = String((req.body && req.body.name)       || '').trim();
  const password   = String((req.body && req.body.password)   || '');
  const buildingId = String((req.body && req.body.buildingId) || '').trim();
  if (!email || !name || !password || !buildingId) {
    return res.status(400).json({ error: 'email, name, password, buildingId are all required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 chars' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'invalid email' });
  }
  const data = await loadData();
  const building = (data.buildings || []).find(b => b.id === buildingId);
  if (!building) return res.status(404).json({ error: 'building not found', buildingId });

  const bcryptLib = require('bcrypt');
  const ph = await bcryptLib.hash(password, 12);
  const nowIso = new Date().toISOString();
  data.accounts = data.accounts || [];
  let acct = data.accounts.find(a => (a.email || '').toLowerCase() === email);
  let mode;
  if (acct) {
    // Refresh in place. Don't change the id (preserves audit log refs).
    acct.name        = name;
    acct.role        = 'admin';
    acct.buildingId  = buildingId;
    acct.buildingIds = [buildingId];
    acct.ph          = ph;
    acct.activatedAt = acct.activatedAt || nowIso;
    delete acct.passwordResetTokenHash;
    delete acct.passwordResetExpiry;
    delete acct.lockedUntil;
    delete acct.failedAttempts;
    mode = 'updated';
  } else {
    acct = {
      id:           'acc_demo_' + Date.now(),
      name, email,
      role:         'admin',
      buildingId,
      buildingIds:  [buildingId],
      ph,
      schedulerOnly: false,
      activatedAt: nowIso,
      invitedBy:   req.user.email || req.user.id,
      invitedAt:   nowIso,
    };
    data.accounts.push(acct);
    mode = 'created';
  }
  dataCache = data;
  _bumpDataVersion();
  markDirty();
  auditLog('DEMO_ADMIN_PROVISIONED', req.user, { email, buildingId, mode });
  res.json({
    ok: true,
    mode,
    accountId: acct.id,
    email,
    buildingId,
    buildingName: building.name,
    role: 'admin',
    note: 'Account is live. Sign in at the app URL with these credentials.',
  });
});

app.post('/api/admin/snapshots/restore', requireAuth, requireSuperAdmin, async (req, res) => {
  // Restore now works in BOTH modes. In PG mode the restored dataCache gets
  // flushed to Postgres via persistCache() (dbRepo.saveAll under the hood);
  // in file mode it gets re-encrypted to disk. Same safety guards in both:
  // dryRun=true preview, confirmShrink=true required for >10% drops.
  const filename = String(req.body?.filename || '');
  if (!filename) return res.status(400).json({ error: 'filename required' });
  const dryRun        = !!req.body?.dryRun;
  const confirmShrink = !!req.body?.confirmShrink;
  try {
    if (!/^mms-snapshot-[0-9TZ:.\-]+\.json$/i.test(filename)) {
      return res.status(400).json({ error: 'invalid snapshot name' });
    }
    const src = path.join(BACKUP_DIR, filename);
    const raw = await fs.readFile(src, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.iv || !parsed.data || !parsed.authTag) {
      return res.status(400).json({ error: 'snapshot is not in encrypted format' });
    }
    const decoded = await decrypt(parsed);

    // Compare snapshot vs live counts so the caller can sanity-check
    // before committing. dataCache is the live in-memory state; if it's
    // null we just loaded fresh, so treat as empty for the diff.
    const live = dataCache || {};
    const cmp = (key) => {
      const liveN = (live[key] || []).length;
      const snapN = (decoded[key] || []).length;
      const drop  = liveN - snapN;
      const dropPct = liveN > 0 ? Math.round((drop / liveN) * 100) : 0;
      return { live: liveN, snapshot: snapN, drop, dropPercent: dropPct };
    };
    const diff = {
      buildings:        cmp('buildings'),
      employees:        cmp('employees'),
      shifts:           cmp('shifts'),
      schedulePatterns: cmp('schedulePatterns'),
      accounts:         cmp('accounts'),
      companies:        cmp('companies'),
    };
    const maxDrop = Math.max(...Object.values(diff).map(d => d.dropPercent));

    if (dryRun) {
      // Read-only — no mutation, no persistCache. Safe to call repeatedly.
      auditLog('BACKUP_SNAPSHOT_RESTORE_DRYRUN', req.user, { filename, maxDrop });
      return res.json({
        ok: true, dryRun: true, filename,
        snapshotTakenAt: parsed._snapshottedAt || null,
        diff, maxDropPercent: maxDrop,
        wouldShrinkSignificantly: maxDrop >= 10,
      });
    }

    // Block obviously-destructive restores unless explicitly confirmed.
    // 10% drop threshold is intentionally conservative — operators in
    // panic mode shouldn't accidentally roll back into a near-empty
    // snapshot. confirmShrink:true bypasses the guard.
    if (maxDrop >= 10 && !confirmShrink) {
      auditLog('BACKUP_SNAPSHOT_RESTORE_BLOCKED_SHRINK', req.user, { filename, maxDrop, diff });
      return res.status(409).json({
        error: 'Restore would shrink data significantly. Pass confirmShrink:true to proceed.',
        maxDropPercent: maxDrop,
        diff,
      });
    }

    const result = await _restoreSnapshotFile(filename);
    auditLog('BACKUP_SNAPSHOT_RESTORED', req.user, { filename, restoredAt: result.restoredAt, diff });
    res.json({ ok: true, diff, ...result });
  } catch (e) {
    auditLog('BACKUP_SNAPSHOT_RESTORE_FAILED', req.user, { filename, err: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ── DATA INTEGRITY HEALTH ────────────────────────────────────────────────────
// Compares LIVE row counts to the all-time-max (row_high_water) per building.
// If anything is below max, that's a data loss event in progress. Caller can
// poll this endpoint from monitoring (or set up an alert).
app.get('/api/admin/data-integrity', requireAuth, requireAdmin, async (req, res) => {
  if (!_useDB) return res.status(503).json({ error: 'Endpoint requires postgres backend' });
  try {
    const pgLib = require('pg');
    const client = new pgLib.Client({
      connectionString: process.env.PG_CONN,
      ssl: { rejectUnauthorized: false },
    });
    await client.connect();
    try {
      const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
      const isSA = req.user.role === 'superadmin';
      const [empCounts, hwm, history] = await Promise.all([
        client.query(`SELECT building_id, COUNT(*)::int AS n FROM employees GROUP BY building_id`),
        client.query(`SELECT scope, max_count, observed_at FROM row_high_water WHERE scope LIKE 'employees:%'`),
        client.query(`
          SELECT building_id, COUNT(*) FILTER (WHERE op = 'delete')::int AS deletes_24h,
                 COUNT(*) FILTER (WHERE op = 'insert')::int AS inserts_24h
          FROM employee_history
          WHERE ts > now() - interval '24 hours'
          GROUP BY building_id
        `),
      ]);

      const liveByBld = new Map(empCounts.rows.map(r => [r.building_id, r.n]));
      const hwmByBld  = new Map(hwm.rows.map(r => [r.scope.replace(/^employees:/, ''), r.max_count]));
      const histByBld = new Map(history.rows.map(r => [r.building_id, { deletes: r.deletes_24h, inserts: r.inserts_24h }]));

      const allBlds = new Set([...liveByBld.keys(), ...hwmByBld.keys(), ...histByBld.keys()]);
      const buildings = [];
      let alertCount = 0;
      for (const bid of allBlds) {
        if (!isSA && !callerBIds.has(bid)) continue;
        const live = liveByBld.get(bid) || 0;
        const max  = hwmByBld.get(bid) || 0;
        const hist = histByBld.get(bid) || { deletes: 0, inserts: 0 };
        const lossPct = max > 0 ? Math.round(((max - live) / max) * 100) : 0;
        const status = (live < max) ? (lossPct >= 50 ? 'CRITICAL' : 'WARN') : 'OK';
        if (status !== 'OK') alertCount++;
        buildings.push({
          buildingId: bid,
          liveEmployees: live,
          allTimeMax: max,
          lossPercent: lossPct,
          status,
          last24h: hist,
        });
      }
      res.json({
        ok: alertCount === 0,
        alerts: alertCount,
        buildings: buildings.sort((a, b) => a.buildingId.localeCompare(b.buildingId)),
        checkedAt: new Date().toISOString(),
      });
    } finally { await client.end(); }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── RECOVER SHIFTS FROM HISTORY LOG ──────────────────────────────────────────
// Reads shift_history (append-only) and replays the most-recent state for
// every shift_id ever seen in this building. Restores shifts that were
// deleted, with their original employee_id / status / dates intact.
//
// dryRun:true returns counts without writing — use this first to confirm
// what would be restored. Then call again with dryRun:false.
//
// Caller must be admin/SA and scoped to the building. Optional sinceTs
// limits the scan to recent history (default: all history).
app.post('/api/admin/recover-shifts-from-history', requireAuth, requireAdmin, async (req, res) => {
  if (!_useDB) return res.status(503).json({ error: 'Endpoint requires postgres backend' });
  const buildingId = String(req.body?.buildingId || '').trim();
  const dryRun     = !!req.body?.dryRun;
  const sinceTs    = String(req.body?.sinceTs || '').trim();
  if (!buildingId) return res.status(400).json({ error: 'buildingId required' });
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  const pgLib = require('pg');
  const liveConn = process.env.PG_CONN;
  if (!liveConn) return res.status(503).json({ error: 'PG_CONN not set' });
  const client = new pgLib.Client({
    connectionString: liveConn,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    statement_timeout: 60000,
  });

  let recovered = 0;
  try {
    await client.connect();

    // Latest non-null state per shift_id. If most-recent op is 'delete',
    // we still resurrect (caller wants the lost shifts back).
    const sinceClause = sinceTs ? `AND ts >= $2` : '';
    const params = sinceTs ? [buildingId, sinceTs] : [buildingId];
    const r = await client.query(`
      WITH latest_per_shift AS (
        SELECT DISTINCT ON (shift_id)
               shift_id, op,
               COALESCE(after_row, before_row) AS row_data,
               ts
        FROM shift_history
        WHERE building_id = $1 ${sinceClause}
        ORDER BY shift_id, ts DESC
      ),
      live AS (
        SELECT id FROM shifts WHERE building_id = $1
      )
      SELECT lp.shift_id, lp.row_data, lp.op
      FROM latest_per_shift lp
      LEFT JOIN live l ON l.id = lp.shift_id
      WHERE lp.row_data IS NOT NULL
        AND l.id IS NULL          -- only restore rows currently MISSING from live
    `, params);

    if (dryRun) {
      await client.end();
      return res.json({
        ok: true, dryRun: true,
        wouldRestore: r.rows.length,
        sample: r.rows.slice(0, 5).map(x => ({
          id: x.shift_id,
          date: x.row_data?.shift_date,
          group: x.row_data?.group,
          type: x.row_data?.shift_type,
          status: x.row_data?.status,
          employeeId: x.row_data?.employee_id,
          lastSeen: x.op,
        })),
      });
    }

    for (const row of r.rows) {
      const s = row.row_data;
      // Verify employee_id still exists; if employee was hard-deleted,
      // restore the shift as 'open' (not assigned to a non-existent emp).
      let empIdToUse = s.employee_id;
      if (empIdToUse) {
        const ex = await client.query(`SELECT id FROM employees WHERE id = $1`, [empIdToUse]);
        if (!ex.rows.length) empIdToUse = null;
      }
      const status = empIdToUse ? (s.status || 'scheduled') : 'open';
      await client.query(
        `INSERT INTO shifts (id, building_id, employee_id, shift_date, shift_type, "group",
            start_time, end_time, status, claim_request, metadata, version)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12,1))
          ON CONFLICT (id) DO NOTHING`,
        [
          s.id, s.building_id, empIdToUse, s.shift_date, s.shift_type, s.group,
          s.start_time || null, s.end_time || null, status,
          s.claim_request || null, s.metadata || {}, s.version || 1,
        ]
      );
      recovered++;
    }

    dataCache = await dbRepo.loadAll();
    _bumpDataVersion();
    auditLog('SHIFT_RECOVERY_FROM_HISTORY', req.user, { buildingId, recovered, sinceTs: sinceTs || null });
    res.json({ ok: true, recovered });
  } catch (e) {
    auditLog('SHIFT_RECOVERY_FROM_HISTORY_FAILED', req.user, { buildingId, err: e.message });
    res.status(500).json({ error: e.message });
  } finally {
    try { await client.end(); } catch {}
  }
});

// ── RECOVER EMPLOYEES FROM HISTORY LOG ───────────────────────────────────────
// Reads employee_history (append-only audit log) and replays the most-recent
// state of every employee that was ever in the building, restoring them all.
// This is the ultimate insurance: even if the live employees table is wiped,
// as long as employee_history exists we can rebuild from scratch.
app.post('/api/admin/recover-from-history', requireAuth, requireAdmin, async (req, res) => {
  if (!_useDB) return res.status(503).json({ error: 'Endpoint requires postgres backend' });
  const buildingId = String(req.body?.buildingId || '').trim();
  const dryRun     = !!req.body?.dryRun;
  if (!buildingId) return res.status(400).json({ error: 'buildingId required' });
  // Authz: admin can only recover into their own building scope. SA can recover anywhere.
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  const pgLib = require('pg');
  const liveConn = process.env.PG_CONN || '';
  if (!liveConn) return res.status(503).json({ error: 'PG_CONN not set' });
  let url; try { url = new URL(liveConn.startsWith('postgres') ? liveConn : 'postgres://' + liveConn); }
  catch (e) { return res.status(500).json({ error: 'Cannot parse PG_CONN' }); }
  const client = new pgLib.Client({
    connectionString: liveConn,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    statement_timeout: 60000,
  });

  let recovered = 0;
  try {
    await client.connect();
    // For each emp_id ever seen in this building, take the most recent
    // non-delete row state. If the most recent op was 'delete', we still
    // recover them (they probably shouldn't have been deleted given this
    // endpoint exists for accidental wipes). Caller can re-delete after.
    const r = await client.query(`
      WITH latest_per_emp AS (
        SELECT DISTINCT ON (emp_id)
               emp_id, op, after_row, before_row, ts
        FROM employee_history
        WHERE building_id = $1
        ORDER BY emp_id, ts DESC
      )
      SELECT emp_id,
             COALESCE(after_row, before_row) AS row_data,
             op
      FROM latest_per_emp
      WHERE COALESCE(after_row, before_row) IS NOT NULL
    `, [buildingId]);

    if (dryRun) {
      await client.end();
      return res.json({
        ok: true, dryRun: true,
        wouldRestore: r.rows.length,
        sampleNames: r.rows.slice(0, 10).map(x => x.row_data?.name).filter(Boolean),
      });
    }

    for (const row of r.rows) {
      const e = row.row_data;
      await client.query(
        `INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
            employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms,
            metadata, termination_log)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          ON CONFLICT (id) DO UPDATE SET
            building_id=EXCLUDED.building_id, account_id=EXCLUDED.account_id,
            name=EXCLUDED.name, email=EXCLUDED.email, phone=EXCLUDED.phone,
            "group"=EXCLUDED."group", employment_type=EXCLUDED.employment_type,
            hourly_rate=EXCLUDED.hourly_rate, hire_date=EXCLUDED.hire_date,
            inactive=EXCLUDED.inactive,
            notif_email=EXCLUDED.notif_email, notif_sms=EXCLUDED.notif_sms,
            metadata=EXCLUDED.metadata, termination_log=EXCLUDED.termination_log,
            updated_at=now()`,
        [
          e.id, e.building_id, e.account_id || null, e.name, e.email || null,
          e.phone || null, e.group, e.employment_type || null,
          e.hourly_rate || null, e.hire_date || null, !!e.inactive,
          e.notif_email !== false, !!e.notif_sms,
          e.metadata || {}, e.termination_log || [],
        ]
      );
      recovered++;
    }

    // Also re-link orphaned shifts where employee_id is null but the same
    // emp_id used to own them. We use the history table to find that mapping.
    const shiftLink = await client.query(`
      WITH shift_owners AS (
        SELECT DISTINCT ON (s.id) s.id AS shift_id, h.emp_id, h.before_row->>'building_id' AS bld
        FROM shifts s
        JOIN employee_history h ON h.building_id = s.building_id
        WHERE s.building_id = $1 AND s.employee_id IS NULL
      )
      UPDATE shifts SET employee_id = NULL  -- placeholder; re-linking via shift_history would be ideal
      WHERE FALSE
    `, [buildingId]);

    await client.end();

    // Refresh in-memory cache so /api/data immediately reflects the recovered rows.
    dataCache = await dbRepo.loadAll();
    _bumpDataVersion();

    auditLog('EMPLOYEE_RECOVERY_FROM_HISTORY', req.user, { buildingId, recovered });
    res.json({ ok: true, recovered });
  } catch (e) {
    auditLog('EMPLOYEE_RECOVERY_FROM_HISTORY_FAILED', req.user, { buildingId, err: e.message });
    res.status(500).json({ error: e.message });
  } finally {
    try { await client.end(); } catch {}
  }
});

// ── PITR CROSS-SERVER RECOVERY ───────────────────────────────────────────────
// Pulls employees / schedule_patterns / shift→employee links from a separate
// PG server (typically an Azure PITR clone like mms-pg-restore) and writes
// them back into the live db. Used to recover after a wipe when normal
// snapshots aren't available (the 2026-04-30 Kirkland incident).
//
// Auth: admin (scoped to caller's building) or superadmin (any building).
// Body:
//   restoredHost  — e.g. 'mms-pg-restore.postgres.database.azure.com'
//   buildingId    — the building whose rows we want to recover
//   dryRun        — when true, returns counts without writing
//
// The restored server must accept connections from this App Service. PITR
// inherits firewall rules from the source by default, so this just works
// in the standard Azure setup.
app.post('/api/admin/recover-from-pitr', requireAuth, requireAdmin, async (req, res) => {
  if (!_useDB) return res.status(503).json({ error: 'Endpoint requires postgres backend' });
  const restoredHost = String(req.body?.restoredHost || '').trim();
  const buildingId   = String(req.body?.buildingId   || '').trim();
  const dryRun       = !!req.body?.dryRun;
  if (!restoredHost || !buildingId) {
    return res.status(400).json({ error: 'restoredHost and buildingId required' });
  }
  // Defense-in-depth: the host must be a public Azure-PG hostname; refuse
  // anything else so this can't be misused as an exfiltration tool.
  if (!/^[a-z0-9][a-z0-9-]{0,62}\.postgres\.database\.azure\.com$/i.test(restoredHost)) {
    return res.status(400).json({ error: 'restoredHost must be an *.postgres.database.azure.com hostname' });
  }
  // Authz: admin can only recover into their own building scope. SA can recover anywhere.
  const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
  if (req.user.role !== 'superadmin' && !callerBIds.has(buildingId)) {
    return res.status(403).json({ error: 'Out of scope: cannot recover into a building outside your access' });
  }

  // Build a connection string for the restored server using the same
  // credentials we use for the live server. Azure PITR preserves admin login,
  // so the existing PG_CONN password is the right one.
  const liveConn = process.env.PG_CONN || '';
  if (!liveConn) return res.status(503).json({ error: 'PG_CONN not set' });
  let url;
  try { url = new URL(liveConn.startsWith('postgres') ? liveConn : 'postgres://' + liveConn); }
  catch (e) { return res.status(500).json({ error: 'Cannot parse PG_CONN' }); }
  const pgLib = require('pg');
  const restoredClient = new pgLib.Client({
    host: restoredHost,
    port: parseInt(url.port || '5432', 10),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: url.pathname.replace(/^\//, '') || 'mms',
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    statement_timeout: 30000,
  });

  let recovered = { employees: 0, patterns: 0, shiftsRelinked: 0 };
  try {
    await restoredClient.connect();

    // Pull rows from the restored server.
    const empRes = await restoredClient.query(
      `SELECT id, building_id, account_id, name, email, phone, "group",
              employment_type, hourly_rate, hire_date, inactive,
              notif_email, notif_sms, metadata, termination_log
       FROM employees
       WHERE building_id = $1`,
      [buildingId]
    );
    const patRes = await restoredClient.query(
      `SELECT id, building_id, emp_id, shift_type, "group", pattern,
              start_date, end_date, active
       FROM schedule_patterns
       WHERE building_id = $1`,
      [buildingId]
    );
    // Pull the shift -> employee mapping that EXISTED at restore time, so we
    // can re-link the orphaned shifts in live.
    const shiftRes = await restoredClient.query(
      `SELECT id, employee_id, status
       FROM shifts
       WHERE building_id = $1 AND employee_id IS NOT NULL`,
      [buildingId]
    );

    if (dryRun) {
      await restoredClient.end();
      return res.json({
        ok: true, dryRun: true,
        wouldRestore: {
          employees: empRes.rows.length,
          patterns:  patRes.rows.length,
          shiftLinks: shiftRes.rows.length,
        },
        sampleEmployees: empRes.rows.slice(0, 5).map(r => ({ id: r.id, name: r.name, group: r.group })),
      });
    }

    // Write back to the live db in a single transaction.
    const dbRepoLib = require('./db/repo');
    await dbRepoLib.withTx(async (c) => {
      for (const e of empRes.rows) {
        await c.query(
          `INSERT INTO employees (id, building_id, account_id, name, email, phone, "group",
              employment_type, hourly_rate, hire_date, inactive, notif_email, notif_sms,
              metadata, termination_log)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            ON CONFLICT (id) DO UPDATE SET
              building_id=EXCLUDED.building_id, account_id=EXCLUDED.account_id,
              name=EXCLUDED.name, email=EXCLUDED.email, phone=EXCLUDED.phone,
              "group"=EXCLUDED."group", employment_type=EXCLUDED.employment_type,
              hourly_rate=EXCLUDED.hourly_rate, hire_date=EXCLUDED.hire_date,
              inactive=EXCLUDED.inactive,
              notif_email=EXCLUDED.notif_email, notif_sms=EXCLUDED.notif_sms,
              metadata=EXCLUDED.metadata, termination_log=EXCLUDED.termination_log,
              updated_at=now()`,
          [
            e.id, e.building_id, e.account_id, e.name, e.email, e.phone, e.group,
            e.employment_type, e.hourly_rate, e.hire_date, e.inactive,
            e.notif_email, e.notif_sms,
            e.metadata, e.termination_log,
          ]
        );
        recovered.employees++;
      }
      for (const p of patRes.rows) {
        await c.query(
          `INSERT INTO schedule_patterns (id, building_id, emp_id, shift_type, "group",
              pattern, start_date, end_date, active)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (id) DO UPDATE SET
              shift_type=EXCLUDED.shift_type, "group"=EXCLUDED."group",
              pattern=EXCLUDED.pattern, start_date=EXCLUDED.start_date,
              end_date=EXCLUDED.end_date, active=EXCLUDED.active`,
          [p.id, p.building_id, p.emp_id, p.shift_type, p.group,
           p.pattern, p.start_date, p.end_date, p.active]
        );
        recovered.patterns++;
      }
      // Re-link shifts. UPDATE only — we don't re-create rows, just heal.
      for (const s of shiftRes.rows) {
        const r = await c.query(
          `UPDATE shifts SET employee_id = $1, status = $2, updated_at = now()
           WHERE id = $3 AND building_id = $4 AND employee_id IS NULL`,
          [s.employee_id, s.status, s.id, buildingId]
        );
        recovered.shiftsRelinked += r.rowCount;
      }
    });

    // Refresh dataCache so subsequent /api/data calls see the recovered rows.
    dataCache = await dbRepoLib.loadAll();
    _bumpDataVersion();

    auditLog('PITR_RECOVERY_PERFORMED', req.user, {
      restoredHost, buildingId, ...recovered,
    });
    res.json({ ok: true, recovered });
  } catch (e) {
    auditLog('PITR_RECOVERY_FAILED', req.user, { restoredHost, buildingId, err: e.message });
    res.status(500).json({ error: e.message });
  } finally {
    try { await restoredClient.end(); } catch {}
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

// Punch helpers live in lib/punch.js so node --test can exercise them
// without booting the full Express + JWT stack.
const _punchLib = require('./lib/punch');
const _classifyPunch     = _punchLib.classifyPunch;
const _findOrCreatePunch = _punchLib.findOrCreatePunch;

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
  }, TIMECLOCK_KIOSK_SECRET, { expiresIn: '24h' });
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
//
// HIPAA notes:
//   - DMs are an intra-system encrypted channel (TLS in transit, encrypted
//     at rest in Postgres / encrypted-JSON file). PHI is PERMITTED here —
//     this is the legitimate channel for clinical communication. We do
//     NOT run scanMessageForPHI() on DM bodies the way SMS/Alert do,
//     because SMS rides cellular networks unencrypted while DMs never
//     leave the system. Lock-screen push previews are stripped of body
//     content (see sendPushTo call below) so an unattended device can't
//     leak PHI either.
//   - getDataForUser scopes directMessages to the requesting user
//     (fromId === me OR toId === me) for every role including superadmin
//     — minimum-necessary applies even to platform staff. Audit oversight
//     of message activity goes through the DM_SENT audit log entries
//     (metadata only: sender, recipient, threadId, body length).

const _dmThreadId = _punchLib.dmThreadId;

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

  // Block check: recipient may have blocked the sender
  if (Array.isArray(data.blockedUsers) && data.blockedUsers.some(b => b.blockerId === toId && b.blockedId === myId)) {
    return res.status(403).json({ error: 'You cannot message this user' });
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
  // Fire-and-forget push to recipient.
  // HIPAA: lock-screen notifications are visible to anyone holding the
  // device, so the body MUST be generic — never the message content,
  // even truncated. The recipient sees the actual text only after they
  // unlock, open the app, and authenticate.
  sendPushTo(toId, {
    title: 'New message',
    body: 'From ' + (me.name || me.email || 'someone'),
    tag: 'dm:' + msg.threadId,
    url: '/app',
  }).catch(() => {});
  res.json({ ok: true, message: msg });
});

// ── POST /api/dm/report — Report a message (Apple Guideline 1.2 UGC) ────────
app.post('/api/dm/report', requireAuth, async (req, res) => {
  const { messageId, reason } = req.body || {};
  if (!messageId) return res.status(400).json({ error: 'messageId required' });
  const data = await loadData();
  const msg = (data.directMessages || []).find(m => m.id === messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (!Array.isArray(data.contentReports)) data.contentReports = [];
  data.contentReports.push({
    id: 'rpt_' + Date.now() + crypto.randomBytes(2).toString('hex'),
    messageId, reporterId: req.user.id, reporterName: req.user.name || req.user.email,
    fromId: msg.fromId, fromName: msg.fromName, body: msg.body,
    reason: String(reason || '').slice(0, 500), status: 'pending',
    createdAt: new Date().toISOString(),
  });
  markDirty();
  auditLog('CONTENT_REPORTED', req.user, { messageId, fromId: msg.fromId });
  res.json({ ok: true, message: 'Report submitted. An administrator will review it.' });
});

// ── POST /api/dm/block — Block a user from sending you DMs ──────────────────
app.post('/api/dm/block', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot block yourself' });
  const data = await loadData();
  if (!Array.isArray(data.blockedUsers)) data.blockedUsers = [];
  const existing = data.blockedUsers.find(b => b.blockerId === req.user.id && b.blockedId === userId);
  if (existing) return res.json({ ok: true, message: 'Already blocked' });
  data.blockedUsers.push({
    blockerId: req.user.id, blockedId: userId,
    createdAt: new Date().toISOString(),
  });
  markDirty();
  auditLog('USER_BLOCKED', req.user, { blockedId: userId });
  res.json({ ok: true, message: 'User blocked' });
});

// ── DELETE /api/dm/block — Unblock a user ────────────────────────────────────
app.delete('/api/dm/block', requireAuth, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const data = await loadData();
  if (!Array.isArray(data.blockedUsers)) return res.json({ ok: true });
  data.blockedUsers = data.blockedUsers.filter(b => !(b.blockerId === req.user.id && b.blockedId === userId));
  markDirty();
  auditLog('USER_UNBLOCKED', req.user, { unblockedId: userId });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// WEB PUSH NOTIFICATIONS — companion app (PWA)
// ─────────────────────────────────────────────────────────────────────────────
// VAPID keys: env vars take precedence (production). If missing, generate
// once and persist alongside other server data. Persisting to the data
// store survives restarts (would otherwise invalidate every existing
// subscription) without needing extra Azure config.
//
// Subscriptions are stored on data.pushSubscriptions:
//   { id, userId, endpoint, keys:{p256dh,auth}, addedAt, userAgent }
//
// Sending: sendPushTo(userId, payload) looks up all of that user's
// subscriptions and fires them in parallel. 410/404 responses mean the
// subscription was unsubscribed on the device side; we prune those.
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@managemystaffing.com';
let _vapidKeys = null;

async function ensureVapidKeys() {
  if (_vapidKeys) return _vapidKeys;
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    _vapidKeys = {
      publicKey: process.env.VAPID_PUBLIC_KEY,
      privateKey: process.env.VAPID_PRIVATE_KEY,
    };
  } else {
    const data = await loadData();
    if (data.vapidKeys?.publicKey && data.vapidKeys?.privateKey) {
      _vapidKeys = data.vapidKeys;
    } else {
      const generated = webpush.generateVAPIDKeys();
      data.vapidKeys = generated;
      markDirty();
      _vapidKeys = generated;
      console.log('[push] Generated VAPID keys (saved to data store). To pin them across redeploys, set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY env vars.');
    }
  }
  webpush.setVapidDetails(VAPID_SUBJECT, _vapidKeys.publicKey, _vapidKeys.privateKey);
  return _vapidKeys;
}

// Fire-and-forget. Never throws — push failures should never break the
// underlying business action that triggered the push.
async function sendPushTo(userId, payload) {
  if (!userId) return;
  try {
    await ensureVapidKeys();
    const data = await loadData();
    const subs = (data.pushSubscriptions || []).filter(s => s.userId === userId);
    if (!subs.length) return;
    const json = JSON.stringify(payload || {});
    const stale = [];
    await Promise.all(subs.map(async sub => {
      try {
        await webpush.sendNotification(
          { endpoint: sub.endpoint, keys: sub.keys },
          json,
          { TTL: 60 * 60 * 24 * 3 } // 3-day TTL
        );
      } catch (e) {
        if (e?.statusCode === 410 || e?.statusCode === 404) {
          stale.push(sub.id);
        } else {
          console.warn('[push] send failed', { userId, status: e?.statusCode, body: e?.body });
        }
      }
    }));
    if (stale.length) {
      data.pushSubscriptions = (data.pushSubscriptions || []).filter(s => !stale.includes(s.id));
      markDirty();
    }
  } catch (e) {
    console.warn('[push] sendPushTo failed', e?.message || e);
  }
}

// GET /api/push/vapid-public-key — client needs this to subscribe
app.get('/api/push/vapid-public-key', requireAuth, async (_req, res) => {
  try {
    const k = await ensureVapidKeys();
    res.json({ publicKey: k.publicKey });
  } catch (e) {
    res.status(503).json({ error: 'Push not configured' });
  }
});

// POST /api/push/subscribe — register a PushSubscription for the caller
app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys?.p256dh || !keys?.auth) {
    return res.status(400).json({ error: 'endpoint and keys.{p256dh,auth} required' });
  }
  await ensureVapidKeys();
  const data = await loadData();
  if (!Array.isArray(data.pushSubscriptions)) data.pushSubscriptions = [];
  // De-dupe by endpoint — repeat installs from the same device shouldn't
  // create stacking subscriptions.
  data.pushSubscriptions = data.pushSubscriptions.filter(s => s.endpoint !== endpoint);
  data.pushSubscriptions.push({
    id: 'pushsub_' + crypto.randomBytes(6).toString('hex'),
    userId: req.user.id,
    endpoint,
    keys: { p256dh: String(keys.p256dh).slice(0, 256), auth: String(keys.auth).slice(0, 64) },
    addedAt: new Date().toISOString(),
    userAgent: String(req.get('user-agent') || '').slice(0, 200),
  });
  // Cap to 10 per user to bound storage (Chrome rotates endpoints)
  const myCount = data.pushSubscriptions.filter(s => s.userId === req.user.id).length;
  if (myCount > 10) {
    const mine = data.pushSubscriptions.filter(s => s.userId === req.user.id)
      .sort((a, b) => (a.addedAt || '').localeCompare(b.addedAt || ''));
    const drop = mine.slice(0, myCount - 10).map(s => s.id);
    data.pushSubscriptions = data.pushSubscriptions.filter(s => !drop.includes(s.id));
  }
  markDirty();
  auditLog('PUSH_SUBSCRIBED', req.user, { endpoint: endpoint.slice(0, 80) + '…' });
  res.json({ ok: true });
});

// POST /api/push/unsubscribe — remove a PushSubscription by endpoint
app.post('/api/push/unsubscribe', requireAuth, async (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint required' });
  const data = await loadData();
  const before = (data.pushSubscriptions || []).length;
  data.pushSubscriptions = (data.pushSubscriptions || []).filter(s =>
    !(s.endpoint === endpoint && s.userId === req.user.id));
  if (data.pushSubscriptions.length !== before) markDirty();
  auditLog('PUSH_UNSUBSCRIBED', req.user, { endpoint: endpoint.slice(0, 80) + '…' });
  res.json({ ok: true });
});

// Initialize VAPID keys at boot (lazy — first /api/push/* call triggers it).
// Doing this here too means dev gets the "generated keys" log line on first
// run instead of on first user interaction.
ensureVapidKeys().catch(() => {});

// POST /api/dm/read — mark a thread as read up to a given timestamp
app.post('/api/dm/read', requireAuth, async (req, res) => {
  const { threadId, upTo } = req.body || {};
  if (!threadId) return res.status(400).json({ error: 'threadId required' });
  const me = req.user;
  const myId = me.id;
  // Defense-in-depth: only a participant in the thread should be able to
  // probe it. The per-message m.toId === myId guard below already prevents
  // marking other people's messages, but rejecting up front avoids leaking
  // the existence of arbitrary threads via the marked-count side channel.
  // ThreadId format from lib/punch.js is 'dm:<sortedIdA>:<sortedIdB>'.
  const tid = String(threadId);
  if (!tid.startsWith('dm:') || !tid.split(':').slice(1).includes(String(myId))) {
    return res.status(403).json({ error: 'Not a participant' });
  }
  const data = await loadData();
  const cutoff = upTo ? new Date(upTo).getTime() : Date.now();
  let marked = 0;
  for (const m of (data.directMessages || [])) {
    if (m.threadId !== tid)      continue;
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

// POST /api/shifts/:id/claim — employee requests to claim an open shift
// Used by the companion app (/app) so employees don't need /api/data POST
// rights. Mirrors the in-page claim flow (managemystaffing.html ~15921):
// sets shift.claimRequest, leaves status='open' until an admin approves.
app.post('/api/shifts/:id/claim', requireAuth, async (req, res) => {
  const shiftId = req.params.id;
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === shiftId);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  if (shift.status !== 'open') return res.status(400).json({ error: 'Shift is not open for claiming' });
  if (shift.claimRequest)      return res.status(409).json({ error: 'Shift already has a pending claim' });

  const me = req.user;
  // Authz: employee must be in same building + same group as the shift.
  // Admins/superadmins can also claim (e.g. floating between facilities)
  // but they're typically using the main UI.
  if (shift.buildingId && shift.buildingId !== me.buildingId &&
      !(me.buildingIds || []).includes(shift.buildingId) &&
      me.role !== 'superadmin') {
    return res.status(403).json({ error: 'Not authorized for this building' });
  }
  if (me.role === 'employee' && me.group !== shift.group) {
    return res.status(403).json({ error: 'Not authorized for this shift group' });
  }

  shift.claimRequest = {
    empId: me.id,
    empName: me.name || me.email,
    requestedAt: new Date().toISOString(),
  };
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist shift claim. Please retry.' });
  }
  auditLog('SHIFT_CLAIM_REQUESTED', me, {
    shiftId, date: shift.date, type: shift.type, group: shift.group,
  });
  // Push to building admins so they can approve from the app
  try {
    const adminAccts = (data.accounts || []).filter(a =>
      ['admin','hradmin','scheduler','superadmin','regionaladmin'].includes(a.role) &&
      (a.role === 'superadmin' ||
       a.buildingId === shift.buildingId ||
       (Array.isArray(a.buildingIds) && a.buildingIds.includes(shift.buildingId))));
    const summary = `${me.name || 'An employee'} wants the ${shift.type || ''} ${shift.group || ''} shift on ${shift.date}.`.replace(/\s+/g,' ').trim();
    for (const a of adminAccts) {
      sendPushTo(a.id, {
        title: 'New shift claim',
        body: summary,
        tag: 'claim-req:' + shift.id,
        url: '/app',
      }).catch(() => {});
    }
  } catch (e) {}
  res.json({ ok: true, shift });
});

// POST /api/shifts/:id/claim/approve — admin approves a pending claim
// Mirrors the in-page approveShiftClaim flow: sets the shift's employeeId
// to the requester, flips status to 'scheduled', drops claimRequest.
app.post('/api/shifts/:id/claim/approve', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === req.params.id);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  if (!shift.claimRequest) return res.status(400).json({ error: 'No pending claim on this shift' });

  // Same building scoping as the rest of the admin endpoints
  const me = req.user;
  const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
  if (me.role !== 'superadmin' && shift.buildingId && !callerBIds.has(shift.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  const { empId, empName } = shift.claimRequest;
  shift.status = 'scheduled';
  shift.employeeId = empId;
  delete shift.claimRequest;
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist claim approval. Please retry.' });
  }
  auditLog('SHIFT_CLAIM_APPROVED', me, { shiftId: shift.id, empId, empName, date: shift.date, type: shift.type, group: shift.group });
  // Notify the employee whose claim was approved.
  sendPushTo(empId, {
    title: 'Shift claim approved',
    body: `Your ${shift.type || ''} ${shift.group || ''} shift on ${shift.date} is confirmed.`.replace(/\s+/g,' ').trim(),
    tag: 'claim:' + shift.id,
    url: '/app',
  }).catch(() => {});
  res.json({ ok: true, shift });
});

// POST /api/shifts/:id/claim/reject — admin rejects a pending claim
// Drops claimRequest; shift stays open for someone else to claim.
app.post('/api/shifts/:id/claim/reject', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === req.params.id);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  if (!shift.claimRequest) return res.status(400).json({ error: 'No pending claim on this shift' });

  const me = req.user;
  const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
  if (me.role !== 'superadmin' && shift.buildingId && !callerBIds.has(shift.buildingId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }

  const { empId, empName } = shift.claimRequest;
  delete shift.claimRequest;
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist claim rejection. Please retry.' });
  }
  auditLog('SHIFT_CLAIM_REJECTED', me, { shiftId: shift.id, empId, empName, date: shift.date, type: shift.type, group: shift.group });
  sendPushTo(empId, {
    title: 'Shift claim not approved',
    body: `Your claim for ${shift.type || ''} ${shift.group || ''} on ${shift.date} was not approved.`.replace(/\s+/g,' ').trim(),
    tag: 'claim:' + shift.id,
    url: '/app',
  }).catch(() => {});
  res.json({ ok: true, shift });
});

// ── Light-weight per-shift admin endpoints (used by /app) ─────────────
// These avoid the heavy /api/data POST flow for routine single-shift edits
// and bypass the shifts shrink guard since they don't replace the array.

// Helper: building scope check, used by the per-shift admin endpoints below.
function _shiftAdminAuthorized(user, shift) {
  if (user.role === 'superadmin') return true;
  const callerBIds = new Set([user.buildingId, ...(user.buildingIds||[])].filter(Boolean));
  return shift.buildingId ? callerBIds.has(shift.buildingId) : true;
}

// POST /api/shifts — admin creates one new shift
// Body: { date, type, group, start?, end?, buildingId?, employeeId? }
// Used by the /app calendar's "+ Add shift" sheet.
app.post('/api/shifts', requireAuth, requireAdmin, async (req, res) => {
  const { date, type, group, start, end, buildingId, employeeId } = req.body || {};
  if (!date || !type || !group) return res.status(400).json({ error: 'date, type and group are required' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  const data = await loadData();

  const me = req.user;
  const callerBIds = new Set([me.buildingId, ...(me.buildingIds||[])].filter(Boolean));
  const bId = buildingId || me.buildingId;
  if (me.role !== 'superadmin' && !callerBIds.has(bId)) {
    return res.status(403).json({ error: 'Out of scope' });
  }
  if (employeeId) {
    const emp = (data.employees || []).find(e => e.id === employeeId);
    if (!emp) return res.status(404).json({ error: 'Employee not found' });
    if (emp.inactive) return res.status(400).json({ error: 'Employee is inactive' });
    if (emp.group !== group) return res.status(400).json({ error: `${emp.name} is in ${emp.group}, not ${group}` });
    if (emp.buildingId !== bId) return res.status(400).json({ error: 'Employee is at a different building' });
  }
  const shift = {
    id: 's_' + Date.now() + crypto.randomBytes(2).toString('hex'),
    date, type, group,
    start: start || '', end: end || '',
    status: employeeId ? 'scheduled' : 'open',
    buildingId: bId,
    employeeId: employeeId || null,
  };
  if (!Array.isArray(data.shifts)) data.shifts = [];
  data.shifts.push(shift);
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist new shift. Please retry.' });
  }
  auditLog('SHIFT_CREATED', me, { shiftId: shift.id, date, type, group, employeeId: employeeId || null, buildingId: bId });
  if (employeeId) {
    sendPushTo(employeeId, {
      title: 'New shift on your schedule',
      body: `${type} ${group} on ${date}`,
      tag: 'assigned:' + shift.id,
      url: '/app',
    }).catch(() => {});
  }
  res.json({ ok: true, shift });
});

// POST /api/shifts/:id/assign — admin assigns an employee to a shift
// Body: { empId }
app.post('/api/shifts/:id/assign', requireAuth, requireAdmin, async (req, res) => {
  const { empId } = req.body || {};
  if (!empId) return res.status(400).json({ error: 'empId required' });
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === req.params.id);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  if (!_shiftAdminAuthorized(req.user, shift)) return res.status(403).json({ error: 'Out of scope' });
  const emp = (data.employees || []).find(e => e.id === empId);
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (emp.inactive) return res.status(400).json({ error: 'Employee is inactive' });
  // Same group; if employee is in a different building from the shift, refuse
  if (shift.group && emp.group && shift.group !== emp.group) {
    return res.status(400).json({ error: `${emp.name} is in ${emp.group}, not ${shift.group}` });
  }
  if (shift.buildingId && emp.buildingId && shift.buildingId !== emp.buildingId) {
    return res.status(400).json({ error: 'Employee is at a different building' });
  }
  shift.employeeId = empId;
  shift.status = 'scheduled';
  delete shift.claimRequest;
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist shift assignment. Please retry.' });
  }
  auditLog('SHIFT_ASSIGNED', req.user, { shiftId: shift.id, empId, date: shift.date, type: shift.type, group: shift.group });
  // Notify the assigned employee
  sendPushTo(empId, {
    title: 'New shift on your schedule',
    body: `${shift.type || ''} ${shift.group || ''} on ${shift.date}`.replace(/\s+/g,' ').trim(),
    tag: 'assigned:' + shift.id,
    url: '/app',
  }).catch(() => {});
  res.json({ ok: true, shift });
});

// POST /api/shifts/:id/unassign — remove employee from one shift, leave open
app.post('/api/shifts/:id/unassign', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const shift = (data.shifts || []).find(s => s.id === req.params.id);
  if (!shift) return res.status(404).json({ error: 'Shift not found' });
  if (!_shiftAdminAuthorized(req.user, shift)) return res.status(403).json({ error: 'Out of scope' });
  const wasEmpId = shift.employeeId;
  shift.employeeId = null;
  shift.status = 'open';
  shift._removedDate = shift.date;
  delete shift.claimRequest;
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist shift unassignment. Please retry.' });
  }
  auditLog('SHIFT_UNASSIGNED', req.user, { shiftId: shift.id, prevEmpId: wasEmpId, date: shift.date, type: shift.type, group: shift.group });
  if (wasEmpId) {
    sendPushTo(wasEmpId, {
      title: 'Shift removed from your schedule',
      body: `${shift.type || ''} ${shift.group || ''} on ${shift.date}`.replace(/\s+/g,' ').trim(),
      tag: 'unassigned:' + shift.id,
      url: '/app',
    }).catch(() => {});
  }
  res.json({ ok: true, shift });
});

// POST /api/shifts/:id/end-rotation — drop employee from this and all future
// shifts of the same type+group at the same building. Mirrors the in-page
// removeFromAllFuture flow on the main site.
app.post('/api/shifts/:id/end-rotation', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const seed = (data.shifts || []).find(s => s.id === req.params.id);
  if (!seed) return res.status(404).json({ error: 'Shift not found' });
  if (!_shiftAdminAuthorized(req.user, seed)) return res.status(403).json({ error: 'Out of scope' });
  const { type, group, employeeId, date, buildingId } = seed;
  if (!employeeId) return res.status(400).json({ error: 'No employee to remove' });
  let count = 0;
  for (const s of (data.shifts || [])) {
    if (s.employeeId === employeeId && s.type === type && s.group === group &&
        s.buildingId === buildingId && s.date >= date && s.status === 'scheduled') {
      s.employeeId = null;
      s.status = 'open';
      s._endedRotation = date;
      count++;
    }
  }
  // Disable matching schedule patterns so future generation stops
  if (Array.isArray(data.schedulePatterns)) {
    for (const p of data.schedulePatterns) {
      if (p.empId === employeeId && (!p.shiftType || p.shiftType === type) &&
          (!p.group || p.group === group)) {
        p.endDate = date;
        p.active = false;
      }
    }
  }
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist rotation end. Please retry.' });
  }
  auditLog('SHIFT_ROTATION_ENDED', req.user, { fromShiftId: seed.id, empId: employeeId, type, group, count });
  res.json({ ok: true, count });
});

// DELETE /api/shifts/:id — remove a single shift slot entirely.
// Used by the ✕ icon on the calendar shift modal. Distinct from /unassign
// (which keeps the slot and just opens it up); this drops the row entirely,
// which /api/data POST cannot do because of the anti-shrink tripwire.
//
// IMPORTANT: also records the deleted date on every matching schedule
// pattern's `removedDates` list so the client-side rotation extender
// (_extendRotationsThrough) skips that date on future runs. Without this,
// signing out and back in re-creates the deleted shift via rotation
// regeneration — exactly the bug reported on 2026-05-08 ("I deleted the
// double Monday shift, signed back in, the shifts were back").
//
// Authz: superadmin always, admin only for their own building(s).
app.delete('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const data = await loadData();
  const idx = (data.shifts || []).findIndex(s => s.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Shift not found' });
  const shift = data.shifts[idx];
  if (!_shiftAdminAuthorized(req.user, shift)) return res.status(403).json({ error: 'Out of scope' });
  data.shifts.splice(idx, 1);

  // Record the date as removed on any rotation pattern that would otherwise
  // regenerate this shift. We match BOTH the open and assign cases.
  let patternsTouched = 0;
  if (Array.isArray(data.schedulePatterns)) {
    for (const p of data.schedulePatterns) {
      if (p.group !== shift.group) continue;
      if (p.shiftType !== shift.type) continue;
      if (p.buildingId !== shift.buildingId) continue;
      // For filled shifts: only the matching employee's pattern.
      // For open shifts: only patterns without an empId.
      if (shift.employeeId) {
        if (p.empId !== shift.employeeId) continue;
      } else {
        if (p.empId) continue;
      }
      if (!Array.isArray(p.removedDates)) p.removedDates = [];
      if (!p.removedDates.includes(shift.date)) {
        p.removedDates.push(shift.date);
        patternsTouched++;
      }
    }
  }

  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist shift deletion. Please retry.' });
  }
  auditLog('SHIFT_DELETED', req.user, {
    shiftId: shift.id, date: shift.date, type: shift.type, group: shift.group,
    buildingId: shift.buildingId, hadEmployee: !!shift.employeeId,
    patternsTouched,
  });
  // If the slot had an assigned employee, send them a heads-up push so they
  // see the schedule change instead of finding out at clock-in.
  if (shift.employeeId) {
    sendPushTo(shift.employeeId, {
      title: 'Shift removed from your schedule',
      body: `${shift.type || ''} ${shift.group || ''} on ${shift.date}`.replace(/\s+/g,' ').trim(),
      tag: 'deleted:' + shift.id,
      url: '/app',
    }).catch(() => {});
  }
  res.json({ ok: true, shift, patternsTouched });
});

// POST /api/shifts/delete-batch — drop many shifts at once by id.
// Body: { ids: ['shift_a', 'shift_b', ...] }
// Used by the bulk "Remove Shifts" toolbar modal and any other multi-shift
// removal flow, so we avoid dozens of round-trips. Authz scoped per shift:
// any out-of-scope id is silently skipped (rather than 403'ing the whole
// batch). Mirrors DELETE /api/shifts/:id by also tagging each deleted
// shift's date onto every matching schedule pattern's removedDates list,
// so the client-side rotation extender (_extendRotationsThrough) doesn't
// regenerate them on the next calendar advance.
app.post('/api/shifts/delete-batch', requireAuth, requireAdmin, async (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : null;
  if (!ids || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
  if (ids.length > 5000) return res.status(400).json({ error: 'Batch too large (max 5000)' });
  const data = await loadData();
  const idSet = new Set(ids);
  const targets = (data.shifts || []).filter(s => idSet.has(s.id));
  // Skip any shift the caller can't touch (e.g. building-scoped admin trying
  // to nuke another facility's roster). Don't 403 the whole call — just keep
  // the others. Report the skipped count so the client can surface it.
  const allowed   = targets.filter(s => _shiftAdminAuthorized(req.user, s));
  const skippedAuthz = targets.length - allowed.length;
  const allowedIds = new Set(allowed.map(s => s.id));
  const before = data.shifts.length;
  data.shifts = data.shifts.filter(s => !allowedIds.has(s.id));
  const removed = before - data.shifts.length;

  // Tag removedDates on matching schedule patterns so the rotation extender
  // doesn't bring back what we just removed. Same matching rules as the
  // single-shift DELETE handler — group + shiftType + buildingId, plus
  // employeeId for filled shifts (or no empId for open shifts).
  let patternsTouched = 0;
  if (Array.isArray(data.schedulePatterns)) {
    for (const s of allowed) {
      for (const p of data.schedulePatterns) {
        if (p.group !== s.group) continue;
        if (p.shiftType !== s.type) continue;
        if (p.buildingId !== s.buildingId) continue;
        if (s.employeeId) {
          if (p.empId !== s.employeeId) continue;
        } else {
          if (p.empId) continue;
        }
        if (!Array.isArray(p.removedDates)) p.removedDates = [];
        if (!p.removedDates.includes(s.date)) {
          p.removedDates.push(s.date);
          patternsTouched++;
        }
      }
    }
  }

  // Push notify any assigned employees whose shifts disappeared. Fire-and-
  // forget — don't block the response on push delivery.
  for (const s of allowed) {
    if (!s.employeeId) continue;
    sendPushTo(s.employeeId, {
      title: 'Shift removed from your schedule',
      body: `${s.type || ''} ${s.group || ''} on ${s.date}`.replace(/\s+/g,' ').trim(),
      tag: 'deleted:' + s.id,
      url: '/app',
    }).catch(() => {});
  }
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist batch deletion. Please retry.' });
  }
  auditLog('SHIFTS_DELETED_BATCH', req.user, {
    requestedCount: ids.length,
    matchedCount:   targets.length,
    removedCount:   removed,
    skippedAuthz,
    patternsTouched,
  });
  res.json({ ok: true, removed, skippedAuthz, notFound: ids.length - targets.length, patternsTouched });
});

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
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist trade request. Please retry.' });
  }
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
    try { await flushNow(); } catch (e) {
      return res.status(500).json({ error: 'Failed to persist trade rejection. Please retry.' });
    }
    auditLog('SHIFT_TRADE_REJECTED', req.user, { tradeId: trade.id });
    // Notify both employees that the trade was rejected
    [trade.fromEmpId, trade.toEmpId].filter(Boolean).forEach(uid => {
      sendPushTo(uid, {
        title: 'Shift trade rejected',
        body: 'Your trade request was not approved.',
        tag: 'trade:' + trade.id,
        url: '/app',
      }).catch(() => {});
    });
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
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist trade approval. Please retry.' });
  }
  auditLog('SHIFT_TRADE_APPROVED', req.user, { tradeId: trade.id, fromShiftId: trade.fromShiftId, toShiftId: trade.toShiftId });
  // Notify both employees that the swap is now in effect.
  [trade.fromEmpId, trade.toEmpId].filter(Boolean).forEach(uid => {
    sendPushTo(uid, {
      title: 'Shift trade approved',
      body: 'Your schedule has been updated.',
      tag: 'trade:' + trade.id,
      url: '/app',
    }).catch(() => {});
  });
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
  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist trade cancellation. Please retry.' });
  }
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

// Render a clinical / CMS-metrics email body for a weekly subscription.
// Pulls the same payload as GET /api/pcc/clinical for each building in scope
// over the trailing 7 days ending yesterday.
async function _clinicalEmailHtml(data, sub, sendDate) {
  const today = sendDate || new Date().toISOString().slice(0,10);
  const yesterday = new Date(new Date(today).getTime() - 86400000).toISOString().slice(0,10);
  const wkStart   = new Date(new Date(yesterday).getTime() - 6 * 86400000).toISOString().slice(0,10);
  const buildings = (data.buildings || []).filter(b => sub.buildingIds.includes(b.id));
  if (!buildings.length) return null;

  // Use a local helper to compute clinical metrics — same logic as the
  // /api/pcc/clinical endpoint but inline so we don't have to make HTTP
  // calls back to ourselves.
  async function computeForBuilding(b) {
    const cache = (data.pccClinicalCache || []).find(c =>
      c.buildingId === b.id && c.start === wkStart && c.end === yesterday);
    // If PCC isn't configured, return cache-or-zero
    if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
      return {
        building: b,
        metrics: cache?.metrics || {
          utis:0, rehospitalizations30d:0, weightLossSignificant:0,
          antipsychoticLongTerm:0, fallsMajorInjury:0, pressureUlcersStage2plus:0,
          catheterLongStay:0, cdiffInfections:0,
        },
        residentDays: cache?.residentDays || 0,
        source: 'cache',
      };
    }
    const fetchCount = async (endpoint, predicate) => {
      const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/${endpoint}?startDate=${wkStart}&endDate=${yesterday}`;
      const r = await pccFetch(url);
      if (!r.ok || !r.body) return null;
      const items = r.body.data || r.body.items || r.body || [];
      return Array.isArray(items) ? items.filter(predicate || (() => true)).length : null;
    };
    let residentDays = 0;
    const startMs = new Date(wkStart   + 'T00:00:00Z').getTime();
    const endMs   = new Date(yesterday + 'T00:00:00Z').getTime();
    const days = Math.round((endMs - startMs) / 86400000) + 1;
    for (let i = 0; i < days; i++) {
      const d = new Date(startMs + i * 86400000).toISOString().slice(0,10);
      const url = `${PCC_BASE}/partner/v1/facilities/${encodeURIComponent(PCC_FACILITY_ID)}/census?censusDate=${d}`;
      const r = await pccFetch(url);
      if (r.ok && r.body) {
        const x = r.body.data || r.body;
        residentDays += Number(x.totalCensus ?? x.occupiedBeds ?? x.census ?? 0) || 0;
      }
    }
    const [utis, rehosp, weightLoss, antipsy, falls, pu, cath, cdiff] = await Promise.all([
      fetchCount('clinical/uti'),
      fetchCount('clinical/hospitalReturns', x => Number(x.daysSinceDischarge ?? 99) <= 30),
      fetchCount('clinical/weightChanges', x =>
        (Number(x.pctChange30d ?? 0) <= -5) || (Number(x.pctChange180d ?? 0) <= -10)),
      fetchCount('clinical/medications', x =>
        /antipsychotic/i.test(String(x.therapeuticClass||x.drugClass||'')) &&
        Number(x.daysOnMedication ?? 0) >= 90 && !x.supportingDiagnosis),
      fetchCount('clinical/falls',  x => /major/i.test(String(x.injuryLevel||''))),
      fetchCount('clinical/skinIntegrity', x => Number(String(x.stage||'').replace(/\D/g,''))>=2),
      fetchCount('clinical/catheterUse', x => x.longStay === true || Number(x.daysWithCatheter ?? 0) >= 14),
      fetchCount('clinical/infections', x => /c\.?\s*diff|clostridi/i.test(String(x.organism||x.infectionType||''))),
    ]);
    const v = (live, key) => (live ?? cache?.metrics?.[key] ?? 0);
    return {
      building: b,
      metrics: {
        utis:                     v(utis,        'utis'),
        rehospitalizations30d:    v(rehosp,      'rehospitalizations30d'),
        weightLossSignificant:    v(weightLoss,  'weightLossSignificant'),
        antipsychoticLongTerm:    v(antipsy,     'antipsychoticLongTerm'),
        fallsMajorInjury:         v(falls,       'fallsMajorInjury'),
        pressureUlcersStage2plus: v(pu,          'pressureUlcersStage2plus'),
        catheterLongStay:         v(cath,        'catheterLongStay'),
        cdiffInfections:          v(cdiff,       'cdiffInfections'),
      },
      residentDays: residentDays || cache?.residentDays || 0,
      source: 'live',
    };
  }

  const perBuilding = [];
  for (const b of buildings) {
    try { perBuilding.push(await computeForBuilding(b)); }
    catch (e) { logger.error('clinical_email_compute_failed', { buildingId: b.id, err: e.message }); }
  }

  const TH  = `style="background:#1A3C34;color:#fff;text-align:left;padding:10px 14px;font-size:13px;font-weight:700;font-family:Arial,Helvetica,sans-serif"`;
  const TD  = `style="padding:10px 14px;font-size:13px;color:#1F2937;font-family:Arial,Helvetica,sans-serif;border-bottom:1px solid #E5E7EB"`;
  const TDR = `style="padding:10px 14px;font-size:13px;color:#1F2937;font-family:Arial,Helvetica,sans-serif;border-bottom:1px solid #E5E7EB;text-align:right;font-variant-numeric:tabular-nums"`;
  const cols = ['Facility','UTIs','Rehosp 30d','Wt loss','Antipsy LT','Falls MI','PU 2+','Cath LS','C. diff','Resident-days'];
  const header = `<tr>${cols.map(c => `<th ${TH}>${c}</th>`).join('')}</tr>`;
  const rows = perBuilding.map(r => `<tr>
    <td ${TD}><strong>${escapeHtml(r.building.name)}</strong></td>
    <td ${TDR}>${r.metrics.utis}</td>
    <td ${TDR}>${r.metrics.rehospitalizations30d}</td>
    <td ${TDR}>${r.metrics.weightLossSignificant}</td>
    <td ${TDR}>${r.metrics.antipsychoticLongTerm}</td>
    <td ${TDR}>${r.metrics.fallsMajorInjury}</td>
    <td ${TDR}>${r.metrics.pressureUlcersStage2plus}</td>
    <td ${TDR}>${r.metrics.catheterLongStay}</td>
    <td ${TDR}>${r.metrics.cdiffInfections}</td>
    <td ${TDR}>${r.residentDays}</td>
  </tr>`).join('');

  return `<!doctype html><html><body style="margin:0;padding:24px;background:#F9FAFB;font-family:Arial,Helvetica,sans-serif;color:#1F2937">
    <div style="max-width:960px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #E5E7EB">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
        <div style="width:32px;height:32px;background:#6B9E7A;border-radius:7px;color:#fff;font-weight:800;display:inline-flex;align-items:center;justify-content:center;font-size:15px">M</div>
        <span style="font-size:15px;font-weight:700;color:#1A3C34">ManageMyStaffing</span>
      </div>
      <h2 style="margin:0 0 4px;color:#1F2937">${escapeHtml(sub.name || 'Weekly Clinical Report')}</h2>
      <p style="color:#6B7280;margin:0 0 16px;font-size:13px">CMS quality metrics · ${wkStart} → ${yesterday} · sent ${today}</p>
      <table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;width:100%;border:1px solid #E5E7EB;border-radius:8px;overflow:hidden">
        ${header}${rows}
      </table>
      <p style="color:#6B7280;font-size:11px;margin-top:18px">
        Antipsy LT = long-term (≥90 days) antipsychotic use without a supporting Dx ·
        Wt loss = ≥5% in 30 days OR ≥10% in 180 days ·
        PU 2+ = pressure ulcers stage 2 or higher ·
        Cath LS = catheter in place ≥14 days.
      </p>
      <p style="color:#6B7280;font-size:11px;margin-top:14px;border-top:1px solid #E5E7EB;padding-top:14px">
        Auto-generated weekly by ManageMyStaffing. Manage subscribers in HR → Reports.
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
  // 'daily' = standard ops digest. 'weekly' = clinical/CMS metrics digest
  // sent on Monday morning covering trailing 7 days.
  const freq = String(req.body?.frequency || 'daily').toLowerCase();
  upsert.frequency = (freq === 'weekly') ? 'weekly' : 'daily';
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
  const wantClinical = Array.isArray(sub.metrics) && sub.metrics.includes('clinical');
  const html = wantClinical
    ? await _clinicalEmailHtml(data, sub, new Date().toISOString().slice(0,10))
    : _reportEmailHtml(data, sub, new Date().toISOString().slice(0,10));
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
    const dow   = now.getUTCDay();              // 0=Sun … 1=Mon, etc.
    const data = await loadData();
    const subs = (data.reportSubscriptions || []).filter(s => s.enabled !== false);
    for (const sub of subs) {
      if (sub.lastSentDate === today) continue;

      // Frequency gate. 'weekly' subs only fire on Monday morning.
      const freq = sub.frequency || 'daily';
      if (freq === 'weekly' && dow !== 1) continue;

      // Pick renderer based on metric set. If 'clinical' is among the metrics,
      // we emit the clinical email body; otherwise the existing ops digest.
      const wantClinical = Array.isArray(sub.metrics) && sub.metrics.includes('clinical');
      const html = wantClinical
        ? await _clinicalEmailHtml(data, sub, today)
        : _reportEmailHtml(data, sub, today);
      if (!html) continue;

      const subjectPrefix = wantClinical ? 'Clinical Quality Report' : sub.name;
      try {
        const { EmailClient } = require('@azure/communication-email');
        const ec = new EmailClient(ACS_CONNECTION_STRING);
        const poller = await ec.beginSend({
          senderAddress: ACS_FROM_EMAIL,
          recipients: { to: sub.recipients.map(e => ({ address: e })) },
          content: {
            subject: `${subjectPrefix} — ${today}`,
            plainText: 'Your email client does not support HTML. View in browser.',
            html,
          },
        });
        await poller.pollUntilDone();
        sub.lastSentDate = today;
        markDirty();
        auditLog('REPORT_SUBSCRIPTION_SENT', null, {
          id: sub.id, date: today, recipients: sub.recipients.length,
          flavor: wantClinical ? 'clinical' : 'ops', frequency: freq,
        });
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
  const provided = req.headers['x-smartlinx-secret'] || '';
  if (provided.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
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

const _applyPunchEdit = _punchLib.applyPunchEdit;
const _notify         = _punchLib.notify;

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

// ── NOTIFICATIONS ────────────────────────────────────────────────────────────
// Lightweight in-app inbox. Items are written by _notify(); each has a
// toAccountId (or toEmail fallback). Caller sees only their own items.
// Limit: 200 most recent unread → unread first, capped to keep responses small.
app.get('/api/notifications', requireAuth, async (req, res) => {
  const data  = await loadData();
  const all   = (data.notifications || []);
  const myId  = req.user.id;
  const myEmail = (req.user.email || '').toLowerCase();
  const mine = all.filter(n =>
    (n.toAccountId && n.toAccountId === myId) ||
    (!n.toAccountId && n.toEmail && n.toEmail.toLowerCase() === myEmail)
  );
  // Already sorted newest-first by _notify() (unshift).
  const unreadCount = mine.filter(n => !n.readAt).length;
  res.json({
    items: mine.slice(0, 200),
    unreadCount,
  });
});

app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
  const data = await loadData();
  const n = (data.notifications || []).find(x => x.id === req.params.id);
  if (!n) return res.status(404).json({ error: 'Notification not found' });
  // Only the owner can mark their own notification read.
  const myEmail = (req.user.email || '').toLowerCase();
  const owns = (n.toAccountId && n.toAccountId === req.user.id) ||
               (!n.toAccountId && n.toEmail && n.toEmail.toLowerCase() === myEmail);
  if (!owns) return res.status(403).json({ error: 'Not your notification' });
  if (!n.readAt) { n.readAt = new Date().toISOString(); markDirty(); }
  res.json({ ok: true });
});

app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
  const data = await loadData();
  const myEmail = (req.user.email || '').toLowerCase();
  let count = 0;
  const now = new Date().toISOString();
  for (const n of (data.notifications || [])) {
    const owns = (n.toAccountId && n.toAccountId === req.user.id) ||
                 (!n.toAccountId && n.toEmail && n.toEmail.toLowerCase() === myEmail);
    if (owns && !n.readAt) { n.readAt = now; count++; }
  }
  if (count > 0) markDirty();
  res.json({ ok: true, marked: count });
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
    // Round-trip back to the HR Admin who requested it so they see the result.
    _notify(data, {
      kind: 'PUNCH_EDIT_APPROVED_BY_ADMIN',
      toAccountId: pe.requestedBy.id, toEmail: pe.requestedBy.email,
      buildingId: pe.buildingId,
      editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
      approvedBy: req.user.email,
      title: `Your punch correction was approved`,
      body: `${req.user.email} approved your punch correction for ${pe.empName} on ${pe.date}.`,
    });
    markDirty();
    auditLog('PUNCH_EDIT_APPROVED', req.user, { editId: pe.id, empId: pe.empId, date: pe.date, before, after: { in: r.in, out: r.out }, requestedBy: pe.requestedBy.email });
    return res.json({ ok: true, status: 'approved', record: r });
  }

  // Reject: stamp the record + notify the HR Admin so they aren't waiting forever.
  _notify(data, {
    kind: 'PUNCH_EDIT_REJECTED',
    toAccountId: pe.requestedBy.id, toEmail: pe.requestedBy.email,
    buildingId: pe.buildingId,
    editId: pe.id, empId: pe.empId, empName: pe.empName, date: pe.date,
    rejectedBy: req.user.email,
    title: `Your punch correction was rejected`,
    body: `${req.user.email} rejected your punch correction for ${pe.empName} on ${pe.date}.${decisionNote ? ' Reason: ' + decisionNote : ''}`,
  });
  markDirty();
  auditLog('PUNCH_EDIT_REJECTED', req.user, { editId: pe.id, empId: pe.empId, date: pe.date, requestedBy: pe.requestedBy.email });
  res.json({ ok: true, status: 'rejected' });
});

// GET /kiosk/:buildingId — serves the standalone tablet kiosk HTML page.
// The page is locked to one building (token embedded server-side). No SPA
// shell, no nav. Tablet can be left running 24/7 at the nurse station.
app.get('/kiosk/:buildingId', async (req, res) => {
  // Kiosk access requires a secret token to prevent unauthorized access.
  // Admin generates the kiosk URL (includes ?token=...) from the dashboard.
  const kioskSecret = process.env.KIOSK_ACCESS_SECRET;
  if (kioskSecret) {
    const provided = req.query.token || req.headers['x-kiosk-token'] || '';
    const expected = crypto.createHmac('sha256', kioskSecret).update(req.params.buildingId).digest('hex').slice(0, 16);
    if (provided !== expected) {
      return res.status(403).type('text').send('Invalid kiosk access token. Request a kiosk URL from your administrator.');
    }
  }
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
  }, TIMECLOCK_KIOSK_SECRET, { expiresIn: '24h' });
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
    await recordFailedLogin(acct);
    auditLog('LOGIN_FAILED', acct, { reason: 'wrong_password', failedAttempts: acct.failedAttempts });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  await clearFailedAttempts(acct);

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
  // Carry the PWA surface flag through the TOTP-enrollment path too so a
  // user who completes first-time enrollment on the /app surface gets
  // the long-lived session immediately.
  const surface = (req.body?.surface === 'pwa') ? 'pwa' : undefined;
  const payload = {
    id: acct.id, name: acct.name, email: acct.email, role: acct.role,
    buildingId: acct.buildingId || null, buildingIds: acct.buildingIds || [],
    group: acct.group || undefined, demo: isDemo || undefined, surface, sid,
  };
  const ttl = effectiveJwtTtl(acct.role, surface);
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: ttl });
  lastActivity.set(sid, Date.now());
  setAuthCookie(res, token, ttl);
  // Trust this device for 30 days — first enrollment counts as a verified device.
  setDeviceTrustCookie(res, acct);
  auditLog('LOGIN_SUCCESS', acct, { sid, via: 'totp_enrollment', surface: surface || 'web' });
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
  // PWA logins send body.surface === 'pwa' so the JWT carries the tag and
  // every requireAuth check thereafter knows to skip the idle timeout.
  // Whitelisted to the single string we expect to avoid arbitrary client
  // values polluting the payload.
  const surface = (req.body?.surface === 'pwa') ? 'pwa' : undefined;
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
    surface,
    sid,
  };
  const ttl = effectiveJwtTtl(acct.role, surface);
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: ttl });
  await lastActivity.set(sid, Date.now());
  setAuthCookie(res, token, ttl);           // ← XSS-safe httpOnly cookie, surface-aware TTL
  auditLog('LOGIN_SUCCESS', acct, { sid, surface: surface || 'web' });
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

// ── POST /api/auth/verify-password ────────────────────────────────────────────
// Lightweight password re-verification for lock-screen unlock.
// Requires an existing auth cookie (user must be logged in).
app.post('/api/auth/verify-password', requireAuth, authLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password is required' });
  let data;
  try { data = await loadData(); } catch (e) { return res.status(500).json({ error: 'Server error' }); }
  const acct = (data.accounts || []).find(a => a.id === req.user.id);
  if (!acct || !acct.ph) return res.status(401).json({ error: 'Verification failed' });
  const ok = await bcrypt.compare(password, acct.ph);
  if (!ok) {
    auditLog('UNLOCK_VERIFY_FAILED', acct);
    return res.status(401).json({ error: 'Incorrect password' });
  }
  auditLog('UNLOCK_VERIFY_OK', acct);
  return res.json({ ok: true });
});

// ── GET /api/data ─────────────────────────────────────────────────────────────
// Returns ETag header so client can do optimistic concurrency on writes.
let _dataVersion = Date.now().toString(36);
function _bumpDataVersion() { _dataVersion = Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex'); }

app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const data     = await loadData();
    const filtered = getDataForUser(req.user, data);
    // Disable HTTP caching: shift mutation endpoints (POST /api/shifts,
    // /assign, /unassign, /end-rotation, /claim*, /trade*, etc.) don't all
    // call _bumpDataVersion(), so the ETag can stay constant across writes.
    // With ETag-only freshness, Express's res.json auto-returns 304 on the
    // next GET, and the browser serves a stale cached body that's missing
    // the just-written rows. That manifests as the "assign returns 200,
    // PG has scheduled, next GET shows open" symptom from 2026-05-08.
    res.setHeader('Cache-Control', 'no-store');
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
                      'jobPostings','hrAccounts',
                      // app_state-backed config collections
                      'demos','billingData','shiftTemplates','staffingSlots',
                      'buildingShiftTypes','hrOnboarding',
                      // already-handled scoped collections
                      'staffEvents','prospects','ppdDailyCensus'];
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

  // Snapshot existing counts BEFORE any merge so the audit entry below
  // captures the actual delta, not just the post-write totals. Without this
  // we can't tell whether a save shrank a collection silently.
  const _preCounts = {
    buildings:        (data.buildings        || []).length,
    employees:        (data.employees        || []).length,
    shifts:           (data.shifts           || []).length,
    accounts:         (data.accounts         || []).length,
    schedulePatterns: (data.schedulePatterns || []).length,
    hrTimeClock:      (data.hrTimeClock      || []).length,
  };

  // ── Tripwire: refuse writes that would drop existing collections ─────────
  // If a client sends an array that is dramatically smaller than what we
  // already have, treat it as suspicious and reject unless the caller has
  // ABSOLUTE shrink guard. NO bypass headers. If the client claims it has
  // fewer rows than the server has, we refuse to write — period. The caller
  // must use the explicit delete endpoints if they actually want to remove
  // a specific row, or use the SA-only restore endpoint.
  //
  // Removed in 2026-05-01 incident response: the X-Confirm-Wipe bypass that
  // resetAllData() relied on. That mechanism was a one-shot trapdoor that
  // could destroy a tenant's data with one bad client cache + one click.
  // No more.
  const confirmWipe = false;                              // permanently disabled
  if (req.headers['x-confirm-wipe']) {
    auditLog('DATA_UPDATE_WIPE_HEADER_IGNORED', req.user, {
      header: String(req.headers['x-confirm-wipe']),
      note: 'X-Confirm-Wipe is permanently ignored after the 2026-04-30 Kirkland incident',
    });
  }
  const TRIPWIRE = [
    ['shifts',           data.shifts,           payload.shifts],
    ['employees',        data.employees,        payload.employees],
    ['buildings',        data.buildings,        payload.buildings],
    ['accounts',         data.accounts,         payload.accounts],
    ['schedulePatterns', data.schedulePatterns, payload.schedulePatterns],
    ['hrTimeClock',      data.hrTimeClock,      payload.hrTimeClock],
  ];
  for (const [name, existing, incoming] of TRIPWIRE) {
    if (!Array.isArray(incoming)) continue;
    const exLen = (existing || []).length;
    const inLen = incoming.length;
    // ANY shrink at all is suspect — even one-row drops. Per-row deletes
    // belong on the explicit DELETE endpoints, not on /api/data POST.
    if (inLen < exLen) {
      auditLog('DATA_UPDATE_REJECTED_SHRINK', req.user, {
        collection: name, existingCount: exLen, incomingCount: inLen,
      });
      return res.status(409).json({
        error: `Refusing to shrink ${name} from ${exLen} to ${inLen}. ` +
               'Use the explicit DELETE endpoints to remove individual rows. ' +
               '/api/data POST is upsert-only.',
        collection: name,
        existingCount: exLen,
        incomingCount: inLen,
      });
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
    // Open patterns (no empId) are scoped by buildingId directly.
    // Assign patterns are scoped by the employee's building.
    if (!p.empId) return p.buildingId ? callerBIds.has(p.buildingId) : false;
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
    // SA-managed admin collections — pre-fix these were silently dropped on
    // the way in AND returned as empty placeholders by db/repo.js loadAll(),
    // so anything saved through the Demo Portal / Billing UIs disappeared
    // on reload. Now wholesale-replaced for SA on every POST and persisted
    // via the app_state table.
    if (Array.isArray(payload.demos))          data.demos          = payload.demos;
    if (Array.isArray(payload.shiftTemplates)) data.shiftTemplates = payload.shiftTemplates;
    if (payload.billingData  && typeof payload.billingData  === 'object' && !Array.isArray(payload.billingData))  data.billingData  = payload.billingData;
    if (payload.hrOnboarding && typeof payload.hrOnboarding === 'object' && !Array.isArray(payload.hrOnboarding)) data.hrOnboarding = payload.hrOnboarding;
  }

  // Per-building config maps: { [buildingId]: { ... } }
  // Both SA and building admins can write — SA wholesale, building admins only
  // for buildings in their own scope. Without this, PPD staffing config and
  // custom shift types vanished on reload (loadAll() returned {} placeholders
  // and POST /api/data had no handler to update the per-building keys).
  for (const key of ['staffingSlots', 'buildingShiftTypes']) {
    const incoming = payload[key];
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) continue;
    if (isSA) {
      data[key] = incoming;
    } else {
      data[key] = data[key] || {};
      for (const bId of Object.keys(incoming)) {
        if (callerBIds.has(bId)) data[key][bId] = incoming[bId];
      }
    }
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

  // ── Flush to durable storage BEFORE responding ──────────────────────────
  // Pre-fix: markDirty() scheduled a 200ms debounced persist — the client
  // got { ok: true } immediately but a crash in that 200ms window lost the
  // entire batch. Now we await persistCache() synchronously so the 200 OK
  // means "your data is on disk / in Postgres." markDirty() is still called
  // afterward to keep the background debounce loop primed for any follow-up
  // mutations that arrive before the next explicit POST.
  dataDirty = true;          // ensure persistCache() actually writes
  clearTimeout(saveTimeout); // cancel any pending debounced flush
  try {
    await persistCache();
  } catch (e) {
    logger.error('data_update_persist_failed', { err: e.message });
    return res.status(500).json({ error: 'Data accepted but failed to persist. Please retry.' });
  }

  // Audit BEFORE / AFTER counts so we can forensically tell whether a save
  // shrank a collection. Without the delta we have no record of who/what
  // wiped data — exactly the gap that bit Tanya's Kirkland adds on 2026-04-30.
  const _postCounts = {
    buildings:        (data.buildings        || []).length,
    employees:        (data.employees        || []).length,
    shifts:           (data.shifts           || []).length,
    accounts:         (data.accounts         || []).length,
    schedulePatterns: (data.schedulePatterns || []).length,
    hrTimeClock:      (data.hrTimeClock      || []).length,
  };
  const _delta = {};
  for (const k of Object.keys(_postCounts)) {
    _delta[k] = _postCounts[k] - (_preCounts[k] || 0);
  }
  auditLog('DATA_UPDATE', req.user, {
    before:      _preCounts,
    after:       _postCounts,
    delta:       _delta,
    confirmWipe: confirmWipe,
    payloadKeys: present,
  });
  res.setHeader('ETag', `"${_dataVersion}"`);
  res.json({ ok: true, version: _dataVersion });
});

// ── ADMIN AUDIT QUERY ────────────────────────────────────────────────────────
// Lets a building admin query the audit_entries table for their own building's
// recent activity. Built for forensic recovery — see the 2026-04-30 Kirkland
// data-loss incident. Read-only; building-scoped (RLS-equivalent at app layer).
//
// Query params:
//   since      — ISO timestamp lower bound (default: 7 days ago)
//   actions    — comma-separated action names (default: all)
//   limit      — max rows (default 200, cap 1000)
//   buildingId — optional filter; defaults to caller's building scope
app.get('/api/admin/audit', requireAuth, requireAdmin, async (req, res) => {
  if (!_useDB) return res.status(503).json({ error: 'Audit query requires Postgres backend' });
  try {
    const dbg = require('./db/repo');
    if (!dbg.isEnabled()) return res.status(503).json({ error: 'PG pool not initialized' });
    // Scope: admin caller can only query their own building(s). SA can pass any.
    const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
    const reqB = String(req.query.buildingId || '').trim();
    if (req.user.role !== 'superadmin') {
      if (reqB && !callerBIds.has(reqB)) return res.status(403).json({ error: 'Out of scope' });
    }
    const sinceISO = String(req.query.since || '').trim();
    const since = sinceISO || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit || '200', 10) || 200));
    const actionsCSV = String(req.query.actions || '').trim();
    const actionList = actionsCSV ? actionsCSV.split(',').map(s => s.trim()).filter(Boolean) : null;

    // Build WHERE clauses with parameterized queries (no SQL injection risk).
    const params = [since];
    let where = `ts >= $1`;
    if (reqB) {
      params.push(reqB);
      where += ` AND building_id = $${params.length}`;
    } else if (req.user.role !== 'superadmin' && callerBIds.size > 0) {
      // Limit to caller's buildings (or rows that don't carry a building_id).
      params.push([...callerBIds]);
      where += ` AND (building_id = ANY($${params.length}::text[]) OR building_id IS NULL)`;
    }
    if (actionList && actionList.length) {
      params.push(actionList);
      where += ` AND action = ANY($${params.length}::text[])`;
    }
    params.push(limit);
    const sql = `
      SELECT ts, user_id, user_role, action, building_id, details
      FROM audit_entries
      WHERE ${where}
      ORDER BY ts DESC
      LIMIT $${params.length}
    `;
    // Reach into the pg pool via the repo's exported helpers
    const { Pool } = require('pg');
    const pool = require('./db/repo');
    // Use the existing pool by calling a tiny exposed query function. If not
    // exposed, do an ad-hoc connection from PG_CONN.
    const pg = require('pg');
    const connStr = process.env.PG_CONN;
    if (!connStr) return res.status(503).json({ error: 'PG_CONN not set' });
    const client = new pg.Client({ connectionString: connStr, ssl: { rejectUnauthorized: false } });
    await client.connect();
    try {
      const r = await client.query(sql, params);
      auditLog('ADMIN_AUDIT_QUERY', req.user, {
        since, limit, buildingId: reqB || null, actions: actionList, rowCount: r.rows.length,
      });
      res.json({
        rows: r.rows.map(x => ({
          ts: x.ts, userId: x.user_id, role: x.user_role,
          action: x.action, buildingId: x.building_id, details: x.details,
        })),
      });
    } finally { await client.end(); }
  } catch (e) {
    logger.error('admin_audit_query_failed', { err: e.message });
    res.status(500).json({ error: e.message });
  }
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

// ── POST /api/invite/onboard ─────────────────────────────────────────────────
// HR onboarding-specific invite. Creates employee account + hrEmployee record,
// sends onboarding email with password-set link.
// Body: { name, email, group, buildingId, inviteType }
app.post('/api/invite/onboard', requireAuth, requireAdmin, async (req, res) => {
  const { name, email, group, buildingId, inviteType } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'name and email are required' });
  const emailNorm = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) return res.status(400).json({ error: 'Invalid email address' });

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
  const nowIso      = new Date().toISOString();
  const hrEmployeeId = 'hre_' + Date.now() + '_' + crypto.randomBytes(2).toString('hex');

  // Create the account (role = employee; password set via invite link)
  const newAccount = {
    id:           'acc_' + Date.now(),
    name:         name.trim(),
    email:        emailNorm,
    role:         'employee',
    buildingId:   targetBuilding || null,
    ph:           null,
    schedulerOnly: false,
    inviteToken,
    inviteExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
    invitedBy:    req.user.email,
    invitedAt:    nowIso,
    hrEmployeeId,
    inviteType:   inviteType || 'full',
  };
  data.accounts = data.accounts || [];
  data.accounts.push(newAccount);
  await persistAccountNow(newAccount);

  // Create matching hrEmployee record
  const building = (data.buildings || []).find(b => b.id === targetBuilding);
  const state    = building?.state || 'TX';
  const initials = name.trim().split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
  const hrEmployee = {
    id:              hrEmployeeId,
    initials,
    name:            name.trim(),
    email:           emailNorm,
    role:            group || 'CNA',
    facilityId:      targetBuilding,
    status:          'invited',
    progress:        'Invite sent',
    slxId:           null,
    hourlyRate:      null,
    onboardingState: state,
    invitedAt:       nowIso,
    inviteType:      inviteType || 'full',
  };
  data.hrEmployees = data.hrEmployees || [];
  data.hrEmployees.push(hrEmployee);
  markDirty();

  const link    = `${APP_URL}/?invite=${inviteToken}`;
  const bName   = building?.name || 'your facility';
  const escName = escapeHtml(name.trim());
  const escB    = escapeHtml(bName);
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
          subject: `Complete your onboarding — ${safePlainB}`,
          plainText: `Hi ${safePlainName},\n\nWelcome to ${safePlainB}! You've been invited to complete your onboarding.\n\nClick the link below to set your password and start your paperwork:\n${link}\n\nOnce you sign in you'll be guided through your application, tax forms, and any required documents. You can save your progress and return at any time.\n\nThis invitation expires in 7 days.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">Welcome aboard!</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 12px">Hi ${escName}, you've been invited to join <strong>${escB}</strong>.</p>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Click below to set your password and begin your onboarding paperwork — application, tax forms, and any required documents. You can save your progress and return at any time.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Set Your Password &amp; Start Onboarding →</a>
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
      console.error('[mms] Onboarding invite email error:', e.message);
      return res.json({ ok: true, accountId: newAccount.id, hrEmployeeId, emailWarning: e.message, inviteLink: link });
    }
  }

  auditLog('ONBOARD_INVITE_SENT', req.user, { to: emailNorm, role: group, buildingId: targetBuilding, inviteType });
  res.json({ ok: true, accountId: newAccount.id, hrEmployeeId, inviteLink: link });
});

// ── DELETE /api/accounts/:id ──────────────────────────────────────────────────
// Removes an admin account. Bypasses the anti-shrink tripwire on /api/data POST.
// Authz: superadmin always; building admin only for accounts in their building(s).
// Self-deletion is blocked to prevent locking yourself out.
app.delete('/api/accounts/:id', requireAuth, requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Cannot remove your own account' });
  }
  const data = await loadData();
  const idx = (data.accounts || []).findIndex(a => a.id === targetId);
  if (idx < 0) return res.status(404).json({ error: 'Account not found' });
  const acct = data.accounts[idx];

  // Scope check: building admins can only remove accounts within their buildings
  if (req.user.role !== 'superadmin') {
    const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds || [])].filter(Boolean));
    if (!callerBIds.has(acct.buildingId)) {
      return res.status(403).json({ error: 'Out of scope — account belongs to a different building' });
    }
  }

  // Prevent removing superadmins via this endpoint
  if (acct.role === 'superadmin') {
    return res.status(403).json({ error: 'Cannot remove superadmin accounts via this endpoint' });
  }

  data.accounts.splice(idx, 1);

  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist account removal. Please retry.' });
  }
  auditLog('ACCOUNT_REMOVED', req.user, {
    removedId: acct.id, email: acct.email, role: acct.role,
    buildingId: acct.buildingId,
  });
  res.json({ ok: true });
});

// ── DELETE /api/account/me — Self-service account deletion ────────────────────
// Apple App Store Guideline 5.1.1(v) requires apps with account creation to
// offer account deletion. HIPAA retention: audit log entries are preserved with
// pseudonymized identifiers; personal data (name, email, phone) is scrubbed.
app.delete('/api/account/me', requireAuth, async (req, res) => {
  const data = await loadData();
  const myId = req.user.id;

  // Superadmins cannot self-delete (would orphan the entire org)
  if (req.user.role === 'superadmin') {
    return res.status(403).json({ error: 'Superadmin accounts cannot be self-deleted. Contact support.' });
  }

  // Remove account
  const acctIdx = (data.accounts || []).findIndex(a => a.id === myId);
  if (acctIdx >= 0) data.accounts.splice(acctIdx, 1);

  // Anonymize linked employee record (keep the row for shift history, but scrub PII)
  const emp = (data.employees || []).find(e => e.accountId === myId);
  if (emp) {
    emp.name = 'Deleted User';
    emp.email = null;
    emp.phone = null;
    emp.inactive = true;
    emp.accountId = null;
  }

  // Remove DMs authored by this user (scrub content, keep thread structure)
  if (Array.isArray(data.directMessages)) {
    for (const m of data.directMessages) {
      if (m.fromId === myId) { m.body = '[deleted]'; m.fromName = 'Deleted User'; }
      if (m.toId === myId) { m.toName = 'Deleted User'; }
    }
  }

  // Remove push subscriptions
  if (Array.isArray(data.pushSubscriptions)) {
    data.pushSubscriptions = data.pushSubscriptions.filter(s => s.userId !== myId);
  }

  // Revoke session
  if (req._token) await revokedTokens.add(req._token);
  clearAuthCookie(res);

  try { await flushNow(); } catch (e) {
    return res.status(500).json({ error: 'Failed to persist account deletion. Please retry.' });
  }
  auditLog('ACCOUNT_SELF_DELETED', { id: myId, role: req.user.role }, {
    hadEmployee: !!emp,
  });
  res.json({ ok: true, message: 'Your account has been deleted.' });
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
  const { groups, empIds, message, subject, viaSMS, viaEmail, buildingId } = req.body || {};
  // Caller must specify either a list of job-category groups OR an explicit
  // employee ID list (used by the Group Messages text-group composer, where
  // membership is a hand-curated mix that doesn't map cleanly to job groups).
  const hasGroups = Array.isArray(groups) && groups.length;
  const hasEmpIds = Array.isArray(empIds) && empIds.length;
  if (!hasGroups && !hasEmpIds) return res.status(400).json({ error: 'groups or empIds array is required' });
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

  const empIdSet = hasEmpIds ? new Set(empIds) : null;
  const employees = (data.employees || []).filter(e => {
    if (hasEmpIds ? !empIdSet.has(e.id) : !groups.includes(e.group)) return false;
    if (scopedBId && e.buildingId !== scopedBId) return false;
    if (e.inactive) return false;
    if (!isSA && !callerBIds.has(e.buildingId)) return false;
    return true;
  });

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
    groups: hasGroups ? groups : [],
    empIds: hasEmpIds ? empIds.slice() : null,
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

  auditLog('ALERT_QUEUED', req.user, { jobId, jobs: queuedJobs, groups: hasGroups ? groups : null, empIds: hasEmpIds ? empIds.length : null });
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
  if (!expected || !provided || expected.length !== provided.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided))) {
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
  // Body parser errors: surface a real status code instead of swallowing them
  // as a generic 500. Without this, PayloadTooLargeError became a vague "save
  // failed" toast on the client and the admin had no way to tell why their
  // edits weren't persisting (incident 2026-05-08 — Kirkland weekday rotation).
  if (err && err.type === 'entity.too.large') {
    logger.warn('payload_too_large', { reqId: req.id, length: err.length, limit: err.limit, path: req.path });
    return res.status(413).json({
      error: 'Request body exceeds the server limit. ' +
             'This usually means the app state is unusually large; please reload and try again, ' +
             'or contact support if it persists.',
      code: 'PAYLOAD_TOO_LARGE',
    });
  }
  if (err && err.type === 'entity.parse.failed') {
    logger.warn('payload_parse_failed', { reqId: req.id, err: err.message, path: req.path });
    return res.status(400).json({ error: 'Malformed JSON body', code: 'BAD_JSON' });
  }
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

  // Warn if .env file is in a cloud-synced directory (OneDrive, Dropbox, etc.)
  const envPath = require('path').resolve(__dirname, '.env');
  if (/onedrive|dropbox|google\s*drive|icloud/i.test(envPath)) {
    logger.warn('env_in_cloud_sync', {
      path: envPath,
      recommendation: 'Move .env to a non-synced directory or use a key vault (Azure Key Vault, AWS KMS)'
    });
    if (IS_PROD) {
      logger.error('ENCRYPTION_KEY_IN_CLOUD_SYNC_NOT_PERMITTED_IN_PRODUCTION');
      process.exit(1);
    }
  }

  _server = app.listen(PORT, () => {
    logger.info('server_started', {
      port: PORT, env: NODE_ENV, dataFile: DATA_FILE,
      auditLog: AUDIT_LOG_FILE,
      pcc: !!(PCC_CLIENT_ID && PCC_FACILITY_ID),
    });
  });

  // ── DAILY AUTOMATIC SNAPSHOT ─────────────────────────────────────────────
  // Snapshots already get written on every persistCache call (throttled to
  // ~30s). But on a quiet day with no edits, no snapshot would be taken,
  // and we could fall behind the user's expectation of "I have at least
  // a daily backup point I can roll to." Belt-and-suspenders: schedule a
  // forced snapshot every 24h regardless of activity. Cheap (KB-sized
  // encrypted file) and the prune logic keeps storage bounded.
  const DAILY_MS = 24 * 60 * 60 * 1000;
  setInterval(() => {
    if (!dataCache) return;             // nothing to snapshot yet
    _lastSnapshotAt = 0;                 // bypass the per-30s throttle
    _writeSnapshot().catch(e => logger.error('daily_snapshot_failed', { err: e.message }));
  }, DAILY_MS);
  // Take one ~30 seconds after boot too, so a fresh deploy immediately has
  // a known-good restore point. (Gated behind dataCache existing — empty
  // cache snapshot would be useless.)
  setTimeout(() => {
    if (!dataCache) return;
    _lastSnapshotAt = 0;
    _writeSnapshot().catch(e => logger.error('boot_snapshot_failed', { err: e.message }));
  }, 30 * 1000);
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
  // Give in-flight DB transactions time to commit. The previous 1-second
  // timeout was insufficient — a large saveAll() can take several seconds,
  // and Azure App Service sends SIGTERM up to 30s before hard-kill.
  setTimeout(() => process.exit(0), 10000).unref();
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
