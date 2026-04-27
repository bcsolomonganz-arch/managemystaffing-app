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
const JWT_TTL_SECONDS      = 60 * 60;            // 1 hour absolute (HIPAA-compliant)
const IDLE_TIMEOUT_SECONDS = 15 * 60;            // 15 min idle → server-enforced via lastActivity
const MAX_FAILED_ATTEMPTS  = 5;
const LOCKOUT_MS           = 30 * 60 * 1000;     // 30 min
const PASSWORD_MIN_LENGTH  = 12;
const AUDIT_LOG_FILE       = process.env.AUDIT_LOG_FILE || path.join(path.dirname(DATA_FILE), 'mms-audit.log');
const AUDIT_HMAC_KEY       = process.env.AUDIT_HMAC_KEY || (() => { throw new Error('AUDIT_HMAC_KEY required for tamper-evident audit log'); })();
const TOTP_ISSUER          = 'ManageMyStaffing';

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

// ── PCC (PointClickCare) CONFIG ───────────────────────────────────────────────
const PCC_CLIENT_ID     = process.env.PCC_CLIENT_ID     || null;
const PCC_CLIENT_SECRET = process.env.PCC_CLIENT_SECRET || null;
const PCC_FACILITY_ID   = process.env.PCC_FACILITY_ID   || null;
const PCC_ORG_UUID      = process.env.PCC_ORG_UUID      || null;
const PCC_BASE          = 'https://connect.pointclickcare.com';

let _pccToken = null, _pccTokenExpiry = 0;

async function getPCCToken() {
  if (_pccToken && Date.now() < _pccTokenExpiry) return _pccToken;
  const creds = Buffer.from(`${PCC_CLIENT_ID}:${PCC_CLIENT_SECRET}`).toString('base64');
  const resp = await fetch(`${PCC_BASE}/auth/token`, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  });
  if (!resp.ok) throw new Error(`PCC auth failed: ${resp.status} ${await resp.text()}`);
  const { access_token, expires_in } = await resp.json();
  _pccToken = access_token;
  _pccTokenExpiry = Date.now() + ((expires_in || 3600) - 60) * 1000;
  return _pccToken;
}

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

// ── IN-MEMORY CACHE + DEBOUNCED SAVE ─────────────────────────────────────────
let dataCache   = null;
let dataDirty   = false;
let saveTimeout = null;

function markDirty() {
  dataDirty = true;
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(persistCache, 2000);
}

async function persistCache() {
  if (!dataDirty) return;
  dataDirty = false;
  clearTimeout(saveTimeout);
  try {
    const payload   = { ...dataCache, _lastSaved: new Date().toISOString() };
    const encrypted = await encrypt(payload);
    const tmp       = DATA_FILE + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(encrypted, null, 2), 'utf8');
    await fs.rename(tmp, DATA_FILE);
    console.log('[mms] Data saved (encrypted)');
  } catch (e) {
    console.error('[mms] Save failed:', e.message);
  }
}

async function loadData() {
  if (dataCache) return dataCache;
  try {
    const raw    = await fs.readFile(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);

    // Detect format: encrypted has { iv, data, authTag }; plain JSON does not
    if (parsed.iv && parsed.data && parsed.authTag) {
      dataCache = await decrypt(parsed);
      console.log('[mms] Data loaded (encrypted)');
    } else {
      // Migrate from plain JSON to encrypted
      dataCache = parsed;
      dataDirty = true;
      await persistCache();
      console.log('[mms] Migrated data file to encrypted format');
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
      console.log('[mms] New encrypted data file created');
    } else {
      console.error('[mms] Data load failed:', e.message);
      throw e;
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

const revokedTokens = {
  async add(token) {
    _memRevokedTokens.add(token);
    if (_redis) {
      try { await _redis.set(`revoked:${token}`, '1', 'EX', JWT_TTL_SECONDS); } catch (e) {}
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
      try { await _redis.set(`act:${sid}`, String(ts), 'EX', JWT_TTL_SECONDS); } catch (e) {}
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
    // Idle timeout: if last activity > 15 min ago, force logout
    const sid = decoded.sid;
    const last = await lastActivity.get(sid);
    if (last && (Date.now() - last) > IDLE_TIMEOUT_SECONDS * 1000) {
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

function requireAdmin(req, res, next) {
  if (!['admin', 'superadmin'].includes(req.user?.role)) {
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

// ── PASSWORD COMPLEXITY (HIPAA §164.308(a)(5)) ───────────────────────────────
function validatePasswordComplexity(pw) {
  if (!pw || typeof pw !== 'string') return 'Password is required';
  if (pw.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (!/[A-Z]/.test(pw)) return 'Password must include an uppercase letter';
  if (!/[a-z]/.test(pw)) return 'Password must include a lowercase letter';
  if (!/[0-9]/.test(pw)) return 'Password must include a number';
  if (!/[^A-Za-z0-9]/.test(pw)) return 'Password must include a symbol';
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
function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure:   IS_PROD,                      // local dev allows http
    sameSite: 'strict',
    maxAge:   JWT_TTL_SECONDS * 1000,
    path:     '/',
    signed:   false,                        // signing the cookie isn't needed (JWT is self-signed)
  });
}
function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/' });
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
    dataFile:     false,
    auditChain:   false,
    encryption:   'AES-256-GCM',
    messaging: {
      acs:   !!ACS_CONNECTION_STRING,
      email: !!ACS_FROM_EMAIL,
      sms:   !!ACS_FROM_PHONE,
    },
  };
  try {
    await loadData();
    checks.dataFile = true;
  } catch (e) {
    return res.status(503).json({ ok: false, ...checks, error: 'data_unreachable' });
  }
  const chain = await verifyAuditChain();
  checks.auditChain = chain.ok;
  if (!chain.ok) return res.status(503).json({ ok: false, ...checks, auditChainError: chain });
  res.json({ ok: true, ...checks });
});

// ── SERVE HTML ────────────────────────────────────────────────────────────────
// Force browsers to revalidate so users always get the latest UI after deploy.
// `must-revalidate` + `no-cache` together tell the browser to send a conditional
// GET on every load. App Service still serves it fast (single file).
app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache, must-revalidate');
  res.sendFile(HTML_FILE);
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
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
          markDirty();
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

  // TOTP gating: all non-demo accounts require TOTP.
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
    hashes.push(await bcrypt.hash(raw, 10));
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
  markDirty();
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
  markDirty();
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
  acct.totpSecret = null;
  acct.totpEnrolledAt = null;
  acct.totpRecoveryCodesHashes = null;
  acct.totpRecoveryCodesGeneratedAt = null;
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
    demo:       isDemo || undefined,
    sid,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL_SECONDS });
  await lastActivity.set(sid, Date.now());
  setAuthCookie(res, token);                // ← XSS-safe httpOnly cookie
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
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const data     = await loadData();
    const filtered = getDataForUser(req.user, data);
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

  const data = await loadData();
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

  // Accounts: protect seed accounts; prevent caller from escalating own role.
  if (Array.isArray(payload.accounts)) {
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
    // Prevent caller from removing TOTP from any account
    for (const a of accountsScoped) {
      const orig = (data.accounts || []).find(x => x.id === a.id);
      if (orig?.totpSecret && !a.totpSecret) a.totpSecret = orig.totpSecret;
      if (orig?.totpEnrolledAt && !a.totpEnrolledAt) a.totpEnrolledAt = orig.totpEnrolledAt;
    }
    data.accounts = accountsScoped;
  }

  // Superadmin-only top-level fields
  if (isSA) {
    if (Array.isArray(payload.companies))   data.companies   = payload.companies;
    if (Array.isArray(payload.jobPostings)) data.jobPostings = payload.jobPostings;
    if (Array.isArray(payload.hrAccounts))  data.hrAccounts  = payload.hrAccounts;
  }

  dataCache = data;
  markDirty();
  auditLog('DATA_UPDATE', req.user, {
    counts: {
      buildings: data.buildings?.length || 0,
      employees: data.employees?.length || 0,
      shifts:    data.shifts?.length    || 0,
    },
  });
  res.json({ ok: true });
});

// ── POST /api/invite ──────────────────────────────────────────────────────────
app.post('/api/invite', requireAuth, requireAdmin, async (req, res) => {
  const { name, email, role, buildingId } = req.body || {};
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
    inviteToken,
    inviteExpiry: Date.now() + 7 * 24 * 60 * 60 * 1000,
    invitedBy:    req.user.email,
    invitedAt:    new Date().toISOString(),
  };
  data.accounts = data.accounts || [];
  data.accounts.push(newAccount);
  markDirty();

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
  markDirty();

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
  res.json({ ok: true, email: acct.email, name: acct.name, buildingId: acct.buildingId });
});

// ── POST /api/invite/accept ───────────────────────────────────────────────────
// Body: { token, password }  — plaintext password, hashed with bcrypt server-side
app.post('/api/invite/accept', authLimiter, async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password are required' });

  const complexityErr = validatePasswordComplexity(password);
  if (complexityErr) return res.status(400).json({ error: complexityErr });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired.' });
  }

  acct.ph             = await bcrypt.hash(password, 12);
  acct.inviteToken    = undefined;
  acct.inviteExpiry   = undefined;
  acct.activatedAt    = new Date().toISOString();
  acct.failedAttempts = 0;
  acct.lockedUntil    = null;
  markDirty();

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

// ── GET /api/pcc/census ───────────────────────────────────────────────────────
app.get('/api/pcc/census', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured.' });
  }
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).replace(/[^0-9-]/g, '');
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;
    const url  = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/census?censusDate=${date}`;
    const resp = await fetch(url, { headers });
    if (!resp.ok) return res.status(502).json({ error: `PCC census API ${resp.status}` });
    const body = await resp.json();
    const d    = body.data || body;
    res.json({
      ok:     true,
      census: d.totalCensus ?? d.occupiedBeds ?? d.census ?? null,
      date:   d.censusDate || date,
      details: {
        totalBeds:     d.totalBeds     || null,
        medicareCount: d.medicareCount || null,
        medicaidCount: d.medicaidCount || null,
        otherCount:    d.otherCount    || null,
      },
    });
  } catch (e) {
    console.error('[mms] PCC census error:', e.message);
    res.status(502).json({ error: `PCC request failed: ${e.message}` });
  }
});

// ── GET /api/pcc/staffing ─────────────────────────────────────────────────────
app.get('/api/pcc/staffing', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured.' });
  }
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).replace(/[^0-9-]/g, '');
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;
    const url    = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/staffShifts?date=${date}`;
    const resp   = await fetch(url, { headers });
    if (!resp.ok) return res.status(502).json({ error: `PCC staffing API ${resp.status}` });
    const body   = await resp.json();
    const shifts = body.data || body.shifts || body || [];
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
    res.json({ ok: true, date, hours, rn24: hours.rn >= 24, shifts: Array.isArray(shifts) ? shifts.length : 0 });
  } catch (e) {
    console.error('[mms] PCC staffing error:', e.message);
    res.status(502).json({ error: `PCC staffing failed: ${e.message}` });
  }
});

// ── GET /api/pcc/staffing/range ───────────────────────────────────────────────
app.get('/api/pcc/staffing/range', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured' });
  }
  const today   = new Date().toISOString().slice(0, 10);
  const start   = (req.query.start || today.slice(0, 8) + '01').replace(/[^0-9-]/g, '');
  const end     = (req.query.end   || today).replace(/[^0-9-]/g, '');
  const startMs = new Date(start).getTime(), endMs = new Date(end).getTime();
  if (isNaN(startMs) || isNaN(endMs) || endMs < startMs || endMs - startMs > 32 * 86400000) {
    return res.status(400).json({ error: 'Invalid date range (max 31 days)' });
  }
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;
    const url    = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/staffShifts?startDate=${start}&endDate=${end}`;
    const resp   = await fetch(url, { headers });
    if (!resp.ok) return res.status(502).json({ error: `PCC range API ${resp.status}` });
    const body   = await resp.json();
    const shifts = body.data || body.shifts || body || [];
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
    console.error('[mms] PCC range error:', e.message);
    res.status(502).json({ error: `PCC range failed: ${e.message}` });
  }
});

// ── GET /jobs.xml ─────────────────────────────────────────────────────────────
app.get('/jobs.xml', async (_req, res) => {
  try {
    const data = await loadData();
    const jobs  = (data.jobPostings || []).filter(j => j.status === 'active');
    const esc   = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const items = jobs.map(j => `  <job>
    <id><![CDATA[${j.id}]]></id>
    <title><![CDATA[${esc(j.title)}]]></title>
    <company><![CDATA[ManageMyStaffing]]></company>
    <city><![CDATA[${esc(j.city||'')}]]></city>
    <state><![CDATA[${esc(j.state||'')}]]></state>
    <country>US</country>
    <postalcode><![CDATA[${esc(j.zip||'')}]]></postalcode>
    <date>${(j.createdAt||'').slice(0,10)}</date>
    <reqid>${esc(j.id)}</reqid>
    <jobtype><![CDATA[${esc(j.jobType||'Full-time')}]]></jobtype>
    <category><![CDATA[${esc(j.department||'Healthcare')}]]></category>
    <description><![CDATA[${esc(j.description||'')}]]></description>
    <salary><![CDATA[${esc(j.salary||'')}]]></salary>
    <url><![CDATA[${APP_URL}/#job-${j.id}]]></url>
  </job>`).join('\n');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<source>
  <publisher>ManageMyStaffing</publisher>
  <publisherurl>${APP_URL}</publisherurl>
  <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
${items}
</source>`;
    res.setHeader('Content-Type', 'application/xml; charset=UTF-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(xml);
  } catch (e) {
    res.status(500).send('<?xml version="1.0"?><error>Feed generation failed</error>');
  }
});

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

  let emailSent = 0, smsSent = 0;
  const errors = [];

  if (!ACS_CONNECTION_STRING) {
    errors.push('Messaging not configured (missing ACS_CONNECTION_STRING)');
  } else {
    if (emailList.length) {
      const { EmailClient } = require('@azure/communication-email');
      const emailClient = new EmailClient(ACS_CONNECTION_STRING);
      for (const emp of emailList) {
        try {
          const body   = message.replace(/\[Name\]/g, emp.name);
          const poller = await emailClient.beginSend({
            senderAddress: ACS_FROM_EMAIL,
            recipients:    { to: [{ address: emp.email, displayName: emp.name }] },
            content: {
              subject:   subject || 'Alert from ManageMyStaffing',
              plainText: body,
              html:      `<pre style="font-family:sans-serif;white-space:pre-wrap">${body.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre>`,
            },
          });
          await Promise.race([
            poller.pollUntilDone(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000)),
          ]);
          emailSent++;
        } catch (e) {
          console.error('[mms] ACS email error:', e.message);
          errors.push(`Email to ${emp.name}: ${e.message}`);
        }
      }
    }
    if (smsList.length) {
      if (!ACS_FROM_PHONE) {
        errors.push('SMS not configured (missing ACS_FROM_PHONE)');
      } else {
        const { SmsClient } = require('@azure/communication-sms');
        const smsClient = new SmsClient(ACS_CONNECTION_STRING);
        for (const emp of smsList) {
          const to = toE164(emp.phone);
          if (!to) { errors.push(`SMS to ${emp.name}: invalid phone`); continue; }
          try {
            const results = await smsClient.send({
              from: ACS_FROM_PHONE, to: [to],
              message: message.replace(/\[Name\]/g, emp.name).slice(0, 1600),
            });
            if (results[0]?.successful) smsSent++;
            else errors.push(`SMS to ${emp.name}: ${results[0]?.errorMessage || 'failed'}`);
          } catch (e) {
            errors.push(`SMS to ${emp.name}: ${e.message}`);
          }
        }
      }
    }
  }

  auditLog('ALERT_SENT', req.user, { emailSent, smsSent, groups });
  res.json({ ok: true, emailSent, smsSent, errors });
});

// ── POST /api/sms ─────────────────────────────────────────────────────────────
app.post('/api/sms', requireAuth, requireAdmin, async (req, res) => {
  const { to, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message are required' });
  if (message.length > 1600) return res.status(400).json({ error: 'message too long (1600 char max)' });
  if (!ACS_CONNECTION_STRING || !ACS_FROM_PHONE) {
    return res.status(503).json({ error: 'SMS not configured' });
  }
  const normalized = toE164(to);
  if (!normalized) return res.status(400).json({ error: `Invalid phone number: ${to}` });

  // Authz: non-superadmins can only SMS phones belonging to employees in their
  // own building(s). This stops toll fraud and external-phishing pivots via
  // company SMS gateway.
  const data = await loadData();
  let scopedEmployees = data.employees || [];
  if (req.user.role !== 'superadmin') {
    const callerBIds = new Set([req.user.buildingId, ...(req.user.buildingIds||[])].filter(Boolean));
    scopedEmployees = scopedEmployees.filter(e => callerBIds.has(e.buildingId));
    const allowed = scopedEmployees.some(e => !e.inactive && toE164(e.phone) === normalized);
    if (!allowed) {
      auditLog('SMS_BLOCKED', req.user, { to: normalized, reason: 'phone_not_in_building_roster' });
      return res.status(403).json({ error: 'Phone number is not in your building roster' });
    }
  }

  // PHI guard (HIPAA §164.312(e)) — block any message containing PHI patterns.
  const phiReason = scanMessageForPHI(message, scopedEmployees);
  if (phiReason) {
    auditLog('SMS_BLOCKED_PHI', req.user, { to: normalized, reason: phiReason });
    return res.status(400).json({ error: `SMS blocked: ${phiReason}. Use a generic notification and link to the app.` });
  }

  try {
    const { SmsClient } = require('@azure/communication-sms');
    const smsClient = new SmsClient(ACS_CONNECTION_STRING);
    const results   = await smsClient.send({ from: ACS_FROM_PHONE, to: [normalized], message: message.slice(0, 1600) });
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
  // Flush pending data writes
  try {
    await persistCache();
    await _auditQueue;
    logger.info('data_flushed');
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
