'use strict';
require('dotenv').config();

const express    = require('express');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const fs         = require('fs').promises;
const fsSync     = require('fs');
const path       = require('path');
const os         = require('os');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3002;
const JWT_SECRET = process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET env var is required'); })();
const DATA_FILE  = process.env.DATA_FILE  || path.join(process.env.HOME || os.homedir() || __dirname, 'mms-data.json');
const DATA_ENCRYPTION_KEY = process.env.DATA_ENCRYPTION_KEY || (() => { throw new Error('DATA_ENCRYPTION_KEY (32-byte hex) required'); })();
const HTML_FILE  = path.join(__dirname, 'managemystaffing.html');
const APP_URL    = process.env.APP_URL || 'https://managemystaffing.com';

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
    if (sa) { sa.ph = null; dirty = true; }
    console.log('[mms] SA password reset — next login sets new password');
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

// ── AUDIT LOGGING (HIPAA §164.312(b)) ─────────────────────────────────────────
function auditLog(action, user, details = {}) {
  const entry = {
    ts:     new Date().toISOString(),
    userId: user?.id    || 'anonymous',
    email:  user?.email || '',
    action,
    ...details,
  };
  console.log('[AUDIT]', JSON.stringify(entry));
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
const revokedTokens = new Set(); // use Redis in production

function requireAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    if (revokedTokens.has(token)) return res.status(401).json({ error: 'Token revoked' });
    req.user = jwt.verify(token, JWT_SECRET);
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

// ── HIPAA DATA MINIMIZATION ───────────────────────────────────────────────────
function getDataForUser(user, fullData) {
  if (user.role === 'superadmin') return fullData;
  const bId = user.buildingId;
  if (!bId) return { ...fullData, buildings: [], employees: [], shifts: [], schedulePatterns: [] };
  return {
    ...fullData,
    buildings:        (fullData.buildings        || []).filter(b => b.id === bId),
    employees:        (fullData.employees        || []).filter(e => e.buildingId === bId),
    shifts:           (fullData.shifts           || []).filter(s => s.buildingId === bId),
    schedulePatterns: (fullData.schedulePatterns || []).filter(p =>
      (fullData.employees || []).some(e => e.id === p.empId && e.buildingId === bId)),
    accounts:         (fullData.accounts         || []).filter(a =>
      a.id === user.id || (a.buildingId && a.buildingId === bId)),
  };
}

// ── RATE LIMITERS ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50,  message: { error: 'Too many requests' } });
const apiLimiter  = rateLimit({ windowMs:       60 * 1000, max: 300, message: { error: 'Too many requests' } });

// ── EXPRESS APP ───────────────────────────────────────────────────────────────
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"], // allow onclick/onchange handlers
      styleSrc:      ["'self'", "'unsafe-inline'"],
      imgSrc:        ["'self'", 'data:'],
    },
  },
}));

app.use(cors({
  origin: [APP_URL, 'http://localhost:3002'],
  credentials: true,
}));

app.use(express.json({ limit: '50mb' }));
app.use('/api/', apiLimiter);

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    mode: 'production',
    hipaaCompliant: true,
    encryption: 'AES-256-GCM',
    messaging: {
      acsConfigured:   !!ACS_CONNECTION_STRING,
      emailConfigured: !!ACS_FROM_EMAIL,
      smsConfigured:   !!ACS_FROM_PHONE,
    },
  });
});

// ── SERVE HTML ────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.sendFile(HTML_FILE));

// ── POST /api/auth/login ──────────────────────────────────────────────────────
// Body: { email, password }
// - Demo accounts accept any password.
// - ph===null (first login): any password → saved as bcrypt hash.
// - ph starts with $2 (bcrypt): bcrypt.compare.
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  let data;
  try { data = await loadData(); } catch (e) { return res.status(500).json({ error: 'Server error' }); }

  const acct = (data.accounts || []).find(a => (a.email || '').toLowerCase() === email.toLowerCase());
  if (!acct) {
    auditLog('LOGIN_FAILED', null, { email, reason: 'unknown_email' });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  let authenticated = false;
  const isDemo = acct.id === SEED_DEMO.id || acct.id === SEED_DEMO_NURSE.id;

  if (isDemo) {
    authenticated = true;
  } else if (!acct.ph) {
    // First login — set permanent bcrypt password
    acct.ph = await bcrypt.hash(password, 12);
    markDirty();
    authenticated = true;
  } else {
    authenticated = await bcrypt.compare(password, acct.ph);
  }

  if (!authenticated) {
    auditLog('LOGIN_FAILED', acct, { reason: 'wrong_password' });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const payload = {
    id:         acct.id,
    name:       acct.name,
    email:      acct.email,
    role:       acct.role,
    buildingId: acct.buildingId || null,
    demo:       isDemo || undefined,
    group:      acct.group || undefined,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

  auditLog('LOGIN_SUCCESS', acct);
  res.json({ token, user: payload });
});

// ── GET /api/auth/verify ──────────────────────────────────────────────────────
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  revokedTokens.add(token);
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
app.post('/api/data', requireAuth, requireAdmin, async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== 'object') return res.status(400).json({ error: 'Invalid payload' });

  // Guard seed account roles
  if (Array.isArray(payload.accounts)) {
    for (const seed of [SEED_SA, SEED_DEMO]) {
      const acct = payload.accounts.find(a => a.id === seed.id);
      if (acct && acct.role !== seed.role) {
        console.warn(`[mms] WARN: blocked role change on ${seed.id}`);
        acct.role = seed.role;
      }
    }
  }

  dataCache = payload;
  markDirty();
  auditLog('DATA_UPDATE', req.user);
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

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec     = new EmailClient(ACS_CONNECTION_STRING);
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: emailNorm, displayName: name.trim() }] },
        content: {
          subject: "You've been invited to ManageMyStaffing",
          plainText: `Hi ${name.trim()},\n\nYou've been invited to manage ${bName} on ManageMyStaffing.\n\nClick the link below to set your password:\n${link}\n\nThis invitation expires in 7 days.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">You've been invited!</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Hi ${name.trim()}, you've been invited to manage <strong>${bName}</strong> on ManageMyStaffing.</p>
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

// ── GET /api/invite/verify ────────────────────────────────────────────────────
app.get('/api/invite/verify', async (req, res) => {
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
app.post('/api/invite/accept', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password are required' });

  const data = await loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired.' });
  }

  acct.ph           = await bcrypt.hash(password, 12);
  acct.inviteToken  = undefined;
  acct.inviteExpiry = undefined;
  acct.activatedAt  = new Date().toISOString();
  markDirty();

  const userPayload = {
    id: acct.id, name: acct.name, email: acct.email,
    role: acct.role, buildingId: acct.buildingId || null,
  };
  const jwtToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '8h' });
  auditLog('INVITE_ACCEPTED', acct);
  res.json({ ok: true, token: jwtToken, user: userPayload });
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

  const data      = await loadData();
  const employees = (data.employees || []).filter(e =>
    groups.includes(e.group) && (!buildingId || e.buildingId === buildingId) && !e.inactive);

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
  if (!ACS_CONNECTION_STRING || !ACS_FROM_PHONE) {
    return res.status(503).json({ error: 'SMS not configured' });
  }
  const normalized = toE164(to);
  if (!normalized) return res.status(400).json({ error: `Invalid phone number: ${to}` });
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
    console.error('[mms] /api/sms error:', e.message);
    res.status(500).json({ error: e.message });
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

// ── STARTUP ───────────────────────────────────────────────────────────────────
(async () => {
  try {
    await loadData();
  } catch (e) {
    console.error('[mms] Fatal startup error:', e.message);
    process.exit(1);
  }

  if (!ACS_CONNECTION_STRING) console.warn('[mms] WARN: ACS_CONNECTION_STRING not set — email/SMS disabled');
  if (!ACS_FROM_PHONE)        console.warn('[mms] WARN: ACS_FROM_PHONE not set — SMS disabled');

  app.listen(PORT, () => {
    console.log(`[mms] ManageMyStaffing running on http://localhost:${PORT}`);
    console.log(`[mms] Data file: ${DATA_FILE} | Encryption: AES-256-GCM`);
    console.log(`[mms] PCC: ${PCC_CLIENT_ID && PCC_FACILITY_ID ? `ENABLED (facilityId=${PCC_FACILITY_ID})` : 'not configured'}`);
  });
})();
