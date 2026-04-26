'use strict';
require('dotenv').config();

const express  = require('express');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');
const os       = require('os');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT      = process.env.PORT      || 3002;
const JWT_SECRET= process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET env var is required'); })();
const DATA_FILE = process.env.DATA_FILE  || path.join(process.env.HOME || os.homedir() || __dirname, 'mms-data.json');
const HTML_FILE = path.join(__dirname, 'managemystaffing.html');

// ── MESSAGING CONFIG — Azure Communication Services ───────────────────────────
const ACS_CONNECTION_STRING = process.env.ACS_CONNECTION_STRING || null;
const ACS_FROM_EMAIL        = process.env.ACS_FROM_EMAIL || 'noreply@751842ed-e753-4e35-9ace-4f2a879b45b7.azurecomm.net';
const ACS_FROM_PHONE        = process.env.ACS_FROM_PHONE || null; // E.164, e.g. +18885550100

// ── PCC (PointClickCare) CONFIG ───────────────────────────────────────────────
const PCC_CLIENT_ID     = process.env.PCC_CLIENT_ID     || null;
const PCC_CLIENT_SECRET = process.env.PCC_CLIENT_SECRET || null;
const PCC_FACILITY_ID   = process.env.PCC_FACILITY_ID   || null;
const PCC_ORG_UUID      = process.env.PCC_ORG_UUID      || null;
const PCC_BASE          = 'https://connect.pointclickcare.com';

// In-memory PCC token cache (resets on restart — intentional, token lifetime ~60min)
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
  _pccTokenExpiry = Date.now() + ((expires_in || 3600) - 60) * 1000; // 60 s buffer
  return _pccToken;
}

// ── SUPER-ADMIN SEED ACCOUNT ─────────────────────────────────────────────────
const SEED_SA = {
  id: 'sa0',
  name: 'Ben Solomon',
  email: 'solomong@managemystaffing.com',
  role: 'superadmin',
  buildingId: null,
  ph: null   // ph:null = any password on first login becomes permanent
};

// ── DEMO ACCOUNT (any password, admin view of Harmony Hills) ─────────────────
const SEED_DEMO = {
  id: 'sa-demo',
  name: 'Demo Admin',
  email: 'demo@demo.com',
  role: 'admin',
  buildingId: 'b1',
  ph: null   // always accepts any password (demo mode)
};

// ── ATOMIC FILE WRITE ─────────────────────────────────────────────────────────
function writeAtomic(filePath, data) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

// ── SEED IDs THAT MUST NEVER APPEAR IN REAL DATA ─────────────────────────────
// These are the client-side demo seed IDs. If they exist in the server data file
// (e.g. from an early session where demo data was accidentally persisted), they
// are stripped out on every load so real users never see demo content.
const SEED_BUILDING_IDS = new Set(['b1','b2','b3','b4',
  'sunrise-snf','willowbrook','golden-acres','harmony-hills',
  'linwood','cross-timbers','north-county','meadowbrook']);
const SEED_EMPLOYEE_IDS_PREFIX = 'e0'; // all seed employees start with 'e0'

// ── LOAD OR INITIALIZE DATA FILE ─────────────────────────────────────────────
function loadData() {
  let data;
  if (!fs.existsSync(DATA_FILE)) {
    data = { accounts: [SEED_SA, SEED_DEMO] };
    writeAtomic(DATA_FILE, data);
    console.log(`[mms] Created data file at ${DATA_FILE} with seed accounts.`);
    return data;
  }
  try {
    data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    console.error('[mms] Failed to parse data file:', e.message);
    throw e;
  }

  if (!Array.isArray(data.accounts)) data.accounts = [];
  let dirty = false;

  // ── Migration: strip any seed buildings / employees / shifts that were
  //    accidentally persisted by a demo or early-setup session.
  if (!data._seedStripped) {
    const beforeB = (data.buildings || []).length;
    const beforeE = (data.employees || []).length;
    data.buildings = (data.buildings || []).filter(b => !SEED_BUILDING_IDS.has(b.id));
    data.employees = (data.employees || []).filter(e => !e.id.startsWith(SEED_EMPLOYEE_IDS_PREFIX));
    // Also strip shifts and patterns that reference removed employees/buildings
    const keepBIds = new Set((data.buildings || []).map(b => b.id));
    const keepEIds = new Set((data.employees || []).map(e => e.id));
    data.shifts           = (data.shifts           || []).filter(s => keepBIds.has(s.buildingId) || keepEIds.has(s.employeeId));
    data.schedulePatterns = (data.schedulePatterns || []).filter(p => keepEIds.has(p.empId));
    const strippedB = beforeB - data.buildings.length;
    const strippedE = beforeE - data.employees.length;
    if (strippedB || strippedE) {
      console.log(`[mms] Migration: stripped ${strippedB} seed buildings and ${strippedE} seed employees from data file.`);
    }
    data._seedStripped = true;
    dirty = true;
  }

  // ── Migration: strip seed HR employees and demo HR accounts ──────────────────
  if (!data._hrSeedStripped) {
    const beforeHE = (data.hrEmployees || []).length;
    const beforeHA = (data.hrAccounts  || []).length;
    // Seed HR employee IDs start with 'hre'; demo HR account IDs are ha1/ha2
    data.hrEmployees = (data.hrEmployees || []).filter(e => !e.id.startsWith('hre'));
    data.hrAccounts  = (data.hrAccounts  || []).filter(a => !['ha1','ha2'].includes(a.id));
    const strippedHE = beforeHE - (data.hrEmployees || []).length;
    const strippedHA = beforeHA - (data.hrAccounts  || []).length;
    if (strippedHE || strippedHA) {
      console.log(`[mms] Migration: stripped ${strippedHE} seed HR employees and ${strippedHA} demo HR accounts from data file.`);
    }
    data._hrSeedStripped = true;
    dirty = true;
  }

  // ── Migration: strip seed time-clock records (empId starts with 'tc-') ───────
  if (!data._tcSeedStripped) {
    const before = (data.hrTimeClock || []).length;
    data.hrTimeClock = (data.hrTimeClock || []).filter(r => !String(r.empId||'').startsWith('tc-'));
    const stripped = before - (data.hrTimeClock || []).length;
    if (stripped) console.log(`[mms] Migration: stripped ${stripped} seed time-clock records.`);
    data._tcSeedStripped = true;
    dirty = true;
  }

  // ── Password reset: if RESET_SA_PASSWORD=1 env var is set, clear the SA
  //    password hash so the next login accepts any password as the new permanent one.
  //    Remove the env var after triggering to prevent repeated resets.
  if (process.env.RESET_SA_PASSWORD === '1') {
    const sa = data.accounts.find(a => a.id === SEED_SA.id);
    if (sa) { sa.ph = null; dirty = true; }
    console.log(`[mms] SA password reset to null — next login sets new permanent password.`);
  }

  // Ensure seed accounts always exist and have the correct immutable fields
  for (const seed of [SEED_SA, SEED_DEMO]) {
    const existing = data.accounts.find(a => a.id === seed.id);
    if (!existing) {
      data.accounts.push(seed);
      dirty = true;
      console.log(`[mms] Seeded missing account: ${seed.email}`);
    } else {
      if (existing.email !== seed.email) {
        existing.email = seed.email;
        dirty = true;
        console.log(`[mms] Updated email for account ${seed.id}: ${seed.email}`);
      }
      // Always enforce the correct role for seed accounts — role must never be escalated
      if (existing.role !== seed.role) {
        console.warn(`[mms] WARN: seed account ${seed.id} had role='${existing.role}', correcting to '${seed.role}'`);
        existing.role = seed.role;
        dirty = true;
      }
    }
  }

  if (dirty) writeAtomic(DATA_FILE, data);
  return data;
}

function saveData(data) {
  writeAtomic(DATA_FILE, data);
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (!['admin', 'superadmin'].includes(req.user?.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
}

// ── EXPRESS APP ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '50mb' }));

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    mode: 'production',
    messaging: {
      acsConfigured:  !!ACS_CONNECTION_STRING,
      emailConfigured: !!ACS_FROM_EMAIL,
      smsConfigured:  !!ACS_FROM_PHONE,
    },
  });
});

// ── SERVE HTML ────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.sendFile(HTML_FILE);
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
// Body: { email: string, passwordHash: string }
// - If account.ph === null (first login), accept any hash and save it permanently.
// - Returns { token, user }
app.post('/api/auth/login', (req, res) => {
  const { email, passwordHash } = req.body || {};
  if (!email || !passwordHash) {
    return res.status(400).json({ error: 'email and passwordHash are required' });
  }

  const data = loadData();
  const accounts = data.accounts || [];

  // Look for account in data file
  const acct = accounts.find(a => (a.email || '').toLowerCase() === email.toLowerCase());
  if (!acct) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  if (acct.id === SEED_DEMO.id) {
    // Demo account — always accepts any password, never persists it
  } else if (acct.ph === null || acct.ph === undefined) {
    // First login — any password becomes permanent
    acct.ph = passwordHash;
    data.accounts = accounts; // ensure reference is updated
    try {
      saveData(data);
    } catch (e) {
      console.error('[mms] Failed to save first-login password:', e.message);
      return res.status(500).json({ error: 'Failed to save credentials' });
    }
  } else if (acct.ph !== passwordHash) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Issue JWT (7-day expiry)
  const userPayload = {
    id:         acct.id,
    name:       acct.name,
    email:      acct.email,
    role:       acct.role,
    buildingId: acct.buildingId || null,
    // Demo accounts use seed data client-side; nothing is persisted server-side
    demo:       (acct.id === SEED_DEMO.id) || undefined,
  };
  const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

  return res.json({ token, user: userPayload });
});

// ── GET /api/auth/verify ──────────────────────────────────────────────────────
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── GET /api/data ─────────────────────────────────────────────────────────────
app.get('/api/data', requireAuth, (_req, res) => {
  try {
    const data = loadData();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Failed to read data file' });
  }
});

// ── POST /api/data ────────────────────────────────────────────────────────────
app.post('/api/data', requireAuth, requireAdmin, (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Invalid payload' });
  }
  // Guard: seed accounts cannot have their roles overwritten via this endpoint
  if (Array.isArray(payload.accounts)) {
    for (const seed of [SEED_SA, SEED_DEMO]) {
      const acct = payload.accounts.find(a => a.id === seed.id);
      if (acct && acct.role !== seed.role) {
        console.warn(`[mms] WARN: POST /api/data attempted to change role of ${seed.id} to '${acct.role}' — blocked`);
        acct.role = seed.role;
      }
    }
  }
  try {
    saveData(payload);
    res.json({ ok: true });
  } catch (e) {
    console.error('[mms] Failed to save data:', e.message);
    res.status(500).json({ error: 'Failed to save data' });
  }
});

// ── POST /api/invite ─────────────────────────────────────────────────────────
// Body: { name, email, role, buildingId }
// Creates a pending account and sends an invite email with a one-time token link.
app.post('/api/invite', requireAuth, requireAdmin, async (req, res) => {
  const { name, email, role, buildingId } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'name and email are required' });
  const emailNorm = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  const allowedRoles = ['admin', 'employee'];
  const acctRole = allowedRoles.includes(role) ? role : 'admin';

  // Super admins can invite for any building; building admins can only invite for their own building
  const callerBuildingId = req.user.buildingId;
  const targetBuilding   = buildingId || callerBuildingId;
  if (req.user.role === 'admin' && targetBuilding !== callerBuildingId) {
    return res.status(403).json({ error: 'Admins can only invite users to their own building' });
  }

  const data = loadData();
  const existing = (data.accounts || []).find(a => a.email.toLowerCase() === emailNorm);
  if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

  const token      = crypto.randomBytes(24).toString('hex');
  const expiry     = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
  const newAccount = {
    id:           'acc_' + Date.now(),
    name:         name.trim(),
    email:        emailNorm,
    role:         acctRole,
    buildingId:   targetBuilding || null,
    ph:           null,          // ph:null = first login sets permanent password
    inviteToken:  token,
    inviteExpiry: expiry,
    invitedBy:    req.user.email,
    invitedAt:    new Date().toISOString(),
  };
  data.accounts = data.accounts || [];
  data.accounts.push(newAccount);
  try { saveData(data); } catch (e) {
    return res.status(500).json({ error: 'Failed to save account' });
  }

  // Send invite email
  const appUrl  = process.env.APP_URL || 'https://managemystaffing.com';
  const link    = `${appUrl}/?invite=${token}`;
  const building = (data.buildings || []).find(b => b.id === targetBuilding);
  const bName   = building?.name || 'your facility';

  if (ACS_CONNECTION_STRING) {
    try {
      const { EmailClient } = require('@azure/communication-email');
      const ec = new EmailClient(ACS_CONNECTION_STRING);
      const poller = await ec.beginSend({
        senderAddress: ACS_FROM_EMAIL,
        recipients: { to: [{ address: emailNorm, displayName: name.trim() }] },
        content: {
          subject: 'You\'ve been invited to ManageMyStaffing',
          plainText: `Hi ${name.trim()},\n\nYou've been invited to manage ${bName} on ManageMyStaffing.\n\nClick the link below to set your password and get started:\n${link}\n\nThis invitation expires in 7 days.\n\nIf you didn't expect this invitation, you can safely ignore this email.\n\n— ManageMyStaffing`,
          html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;background:#f9fafb">
  <div style="background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
      <div style="width:36px;height:36px;background:#6B9E7A;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px">M</div>
      <span style="font-size:17px;font-weight:700;color:#111827">ManageMyStaffing</span>
    </div>
    <h2 style="font-size:20px;font-weight:700;color:#111827;margin:0 0 8px">You've been invited!</h2>
    <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Hi ${name.trim()}, you've been invited to manage <strong>${bName}</strong> on ManageMyStaffing.</p>
    <a href="${link}" style="display:inline-block;background:#6B9E7A;color:#fff;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:14px">Set Your Password &amp; Sign In →</a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0">This invitation expires in 7 days. If you didn't expect this, you can safely ignore this email.</p>
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
      // Account was created; warn about email but don't fail the request
      return res.json({ ok: true, accountId: newAccount.id, emailWarning: 'Account created but invite email failed: ' + e.message, inviteLink: link });
    }
  }

  console.log(`[mms] Invite sent to ${emailNorm} by ${req.user.email}`);
  res.json({ ok: true, accountId: newAccount.id, inviteLink: link });
});

// ── GET /api/invite/verify?token= ─────────────────────────────────────────────
app.get('/api/invite/verify', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'token is required' });
  const data = loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired. Please request a new one.' });
  }
  res.json({ ok: true, email: acct.email, name: acct.name, buildingId: acct.buildingId });
});

// ── POST /api/invite/accept ──────────────────────────────────────────────────
// Body: { token, passwordHash }
// Sets the account password and activates the account. Returns a JWT.
app.post('/api/invite/accept', (req, res) => {
  const { token, passwordHash } = req.body || {};
  if (!token || !passwordHash) return res.status(400).json({ error: 'token and passwordHash are required' });

  const data = loadData();
  const acct = (data.accounts || []).find(a => a.inviteToken === token);
  if (!acct) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (acct.inviteExpiry && Date.now() > acct.inviteExpiry) {
    return res.status(410).json({ error: 'This invitation has expired.' });
  }

  // Activate account
  acct.ph           = passwordHash;
  acct.inviteToken  = undefined;
  acct.inviteExpiry = undefined;
  acct.activatedAt  = new Date().toISOString();
  try { saveData(data); } catch (e) {
    return res.status(500).json({ error: 'Failed to activate account' });
  }

  const userPayload = {
    id: acct.id, name: acct.name, email: acct.email,
    role: acct.role, buildingId: acct.buildingId || null,
  };
  const jwtToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });
  console.log(`[mms] Invite accepted by ${acct.email}`);
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

// ── GET /api/pcc/census?date=YYYY-MM-DD ───────────────────────────────────────
app.get('/api/pcc/census', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({
      error: 'PCC not configured. Set PCC_CLIENT_ID, PCC_CLIENT_SECRET, PCC_FACILITY_ID (and optionally PCC_ORG_UUID) in Azure App Settings.',
    });
  }
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).replace(/[^0-9-]/g, '');
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;
    // PCC census endpoint — partner/v1 path (exact path may vary by partnership tier)
    const url  = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/census?censusDate=${date}`;
    const resp = await fetch(url, { headers });
    if (!resp.ok) {
      const txt = await resp.text();
      return res.status(502).json({ error: `PCC census API ${resp.status}: ${txt.slice(0, 300)}` });
    }
    const body = await resp.json();
    // Normalise across PCC API versions (partner/v1 vs older)
    const d = body.data || body;
    const census = d.totalCensus ?? d.occupiedBeds ?? d.census ?? null;
    res.json({
      ok:      true,
      census,
      date:    d.censusDate || date,
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

// ── GET /api/pcc/staffing?date=YYYY-MM-DD ────────────────────────────────────
// Returns total hours by staff type (rn/lpn/cna/cma/nm) for a single date from PCC.
// Maps PCC position codes/titles to MMS staff types using flexible regex matching.
app.get('/api/pcc/staffing', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({
      error: 'PCC not configured. Set PCC_CLIENT_ID, PCC_CLIENT_SECRET, PCC_FACILITY_ID in Azure App Settings.',
    });
  }
  const date = (req.query.date || new Date().toISOString().slice(0, 10)).replace(/[^0-9-]/g, '');
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;

    const url  = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/staffShifts?date=${date}`;
    const resp = await fetch(url, { headers });
    if (!resp.ok) {
      const txt = await resp.text();
      return res.status(502).json({ error: `PCC staffing API ${resp.status}: ${txt.slice(0, 300)}` });
    }
    const body   = await resp.json();
    const shifts = body.data || body.shifts || body || [];

    const hours = { rn: 0, lpn: 0, cna: 0, cma: 0, nm: 0 };
    for (const s of (Array.isArray(shifts) ? shifts : [])) {
      const hrs = parseFloat(s.workedHours ?? s.scheduledHours ?? s.hours ?? 0) || 0;
      const key = (s.positionCode || s.jobCode || s.position || '').toUpperCase();
      const ttl = (s.positionDesc || s.jobTitle || s.title || '').toUpperCase();
      const hay = key + ' ' + ttl;
      if (/\bRN\b|REGISTERED NURSE/.test(hay))                                     hours.rn  += hrs;
      else if (/\bLPN\b|\bLVN\b|LICENSED PRACTICAL|LICENSED VOCATIONAL/.test(hay)) hours.lpn += hrs;
      else if (/\bCNA\b|NURSE AID|NURSE ASSISTANT|CERTIFIED NURSING/.test(hay))    hours.cna += hrs;
      else if (/\bCMA\b|MED AIDE|MEDICATION AIDE|MEDICATION TECH/.test(hay))       hours.cma += hrs;
      else if (/DIRECTOR OF NURSING|\bDON\b|NURSE MANAGER|DIR OF NURS/.test(hay))  hours.nm  += hrs;
    }

    res.json({
      ok:     true,
      date,
      hours,
      rn24:   hours.rn >= 24,
      shifts: Array.isArray(shifts) ? shifts.length : 0,
    });
  } catch (e) {
    console.error('[mms] PCC staffing error:', e.message);
    res.status(502).json({ error: `PCC staffing request failed: ${e.message}` });
  }
});

// ── GET /api/pcc/staffing/range?start=YYYY-MM-DD&end=YYYY-MM-DD ──────────────
// Returns per-day hours + monthly averages (rn/lpn/cna/cma/nm) for CMS star calcs.
// Max range: 31 days.
app.get('/api/pcc/staffing/range', requireAuth, requireAdmin, async (req, res) => {
  if (!PCC_CLIENT_ID || !PCC_CLIENT_SECRET || !PCC_FACILITY_ID) {
    return res.status(503).json({ error: 'PCC not configured' });
  }
  const today  = new Date().toISOString().slice(0, 10);
  const start  = (req.query.start || today.slice(0, 8) + '01').replace(/[^0-9-]/g, '');
  const end    = (req.query.end   || today).replace(/[^0-9-]/g, '');
  const startMs = new Date(start).getTime();
  const endMs   = new Date(end).getTime();
  if (isNaN(startMs) || isNaN(endMs) || endMs < startMs || endMs - startMs > 32 * 86400000) {
    return res.status(400).json({ error: 'Invalid date range (max 31 days)' });
  }
  try {
    const token   = await getPCCToken();
    const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };
    if (PCC_ORG_UUID) headers['x-pcc-appkey'] = PCC_ORG_UUID;

    const url  = `${PCC_BASE}/partner/v1/facilities/${PCC_FACILITY_ID}/staffShifts?startDate=${start}&endDate=${end}`;
    const resp = await fetch(url, { headers });
    if (!resp.ok) {
      const txt = await resp.text();
      return res.status(502).json({ error: `PCC staffing range API ${resp.status}: ${txt.slice(0, 300)}` });
    }
    const body   = await resp.json();
    const shifts = body.data || body.shifts || body || [];

    // Aggregate per date
    const byDate = {};
    for (const s of (Array.isArray(shifts) ? shifts : [])) {
      const d   = (s.shiftDate || s.date || start).slice(0, 10);
      if (!byDate[d]) byDate[d] = { rn: 0, lpn: 0, cna: 0, cma: 0, nm: 0 };
      const hrs = parseFloat(s.workedHours ?? s.scheduledHours ?? s.hours ?? 0) || 0;
      const key = (s.positionCode || s.jobCode || s.position || '').toUpperCase();
      const ttl = (s.positionDesc || s.jobTitle || s.title || '').toUpperCase();
      const hay = key + ' ' + ttl;
      if (/\bRN\b|REGISTERED NURSE/.test(hay))                                     byDate[d].rn  += hrs;
      else if (/\bLPN\b|\bLVN\b|LICENSED PRACTICAL|LICENSED VOCATIONAL/.test(hay)) byDate[d].lpn += hrs;
      else if (/\bCNA\b|NURSE AID|NURSE ASSISTANT|CERTIFIED NURSING/.test(hay))    byDate[d].cna += hrs;
      else if (/\bCMA\b|MED AIDE|MEDICATION AIDE|MEDICATION TECH/.test(hay))       byDate[d].cma += hrs;
      else if (/DIRECTOR OF NURSING|\bDON\b|NURSE MANAGER|DIR OF NURS/.test(hay))  byDate[d].nm  += hrs;
    }

    const days = Object.keys(byDate).sort();
    const n    = days.length || 1;
    let totRn = 0, totLpn = 0, totCna = 0, totCma = 0, totNm = 0, rn24Days = 0;
    for (const d of days) {
      const r = byDate[d];
      totRn  += r.rn;  totLpn += r.lpn; totCna += r.cna;
      totCma += r.cma; totNm  += r.nm;
      if (r.rn >= 24) rn24Days++;
    }

    res.json({
      ok:           true,
      start, end,
      daysInPeriod: n,
      rn24Days,
      avgDaily: {
        rn:      +(totRn  / n).toFixed(2),
        lpn:     +(totLpn / n).toFixed(2),
        cna:     +(totCna / n).toFixed(2),
        cma:     +(totCma / n).toFixed(2),
        nm:      +(totNm  / n).toFixed(2),
        nursing: +((totRn + totLpn + totCna + totCma + totNm) / n).toFixed(2),
      },
      byDate,
    });
  } catch (e) {
    console.error('[mms] PCC staffing range error:', e.message);
    res.status(502).json({ error: `PCC staffing range failed: ${e.message}` });
  }
});

// ── GET /jobs.xml — public XML job feed (Indeed / LinkedIn job crawler format) ─
app.get('/jobs.xml', (_req, res) => {
  try {
    const data = loadData();
    const jobs = (data.jobPostings || []).filter(j => j.status === 'active');
    const baseUrl = process.env.APP_URL || 'https://managemystaffing.com';
    const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const items = jobs.map(j => `  <job>
    <id><![CDATA[${j.id}]]></id>
    <title><![CDATA[${esc(j.title)}]]></title>
    <company><![CDATA[ManageMyStaffing]]></company>
    <city><![CDATA[${esc(j.city || '')}]]></city>
    <state><![CDATA[${esc(j.state || '')}]]></state>
    <country>US</country>
    <postalcode><![CDATA[${esc(j.zip || '')}]]></postalcode>
    <date>${(j.createdAt || '').slice(0, 10)}</date>
    <reqid>${esc(j.id)}</reqid>
    <jobtype><![CDATA[${esc(j.jobType || 'Full-time')}]]></jobtype>
    <category><![CDATA[${esc(j.department || 'Healthcare')}]]></category>
    <description><![CDATA[${esc(j.description || '')}]]></description>
    <salary><![CDATA[${esc(j.salary || '')}]]></salary>
    <url><![CDATA[${baseUrl}/#job-${j.id}]]></url>
  </job>`).join('\n');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<source>
  <publisher>ManageMyStaffing</publisher>
  <publisherurl>${baseUrl}</publisherurl>
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

// ── GET /api/jobs — public job listing (for external embeds / sharing) ────────
app.get('/api/jobs', (_req, res) => {
  try {
    const data = loadData();
    const jobs = (data.jobPostings || []).filter(j => j.status === 'active')
      .map(({ id, title, department, jobType, city, state, salary, description, createdAt }) =>
        ({ id, title, department, jobType, city, state, salary, description, createdAt }));
    res.json({ jobs });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load jobs' });
  }
});

// ── POST /api/alert ───────────────────────────────────────────────────────────
// Body: { groups, message, subject, viaSMS, viaEmail, buildingId }
// Sends real emails + SMS via Azure Communication Services.
function toE164(raw) {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, '');
  if (d.length === 10) return '+1' + d;
  if (d.length === 11 && d[0] === '1') return '+' + d;
  return null;
}

app.post('/api/alert', requireAuth, requireAdmin, async (req, res) => {
  const { groups, message, subject, viaSMS, viaEmail, buildingId } = req.body || {};
  if (!Array.isArray(groups) || !groups.length)
    return res.status(400).json({ error: 'groups array is required' });
  if (!message) return res.status(400).json({ error: 'message is required' });

  const data = loadData();
  const employees = (data.employees || []).filter(e =>
    groups.includes(e.group) &&
    (!buildingId || e.buildingId === buildingId) &&
    !e.inactive
  );

  const emailList = viaEmail ? employees.filter(e => e.notifEmail && e.email) : [];
  const smsList   = viaSMS   ? employees.filter(e => e.notifSMS  && e.phone)  : [];

  let emailSent = 0, smsSent = 0;
  const errors = [];

  if (!ACS_CONNECTION_STRING) {
    errors.push('Messaging not configured (missing ACS_CONNECTION_STRING)');
  } else {

    // ── Email via Azure Communication Services ──────────────────────────────
    if (emailList.length) {
      const { EmailClient } = require('@azure/communication-email');
      const emailClient = new EmailClient(ACS_CONNECTION_STRING);
      const EMAIL_TIMEOUT_MS = 30000; // 30-second per-email timeout
      for (const emp of emailList) {
        try {
          const body = message.replace(/\[Name\]/g, emp.name);
          const poller = await emailClient.beginSend({
            senderAddress: ACS_FROM_EMAIL,
            recipients: { to: [{ address: emp.email, displayName: emp.name }] },
            content: {
              subject: subject || 'Alert from ManageMyStaffing',
              plainText: body,
              html: `<pre style="font-family:sans-serif;white-space:pre-wrap">${body.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre>`,
            },
          });
          // Race the poller against a hard timeout so Express route never hangs
          await Promise.race([
            poller.pollUntilDone(),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('Email send timed out after 30s')), EMAIL_TIMEOUT_MS)
            ),
          ]);
          emailSent++;
        } catch (e) {
          console.error('[mms] ACS email error for', emp.email, e.message);
          errors.push(`Email to ${emp.name}: ${e.message}`);
        }
      }
    }

    // ── SMS via Azure Communication Services ────────────────────────────────
    if (smsList.length) {
      if (!ACS_FROM_PHONE) {
        errors.push('SMS not configured (missing ACS_FROM_PHONE)');
      } else {
        const { SmsClient } = require('@azure/communication-sms');
        const smsClient = new SmsClient(ACS_CONNECTION_STRING);
        for (const emp of smsList) {
          const to = toE164(emp.phone);
          if (!to) { errors.push(`SMS to ${emp.name}: invalid phone ${emp.phone}`); continue; }
          try {
            // to field is string[] per @azure/communication-sms v1.x API
            const results = await smsClient.send({
              from: ACS_FROM_PHONE,
              to: [to],
              message: message.replace(/\[Name\]/g, emp.name).slice(0, 1600),
            });
            if (results[0]?.successful) smsSent++;
            else errors.push(`SMS to ${emp.name}: ${results[0]?.errorMessage || 'failed'}`);
          } catch (e) {
            console.error('[mms] ACS SMS error for', emp.phone, e.message);
            errors.push(`SMS to ${emp.name}: ${e.message}`);
          }
        }
      }
    }
  }

  console.log(`[mms] Alert by ${req.user.email}: ${emailSent} emails, ${smsSent} SMS`);
  res.json({ ok: true, emailSent, smsSent, errors });
});

// ── POST /api/demo/message ────────────────────────────────────────────────────
// Sends a direct email message to a demo prospect. Super admin only.
// Body: { to, name, subject, message }
app.post('/api/demo/message', requireAuth, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'superadmin only' });
  const { to, name, subject, message } = req.body || {};
  if (!to || !message) return res.status(400).json({ error: 'to and message are required' });

  if (!ACS_CONNECTION_STRING || !ACS_FROM_EMAIL) {
    return res.status(503).json({ error: 'Email not configured — set ACS_CONNECTION_STRING and ACS_FROM_EMAIL' });
  }

  const { EmailClient } = require('@azure/communication-email');
  const emailClient = new EmailClient(ACS_CONNECTION_STRING);

  const htmlBody = message
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>');

  const sendPromise = emailClient.beginSend({
    senderAddress: ACS_FROM_EMAIL,
    recipients: { to: [{ address: to, displayName: name || to }] },
    content: {
      subject: subject || 'Message from ManageMyStaffing',
      plainText: message,
      html: `<div style="font-family:sans-serif;font-size:14px;color:#111">${htmlBody}</div>`,
    },
  }).then(p => p.pollUntilDone());

  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000));

  Promise.race([sendPromise, timeout])
    .then(() => {
      console.log(`[mms] Demo message sent to ${to}`);
      res.json({ ok: true });
    })
    .catch(err => {
      console.error('[mms] Demo message error:', err.message);
      res.status(500).json({ error: 'Failed to send message', detail: err.message });
    });
});

// ── START ─────────────────────────────────────────────────────────────────────
// Ensure data file exists on startup
try { loadData(); } catch (e) { process.exit(1); }

// Warn about missing messaging configuration at startup
if (!ACS_CONNECTION_STRING) console.warn('[mms] WARN: ACS_CONNECTION_STRING not set — email/SMS alerts disabled');
if (!ACS_FROM_PHONE)        console.warn('[mms] WARN: ACS_FROM_PHONE not set — SMS alerts disabled');

app.listen(PORT, () => {
  console.log(`[mms] ManageMyStaffing running on http://localhost:${PORT}`);
  console.log(`[mms] Data file: ${DATA_FILE}`);
  console.log(`[mms] Messaging: ACS=${!!ACS_CONNECTION_STRING} Email=${!!ACS_FROM_EMAIL} SMS=${!!ACS_FROM_PHONE}`);
  console.log(`[mms] PCC integration: ${PCC_CLIENT_ID && PCC_CLIENT_SECRET && PCC_FACILITY_ID ? `ENABLED (facilityId=${PCC_FACILITY_ID})` : 'not configured'}`);
});
