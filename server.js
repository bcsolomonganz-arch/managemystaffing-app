'use strict';
require('dotenv').config();

const express  = require('express');
const jwt      = require('jsonwebtoken');
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
  // Ensure seed accounts always exist and up-to-date (migration for existing data files)
  if (!Array.isArray(data.accounts)) data.accounts = [];
  let dirty = false;
  for (const seed of [SEED_SA, SEED_DEMO]) {
    const existing = data.accounts.find(a => a.id === seed.id);
    if (!existing) {
      data.accounts.push(seed);
      dirty = true;
      console.log(`[mms] Seeded missing account: ${seed.email}`);
    } else if (existing.email !== seed.email) {
      // Email changed in seed — update the stored record
      existing.email = seed.email;
      dirty = true;
      console.log(`[mms] Updated email for account ${seed.id}: ${seed.email}`);
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
  try {
    saveData(payload);
    res.json({ ok: true });
  } catch (e) {
    console.error('[mms] Failed to save data:', e.message);
    res.status(500).json({ error: 'Failed to save data' });
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
});
