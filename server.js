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

// ── SUPER-ADMIN SEED ACCOUNT ─────────────────────────────────────────────────
const SEED_SA = {
  id: 'sa0',
  name: 'Ben Solomon',
  email: 'solomong@managemycensus.com',
  role: 'superadmin',
  buildingId: null,
  ph: null   // ph:null = any password on first login becomes permanent
};

// ── ATOMIC FILE WRITE ─────────────────────────────────────────────────────────
function writeAtomic(filePath, data) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

// ── LOAD OR INITIALIZE DATA FILE ─────────────────────────────────────────────
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = { accounts: [SEED_SA] };
    writeAtomic(DATA_FILE, initial);
    console.log(`[mms] Created data file at ${DATA_FILE} with seed super-admin.`);
    return initial;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    console.error('[mms] Failed to parse data file:', e.message);
    throw e;
  }
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
  res.json({ ok: true, mode: 'production' });
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

  if (acct.ph === null || acct.ph === undefined) {
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

// ── START ─────────────────────────────────────────────────────────────────────
// Ensure data file exists on startup
try { loadData(); } catch (e) { process.exit(1); }

app.listen(PORT, () => {
  console.log(`[mms] ManageMyStaffing running on http://localhost:${PORT}`);
  console.log(`[mms] Data file: ${DATA_FILE}`);
});
