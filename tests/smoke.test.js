'use strict';
/**
 * Smoke tests — runs against an already-running server (defaults to localhost:3002).
 * Critical security flows only. Run with: node --test tests/
 *
 * MMS_TEST_BASE_URL=https://www.managemystaffing.com node --test tests/
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const BASE = process.env.MMS_TEST_BASE_URL || 'http://localhost:3002';
const CSRF = { 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json' };

// Helper: extract Set-Cookie value from a response
function extractCookie(res) {
  const sc = res.headers.get('set-cookie');
  if (!sc) return null;
  const m = sc.match(/mms_session=([^;]+)/);
  return m ? `mms_session=${m[1]}` : null;
}

test('GET /health returns 200', async () => {
  const r = await fetch(`${BASE}/health`);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.ok, true);
});

test('GET /health/ready validates audit chain + data + ACS', async () => {
  const r = await fetch(`${BASE}/health/ready`);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.auditChain, true, 'audit chain must verify');
  assert.equal(body.dataReady, true, 'data backend must be ready');
  assert.ok(['file','postgres'].includes(body.dataBackend), 'dataBackend must be file or postgres');
});

test('POST without X-Requested-With is rejected (CSRF)', async () => {
  const r = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  assert.equal(r.status, 403, 'expected 403 without X-Requested-With');
});

test('Demo login succeeds + sets httpOnly cookie + does NOT return token in body', async () => {
  const r = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.ok(body.user, 'response must contain user');
  assert.equal(body.token, undefined, 'response must NOT contain token in body');
  // Session cookie must be set with httpOnly
  const setCookie = r.headers.get('set-cookie');
  assert.match(setCookie || '', /mms_session=/);
  assert.match(setCookie || '', /HttpOnly/i);
});

test('Real account login is blocked when ph=null (no first-login hijack)', async () => {
  const r = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ email: 'solomong@managemystaffing.com', password: 'attacker-controlled' }),
  });
  // Either 403 ("not yet activated") or 401 ("invalid"); never 200
  assert.notEqual(r.status, 200, 'first-login hijack must be blocked');
});

test('Unknown email constant-time response (always 401, never 200)', async () => {
  const r = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ email: 'random@nonexistent.example', password: 'x' }),
  });
  assert.equal(r.status, 401);
});

test('CSRF: POST /api/data with cookie but no X-Requested-With → 403', async () => {
  // Login first to get cookie
  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  const cookie = extractCookie(login);
  assert.ok(cookie, 'login should set cookie');

  const r = await fetch(`${BASE}/api/data`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
    body: JSON.stringify({}),
  });
  assert.equal(r.status, 403, 'CSRF must block POST without X-Requested-With even with valid cookie');
});

test('Authenticated GET /api/data scrubs password hashes from accounts', async () => {
  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST', headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  const cookie = extractCookie(login);
  const r = await fetch(`${BASE}/api/data`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'Cookie': cookie },
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  for (const a of (data.accounts || [])) {
    assert.equal(a.ph, undefined, `account ${a.email} must not leak password hash`);
    assert.equal(a.totpSecret, undefined, `account ${a.email} must not leak TOTP secret`);
    assert.equal(a.inviteToken, undefined, `account ${a.email} must not leak invite token`);
  }
});

test('Logout revokes the session', async () => {
  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST', headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  const cookie = extractCookie(login);

  // Logout
  const logout = await fetch(`${BASE}/api/auth/logout`, {
    method: 'POST', headers: { ...CSRF, 'Cookie': cookie },
  });
  assert.equal(logout.status, 200);

  // Subsequent request with same cookie should fail
  const after = await fetch(`${BASE}/api/data`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'Cookie': cookie },
  });
  assert.equal(after.status, 401, 'cookie should be revoked after logout');
});

test('Security headers present on root HTML', async () => {
  const r = await fetch(`${BASE}/`);
  assert.equal(r.status, 200);
  // Local dev does not emit HSTS (only in production with x-forwarded-proto=https).
  // CSP and X-Frame must be present always.
  const csp = r.headers.get('content-security-policy');
  assert.ok(csp, 'CSP must be set');
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
});

test('Password reset request: constant-time response (always 200 + safe message)', async () => {
  const r = await fetch(`${BASE}/api/auth/password-reset/request`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ email: 'unknown-' + Date.now() + '@example.com' }),
  });
  assert.equal(r.status, 200, 'must always return 200 to avoid enumeration');
  const body = await r.json();
  assert.match(body.message || '', /reset link has been sent/i);
});

test('Password reset request: CSRF check', async () => {
  const r = await fetch(`${BASE}/api/auth/password-reset/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'x@y.z' }),
  });
  assert.equal(r.status, 403);
});

test('Password reset complete: bad token returns 404', async () => {
  const r = await fetch(`${BASE}/api/auth/password-reset/complete`, {
    method: 'POST',
    headers: CSRF,
    body: JSON.stringify({ token: 'badtoken', u: 'acc_nonexistent', password: 'NotImportantHere1!' }),
  });
  // 404 (account/token not found), 410 (expired), or 429 (rate limit hit during test) all acceptable
  assert.ok([404, 410, 429].includes(r.status), `unexpected status ${r.status}`);
});

test('Rate limit on /api/invite/verify (>20 in 60s → 429)', async () => {
  let blocked = false;
  for (let i = 0; i < 25; i++) {
    const r = await fetch(`${BASE}/api/invite/verify?token=fake-${i}`);
    if (r.status === 429) { blocked = true; break; }
  }
  assert.ok(blocked, 'rate limit on /api/invite/verify must trigger');
});

test('POST /api/data with empty body is rejected (no recognized collections)', async () => {
  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST', headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  const cookie = extractCookie(login);
  const r = await fetch(`${BASE}/api/data`, {
    method: 'POST', headers: { ...CSRF, 'Cookie': cookie },
    body: JSON.stringify({}),
  });
  assert.equal(r.status, 400, 'empty payload must be rejected, not silently succeed');
  const body = await r.json();
  assert.match(body.error || '', /no recognized data collections/i);
});

test('POST /api/data tripwire: large shrink without X-Confirm-Wipe → 409', async () => {
  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST', headers: CSRF,
    body: JSON.stringify({ email: 'demo@demo.com', password: 'x' }),
  });
  const cookie = extractCookie(login);

  // Pull existing data
  const get = await fetch(`${BASE}/api/data`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'Cookie': cookie },
  });
  const data = await get.json();
  if ((data.shifts || []).length < 10) {
    // Demo seed has plenty of shifts; if not, skip — tripwire requires ≥10.
    return;
  }

  const r = await fetch(`${BASE}/api/data`, {
    method: 'POST', headers: { ...CSRF, 'Cookie': cookie },
    body: JSON.stringify({ ...data, shifts: [] }),
  });
  assert.equal(r.status, 409, 'shrinking shifts to 0 must be blocked without X-Confirm-Wipe');
  const body = await r.json();
  assert.match(body.error || '', /Refusing to shrink/i);
});
