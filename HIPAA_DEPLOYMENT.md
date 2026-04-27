# ManageMyStaffing — HIPAA Production Deployment Guide

This document captures everything needed to take MMS from its current hardened state to a fully HIPAA-compliant production deployment. **Code-side hardening is complete.** Infrastructure work below MUST be completed by a qualified DevOps/security engineer before storing real PHI.

---

## ✅ Code-side fixes already applied

### Authentication & sessions
- TOTP (RFC 6238) required for all non-demo accounts; QR-code enrollment on first login
- Account lockout: 5 failed password attempts → 30-min lockout
- Server-side password complexity (12 chars + upper + lower + number + symbol)
- First-login hijack closed: `ph === null` accounts MUST redeem invite token
- Demo accounts disabled when `NODE_ENV=production`
- JWT TTL reduced 8h → 1h
- Server-enforced 15-min idle timeout (revokes token on inactive session)
- Client-side 15-min idle auto-logout
- Constant-time login (dummy bcrypt for unknown emails)
- IP rate limit on `/api/auth/login` (10 / 15 min) and `/api/invite/verify` (20 / min)

### Authorization
- `POST /api/data` now does per-collection MERGE with building-scoped authz, not wholesale replace. Admins cannot:
  - Modify entities outside their building(s)
  - Modify seed accounts (SA, demo)
  - Escalate their own role
  - Remove TOTP secrets from any account
- `POST /api/sms` only allows phones present on caller's building roster
- `POST /api/alert` only allows caller's building(s)

### Audit log (HIPAA §164.312(b))
- Append-only file at `mms-audit.log` (mode 0600)
- HMAC-SHA256 chain — each entry includes `prevHash`; tampering with any entry breaks the chain
- `verifyAuditChain()` exposed via `/health/ready`
- Captures: LOGIN_SUCCESS / LOGIN_FAILED / LOGIN_BLOCKED_LOCKED / ACCOUNT_LOCKED / TOTP_ENROLLED / TOTP_FAILED / SESSION_IDLE_TIMEOUT / DATA_ACCESS / DATA_UPDATE / INVITE_SENT / INVITE_RESENT / INVITE_ACCEPTED / SMS_SENT / SMS_BLOCKED / ALERT_SENT / DEMO_MSG_SENT / LOGOUT

### Network / transport
- Helmet CSP hardened: `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`
- HSTS: 2 years + includeSubDomains + preload
- HTTP→HTTPS redirect when `NODE_ENV=production`
- `app.set('trust proxy', 1)` so rate limiter keys on real client IP
- CORS allow-list: only `APP_URL` in production
- `X-Powered-By` removed
- Body limit reduced 50mb → 1mb
- Per-request `X-Request-Id` for log correlation

### Email & SMS
- Invite email body HTML-escapes user-controlled `name` and building name (was raw injection)
- CRLF stripped from plaintext email name fields
- New domain `managemystaffing.com` configured in Azure ACS Email with verified SPF, DKIM, DKIM2, DMARC records
- Sender username `noreply@managemystaffing.com` registered with display name "ManageMyStaffing"

### Operational
- Structured JSON logging (level + ts + msg + meta)
- `/health/ready` deep probe (data file + audit chain + ACS config)
- Graceful SIGTERM/SIGINT shutdown — flushes data + audit queue before exit
- Uncaught exception handler that triggers shutdown
- Stack traces hidden from clients in production
- Refuses to start if `DATA_ENCRYPTION_KEY` is wrong length, `JWT_SECRET` is too short, or data file path contains "OneDrive" in production
- Refuses to start if `AUDIT_HMAC_KEY` is missing
- Bootstrap invite link auto-printed to console on first install or `RESET_SA_PASSWORD=1`
- `RESET_SA_PASSWORD=1` flow now forces TOTP re-enrollment

### Client-side
- TOTP enrollment modal with QR code + manual secret display
- TOTP verification modal for subsequent logins
- 15-min idle timer that auto-logs out
- `sanitizeColor()` allow-list applied to building card color interpolation (XSS hardening)
- Password complexity matched server-side rules in invite-accept flow
- Invite-accept no longer auto-issues a token — forces login + TOTP enrollment

---

## ⚠️ Infrastructure work required for HIPAA production

These cannot be done in code; they require provisioning and operational decisions.

### 🔴 IMMEDIATE (before storing real PHI)

#### 1. Move `.env` off OneDrive
The current `.env` lives at `C:\Users\bcsol\OneDrive\AI Folder\ManageMyStaffing\.env`. OneDrive sync exposes the encryption key + audit HMAC key + ACS access key to anyone with OneDrive access. **The encryption key sitting next to the encrypted data file makes the encryption useless against anyone with file access.**

```bash
# Move the entire app off OneDrive to a local-only directory
# In production this is moot — secrets live in Key Vault, not .env
```

#### 2. Rotate the remaining secrets (ACS already rotated)
```bash
# Generate fresh secrets:
node -e 'console.log("JWT_SECRET=" + require("crypto").randomBytes(48).toString("base64"))'
node -e 'console.log("DATA_ENCRYPTION_KEY=" + require("crypto").randomBytes(32).toString("hex"))'
node -e 'console.log("AUDIT_HMAC_KEY=" + require("crypto").randomBytes(32).toString("hex"))'

# To rotate DATA_ENCRYPTION_KEY in place (re-encrypts data file):
OLD_DATA_ENCRYPTION_KEY=<current> NEW_DATA_ENCRYPTION_KEY=<new> node rotate-data-key.js
```

⚠️ Rotating `JWT_SECRET` invalidates all current sessions (users will need to re-login).
⚠️ Rotating `AUDIT_HMAC_KEY` breaks the chain of existing entries — only do at deployment time when audit log is empty/archived.

#### 3. Sign Microsoft HIPAA BAA
Azure Communication Services is HIPAA-eligible **only when covered by a Business Associate Agreement**. Without a signed BAA, sending PHI through ACS Email is a HIPAA violation.

→ Visit Microsoft 365 admin center → Security & Privacy → Service Trust → Sign HIPAA BAA. Confirm ACS is in the eligible-services scope.

#### 4. Stop sending PHI via SMS
SMS is **never encrypted in transit by carriers**. HIPAA prohibits sending PHI over unencrypted channels. Audit every SMS template for patient-identifiable information. Recommend: SMS only for non-PHI ("You have a new shift to claim — sign in to view") and PHI inside the authenticated app only.

#### 5. Migrate to Azure Key Vault
Replace `.env` for all secrets in production:
```js
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');
const client = new SecretClient(`https://<vault>.vault.azure.net`, new DefaultAzureCredential());
const jwtSecret = (await client.getSecret('JWT_SECRET')).value;
```
Use Azure Managed Identity on App Service so no credentials live in code.

### 🟠 BEFORE SCALING TO MULTI-INSTANCE

#### 6. Migrate to Azure Database for PostgreSQL
The file-based encrypted JSON store **breaks with >1 instance** (race conditions, no transactions). Schema sketch:

```sql
CREATE TABLE accounts (
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  role TEXT NOT NULL, building_id TEXT, building_ids TEXT[],
  password_hash TEXT, totp_secret TEXT, totp_enrolled_at TIMESTAMPTZ,
  failed_attempts INT DEFAULT 0, locked_until TIMESTAMPTZ,
  invite_token TEXT, invite_expiry TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE buildings (id TEXT PRIMARY KEY, name TEXT, address TEXT, color TEXT, beds INT, company_id TEXT);
CREATE TABLE employees (id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, building_id TEXT, "group" TEXT, employment_type TEXT, inactive BOOL);
CREATE TABLE shifts (id TEXT PRIMARY KEY, date DATE, type TEXT, "group" TEXT, building_id TEXT, employee_id TEXT, status TEXT, claim_request JSONB);
CREATE INDEX shifts_date_building ON shifts(date, building_id);
-- Row-Level Security on building_id for tenant isolation
ALTER TABLE employees ENABLE ROW LEVEL SECURITY;
CREATE POLICY emp_tenant ON employees USING (building_id = ANY(current_setting('app.building_ids')::text[]));
```

Replace `loadData/persistCache` with parameterized SQL. Use a connection pool (`pg` driver). Use a transaction per write.

#### 7. Move audit log to Azure Storage with WORM (immutable blob)
File-based audit log on App Service local disk is not durable across restarts/scaling. Stream entries to an Azure Storage container with a **legal hold or time-based retention policy** (≥6 years per HIPAA §164.530(j)). Continue HMAC-chaining each entry.

#### 8. Move `revokedTokens` and `lastActivity` to Redis
Currently in-memory `Set` and `Map` — lost on restart, not shared between instances. Use Azure Cache for Redis with TTL = JWT exp.

#### 9. Move alert/email send to a queue
`/api/alert` synchronously loops `await poller.pollUntilDone()` per recipient — at 500 employees this exceeds App Service's 230s timeout. Push job to Azure Service Bus, return 202 + jobId. Worker process handles delivery with retry/backoff.

### 🟡 OPERATIONAL ESSENTIALS

#### 10. Application Insights / Sentry
Wire pino → Application Insights for log retention; Sentry for exception tracking. Required for §164.308(a)(1)(ii)(D) Information System Activity Review.

#### 11. Backup + DR
- DB: Postgres geo-redundant backups + point-in-time restore
- Audit log: Azure Storage with versioning + soft-delete (180 days) + read-only retention
- Document RTO ≤ 4h, RPO ≤ 1h in the contingency plan (§164.308(a)(7))

#### 12. TLS termination
Behind Azure App Service / Front Door — both terminate TLS automatically. Confirm `X-Forwarded-Proto: https` is set so the in-app redirect works.

#### 13. Microsoft Sender Reputation
Submit `managemystaffing.com` at https://sendersupport.olc.protection.outlook.com/pm/ — Microsoft 365 / Outlook will junk emails from new domains until reputation builds.

#### 14. Toll-free verification (TFV) for SMS
Already submitted; pending Microsoft review. Until verified, US carriers will block SMS from `+18556682831`.

---

## Required environment variables

```bash
# Core (all required, server refuses to start without them)
PORT=3002
NODE_ENV=production
JWT_SECRET=<48+ random bytes base64>
DATA_ENCRYPTION_KEY=<32-byte hex>
AUDIT_HMAC_KEY=<32-byte hex>
DATA_FILE=/var/lib/mms/mms-data.json    # NOT in OneDrive
APP_URL=https://managemystaffing.com

# Azure ACS
ACS_CONNECTION_STRING=endpoint=https://...;accesskey=...
ACS_FROM_EMAIL=noreply@managemystaffing.com
ACS_FROM_PHONE=+18556682831

# PCC (optional)
PCC_CLIENT_ID=...
PCC_CLIENT_SECRET=...
PCC_FACILITY_ID=...
PCC_ORG_UUID=...

# Optional
AUDIT_LOG_FILE=/var/lib/mms/mms-audit.log
RESET_SA_PASSWORD=1   # one-time: prints invite link to console
```

---

## HIPAA scorecard after fixes

| Safeguard | Code | Infra | Status |
|---|---|---|---|
| §164.312(a)(1) — Unique user ID + password | ✓ | — | ✅ |
| §164.312(a)(1) — Encryption at rest | ✓ | needs Key Vault | ⚠️ |
| §164.312(a)(1) — Encryption in transit | ✓ HSTS+redirect | needs TLS at edge | ⚠️ |
| §164.312(a)(1) — Automatic logoff | ✓ 15 min | — | ✅ |
| §164.312(a)(1) — Emergency access | — | needs ops procedure | ❌ |
| §164.312(b) — Audit controls (HMAC chain) | ✓ | needs WORM storage | ⚠️ |
| §164.312(c) — Integrity | ✓ per-entity authz | needs DB | ⚠️ |
| §164.312(d) — Authentication (TOTP) | ✓ | — | ✅ |
| §164.312(d) — Lockout / complexity | ✓ | — | ✅ |
| §164.312(e) — SMS PHI | — | **ban PHI in SMS** | ❌ |
| §164.308(a)(4) — Write authz | ✓ | — | ✅ |
| §164.308(a)(5) — Password reqs | ✓ | — | ✅ |
| §164.308(a)(6) — Incident detection | ✓ audit + lockout | needs alerting | ⚠️ |
| §164.308(a)(7) — Backup/DR | — | needs DB + Storage | ❌ |
| §164.314(a) — BAA with Azure | — | **must sign** | ❌ |
| §164.530(j) — 6-year retention | ✓ append-only | needs WORM | ⚠️ |

**Verdict: After completing items 1–9 above, MMS will be production-ready for HIPAA workloads.** Items 10–14 are operational essentials that should be in place before clinical go-live.
