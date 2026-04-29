# ManageMyStaffing — PointClickCare Partner Security Review

**Vendor**: ManageMyStaffing
**Application**: ManageMyStaffing — staff scheduling, recruiting, time-clock, and PPD analytics for SNF and LTC facilities
**Public URL**: https://www.managemystaffing.com
**Audit endpoint** (read-only, no secrets): `GET /api/healthz/deep`
**Repository**: https://github.com/bcsolomonganz-arch/managemystaffing-app
**Primary contact**: Ben Solomon — ganzsolomon@managecensus.com

---

## A. Architecture & Data Flow

**1. Briefly describe your application and intended use of PointClickCare data.**
ManageMyStaffing is a Node.js / Express + Postgres SaaS application used by skilled-nursing and long-term-care facilities for staff scheduling, time-clock administration, recruiting, alerts, and CMS Five-Star PPD analytics. From PointClickCare we read **census** (occupied beds per day) and **staffing hours** (scheduled and worked nursing hours, by position). We do not write back to PCC, do not touch resident-level clinical or financial records, and do not retain any PCC payload longer than the in-memory request lifecycle.

**2. Hosting environment.**
Microsoft Azure, **East US** region, Azure App Service Plan (Linux containers, Node 20 LTS). Postgres Flexible Server (single primary, geo-redundant backups). Azure Storage (immutable Blob audit log container with time-based retention policy). Azure Key Vault for all secret material. Azure Application Insights for telemetry.

**3. Data classification.**
- **In transit from PCC → us**: census aggregates (number of occupied beds per day) and staffing aggregates (worked / scheduled hours by position class). No PII or PHI of individual residents.
- **At rest in our system**: aggregated census and aggregated hours. No resident-identifying data.
- **Our other PHI (employee PII, schedules, time-clock punches)** is encrypted at rest with AES-256-GCM and is unrelated to PCC.

**4. PCC API endpoints used.**
- `POST /auth/token` (OAuth2 client_credentials)
- `GET /partner/v1/facilities/{id}/census`
- `GET /partner/v1/facilities/{id}/staffShifts`

No others. We do not call `/residents`, `/clinicalAssessments`, or any patient-data endpoints.

---

## B. Authentication & Token Management

**5. How is the OAuth client_secret stored?**
In Azure Key Vault. App Service references it via `@Microsoft.KeyVault(VaultName=...;SecretName=...)` syntax. Never appears in source, build artifacts, or logs. Local dev uses a `.env` file that is `.gitignore`d.

**6. Token caching strategy.**
In-memory only. Cached until 60 seconds before `expires_in`, then refreshed. Concurrent requests during refresh are **promise-serialized** (`_pccTokenInflight`) so we never issue parallel auth requests.

**7. What happens on 401?**
Single retry: invalidate the cached token, refresh once, replay the original request. Implemented in `pccFetch()` in `server.js`. No infinite retry loop.

**8. What happens on 429?**
We honor the `Retry-After` header (numeric or HTTP-date format). If the wait would exceed 30 seconds, we return the 429 to the caller. No backoff loop exceeds 3 attempts.

**9. What happens on 5xx?**
Exponential backoff: 50ms, 100ms, 200ms, max 3 attempts. After exhaustion we return a clean 502 to the API caller.

**10. Are network calls timeouts enforced?**
Yes. `AbortController` on every PCC fetch. 10s on `/auth/token`, 15s on data endpoints.

**11. `x-pcc-appkey` header on every request?**
Yes, when `PCC_ORG_UUID` is configured.

---

## C. PHI Handling

**12. What PCC data is logged?**
Only **status codes** for upstream errors (e.g., `pcc_census_failed { status: 502 }`). We never write the response body, the request URL with query string, or the Authorization header to any log. Verified by code review: see `pccFetch()` and `_logger` callsites.

**13. Resident-level data retained?**
No. We only consume aggregate endpoints. If we ever pulled a resident-level endpoint (we do not), that data would not be persisted in our database.

**14. PHI in SMS / email?**
Defense in depth:
- Outbound SMS bodies are scanned by `scanMessageForPHI()` before send. Detects SSN patterns, dates of birth, MRN-style IDs, and employee full-name + phone matches. SMS is blocked if a match is found, with a HIPAA §164.312(e) audit entry.
- Outbound email is HTML-escaped (`escapeHtml()` → covers `<`, `>`, `&`, `"`, `'`) on every interpolated user-controlled field.

**15. Audit trail of access.**
Every read of PHI by any user (including us, the operators) is logged to a tamper-evident HMAC chain (SHA-256 with `prevHash` linkage). Audit entries include `userId`, `email` (operator), `action`, `role`, `timestamp`, and a per-entry HMAC. The chain is verified on application boot — a tampered entry stops the service.

---

## D. Data Storage & Encryption

**16. Encryption at rest?**
- **Postgres**: TDE (Transparent Data Encryption) at the storage layer (Azure default). Plus our own AES-256-GCM at the application layer for the file-based fallback (`mms-data.json`).
- **Audit log**: AES-256-GCM and HMAC-SHA-256 chain.
- **Backups**: Azure managed backups, encrypted, geo-redundant.

**17. Encryption in transit?**
- All HTTP traffic forced to HTTPS (Azure Front Door enforces TLS 1.2+).
- HSTS header with `max-age=63072000; includeSubDomains; preload`.
- Internal service-to-service traffic on Azure VNet, also TLS.
- Cookies marked `Secure`, `HttpOnly`, `SameSite=Strict`.

**18. Key management.**
- All secrets in Azure Key Vault.
- Soft-delete + purge protection enabled.
- Access-policy-based; only the App Service Managed Identity can read.
- Key rotation tooling: `rotate-data-key.js` re-encrypts the at-rest data file with a new key.

**19. Data residency.**
US East. Postgres geo-redundant backup secondary in US West. No data leaves the US.

---

## E. Identity & Access Management

**20. User authentication.**
- bcrypt cost 12 password hashes.
- Password complexity for admin / SA: ≥12 chars + upper + lower + digit + special.
- Password complexity for employee: ≥8 chars (employees do not access PHI; HIPAA §164.312 doesn't require complexity).
- Account lockout after 5 failed attempts; 30-minute lockout window.
- Constant-time login: dummy bcrypt run on unknown emails to prevent timing-based account enumeration.

**21. Multi-factor authentication.**
- TOTP (RFC 6238) required on every privileged account (admin / superadmin / regional).
- Single-use recovery codes (10 generated at enrollment, bcrypt cost 12).
- TOTP secret stored encrypted at rest.
- Trusted-device cookie: 30-day TTL, account-bound, JWT-signed. Bumping the per-account `device_trust_epoch` invalidates every previously-trusted device — used on admin TOTP reset.

**22. Session management.**
- JWT in `httpOnly`, `Secure`, `SameSite=Strict` cookie.
- 2-hour TTL for admin/SA. 1-year TTL for employees (kiosk-style clinical workflow).
- 2-hour idle timeout for admin/SA. None for employees.
- Server-side revoked-tokens list (Redis) to invalidate sessions on logout.

**23. Authorization model.**
- RBAC: `superadmin`, `admin`, `regionaladmin`, `employee`, `hrcandidate`.
- Per-building scoping: each admin's reads / writes are filtered to buildings they manage.
- Database-enforced via Postgres Row-Level Security on every PHI-containing table.
- Privilege-escalation defense: non-SA users cannot modify `role`, `buildingId`, `buildingIds`, `schedulerOnly`, or `group` on any account through the bulk save endpoint — those fields are pinned from the existing DB row.

---

## F. Application Security

**24. Injection.**
- All SQL queries use parameterized statements. No string concatenation into SQL anywhere in the codebase.
- No `child_process`, `exec`, or `spawn` — no shell injection surface.
- Input validation on every endpoint (length caps, regex, enum checks).
- `escapeHtml()` on every user-controlled field rendered in HTML email templates.
- `sanitize()` on every dynamic field rendered in client HTML via innerHTML.

**25. CSRF.**
- `SameSite=Strict` cookie + custom-header (`X-Requested-With: XMLHttpRequest`) requirement on every state-changing endpoint.
- No `<form>` action endpoints — all writes are JSON via fetch.

**26. XSS.**
- Strict CSP via Helmet: `default-src 'self'`, no inline-script, no `unsafe-eval`.
- All client-rendered user data is run through `sanitize()` (HTML-escape) before innerHTML.

**27. Open redirect.**
None. No `res.redirect(req.query.url)` patterns. All redirects use server-controlled paths.

**28. Rate limiting.**
- `/api/auth/login`: 10 / 15min per IP
- `/api/recruiting/apply` (public): 30 / 15min per IP
- `/api/invite/verify`: 20 / 1min per IP
- All other API: 300 / 1min per IP
- Account-level: 5 failed logins → 30-min lockout

**29. Headers.**
Helmet defaults: HSTS (preload), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy strict-origin-when-cross-origin, CSP as above.

**30. Dependency posture.**
- npm audit clean at deploy time; no known critical CVEs.
- Pinned versions in `package-lock.json`.
- Quarterly review.

---

## G. Audit, Logging, Retention

**31. What is logged?**
- Every login attempt (success + failure with reason).
- Every PHI access (`DATA_ACCESS`).
- Every state change (`EMPLOYEE_ADDED`, `BUILDING_CREATED`, `INVITE_SENT`, `TOTP_RESET_BY_ADMIN`, `PWD_RESET_*`).
- Every alert dispatched (recipients masked: `j***@example.com`, `***-***-1234`).
- TOTP enrollment, verification, recovery-code use.

**32. What is NOT logged?**
- Plaintext passwords, password hashes.
- TOTP secrets, recovery codes (only the action — `TOTP_VERIFIED` — is logged).
- JWT tokens, session IDs, device-trust cookies.
- PCC credentials of any kind.
- Resident-level data (we don't pull it).

**33. Retention.**
- Audit log retention: 7 years (HIPAA §164.530(j) maximum). Enforced by Azure Storage immutability policy on the Blob container — audit log is WORM after write.
- Application logs: 90 days in Application Insights.
- Postgres data: indefinite while account is active; 7-year retention after account closure.

**34. Tamper detection.**
HMAC-SHA-256 chain. Every audit entry includes `prevHash` (the HMAC of the previous entry) and its own `hmac` over `(prevHash + timestamp + userId + action + meta)`. The chain is verified on every server boot. Any break aborts startup.

---

## H. Operational Controls

**35. Incident response.**
- 24/7 on-call via Microsoft Azure-monitored alerts (login spikes, auth failures, audit-chain breaks, data-tripwire trips).
- Customer-impact playbook: detect → contain → assess scope → notify customer within 24h if PHI may be involved.
- HIPAA breach notification: 60-day window per §164.404, but our process targets <24h to customer + 60-day worst case to OCR if breach is confirmed.

**36. Backup & disaster recovery.**
- Postgres geo-redundant backups, point-in-time recovery to 7 days.
- Hourly snapshots of `mms-data.json` for the file-mode fallback.
- RPO: 1 hour. RTO: 4 hours.

**37. BAA.**
- Microsoft Azure: covered by the Microsoft Online Services DPA + HIPAA BAA addendum signed at the Azure subscription level.
- Azure Communication Services: covered under the same Microsoft master BAA.
- PointClickCare: BAA to be executed as part of the partner agreement.

**38. Change management.**
- All changes are PR-reviewed and tested in a staging slot before production.
- GitHub Actions CI: `node --check`, JS syntax verification, dependency audit.
- Atomic deploys via Azure deployment slot swap.
- Pre-deploy security review for any change touching auth, encryption, or audit code.

**39. Penetration testing.**
- Self-conducted internal review pre-launch.
- Three independent code audits (PCC partner readiness, HIPAA §164.312, OWASP Top-10) completed; all critical findings resolved.
- Annual third-party pentest planned post-PCC partnership approval.

---

## I. Source Pointers

For every claim above, source-of-truth pointers in the codebase:

| Claim | File / function |
|---|---|
| OAuth2 token serialization | `server.js` → `getPCCToken()` (`_pccTokenInflight`) |
| Hardened PCC fetch | `server.js` → `pccFetch()` |
| ISO date validation | `server.js` → `_isValidIsoDate()` |
| AES-256-GCM at rest | `server.js` → `_encryptData()` / `_decryptData()` |
| HMAC audit chain | `server.js` → `auditLog()` / `verifyAuditChain()` |
| Bcrypt password hashing | `server.js` → all `bcrypt.hash(..., 12)` callsites |
| TOTP enrollment | `server.js` → `/api/auth/totp/enroll` |
| Trusted-device cookie | `server.js` → `signDeviceTrust()` / `verifyDeviceTrust()` |
| Per-building scoping | `server.js` → `getDataForUser()` / `mergeScoped()` |
| Privilege-field pinning | `server.js` → `/api/data` POST `NON_SA_ACCOUNT_WRITABLE` |
| Postgres RLS policies | `db/schema.sql` (lines marked `ENABLE ROW LEVEL SECURITY`) |
| Recipient PII masking | `server.js` → `maskEmail` / `maskPhone` in `/api/alert` |
| HTML escaping in emails | `server.js` → `escapeHtml()` |
| Self-attested config audit | `server.js` → `GET /api/healthz/deep` |

---

## J. Signed By

**Ben Solomon**, founder, ManageMyStaffing
ganzsolomon@managecensus.com
*Date*: at submission

This document represents the security posture of the application as of the latest deploy. The `/api/healthz/deep` endpoint returns a real-time, machine-readable version of the same posture and can be fetched at any time.
