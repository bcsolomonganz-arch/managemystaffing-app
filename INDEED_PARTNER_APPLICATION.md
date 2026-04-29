# Indeed Partner Program — Application Materials

**Applicant**: ManageMyStaffing
**Public URL**: https://www.managemystaffing.com
**Primary contact**: Ben Solomon — ganzsolomon@managecensus.com
**Application date**: 2026

This document collects the answers you'll paste into Indeed's Partner Program
intake form, plus the supporting technical evidence Indeed will ask for during
review.

---

## 1. About ManageMyStaffing

**One-sentence pitch.** ManageMyStaffing is a HIPAA-compliant staff scheduling,
recruiting, and time-clock platform purpose-built for skilled-nursing and
long-term-care facilities.

**Founded.** 2025

**Customers.** 10 active employer facilities (skilled-nursing operators across
TX, OK, and IA) at time of application. All on a unified platform with
per-facility scoping.

**Team size.** Small founding team, single-tenant software hosted on Azure.

**Competitive positioning.** Most ATS / scheduling platforms are
healthcare-agnostic. ManageMyStaffing is built around CMS Five-Star PPD
analytics, PointClickCare census integration, and the specific role taxonomy
of SNF / LTC operations (RN, LPN, CNA, CMA, NM, dietary, housekeeping,
laundry). Each posting carries facility-level metadata that maps cleanly to
the way SNFs hire.

**Hosting.** Azure (App Service, Postgres, Storage, Key Vault, Communication
Services). US-East primary, geo-redundant backups.

---

## 2. Why we want to be in the Indeed Marketplace

Our customers are SNF operators with chronically open shifts. Indeed is
already the dominant top-of-funnel for healthcare hourly hiring, and our
customers ask us to integrate. A formal Marketplace listing:

1. Standardizes the integration so each new ManageMyStaffing customer can
   connect their Indeed account with one click instead of opening a feed
   support ticket per customer.
2. Lets us push back **disposition data** (interviewed / hired / rejected) so
   Indeed's algorithms learn from real outcomes and surface our jobs more
   effectively.
3. Surfaces ManageMyStaffing as a discoverable healthcare-staffing ATS, which
   Indeed's account managers can recommend when they encounter SNF / LTC
   operators that don't have an ATS yet.

---

## 3. Technical readiness

We've built to Indeed's published partner spec. **All four required
integrations are implemented and live in production.** The endpoints are not
yet enabled (gated behind missing `INDEED_*` credentials) but flip on the
moment Indeed issues partner credentials.

### 3.1 Required: Indeed-spec XML feed (jobs push)

Live at `https://www.managemystaffing.com/jobs.xml`. Emits only `status:active`
postings; "Take Down" / "Repost" inside our app flips a job in or out of the
next crawl. Spec details:

- Top-level `<source>` with `<publisher>`, `<publisherurl>`, `<lastBuildDate>`
- Each `<job>` contains `<title>`, `<date>`, `<referencenumber>`, `<url>`,
  `<company>`, `<city>`, `<state>`, `<country>`, `<postalcode>`,
  `<description>`, `<salary>`, `<jobtype>`, `<category>`
- `<jobtype>` mapped to Indeed's vocabulary: fulltime / parttime / perdiem /
  contract / temporary
- `<url>` points to a hosted apply page on our domain (`/apply/<jobId>`) so
  Indeed's "Apply" button lands on us, not a third-party tracker
- `<referencenumber>` carries our internal `jobId` so Indeed can echo it
  back as `jobMeta.partnerJobId` on every Apply payload

We also emit ZipRecruiter and LinkedIn feed variants from the same data
source for partner-portfolio convenience.

### 3.2 Required: Indeed Apply receiver

Endpoint: `POST /api/indeed/apply` on `www.managemystaffing.com`. Behavior:

- Verifies `X-Indeed-Signature` HMAC-SHA-256 against `INDEED_PARTNER_SECRET`
  using `crypto.timingSafeEqual` (constant-time)
- Parses Indeed Apply JSON payload (applicant + job + questions + resume URL +
  cover letter)
- Looks up our internal job via `jobMeta.partnerJobId` and verifies the job
  is still `active`
- Validates email format and length; rejects with 400 on malformed input
- Dedupes by Indeed `applyId` first, then by (email, jobId) within 7 days —
  protects against replay or accidental double-POST
- Creates a prospect record with `source: 'indeed_apply'` and
  `indeedApplyId` for downstream correlation
- Returns 200 `{ ok: true, prospectId }` to Indeed for ack
- Audit event: `INDEED_APPLY_RECEIVED` with masked email
- Cap of 5,000 prospects per facility to bound storage

### 3.3 Required: Disposition sync (push)

Function `pushIndeedDisposition(applyId, status)` in `server.js`. Triggered:

- On every prospect status transition through `POST /api/data` (we snapshot
  pre-merge statuses for all `indeedApplyId`-bearing prospects and fire on
  any change)
- On `POST /api/recruiting/onboard` when an admin clicks "Onboard" on an
  Indeed-sourced prospect

Implementation details:

- OAuth2 client_credentials grant against `apis.indeed.com/oauth/v2/tokens`
- Stampede-safe via promise serialization (`_indeedTokenInflight`); concurrent
  callers share a single in-flight token fetch
- Token cached in memory, refreshed 60 seconds before `expires_in`
- `AbortController` 10-second timeout on every call
- 401 → token refresh + single retry
- Status codes mapped to Indeed's controlled vocabulary:
  `new → NEW`, `contacted → INTERVIEW_SCHEDULED`,
  `reviewing → INTERVIEW_SCHEDULED`, `onboarding → OFFER_EXTENDED`,
  `hired → HIRED`, `rejected → REJECTED`
- All failures logged with status code only — never the request body or the
  bearer token

### 3.4 Required: Status-event webhook

Endpoint: `POST /api/indeed/event`. Same HMAC verification as Apply receiver.
Handles:

- `WITHDRAWN` / `CANDIDATE_WITHDREW` — flips local prospect to `rejected` and
  appends a note
- `DUPLICATE` — logs in notes; status preserved
- Any other event type — logged in notes for human review
- Orphan events (no matching prospect) audited as `INDEED_EVENT_ORPHAN`

---

## 4. Security & compliance posture

**HIPAA**: Yes. We are a Business Associate to our SNF / LTC customers and
sign BAAs with each. PHI we hold:

- Employee PII (name, DOB, hourly rate, phone, email)
- Shift schedules tied to facility
- Time-clock punches
- Aggregated census from PointClickCare (no resident PII)

**Encryption.** AES-256-GCM at rest for the data file; Postgres TDE; TLS 1.2+
in transit with HSTS preload.

**Authentication.** bcrypt cost 12, TOTP for admins, single-use recovery
codes, account lockout, 2-hour idle timeout, trusted-device cookie 30-day
TTL.

**Audit.** Tamper-evident HMAC-SHA-256 chain on every PHI access. 7-year
retention via Azure Storage immutability.

**Authorization.** RBAC + per-building scoping enforced at the application
layer AND via Postgres Row-Level Security at the database layer.

**Subprocessors with BAAs in place.** Microsoft Azure (App Service, Postgres,
Storage, Key Vault, Application Insights), Azure Communication Services
(email + SMS), PointClickCare (when configured).

A full self-attested security report is available at
`https://www.managemystaffing.com/api/healthz/deep` (public, no secrets, no
auth required). Indeed's security review team can fetch it directly during
assessment.

A complete `PCC Partner Security Review` document is also on file (drafted
for PointClickCare partner application; ~95% applies verbatim to Indeed's
review). Available on request.

---

## 5. Operational answers

**Q. How do you handle PHI in the Indeed Apply flow?**
A. Indeed Apply applications themselves don't contain PHI — they're
applicant-supplied job-application data. Once an applicant is hired through
the platform, they become an employee and any PHI we collect (DOB, address,
SSN if needed for I-9, etc.) is collected via our HIPAA-compliant onboarding
flow on our domain, never through Indeed's surfaces.

**Q. How do you handle a candidate's "right to be forgotten" request?**
A. We expose a `DELETE /api/recruiting/prospects/:id` endpoint to admins
(role-gated). On request from a candidate, the operating admin deletes the
record. The audit log retains the action (per HIPAA / state law) but the
prospect's PII is removed from the active dataset.

**Q. What happens if Indeed Apply sends a duplicate application?**
A. We dedupe by `indeedApplyId` first, then by (email, jobId) within 7 days.
Re-submissions update the existing record's `appliedAt` timestamp and any
new fields (e.g., updated resume) without creating a duplicate prospect.

**Q. Can Indeed audit our integration sandbox?**
A. Yes. Once partner credentials are issued, we enable the endpoints in our
staging slot (`mms-app-248457-staging.azurewebsites.net`) and provide test
credentials so Indeed's QA team can run end-to-end scripts against an
isolated environment before flipping production.

---

## 6. Customer references (request)

Available on request. We have written authorization from 3 of our 10 customer
facilities to share named references with Indeed during the partnership
review process. Other 7 prefer to remain unnamed but will confirm usage if
Indeed reaches out directly.

---

## 7. Indicative volume

- 10 employer facilities live
- ~50–80 active job postings at steady state across the customer base
- ~15–30 applications per active posting per month (Indeed's national SNF
  CNA/RN baseline) → ~10,000+ Indeed Apply candidate flows expected per year
  once Marketplace listing is live
- Disposition push: roughly 1× per applicant within 30 days of application
  (interviewed + hired/rejected outcomes)

---

## 8. Logo & brand assets

ManageMyStaffing logo: stylized green house with medical cross
- Brand color: `#6B9E7A`
- High-res PNG / SVG: available on request, can host at
  `/static/logo-256.png`, `/static/logo.svg` for Indeed's directory
- Display name: **ManageMyStaffing**
- Short tagline: *"Staff scheduling and recruiting for skilled-nursing
  facilities."*

---

## 9. Requested next steps

1. **Issue partner credentials**: `INDEED_PARTNER_SECRET` (HMAC),
   `INDEED_API_CLIENT_ID`, `INDEED_API_CLIENT_SECRET`.
2. **Sandbox certification window** (1–2 weeks): Indeed runs scripted tests
   against our staging environment. We've written end-to-end coverage for
   Apply receiver, event webhook, and disposition push and will provide the
   test report.
3. **Marketplace listing launch**: logo, name, tagline, integration page
   linking back to `https://www.managemystaffing.com`.
4. **Annual partnership review** to discuss tier promotion as customer
   volume grows.

---

## 10. Sign-off

**Ben Solomon**, founder, ManageMyStaffing
ganzsolomon@managecensus.com

This document and the integration code referenced are version-controlled in
our private GitHub repository. Specific code review access can be granted on
request to Indeed Partner Engineering during the technical review phase.
