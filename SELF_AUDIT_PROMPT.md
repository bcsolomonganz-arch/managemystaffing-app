# ManageMyStaffing — Self-Audit Prompt

Use the prompt below whenever you want Claude to do a full deficiency check on
the codebase. Paste it into a new session (or at the start of a session after
reading the files).

---

## PROMPT (copy everything between the dashes)

---

You are auditing the ManageMyStaffing codebase for deficiencies. The project is
a HIPAA-compliant SNF staffing platform consisting of:

- `managemystaffing.html` — single-file SPA (~190 KB HTML/CSS/JS)
- `server.js` — Node.js/Express backend (JWT auth, file persistence, ACS alerts)
- `package.json` — dependency manifest

Read both files in full before reporting findings. Check every item in the
checklist below and report each finding as:

  [SEVERITY] CATEGORY — short title
  File: <filename>, near line <N>
  Problem: <what is wrong>
  Fix: <exact change needed>

Severity levels: CRITICAL / HIGH / MEDIUM / LOW

---

### CHECKLIST

#### 1. External API calls — will they actually work?
- Are SDK method signatures correct for the installed package versions
  (check `package.json` for exact versions)?
- Are all required fields present and the right type (string vs array, etc.)?
- Is there a timeout or circuit-breaker so a slow API cannot hang the server?
- Are response shapes being read correctly (e.g., `.successful`, `.errorMessage`)?

#### 2. Environment variables — will the server start and operate?
- Does the server fail loudly at startup if a required env var is missing?
- Are optional env vars checked before use and errors surfaced to the user?
- Is there a startup log line confirming which features are enabled/disabled?

#### 3. Authentication & authorisation
- Are all sensitive routes protected with `requireAuth` AND `requireAdmin`
  where appropriate?
- Can a non-admin token reach admin-only data endpoints?
- Is the JWT secret strong enough (≥32 random bytes)?
- Are tokens validated on every request, not just cached?

#### 4. Data integrity
- Are all file writes atomic (write-to-tmp then rename)?
- Can a crashed write leave a corrupt data file?
- Is there input validation on every POST body (type checks, required fields)?
- Can a client overwrite seed accounts or escalate their own role via `POST /api/data`?

#### 5. Error handling — will failures be visible?
- Do all async routes have try/catch that return JSON errors (not crash the process)?
- Are errors logged to console with enough context to diagnose?
- Do long-running async operations (pollers, external calls) have timeouts?
- Does the UI surface server errors to the user (toast, message) rather than
  silently failing?

#### 6. Front-end ↔ back-end contract
- Does every `fetch()` call in the HTML check `response.ok` before parsing JSON?
- Are error responses from the server displayed to the user?
- Does the UI optimistically mutate state before the server confirms? If so,
  is there rollback on failure?
- Are all API paths correct (no hardcoded `localhost` in production paths)?

#### 7. Security
- Is user-supplied content escaped before being injected into HTML/innerHTML?
- Are there any `eval()`, `new Function()`, or `innerHTML` XSS risks?
- Are JWT payloads (claims) validated after `verify()` — role, id, etc.?
- Is there rate-limiting or brute-force protection on `/api/auth/login`?
- Are sensitive values (passwords, keys, tokens) ever logged to console?

#### 8. HIPAA / audit log
- Is every data-access or mutation event written to the audit log?
- Does the audit log include: timestamp, user ID, action, affected record ID?
- Is the audit log append-only (no route allows deletion or overwrite)?
- Is PHI never sent in URLs (query-string params)?

#### 9. UI / UX correctness
- Are all toggle states (Schedule/HR mode, notification checkboxes) persisted
  correctly across page reloads?
- Do modal dialogs close on success/cancel without leaving stale state?
- Are loading/spinner states shown during async operations?
- Are all icon-only buttons labelled with `aria-label` for accessibility?

#### 10. Dependency hygiene
- Are any packages in `package.json` unused (listed but never `require()`d)?
- Are any packages `require()`d inside route handlers instead of at the top
  (causes repeated file-system lookups on every request)?
- Are any package versions pinned to beta/pre-release that have a stable
  equivalent?

---

After completing the checklist, also answer these three questions:

1. **Will email alerts actually send today, end-to-end?**  
   Trace the full code path from the UI button click through the API call and
   ACS SDK and state exactly where it will succeed or fail.

2. **Will SMS alerts actually send today, end-to-end?**  
   Same trace for SMS.

3. **What is the single highest-priority fix that would have the most impact
   on reliability right now?**

---
