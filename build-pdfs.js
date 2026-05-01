// One-shot script to build the two operator PDFs:
//   1. PCC_PARTNER_SECURITY_REVIEW.pdf  — converted from the markdown
//   2. ManageMyStaffing_Instructions.pdf — built from scratch
//
// Run with: node build-pdfs.js
// Both files are written into the project root.

const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

const ROOT  = __dirname;
const BRAND = '#6B9E7A';
const BRAND_DARK = '#3F6452';
const TEXT  = '#1F2937';
const MUTED = '#6B7280';
const BG_TINT = '#F0F8F2';
const RULE  = '#E5E7EB';

// ---------- shared helpers ---------------------------------------------------

function newDoc(title) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 64, bottom: 64, left: 64, right: 64 },
    info: { Title: title, Author: 'ManageMyStaffing', Creator: 'ManageMyStaffing' },
    autoFirstPage: false,
  });
  return doc;
}

// Header + footer + page numbers, applied AFTER all content has been written.
// pdfkit doesn't have a "header on every page" hook, so we walk the page
// range at the end and stamp.
function applyChrome(doc, title) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    // Skip chrome on the cover page (page 0).
    if (i === range.start) continue;
    // Header rule
    doc.save();
    doc.lineWidth(0.5).strokeColor(RULE).moveTo(64, 40).lineTo(548, 40).stroke();
    doc.font('Helvetica').fontSize(8).fillColor(MUTED)
       .text(title, 64, 28, { lineBreak: false });
    doc.text('ManageMyStaffing', 0, 28, { align: 'right', width: 548 - 64, lineBreak: false });
    // Footer
    doc.lineWidth(0.5).strokeColor(RULE).moveTo(64, 752).lineTo(548, 752).stroke();
    doc.fontSize(8).fillColor(MUTED)
       .text(`Page ${i - range.start + 1} of ${range.count}`, 0, 760, { align: 'center', width: 612 });
    doc.restore();
  }
}

// Logo: stylized house + medical cross, vector-drawn.
function drawLogo(doc, x, y, size = 64) {
  doc.save();
  const s = size / 100;          // 100×92 base
  // Roof + body
  doc.fillColor(BRAND);
  doc.path(`M${x + 50*s},${y + 5*s} L${x + 0*s},${y + 52*s} Q${x + 0*s},${y + 56*s} ${x + 4*s},${y + 56*s} L${x + 96*s},${y + 56*s} Q${x + 100*s},${y + 56*s} ${x + 100*s},${y + 52*s} Z`).fill();
  doc.rect(x + 3*s, y + 50*s, 94*s, 42*s).fill();
  doc.rect(x + 70*s, y + 2*s, 14*s, 26*s).fill();   // chimney
  // Cross window pattern (inverted out of the roof)
  doc.fillColor('#ffffff');
  doc.rect(x + 38*s, y + 20*s, 9*s, 9*s).fill();
  doc.rect(x + 52*s, y + 20*s, 9*s, 9*s).fill();
  doc.rect(x + 38*s, y + 32*s, 9*s, 9*s).fill();
  doc.rect(x + 52*s, y + 32*s, 9*s, 9*s).fill();
  // Door / cross
  doc.fillColor('#ffffff');
  doc.rect(x + 45*s, y + 60*s, 10*s, 30*s).fill();   // door rect
  // Medical cross
  doc.fillColor(BRAND);
  doc.rect(x + 47*s, y + 65*s, 6*s, 18*s).fill();
  doc.rect(x + 41*s, y + 71*s, 18*s, 6*s).fill();
  doc.restore();
}

function coverPage(doc, title, subtitle, footerLine) {
  doc.addPage();
  drawLogo(doc, 64, 100, 110);
  doc.font('Helvetica-Bold').fontSize(11).fillColor(BRAND_DARK)
     .text('MANAGEMYSTAFFING', 192, 130, { lineBreak: false });
  doc.font('Helvetica').fontSize(10).fillColor(MUTED)
     .text('Staff scheduling · recruiting · time clock · PPD analytics', 192, 148, { lineBreak: false });

  doc.moveTo(64, 270).lineTo(548, 270).strokeColor(BRAND).lineWidth(2).stroke();

  doc.font('Helvetica-Bold').fontSize(28).fillColor(TEXT)
     .text(title, 64, 300, { width: 484 });
  if (subtitle) {
    doc.moveDown(0.3);
    doc.font('Helvetica').fontSize(13).fillColor(MUTED).text(subtitle, { width: 484 });
  }

  doc.font('Helvetica').fontSize(10).fillColor(MUTED)
     .text(`Generated ${new Date().toISOString().slice(0,10)}`, 64, 700);
  if (footerLine) doc.text(footerLine, 64, 716);
  doc.text('https://www.managemystaffing.com', 64, 732);
}

function h1(doc, text) {
  if (doc.y > 600) doc.addPage();
  else if (doc.y < 100) doc.y = 100;
  doc.moveDown(0.5);
  doc.font('Helvetica-Bold').fontSize(18).fillColor(BRAND_DARK).text(text);
  doc.moveTo(doc.x, doc.y + 2).lineTo(548, doc.y + 2).strokeColor(BRAND).lineWidth(1).stroke();
  doc.moveDown(0.6);
}

function h2(doc, text) {
  if (doc.y > 680) doc.addPage();
  doc.moveDown(0.4);
  doc.font('Helvetica-Bold').fontSize(13).fillColor(TEXT).text(text);
  doc.moveDown(0.25);
}

function h3(doc, text) {
  if (doc.y > 700) doc.addPage();
  doc.moveDown(0.3);
  doc.font('Helvetica-Bold').fontSize(11).fillColor(BRAND_DARK).text(text);
  doc.moveDown(0.15);
}

function body(doc, text, opts = {}) {
  doc.font('Helvetica').fontSize(10).fillColor(TEXT);
  doc.text(text, { align: 'left', lineGap: 2, ...opts });
}

function bodyMuted(doc, text) {
  doc.font('Helvetica').fontSize(9).fillColor(MUTED).text(text, { lineGap: 2 });
}

function bullet(doc, text) {
  doc.font('Helvetica').fontSize(10).fillColor(TEXT)
     .text(`•  ${text}`, { indent: 14, lineGap: 2 });
}

function code(doc, text) {
  doc.font('Courier').fontSize(9).fillColor('#374151');
  // Tinted box
  const startY = doc.y;
  const lines = doc.heightOfString(text, { width: 484 });
  doc.save();
  doc.rect(60, startY - 3, 488, lines + 6).fill('#F3F4F6');
  doc.restore();
  doc.font('Courier').fontSize(9).fillColor('#374151')
     .text(text, 68, startY, { width: 472, lineGap: 1 });
  doc.y += 4;
}

function calloutBox(doc, label, text) {
  const startY = doc.y;
  doc.save();
  // Light-green tint
  doc.rect(64, startY, 484, 50).fill(BG_TINT);
  doc.rect(64, startY, 4, 50).fill(BRAND);
  doc.restore();
  doc.font('Helvetica-Bold').fontSize(9).fillColor(BRAND_DARK)
     .text(label.toUpperCase(), 76, startY + 8, { lineBreak: false });
  doc.font('Helvetica').fontSize(9).fillColor(TEXT)
     .text(text, 76, startY + 22, { width: 460, lineGap: 1.5 });
  // Recompute height — if it overflowed the 50 we just stamped, expand box
  const used = Math.max(50, doc.y - startY + 8);
  if (used > 50) {
    doc.save();
    doc.rect(64, startY, 484, used).fill(BG_TINT);
    doc.rect(64, startY, 4, used).fill(BRAND);
    doc.restore();
    doc.font('Helvetica-Bold').fontSize(9).fillColor(BRAND_DARK)
       .text(label.toUpperCase(), 76, startY + 8, { lineBreak: false });
    doc.font('Helvetica').fontSize(9).fillColor(TEXT)
       .text(text, 76, startY + 22, { width: 460, lineGap: 1.5 });
  }
  doc.y = startY + used + 8;
}

// ---------- generic markdown → PDF converter ---------------------------------

// Convert a markdown file at `mdPath` to a PDF at `outPath`, using the cover
// page metadata supplied. We don't run a full markdown engine — we walk
// line-by-line and recognize the few patterns these documents use (headings,
// lists, tables, code, blank lines).

function buildPdfFromMarkdown({ mdPath, outPath, docTitle, coverTitle, coverSubtitle, coverFooter }) {
  const md = fs.readFileSync(mdPath, 'utf8');
  const lines = md.split(/\r?\n/);

  const doc = newDoc(docTitle);
  doc.pipe(fs.createWriteStream(outPath));

  coverPage(doc, coverTitle, coverSubtitle, coverFooter);

  doc.addPage();

  let inTable = false, tableRows = [];
  let inCode  = false, codeBuf = [];

  const flushTable = () => {
    if (!tableRows.length) return;
    renderTable(doc, tableRows);
    tableRows = [];
    inTable = false;
  };
  const flushCode = () => {
    if (!codeBuf.length) return;
    code(doc, codeBuf.join('\n'));
    codeBuf = [];
    inCode = false;
  };

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Code fences
    if (/^```/.test(line)) {
      if (inCode) { flushCode(); }
      else        { inCode = true; }
      continue;
    }
    if (inCode) { codeBuf.push(line); continue; }

    // Tables (markdown pipe syntax)
    if (/^\s*\|/.test(line)) {
      if (/^\s*\|[\s\-:|]+\|\s*$/.test(line)) continue;        // separator line, skip
      const cells = line.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(s => s.trim());
      tableRows.push(cells);
      inTable = true;
      continue;
    } else if (inTable) {
      flushTable();
    }

    // Horizontal rule
    if (/^\s*---+\s*$/.test(line)) {
      doc.moveDown(0.3);
      doc.strokeColor(RULE).lineWidth(0.5).moveTo(64, doc.y).lineTo(548, doc.y).stroke();
      doc.moveDown(0.5);
      continue;
    }

    // Headings
    let m;
    if ((m = line.match(/^#\s+(.*)/))) {
      // Top-level heading inside the doc — render as h1
      h1(doc, stripInline(m[1]));
      continue;
    }
    if ((m = line.match(/^##\s+(.*)/))) {
      h1(doc, stripInline(m[1]));
      continue;
    }
    if ((m = line.match(/^###\s+(.*)/))) {
      h2(doc, stripInline(m[1]));
      continue;
    }
    if ((m = line.match(/^####\s+(.*)/))) {
      h3(doc, stripInline(m[1]));
      continue;
    }

    // Bullets
    if ((m = line.match(/^\s*[-*]\s+(.*)/))) {
      bullet(doc, stripInline(m[1]));
      continue;
    }

    // Bold-only "**Question?**" lead-in turns into a sub-heading
    if (/^\*\*.*\*\*$/.test(line.trim())) {
      h3(doc, stripInline(line.trim()));
      continue;
    }

    // Bold lead followed by paragraph (e.g. **Q.** Answer): treat as one paragraph
    if (line.trim()) {
      paragraphWithInline(doc, line);
    } else {
      doc.moveDown(0.4);
    }
  }

  flushTable();
  flushCode();

  applyChrome(doc, docTitle);
  doc.end();
  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(outPath));
    doc.on('error', reject);
  });
}

// Concrete builders calling the shared converter.
function buildSecurityPdf() {
  return buildPdfFromMarkdown({
    mdPath: path.join(ROOT, 'PCC_PARTNER_SECURITY_REVIEW.md'),
    outPath: path.join(ROOT, 'PCC_PARTNER_SECURITY_REVIEW.pdf'),
    docTitle: 'PCC Partner Security Review',
    coverTitle: 'PointClickCare Partner\nSecurity Review',
    coverSubtitle: 'Self-attested security posture for partner-engineering review',
    coverFooter: 'Prepared for PointClickCare Partner Engineering',
  });
}

function buildIndeedPartnerPdf() {
  return buildPdfFromMarkdown({
    mdPath: path.join(ROOT, 'INDEED_PARTNER_APPLICATION.md'),
    outPath: path.join(ROOT, 'INDEED_PARTNER_APPLICATION.pdf'),
    docTitle: 'Indeed Partner Program Application',
    coverTitle: 'Indeed Partner Program\nApplication',
    coverSubtitle: 'Marketplace listing application & technical readiness',
    coverFooter: 'Prepared for Indeed Partner Engineering',
  });
}

// Strip inline markdown (bold, italic, code) for plain text rendering.
function stripInline(s) {
  return String(s)
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/_([^_]+)_/g, '$1');
}

// Render a paragraph that may contain bold (**...**) + inline code (`...`)
function paragraphWithInline(doc, line) {
  doc.font('Helvetica').fontSize(10).fillColor(TEXT);
  // Split on **bold** while preserving order
  const parts = [];
  let rest = line;
  while (rest.length) {
    const m = rest.match(/(\*\*([^*]+)\*\*|`([^`]+)`)/);
    if (!m) { parts.push({ text: rest, bold: false, code: false }); break; }
    if (m.index > 0) parts.push({ text: rest.slice(0, m.index), bold: false, code: false });
    if (m[2] !== undefined) parts.push({ text: m[2], bold: true, code: false });
    else                    parts.push({ text: m[3], bold: false, code: true });
    rest = rest.slice(m.index + m[0].length);
  }
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    const isLast = i === parts.length - 1;
    if (p.code) doc.font('Courier').fontSize(9).fillColor('#374151');
    else if (p.bold) doc.font('Helvetica-Bold').fontSize(10).fillColor(TEXT);
    else doc.font('Helvetica').fontSize(10).fillColor(TEXT);
    doc.text(p.text, { continued: !isLast, lineGap: 2 });
  }
}

function renderTable(doc, rows) {
  if (!rows.length) return;
  const cols = rows[0].length;
  const colW = (484 - 8) / cols;
  const padX = 6, padY = 4;
  doc.moveDown(0.3);
  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const isHeader = r === 0;
    const startY = doc.y;
    let maxLines = 1;
    // Calculate row height
    doc.font(isHeader ? 'Helvetica-Bold' : 'Helvetica').fontSize(9);
    for (let c = 0; c < cols; c++) {
      const h = doc.heightOfString(stripInline(row[c] || ''), { width: colW - padX * 2 });
      maxLines = Math.max(maxLines, h);
    }
    const rowH = maxLines + padY * 2;
    if (startY + rowH > 720) { doc.addPage(); }
    const yy = doc.y;
    if (isHeader) {
      doc.save(); doc.rect(64, yy, 484, rowH).fill(BRAND_DARK); doc.restore();
    } else if (r % 2 === 0) {
      doc.save(); doc.rect(64, yy, 484, rowH).fill('#F9FAFB'); doc.restore();
    }
    for (let c = 0; c < cols; c++) {
      doc.font(isHeader ? 'Helvetica-Bold' : 'Helvetica').fontSize(9)
         .fillColor(isHeader ? '#FFFFFF' : TEXT)
         .text(stripInline(row[c] || ''), 64 + c * colW + padX, yy + padY, { width: colW - padX * 2, lineGap: 1 });
    }
    doc.y = yy + rowH;
  }
  doc.fillColor(TEXT);
  doc.moveDown(0.5);
}

// ---------- DOC 2 — OPERATOR INSTRUCTIONS ------------------------------------

function buildInstructionsPdf() {
  const outPath = path.join(ROOT, 'ManageMyStaffing_Instructions.pdf');
  const doc = newDoc('ManageMyStaffing — Operator Guide');
  doc.pipe(fs.createWriteStream(outPath));

  coverPage(doc,
    'ManageMyStaffing\nOperator Guide',
    'Day-to-day instructions for super admins, building admins, and HR users',
    'For internal use — covers signing in, scheduling, recruiting, PPD, time clock, and security');

  // ── TOC ────────────────────────────────────────────────────────────────
  doc.addPage();
  h1(doc, 'Contents');
  const sections = [
    '1.  Signing in',
    '2.  Super Admin platform overview',
    '3.  Entering a facility (and getting back out)',
    '4.  Recruiting — posting to Indeed, ZipRecruiter, and LinkedIn',
    '5.  Recruiting — managing applicants + in-app chat',
    '6.  PPD Calculator and PPD Calendar',
    '7.  Staff Events calendar',
    '8.  Texts sidebar (alert log + replies)',
    '9.  Direct Messages (in-app 1-to-1 chat)',
    '10. HR module (super-admin-only for now)',
    '11. Time Clock — three entry paths (kiosk / mobile / SmartLinx / CSV)',
    '12. Agency time entry on open shifts',
    '13. Reports — daily / weekly / monthly email digests',
    '14. PBJ Reports — quarterly XML export + archive',
    '15. Shift Trade Requests',
    '16. Mass Shift Swap',
    '17. Adding & editing facilities (CCN, geofence, kiosk URL)',
    '18. Roster — access levels, badges, PINs, IDs',
    '19. Onboarding → Roster push',
    '20. Security and HIPAA features',
    '21. Glossary',
  ];
  doc.font('Helvetica').fontSize(11).fillColor(TEXT);
  for (const s of sections) doc.text(s, { lineGap: 4 });

  // ── 1. SIGNING IN ──────────────────────────────────────────────────────
  doc.addPage();
  h1(doc, '1. Signing in');
  body(doc, 'Open https://www.managemystaffing.com in any modern browser. Two factors are needed for privileged accounts (admin / super admin / regional admin); employees use email + password only.');
  h2(doc, 'Step-by-step');
  bullet(doc, 'Email — your registered email address. Recent accounts auto-fill from local storage if you have signed in before.');
  bullet(doc, 'Password — minimum 12 characters with upper, lower, digit, and special for admins; 8 characters for employees.');
  bullet(doc, 'Click the eye icon at the right of the password field to reveal what you have typed.');
  bullet(doc, 'TOTP — when prompted, enter the 6-digit code from your authenticator app, OR a single-use recovery code (format xxxxxxxx-xxxxxxxx).');
  bullet(doc, 'After your first successful TOTP on a browser, that browser is trusted for 30 days. You will not be re-prompted on the same browser inside that window.');
  calloutBox(doc, 'Forgot your password?',
    'Click "Trouble signing in?" → enter your email → check your inbox for a reset link. The link expires in 1 hour. Setting a new password automatically signs you out of all other sessions.');

  h2(doc, 'Idle timeout');
  bullet(doc, 'Admins / super admins / regional admins are auto-logged out after 2 hours of inactivity.');
  bullet(doc, 'Employees are not auto-logged out (clinical-workflow / kiosk style).');
  bullet(doc, 'Sessions also have a hard 2-hour cap regardless of activity for privileged accounts.');

  // ── 2. SA PLATFORM OVERVIEW ────────────────────────────────────────────
  h1(doc, '2. Super Admin platform overview');
  body(doc, 'The super-admin home page shows a portfolio view of every facility (building) on the platform. Use the left sidebar to switch between Platform, Demos, and Billing.');

  h2(doc, 'Sidebar');
  bullet(doc, 'Platform — list of every building with key stats (staff count, today shifts, open shifts, last activity).');
  bullet(doc, 'Demos — leads + demo accounts for prospects.');
  bullet(doc, 'Billing — per-facility billing data.');

  h2(doc, 'Cards');
  bullet(doc, 'Each facility card shows building name + state, open shifts, total staff, today shifts, and a primary action: "Enter Dashboard".');
  bullet(doc, '"+ Add Building" creates a new facility. The first admin gets an auto-generated invite link.');
  bullet(doc, 'Click any company name to drill into a single company\'s portfolio of buildings.');

  // ── 3. ENTERING A FACILITY ─────────────────────────────────────────────
  h1(doc, '3. Entering a facility (and getting back out)');
  body(doc, 'Clicking "Enter Dashboard" on a facility card swaps your view to that facility\'s admin dashboard. The app treats you as the building\'s admin while you are inside, but your original SA identity is preserved for HR-module access.');

  h2(doc, 'What changes when you enter a facility');
  bullet(doc, 'The sidebar switches to Staff Groups, Tools (PPD Calculator, Staff Events, Texts), and Notifications.');
  bullet(doc, 'The HR/Schedule mode toggle appears at the top of the sidebar (super admins only).');
  bullet(doc, 'Calendar / day / week views show only that facility\'s shifts.');
  bullet(doc, 'Right-side panel shows employee counts and quick actions.');

  h2(doc, 'Getting back out');
  bullet(doc, 'There is a small "Back to Platform" link in the header — click it to return to the SA portfolio.');
  bullet(doc, 'Or click the avatar dropdown → Sign Out and sign back in.');

  // ── 4. RECRUITING — XML feeds ──────────────────────────────────────────
  h1(doc, '4. Recruiting — posting to Indeed, ZipRecruiter, and LinkedIn');
  body(doc, 'ManageMyStaffing hosts an XML feed of every active job posting. You submit the feed URL once per platform; from then on, every job you create or take down inside our app appears or disappears on those platforms automatically.');

  h2(doc, 'Three feed URLs');
  bullet(doc, 'Indeed:        https://www.managemystaffing.com/jobs.xml');
  bullet(doc, 'ZipRecruiter:  https://www.managemystaffing.com/jobs/ziprecruiter.xml');
  bullet(doc, 'LinkedIn:      https://www.managemystaffing.com/jobs/linkedin.xml');

  h2(doc, 'One-time setup, per platform');
  h3(doc, 'Indeed');
  bullet(doc, 'Sign in to https://employers.indeed.com.');
  bullet(doc, 'Open Bulk Posting → XML Feed → Add a Feed.');
  bullet(doc, 'Paste your jobs.xml URL. Indeed approves typically within hours.');

  h3(doc, 'ZipRecruiter');
  bullet(doc, 'Sign in to https://www.ziprecruiter.com/employers.');
  bullet(doc, 'Open Job Feed Setup → Add a Feed.');
  bullet(doc, 'Paste your ziprecruiter.xml URL.');

  h3(doc, 'LinkedIn');
  bullet(doc, 'LinkedIn Limited Listings requires whitelisting per company.');
  bullet(doc, 'Visit https://business.linkedin.com/talent-solutions/post-jobs and request feed access.');
  bullet(doc, 'Once approved, paste your linkedin.xml URL.');

  h2(doc, 'Posting a new job');
  bullet(doc, 'Click "+ Post New Job" in the Recruiting page header.');
  bullet(doc, 'Fill in title, department, job type, location, salary range, description, requirements.');
  bullet(doc, 'Use "Suggest a starter ad" to drop in a short, slightly tongue-in-cheek template tailored to the department.');
  bullet(doc, 'The Indeed compliance linter runs live as you type. ERRORS block save (e.g., discriminatory language, all caps title). WARNINGS show a confirm dialog (e.g., missing salary in disclosure-law states).');
  bullet(doc, 'When you save with status "Active", the job appears in the next platform crawl (typically within an hour).');

  h2(doc, 'Take Down / Repost');
  bullet(doc, 'Each active job card has a "Take Down" button — flips the job to closed and drops it from the next platform crawl.');
  bullet(doc, 'Closed jobs show "Repost" — flips back to active.');
  bullet(doc, 'You never need to log back into Indeed / ZipRecruiter / LinkedIn for these actions.');

  // ── 5. RECRUITING — APPLICANTS ─────────────────────────────────────────
  h1(doc, '5. Recruiting — managing applicants');
  body(doc, 'When a candidate applies through any of the three platforms, they land on our hosted apply page (/apply/<jobId>). Their name, email, and phone are captured into a prospect card automatically.');

  h2(doc, 'Applicants table');
  bullet(doc, 'Click the "Applicants" button in the Recruiting page header to scroll to the table.');
  bullet(doc, 'Each row shows applicant + applied-for job + when applied + status pill + actions.');
  bullet(doc, 'Status pills: New, Contacted, Reviewing, Onboarding, Hired, Rejected.');
  bullet(doc, 'Sort newest-first by default.');

  h2(doc, 'Per-applicant actions');
  bullet(doc, 'Message — opens an in-app SMS chat modal anchored to that applicant. Their replies appear in the same thread.');
  bullet(doc, 'Onboard — sends an onboarding email with a link to fill out new-hire paperwork.');
  bullet(doc, 'Reject — flips status to rejected.');

  h2(doc, 'Building filter (super admins + regional admins)');
  bullet(doc, 'Drop-down selector at the top of the Recruiting page filters jobs and prospects to a single building (or "All buildings").');
  bullet(doc, 'Single-building admins do not see the selector — they only see their own facility\'s data.');

  // ── 6. PPD CALCULATOR + CALENDAR ───────────────────────────────────────
  h1(doc, '6. PPD Calculator and PPD Calendar');
  body(doc, 'CMS Five-Star compliance hinges on Per-Patient-Day (PPD) staffing ratios. The PPD Calculator computes today\'s ratios; the PPD Calendar shows a month at a glance.');

  h2(doc, 'PPD Calculator (today)');
  bullet(doc, 'Census — enter occupied beds, or click "Sync PCC Census" to pull live from PointClickCare.');
  bullet(doc, 'Hours per position — auto-filled from scheduled shifts; editable.');
  bullet(doc, 'PPD ratios computed by department, with a Total Nursing PPD row at the bottom (CMS minimum 3.48).');
  bullet(doc, 'Cost / Day column — only visible to admins who have Full access (not Scheduler-only).');
  bullet(doc, 'CMS Five-Star Staffing Rating panel scores RN PPD and Total Nursing PPD against CMS thresholds.');

  h2(doc, 'PPD Calendar (month view)');
  bullet(doc, 'Below the daily form. Each cell shows the day, census (editable inline), total PPD, direct-care PPD, and daily staffing cost.');
  bullet(doc, 'Today\'s cell is highlighted with a green border.');
  bullet(doc, 'Click "Sync Month from PCC" to pull census for every day at once.');
  bullet(doc, 'Header summary: month-average PPD, total / direct-care hours, total month cost.');

  // ── 7. STAFF EVENTS ────────────────────────────────────────────────────
  h1(doc, '7. Staff Events calendar');
  body(doc, 'Side-bar item under Tools. Month-grid calendar of birthdays, work anniversaries, and custom events.');

  h2(doc, 'Auto-derived events');
  bullet(doc, 'Birthdays — derived from each employee\'s Date of Birth (set on the Add Employee form).');
  bullet(doc, 'Anniversaries — derived from each employee\'s Hire Date. First anniversary appears one year after hire.');

  h2(doc, 'Custom events (admin-editable)');
  bullet(doc, 'Click any day to add a custom event — type can be Nursing, Activity, Appreciation, or Other.');
  bullet(doc, 'Click the × on a custom event to remove it.');
  bullet(doc, 'Color-coded legend at the bottom of the page.');
  bullet(doc, 'Per-building scoped — admins only see their own facility\'s events.');

  // ── 8. TEXTS ───────────────────────────────────────────────────────────
  h1(doc, '8. Texts sidebar (alert log + replies)');
  body(doc, 'The Texts sidebar item shows every SMS or email alert sent from this facility, plus any inbound SMS replies.');

  h2(doc, 'What you see');
  bullet(doc, 'Most recent alerts at the top: subject, sender, recipient groups, channel chips (SMS / Email + recipient counts), full message body.');
  bullet(doc, 'Inbound replies appear under the originating alert in green-bordered bubbles.');
  bullet(doc, 'Recipient email and phone are masked in the audit log (e.g. j***@example.com, ***-***-1234) per HIPAA minimum-necessary.');

  h2(doc, 'Badge for unread');
  bullet(doc, 'When new replies arrive, the Texts sidebar item gets a yellow background and a count badge.');
  bullet(doc, 'Opening the Texts view marks everything as seen.');

  h2(doc, 'Inbound webhook');
  bullet(doc, 'Configure your messaging provider (Twilio or Azure Communication Services) to POST inbound SMS to /api/sms/inbound.');
  bullet(doc, 'Use the SMS_WEBHOOK_SECRET env var as a shared secret in the X-Webhook-Secret header.');
  bullet(doc, 'Replies are matched to the most recent alert that texted that phone number within the last 7 days.');

  // ── 9. HR MODULE ───────────────────────────────────────────────────────
  h1(doc, '9. HR module (super-admin-only for now)');
  body(doc, 'The HR module is currently restricted to the SA login (solomong@managemystaffing.com). It is a separate sidebar with its own pages: Hiring, Employees, Doc Review, Schedule, Shift Board, Time Clock, Data Center, Onboarding Flow, Integrations, Recruiting, PBJ Reports, Accounts, Audit Log, Billing.');

  h2(doc, 'Switching modes');
  bullet(doc, 'When you are inside a facility as SA, the sidebar shows a Schedule / HR toggle at the top.');
  bullet(doc, 'Click HR to switch to the HR sidebar; click Schedule to come back.');
  bullet(doc, 'The toggle is hidden on the SA Platform overview — only visible after you enter a facility.');
  bullet(doc, 'Other admins (non-SA) never see the toggle.');

  // ── 10. TIME CLOCK ─────────────────────────────────────────────────────
  h1(doc, '10. Time Clock — CSV import + missed-punch reports');
  body(doc, 'HR > Time Clock displays every punch record. Three types of irregularities are highlighted: late, missed, and no-clockout.');

  h2(doc, 'CSV import');
  bullet(doc, 'Click "Import CSV" — file picker opens.');
  bullet(doc, 'Accepted columns (case-insensitive): empId / employee_id / id, name / employee, date / shift_date, in / clock_in, out / clock_out, role / position.');
  bullet(doc, 'Each row is auto-classified by cross-referencing the scheduled shift:');
  bullet(doc, '   – missing clock-in → status: missed');
  bullet(doc, '   – missing clock-out → status: no-out');
  bullet(doc, '   – clock-in more than 7 minutes late → status: late');
  bullet(doc, '   – otherwise → status: normal');
  bullet(doc, 'Hours are computed from in/out, with overnight-shift handling.');
  bullet(doc, 'Re-importing the same day for the same employee overwrites the previous row — so you can re-export and re-import without creating duplicates.');

  h2(doc, 'Missed Punches panel');
  bullet(doc, 'Top-right of the Time Clock page. Tabs: Today, This Week, This Month.');
  bullet(doc, 'Each row shows the employee, their punch reliability score (0–100, last 30 days), and the count of missed / late / no-out incidents.');

  h2(doc, 'Dashboard cards');
  bullet(doc, 'The 5-card admin dashboard pulls from the same Time Clock data: Daily PPD, Open Shifts, Missed Punches, Tardiness, Early Sign-In.');
  bullet(doc, 'Click any card to jump to the detailed view (PPD calc, Open Shifts filter, Time Clock missed-punch panel, etc.).');

  h2(doc, 'Tablet kiosk');
  bullet(doc, 'URL: https://www.managemystaffing.com/kiosk/<buildingId> — get it from the SA building card "Kiosk URL" button.');
  bullet(doc, 'Open on a tablet at the nurse station; leave it running 24/7. Auto-issued kiosk JWT lasts a year.');
  bullet(doc, 'Employees enter their 4-digit PIN, tap Clock In or Clock Out. Confirmations show employee name + today\'s hours.');
  bullet(doc, 'Three failed PINs in 60s locks the kiosk for 5 minutes.');
  bullet(doc, 'Set PINs from the Roster — green "Set PIN" button on each row. PINs are bcrypt-hashed, unique within a building.');

  h2(doc, 'Mobile employee punch (geofenced)');
  bullet(doc, 'Employee opens the app on their phone → My Schedule → "Clock In" button at the top.');
  bullet(doc, 'Browser asks for location; coords are sent with the punch.');
  bullet(doc, 'Server verifies coords are within building.geofenceRadiusM (default 200m). No coords on the building → fence skipped.');
  bullet(doc, 'Optional selfie verification: enable building.requireSelfie on the Edit Facility form. Camera prompt → photo attached to the punch event for HR review.');

  h2(doc, 'SmartLinx / external clock integration');
  bullet(doc, 'POST /api/timeclock/smartlinx with X-SmartLinx-Secret header (set the SMARTLINX_WEBHOOK_SECRET env var first).');
  bullet(doc, 'Body: { badgeId, action: \'in\'|\'out\', timestamp, deviceId? } — single punch or { punches: [...] } batch.');
  bullet(doc, 'Map each employee\'s badge ID via Roster → IDs button.');
  bullet(doc, 'A small bridge script polls your Slate/Kronos/etc. and POSTs new punches; same _applyPunch pipeline classifies status against scheduled shift.');

  h2(doc, 'Admin punch correction');
  bullet(doc, 'HR → Time Clock → Edit button on any row.');
  bullet(doc, 'Three prompts: in time, out time, reason. Edit appended to record.events[] with editor + before/after for audit.');

  // ── 12. AGENCY TIME ────────────────────────────────────────────────────
  h1(doc, '12. Agency time entry on open shifts');
  body(doc, 'When an open shift is filled by an agency / contract worker (not a regular employee), admin records the hours here. Hours feed into PBJ + PPD + daily cost as agency-source nursing hours.');
  bullet(doc, 'Click the yellow "AGENCY" button on any open shift slot.');
  bullet(doc, 'Modal: worker name, agency, in/out time, hourly rate, license number.');
  bullet(doc, 'Saves an hrTimeClock record with kind:\'agency\' + flips the shift to status:agency-filled with the agency name displayed inline.');
  bullet(doc, 'PBJ export tags these entries with payTypeCode=3 (agency) automatically.');

  // ── 13. REPORTS ────────────────────────────────────────────────────────
  h1(doc, '13. Reports — daily / weekly / monthly email digests');
  body(doc, 'HR → Reports lets admins set up email subscriptions that send an inline HTML table every morning at 6am Central. No attachments — the table renders directly in the email body.');
  h2(doc, 'Subscription fields');
  bullet(doc, 'Recipients (up to 20 emails) — comma-separated.');
  bullet(doc, 'Buildings — one for a single facility, multiple for a regional admin digest.');
  bullet(doc, 'Metrics: Daily PPD, OT hours, Daily cost, Missed punches. Pick any combination.');
  h2(doc, 'Roll-ups');
  bullet(doc, 'Friday emails add a "Weekly Totals" table covering the past 7 days.');
  bullet(doc, 'The last day of the month adds a "Monthly Totals" table.');
  h2(doc, 'Multi-building digests');
  bullet(doc, 'When more than one building is selected, the table has one row per facility and a "Total" row at the bottom — perfect for regional admins.');
  bullet(doc, '"Send test now" button verifies setup before the first scheduled run.');

  // ── 14. PBJ REPORTS ────────────────────────────────────────────────────
  h1(doc, '14. PBJ Reports — quarterly XML export + archive');
  body(doc, 'CMS Payroll-Based Journal submission for SNF/LTC. The XML pulls staffing hours from the HR Time Clock and the daily census from the PPD Calendar / PCC sync.');
  h2(doc, 'Generating');
  bullet(doc, 'HR → PBJ Reports → pick facility, year, quarter.');
  bullet(doc, '"Preview Summary" shows employee count, punch lines, census days, plus warnings for missing CCN / state code / unmapped roles.');
  bullet(doc, '"Download XML" returns a CMS-spec file named pbj_<CCN>_<YEAR>Q<N>.xml — upload to CASPER or iQIES.');
  h2(doc, 'Job-code mapping (default)');
  bullet(doc, 'Nurse Management → 11 (Director of Nursing)');
  bullet(doc, 'Charge Nurse → 6 (LPN/LVN)');
  bullet(doc, 'CNA → 7, CMA → 9');
  bullet(doc, 'Cook → 26, Dietary Aid → 27');
  bullet(doc, 'Override per employee in Roster → IDs button when default is wrong.');
  h2(doc, 'Archive');
  bullet(doc, 'Every generated XML is auto-saved to Azure Blob storage so you can re-download a previous quarter without regenerating.');
  bullet(doc, '"Past Quarters" table lists every archive for the selected year, with download links.');
  bullet(doc, 'Re-running the same quarter overwrites the archive — useful when you correct a missed punch and re-export.');

  // ── 15. SHIFT TRADES ───────────────────────────────────────────────────
  h1(doc, '15. Shift Trade Requests');
  body(doc, 'Employee-initiated swap with admin approval.');
  bullet(doc, 'Employee taps a future shift on My Schedule → "↔ Request Shift Trade" button.');
  bullet(doc, 'Picker shows other employees\' upcoming shifts in the same group at the same building.');
  bullet(doc, 'Pick one → request is submitted; both employees see "Trade pending admin approval" on that shift.');
  bullet(doc, 'Admin sees a "Shift Trades" badge in the sidebar Notifications. Click → queue with Approve / Reject buttons.');
  bullet(doc, 'On approve, the server atomically swaps employeeIds on both shifts.');
  bullet(doc, 'Initiator can cancel a pending request. Cross-group / cross-building trades are blocked.');

  // ── 16. MASS SHIFT SWAP ────────────────────────────────────────────────
  h1(doc, '16. Mass Shift Swap');
  body(doc, 'Admin tool for vacation / leave coverage. Reassigns all of one employee\'s scheduled shifts in a date range to another employee.');
  bullet(doc, 'Click "Mass Swap" in the admin header.');
  bullet(doc, 'Pick From and To employees (same staff group), date range.');
  bullet(doc, '"Preview" shows how many shifts will move and how many days conflict (target already has a shift).');
  bullet(doc, '"Execute Swap" performs the reassignment. Skipped conflicts are reported in the success toast.');

  // ── 17. ADD/EDIT FACILITIES ────────────────────────────────────────────
  h1(doc, '17. Adding & editing facilities (CCN, geofence, kiosk URL)');
  body(doc, 'SA only. The "+ Add Building" button on the Platform overview creates new facilities. Existing buildings have an "⚙ Edit" button on each card.');
  h2(doc, 'Add facility form fields');
  bullet(doc, 'Name, address, phone, beds, state, ZIP, CCN (CMS Certification Number — required for PBJ filing).');
  bullet(doc, 'Primary admin: name, email, auto-generated temporary password. Invitation emailed on save.');
  h2(doc, 'Edit facility (operational fields)');
  bullet(doc, 'CCN, state code — needed for PBJ submissions.');
  bullet(doc, 'Latitude, longitude — drives the mobile-punch geofence. Click "Geocode from address" to auto-fill from the street address (uses OpenStreetMap).');
  bullet(doc, 'Geofence radius (meters, default 200) — how far from the facility the mobile punch is accepted.');
  bullet(doc, '"Activate SMS" — provisions a local-area-code SMS number for this facility (requires 10DLC brand registration first).');
  bullet(doc, '"📱 Kiosk URL" — copies the per-building kiosk URL to clipboard for tablet setup.');

  // ── 18. ROSTER ─────────────────────────────────────────────────────────
  h1(doc, '18. Roster — access levels, badges, PINs, IDs');
  body(doc, 'Per-employee row actions for everything an admin needs to manage one person.');
  h2(doc, 'Access pill (color-coded by current level)');
  bullet(doc, 'Grey "Employee" — sees own schedule + open shifts only.');
  bullet(doc, 'Blue "Admin" — full Building Admin, sees hourly rates / OT / cost / PPD financials.');
  bullet(doc, 'Amber "Scheduler" — admin without financial visibility.');
  bullet(doc, 'Click the pill → modal with three radio cards. Promoting auto-creates an account + sends invite email. Demoting removes the linked admin account but preserves the employee record.');
  bullet(doc, 'Cannot change your own access (would let you lock yourself out). Cannot demote the only admin of a building.');
  h2(doc, 'Other row buttons');
  bullet(doc, 'Message — opens the in-app DM thread with this person.');
  bullet(doc, 'IDs — set badge ID (for SmartLinx), PBJ job-code override, DOB, hire date.');
  bullet(doc, 'Set/Reset PIN — 4–6 digit kiosk PIN (bcrypt-hashed, unique within building).');
  bullet(doc, 'Inactivate / Reactivate — soft-delete with a termination log.');
  h2(doc, 'Discipline notes');
  bullet(doc, 'Each employee row has a Discipline dropdown. Notes carry over for inactive employees: re-adding the same name + DOB pulls the old card back, write-ups intact.');

  // ── 19. ONBOARDING → ROSTER PUSH ───────────────────────────────────────
  h1(doc, '19. Onboarding → Roster push');
  body(doc, 'Promote a finished onboardee directly to the active staff roster.');
  bullet(doc, 'HR → Doc Review → green "+ Push to Roster" button on each pending row.');
  bullet(doc, 'Confirms, prompts for hourly rate if missing, then maps onboarding fields → employees row (name, role, email, phone, DOB, hire date, hourly rate).');
  bullet(doc, 'Original HR record is marked status:active and linked back via onboardingHrId.');

  // ── 20. SECURITY + HIPAA ───────────────────────────────────────────────
  h1(doc, '20. Security and HIPAA features');
  body(doc, 'A summary of the HIPAA §164.312 (technical safeguards) controls in place. For the full self-attested posture, hit /api/healthz/deep at any time.');

  h2(doc, 'Authentication and access');
  bullet(doc, 'bcrypt cost 12 password hashing.');
  bullet(doc, 'Account lockout after 5 failed logins (30-min window).');
  bullet(doc, 'TOTP required on every privileged account, with single-use recovery codes.');
  bullet(doc, 'Trusted-device cookie: 30-day TTL, account-bound.');
  bullet(doc, 'Idle timeout: 2h admin, no auto-logout for employees.');
  bullet(doc, 'Per-building authorization scoping; Postgres Row-Level Security enabled.');

  h2(doc, 'Encryption');
  bullet(doc, 'AES-256-GCM for data file at rest. Postgres TDE at the storage layer.');
  bullet(doc, 'TLS 1.2+ in transit. HSTS enabled with 2-year preload.');
  bullet(doc, 'All secrets in Azure Key Vault.');

  h2(doc, 'Audit and integrity');
  bullet(doc, 'Tamper-evident audit log (HMAC-SHA-256 chain with prevHash linkage).');
  bullet(doc, 'Audit chain verified on every server boot.');
  bullet(doc, 'Optimistic concurrency on writes (ETag / If-Match).');
  bullet(doc, 'Tripwire on bulk-data shrink: any write that drops a collection by more than 50%% requires X-Confirm-Wipe header.');
  bullet(doc, '7-year audit log retention via Azure Storage immutability policy.');

  h2(doc, 'PHI guards');
  bullet(doc, 'Outbound SMS scanned for SSN / DOB / MRN / employee names — blocked if matched.');
  bullet(doc, 'Email body fully HTML-escaped on every interpolated user-controlled field.');
  bullet(doc, 'GET /api/data scrubs every secret field (ph, totpSecret, recovery codes, etc.) before sending to the client.');
  bullet(doc, 'Recipient PII masked in the long-lived alert log.');

  h2(doc, 'Privilege-escalation defense');
  bullet(doc, 'Non-SA users cannot modify role / buildingId / buildingIds / schedulerOnly / group via the bulk save endpoint. Those fields are pinned from the existing DB row.');
  bullet(doc, 'Self-role-escalation explicitly blocked (audit logged as blocked_self_role_escalation).');

  h2(doc, 'Access levels');
  bullet(doc, 'Full Admin — sees hourly rates, PPD cost columns, OT cost panel.');
  bullet(doc, 'Scheduler Access — schedule-only. Hourly rate field, Cost/Day, Total Daily Cost, and OT panel are all hidden. Toggle from Manage Admins or set on invite.');

  // ── 12. GLOSSARY ───────────────────────────────────────────────────────
  h1(doc, '12. Glossary');
  const glossary = [
    ['BAA',          'Business Associate Agreement. Legal contract required between covered entities and any subprocessor that handles PHI.'],
    ['Census',       'Number of occupied resident beds on a given day.'],
    ['CMS',          'Centers for Medicare & Medicaid Services. Sets the staffing rating thresholds.'],
    ['Direct-care PPD', 'Hours of NM + RN + LPN + CNA + CMA divided by census.'],
    ['HIPAA',        'Health Insurance Portability and Accountability Act.'],
    ['PBJ',          'Payroll-Based Journal. CMS\'s quarterly staffing data submission.'],
    ['PCC',          'PointClickCare — the EHR system we integrate with.'],
    ['PHI',          'Protected Health Information.'],
    ['PPD',          'Per Patient Day — staffing hours divided by census.'],
    ['RBAC',         'Role-Based Access Control.'],
    ['RLS',          'Row-Level Security (Postgres).'],
    ['SA',           'Super Admin (platform-wide privileges).'],
    ['TOTP',         'Time-based One-Time Password (RFC 6238). 6-digit code from your authenticator app.'],
  ];
  for (const [term, def] of glossary) {
    doc.font('Helvetica-Bold').fontSize(10).fillColor(BRAND_DARK);
    doc.text(term + ' — ', { continued: true });
    doc.font('Helvetica').fontSize(10).fillColor(TEXT);
    doc.text(def, { lineGap: 2 });
  }

  applyChrome(doc, 'ManageMyStaffing — Operator Guide');
  doc.end();
  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(outPath));
    doc.on('error', reject);
  });
}

// ---------- main -------------------------------------------------------------

(async () => {
  try {
    const a = await buildSecurityPdf();
    console.log('Wrote', a, fs.statSync(a).size, 'bytes');
    const b = await buildInstructionsPdf();
    console.log('Wrote', b, fs.statSync(b).size, 'bytes');
    const c = await buildIndeedPartnerPdf();
    console.log('Wrote', c, fs.statSync(c).size, 'bytes');
  } catch (e) {
    console.error('PDF build failed:', e.message);
    process.exit(1);
  }
})();
