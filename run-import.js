'use strict';
// Runs smartlinx-import.sql against the live mms-pg-248457 server.
// Connection string + sql path come from CLI args / env.
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const sqlPath = process.argv[2] || path.join(__dirname, 'smartlinx-import.sql');
const conn = process.env.MMS_PG_CONN
  || `postgres://mmsadmin:${encodeURIComponent(process.env.PG_PW || '')}@mms-pg-248457.postgres.database.azure.com:5432/mms?sslmode=require`;

(async () => {
  const sql = fs.readFileSync(sqlPath, 'utf8');
  console.log(`SQL: ${sql.length} chars, ${sql.split('\n').length} lines`);
  const dryRun = process.argv.includes('--dry-run');
  const c = new Client({
    connectionString: conn,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 15000,
    statement_timeout: 120000,
  });
  await c.connect();
  console.log('Connected to', (await c.query('SELECT current_database(), inet_server_addr() AS addr')).rows[0]);

  const before = await c.query(`SELECT
    (SELECT COUNT(*) FROM buildings)::int AS bld,
    (SELECT COUNT(*) FROM employees)::int AS emp,
    (SELECT COUNT(*) FROM companies)::int AS co`);
  console.log('BEFORE:', before.rows[0]);

  if (dryRun) {
    console.log('DRY RUN — wrapping in BEGIN/ROLLBACK');
    await c.query('BEGIN');
    try {
      await c.query(sql);
      console.log('Statements ran without error.');
    } catch (e) {
      console.error('ERROR:', e.message);
    } finally {
      await c.query('ROLLBACK');
      console.log('Rolled back. Nothing committed.');
    }
  } else {
    // The SQL file already has its own BEGIN/COMMIT
    try {
      await c.query(sql);
      console.log('Import committed.');
    } catch (e) {
      console.error('IMPORT FAILED:', e.message);
      try { await c.query('ROLLBACK'); } catch {}
      process.exit(1);
    }
  }

  const after = await c.query(`SELECT
    (SELECT COUNT(*) FROM buildings)::int AS bld,
    (SELECT COUNT(*) FROM employees)::int AS emp,
    (SELECT COUNT(*) FROM companies)::int AS co`);
  console.log('AFTER:', after.rows[0]);

  console.log('\nPer-building staff counts (SkyBlue Healthcare):');
  const perBld = await c.query(`
    SELECT b.name, COUNT(e.id) AS staff
    FROM buildings b
    LEFT JOIN employees e ON e.building_id = b.id AND e.inactive = false
    WHERE b.company_id = 'co_skyblue'
    GROUP BY b.name
    ORDER BY b.name`);
  for (const r of perBld.rows) console.log(`  ${String(r.staff).padStart(4)}  ${r.name}`);

  await c.end();
})().catch(e => { console.error(e); process.exit(1); });
