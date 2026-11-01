const fs = require('node:fs');
const path = require('node:path');
const { AsyncLocalStorage } = require('node:async_hooks');
const pg = require('pg');
const { Pool } = pg;

const root = path.resolve(__dirname, '..');
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required. Configure the Supabase PostgreSQL connection string.');
}

pg.types.setTypeParser(20, value => Number(value));
pg.types.setTypeParser(1700, value => Number(value));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'disable' ? false : { rejectUnauthorized: true },
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});
const transactionContext = new AsyncLocalStorage();
const tableWithId = /INSERT\s+INTO\s+(users|subjects|units|topics|coverage_history|questions|assessments|resources|recommendations|admin_activity|assessment_topic_results)\b/i;

function toPostgres(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

async function execute(sql, params = [], mode = 'all') {
  const client = transactionContext.getStore() || pool;
  const wantsId = mode === 'run' && tableWithId.test(sql) && /^\s*INSERT\b/i.test(sql) && !/\bRETURNING\b/i.test(sql);
  const result = await client.query(`${toPostgres(sql)}${wantsId ? ' RETURNING id' : ''}`, params);
  if (mode === 'get') return result.rows[0];
  if (mode === 'run') return { changes: result.rowCount, lastInsertRowid: result.rows[0]?.id };
  return result.rows;
}

const db = {
  pool,
  prepare(sql) {
    return {
      all: (...params) => execute(sql, params, 'all'),
      get: (...params) => execute(sql, params, 'get'),
      run: (...params) => execute(sql, params, 'run')
    };
  },
  async transaction(callback) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const value = await transactionContext.run(client, callback);
      await client.query('COMMIT');
      return value;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  },
  async close() { await pool.end(); }
};

async function initDb() {
  const schema = fs.readFileSync(path.join(root, 'supabase', 'migrations', '20261101000000_schema.sql'), 'utf8');
  await pool.query(schema);
}

async function seedSyllabus() {
  const seed = JSON.parse(fs.readFileSync(path.join(root, 'data', 'syllabus.json'), 'utf8'));
  await db.transaction(async () => {
    for (const subject of seed.subjects) {
      await db.prepare(`INSERT INTO subjects(code,name,semester) VALUES(?,?,?) ON CONFLICT(code) DO UPDATE SET name=excluded.name, semester=excluded.semester`).run(subject.code, subject.name, subject.semester);
      const sid = (await db.prepare('SELECT id FROM subjects WHERE code=?').get(subject.code)).id;
      for (const unit of subject.units) {
        await db.prepare(`INSERT INTO units(subject_id,number,title) VALUES(?,?,?) ON CONFLICT(subject_id,number) DO UPDATE SET title=excluded.title`).run(sid, unit.number, unit.title);
        const uid = (await db.prepare('SELECT id FROM units WHERE subject_id=? AND number=?').get(sid, unit.number)).id;
        for (const [position, title] of unit.topics.entries()) {
          await db.prepare(`INSERT INTO topics(unit_id,title,position) VALUES(?,?,?) ON CONFLICT(unit_id,title) DO UPDATE SET position=excluded.position`).run(uid, title, position);
        }
      }
    }
  });
}

module.exports = { db, initDb, seedSyllabus, root };
