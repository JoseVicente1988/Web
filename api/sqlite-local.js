// api/sqlite-local.js
import fs from "fs";
import path from "path";
import initSqlJs from "sql.js";

const REPO_SEED = path.join(process.cwd(), "db", "shopping.db"); // opcional: pon tu ruta de seed
const TMP_DB = "/tmp/shopping.db";

let SQL = null;
let db = null;
let loaded = false;

async function loadBytes() {
  // 1) si hay snapshot previo en /tmp, úsalo
  if (fs.existsSync(TMP_DB)) {
    return fs.readFileSync(TMP_DB);
  }
  // 2) si hay seed en el repo, úsalo
  if (fs.existsSync(REPO_SEED)) {
    return fs.readFileSync(REPO_SEED);
  }
  // 3) nada: DB nueva
  return null;
}

async function saveBytes(bytes) {
  try {
    fs.writeFileSync(TMP_DB, Buffer.from(bytes));
  } catch (_) {
    // en serverless puede fallar si /tmp no existe; lo intentamos crear
    try {
      fs.mkdirSync(path.dirname(TMP_DB), { recursive: true });
      fs.writeFileSync(TMP_DB, Buffer.from(bytes));
    } catch {}
  }
}

export async function openDB() {
  if (loaded && db) return db;
  if (!SQL) {
    SQL = await initSqlJs({
      locateFile: (f) => `https://sql.js.org/dist/${f}`
    });
  }
  const bytes = await loadBytes();
  db = bytes ? new SQL.Database(bytes) : new SQL.Database();
  loaded = true;
  return db;
}

export async function exec(sql) {
  await openDB();
  db.exec(sql);
  await persist();
}

export async function run(sql, params = []) {
  await openDB();
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
  await persist();
}

export async function all(sql, params = []) {
  await openDB();
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

export async function getOne(sql, params = []) {
  const rows = await all(sql, params);
  return rows[0] || null;
}

async function persist() {
  // export de toda la DB a bytes
  const bytes = db.export();
  await saveBytes(bytes);
}
