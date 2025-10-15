// api/_db.js
// Abre tu SQLite empaquetado en la lambda (Vercel) desde api/_assets/.
// LECTURA estable. Si escribes, será efímero (vida de la instancia).

const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");

let _dbPromise = null;

function existingPath(paths) {
  for (const p of paths) {
    try { if (fs.existsSync(p)) return p; } catch (_) {}
  }
  return null;
}

async function loadSql() {
  // Vercel empaqueta node_modules; require.resolve encuentra el wasm
  const wasmPath = require.resolve("sql.js/dist/sql-wasm.wasm");
  return await initSqlJs({ locateFile: () => wasmPath });
}

async function openDBFromFile() {
  const SQL = await loadSql();

  // Candidatos: dentro del bundle (api/_assets) y por si acaso raíz
  const candidates = [
    path.join(__dirname, "_assets", "shoping.db"),
    path.join(__dirname, "_assets", "shopping.db"),
    path.join(process.cwd(), "api", "_assets", "shoping.db"),
    path.join(process.cwd(), "api", "_assets", "shopping.db"),
    path.join(process.cwd(), "shoping.db"),
    path.join(process.cwd(), "shopping.db")
  ];

  const dbPath = existingPath(candidates);
  if (!dbPath) {
    throw new Error(
      "No encuentro la base de datos. Pon 'shoping.db' (o 'shopping.db') en 'api/_assets/'."
    );
  }

  const fileBuffer = fs.readFileSync(dbPath);
  const db = new SQL.Database(new Uint8Array(fileBuffer)); // copia en memoria
  return db;
}

async function getDB() {
  if (!_dbPromise) _dbPromise = openDBFromFile();
  return _dbPromise;
}

function runSelect(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function listTables(db) {
  const rows = runSelect(
    db,
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
  );
  return rows.map(r => r.name);
}

function findProductsTable(db) {
  const tables = listTables(db);
  const candidates = tables.filter(t =>
    /product|producto|items?|goods|inventory|shop|article/i.test(t)
  );
  return candidates[0] || null;
}

module.exports = { getDB, runSelect, listTables, findProductsTable };
