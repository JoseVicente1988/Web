// api/_db.js
// Lee / abre shoping.db desde el root del repo con sql.js (WASM).
// Modo LECTURA estable en Vercel. Escribir sólo sería efímero.

const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");

let _dbPromise = null;

async function loadSql() {
  return await initSqlJs({
    locateFile: (file) => require.resolve("sql.js/dist/" + file)
  });
}

async function openDBFromFile() {
  const SQL = await loadSql();

  const dbPath = path.join(process.cwd(), "shoping.db");
  if (!fs.existsSync(dbPath)) {
    const hint = fs.existsSync(path.join(process.cwd(), "shopping.db")) ? "¿Te equivocaste y se llama shopping.db?" : "Coloca shoping.db en la raíz del repo.";
    throw new Error("No se encuentra 'shoping.db' en el root del proyecto. " + hint);
  }

  const fileBuffer = fs.readFileSync(dbPath);
  const u8 = new Uint8Array(fileBuffer);
  const db = new SQL.Database(u8); // Abre la DB desde el archivo (copia en memoria)
  return db;
}

async function getDB() {
  if (!_dbPromise) _dbPromise = openDBFromFile();
  return await _dbPromise;
}

// Helpers seguros (solo SELECT). Si quieres mutar, añade otro helper.
function runSelect(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Descubre tablas existentes
function listTables(db) {
  const rows = runSelect(
    db,
    `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;`
  );
  return rows.map(r => r.name);
}

// Detección heurística de tabla "productos"
function findProductsTable(db) {
  const tables = listTables(db);
  const candidates = tables.filter(t =>
    /product|producto|items?|goods|inventory/i.test(t)
  );
  // si no hay heurística, devuelve null
  return candidates[0] || null;
}

module.exports = { getDB, runSelect, listTables, findProductsTable };
