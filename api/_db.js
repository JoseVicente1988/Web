// api/_db.js
// Abre shoping.db / shopping.db empaquetado en la lambda (Vercel).
// LECTURA estable. Escritura sería efímera (si la haces, hazla en /tmp).

const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");

let _dbPromise = null;

function tryPaths(basenames) {
  const candidates = [];

  for (const base of basenames) {
    // 1) Junto al código de la función (ruta del bundle)
    candidates.push(path.join(__dirname, base));
    candidates.push(path.join(__dirname, "..", base));
    // 2) Raíz del proyecto (a veces Vercel mantiene cwd en /var/task/user)
    candidates.push(path.join(process.cwd(), base));
  }

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch (_) {}
  }
  return null;
}

async function loadSql() {
  // sql-wasm.wasm lo empaquetamos vía includedFiles, así que existe.
  const wasmPath = require.resolve("sql.js/dist/sql-wasm.wasm");
  return await initSqlJs({
    locateFile: () => wasmPath
  });
}

async function openDBFromFile() {
  const SQL = await loadSql();

  const dbPath = tryPaths(["shoping.db", "shopping.db"]);
  if (!dbPath) {
    throw new Error(
      "No encuentro 'shoping.db' ni 'shopping.db' en el bundle. " +
      "Asegúrate de subir el archivo al root del repo y que 'vercel.json' tenga 'includedFiles'."
    );
  }

  const fileBuffer = fs.readFileSync(dbPath);
  const u8 = new Uint8Array(fileBuffer);
  const db = new SQL.Database(u8); // copia en memoria de tu .db

  // Si quisieras escribir durante la vida de la lambda:
  // const tmp = "/tmp/runtime.db";
  // fs.writeFileSync(tmp, Buffer.from(db.export()));
  // y luego reabrir desde tmp para mutaciones.

  return db;
}

async function getDB() {
  if (!_dbPromise) _dbPromise = openDBFromFile();
  return await _dbPromise;
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
