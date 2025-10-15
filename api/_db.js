// api/_db.js
// DB auto-creada "in situ" desde schema/seed incluidos en el repo.
// Usa sql.js (WASM) para evitar binarios nativos en serverless.
// En Vercel no persiste entre despliegues/fríos: sirve para demo/preview.

const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");

let _dbPromise = null; // Singleton por proceso (reutiliza entre invocaciones calientes)

async function loadSqlJs() {
  // Asegura que el runtime encuentra el WASM empaquetado
  return await initSqlJs({
    locateFile: (file) => require.resolve("sql.js/dist/" + file)
  });
}

function readFileText(relPath) {
  const p = path.join(process.cwd(), relPath);
  return fs.readFileSync(p, "utf8");
}

function readJSON(relPath) {
  const p = path.join(process.cwd(), relPath);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

async function createOrLoadDB() {
  const SQL = await loadSqlJs();

  // En serverless lo más seguro es mantener la DB en memoria.
  // Si quieres intentar /tmp (persiste dentro de la misma instancia caliente), descomenta:
  // const tmpPath = "/tmp/app.db";
  // let db;
  // if (fs.existsSync(tmpPath)) {
  //   const filebuffer = fs.readFileSync(tmpPath);
  //   db = new SQL.Database(filebuffer);
  // } else {
  //   db = new SQL.Database();
  // }

  const db = new SQL.Database(); // Memoria pura (recomendado en serverless)

  // 1) Ejecutar schema idempotente
  const schemaSQL = readFileText("db/schema.sql");
  db.run(schemaSQL);

  // 2) Seed si la tabla está vacía (ejemplo: users)
  try {
    const res = db.exec("SELECT COUNT(*) as c FROM users");
    const count = res?.[0]?.values?.[0]?.[0] || 0;
    if (count === 0) {
      const seed = readJSON("db/seed.json");
      const users = Array.isArray(seed.users) ? seed.users : [];
      const stmt = db.prepare("INSERT INTO users (email, name) VALUES (?, ?)");
      for (const u of users) {
        stmt.run([u.email, u.name]);
      }
      stmt.free();
    }
  } catch (e) {
    // Si la tabla users no existe en tu schema, simplemente ignorar
  }

  // 3) Si estuvieras usando /tmp, podrías guardar:
  // const data = db.export();
  // fs.writeFileSync(tmpPath, Buffer.from(data));

  return db;
}

async function getDB() {
  if (!_dbPromise) _dbPromise = createOrLoadDB();
  return await _dbPromise;
}

function runQuery(db, sql, params = []) {
  // Para SELECT
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

function runExecute(db, sql, params = []) {
  // Para INSERT/UPDATE/DELETE (sin retorno)
  const stmt = db.prepare(sql);
  stmt.run(params);
  stmt.free();
}

module.exports = {
  getDB,
  runQuery,
  runExecute
};
