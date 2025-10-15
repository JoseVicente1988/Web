// api/products.js
// GET /api/products  -> lista productos de la tabla detectada
// Opcional: ?q=... filtra por nombre/título

const { getDB, runSelect, findProductsTable } = require("./_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    const table = findProductsTable(db);
    if (!table) {
      res.status(404).json({
        ok: false,
        error: "No se detectó tabla de productos. Renombra tu tabla a algo como 'products' | 'productos' | 'items'."
      });
      return;
    }

    const q = (req.query?.q || "").toString().trim();
    // Intento de columnas típicas
    // Primero detecta columnas
    const cols = runSelect(db, `PRAGMA table_info(${table});`).map(c => c.name);
    const nameCol = cols.find(c => /name|nombre|title/i.test(c)) || cols[0];
    const priceCol = cols.find(c => /price|precio|amount|cost/i.test(c)) || null;
    const idCol = cols.find(c => /^id$/i.test(c)) || cols[0];

    let sql = `SELECT ${idCol} as id, ${nameCol} as name${priceCol ? `, ${priceCol} as price` : ""} FROM ${table}`;
    const params = [];

    if (q) {
      sql += ` WHERE ${nameCol} LIKE ?`;
      params.push(`%${q}%`);
    }
    sql += ` ORDER BY ${idCol} ASC LIMIT 200`;

    const rows = runSelect(db, sql, params);
    res.status(200).json({ ok: true, table, count: rows.length, items: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
