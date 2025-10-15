// api/products.js
// GET /api/products?q=... -> lista productos desde la tabla detectada
const { getDB, runSelect, findProductsTable } = require("./_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    const table = findProductsTable(db);
    if (!table) {
      res.status(404).json({
        ok: false,
        error:
          "No se detectó tabla de productos. Renombra a 'products' | 'productos' | 'items' | 'inventory'… o dime el nombre real y lo fijo."
      });
      return;
    }

    const q = (req.query?.q || "").toString().trim();

    // Detecta columnas
    const cols = runSelect(db, `PRAGMA table_info(${table});`).map(c => c.name);
    const idCol = cols.find(c => /^id$/i.test(c)) || cols[0];
    const nameCol = cols.find(c => /name|nombre|title/i.test(c)) || cols[0];
    const priceCol = cols.find(c => /price|precio|amount|cost/i.test(c)) || null;

    let sql = `SELECT ${idCol} AS id, ${nameCol} AS name${
      priceCol ? `, ${priceCol} AS price` : ""
    } FROM ${table}`;
    const params = [];
    if (q) {
      sql += ` WHERE ${nameCol} LIKE ?`;
      params.push(`%${q}%`);
    }
    sql += ` ORDER BY ${idCol} ASC LIMIT 200`;

    const items = runSelect(db, sql, params);
    res.status(200).json({ ok: true, table, count: items.length, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
