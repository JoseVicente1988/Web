// api/db/dump.js
const { getDB, listTables, runSelect } = require("../_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    const tables = listTables(db);
    const data = {};
    for (const t of tables) {
      data[t] = runSelect(db, `SELECT * FROM ${t} LIMIT 10;`);
    }
    res.status(200).json({ ok: true, tables, sample: data });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
