const { getDB, listTables, runSelect } = require("../_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    const tables = listTables(db);
    const sample = {};
    for (const t of tables) {
      sample[t] = runSelect(db, `SELECT * FROM ${t} LIMIT 10;`);
    }
    res.status(200).json({ ok: true, tables, sample });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
