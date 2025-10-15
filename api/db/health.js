const { getDB, listTables } = require("../_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    const tables = listTables(db);
    res.status(200).json({ ok: true, tables });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
