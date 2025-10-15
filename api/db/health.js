// api/db/health.js
const { getDB, runQuery } = require("../_db");

module.exports = async (req, res) => {
  try {
    const db = await getDB();
    // Comprueba que la tabla 'users' existe y que hay filas (del seed)
    let ok = true;
    let usersCount = 0;
    try {
      const rows = runQuery(db, "SELECT COUNT(*) as c FROM users");
      usersCount = rows?.[0]?.c || 0;
    } catch (e) {
      ok = false;
    }
    res.status(200).json({
      ok,
      usersCount
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
