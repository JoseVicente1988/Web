const { getDB, runSelect } = require("../_db");

function parseBody(req) {
  try {
    if (!req.body) return {};
    return typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return {};
  }
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Use POST con JSON { sql, params }" });
    return;
  }

  const body = parseBody(req);
  const sql = (body.sql || "").trim();
  const params = Array.isArray(body.params) ? body.params : [];

  if (!sql || !/^select\s/i.test(sql)) {
    res.status(400).json({ ok: false, error: "Solo se permiten consultas SELECT." });
    return;
  }

  try {
    const db = await getDB();
    const rows = runSelect(db, sql, params);
    res.status(200).json({ ok: true, rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
