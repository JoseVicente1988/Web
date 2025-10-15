// api/users.js
const { z } = require("zod");
const { getDB, runQuery, runExecute } = require("./_db");

const NewUser = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(120)
});

module.exports = async (req, res) => {
  try {
    const db = await getDB();

    if (req.method === "GET") {
      const rows = runQuery(db, "SELECT id, email, name, created_at FROM users ORDER BY id ASC");
      res.status(200).json({ ok: true, users: rows });
      return;
    }

    if (req.method === "POST") {
      const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
      const parsed = NewUser.safeParse(body);
      if (!parsed.success) {
        res.status(400).json({ ok: false, error: parsed.error.message });
        return;
      }
      const { email, name } = parsed.data;

      // UNIQUE(email) → si existe, tirará error; puedes atrapar y devolver 409.
      try {
        runExecute(db, "INSERT INTO users (email, name) VALUES (?, ?)", [email, name]);
      } catch (e) {
        if ((e.message || "").toLowerCase().includes("unique")) {
          res.status(409).json({ ok: false, error: "Email already exists" });
          return;
        }
        throw e;
      }

      const rows = runQuery(db, "SELECT id, email, name, created_at FROM users WHERE email = ?", [email]);
      res.status(201).json({ ok: true, user: rows?.[0] || null });
      return;
    }

    res.status(405).json({ ok: false, error: "Method Not Allowed" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
};
