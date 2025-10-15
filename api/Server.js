// Vercel catch-all API — porta tu Server.js a serverless manteniendo rutas
// Runtime: Node.js (@vercel/node)

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const { URL } = require("url");

// -------- Config original --------
const MAX_BODY_BYTES = 256 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_AUTH = 40;
const RATE_LIMIT_MAX_GENERIC = 300;
const PASSWORD_MIN_LEN = 8;
const PASSWORD_MAX_LEN = 72;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días

// -------- DB helper para Vercel --------
// Usamos /tmp (escribible). Si existe shopping.db en el repo, lo copiamos a /tmp al vuelo.
const ROOT_DB = path.join(process.cwd(), "shopping.db");
const TMP_DB = path.join("/tmp", "shopping.db");

function ensureDbOnTmp() {
  try {
    if (!fs.existsSync(TMP_DB)) {
      if (fs.existsSync(ROOT_DB)) {
        fs.copyFileSync(ROOT_DB, TMP_DB);
      } else {
        // crear vacío
        fs.writeFileSync(TMP_DB, "");
      }
    }
  } catch (e) {
    // última opción: usar en cwd (sólo lectura si el FS está bloqueado)
  }
}

let db;
function getDb() {
  if (db) return db;
  ensureDbOnTmp();
  const dbPath = fs.existsSync(TMP_DB) ? TMP_DB : ROOT_DB;
  db = new Database(dbPath);
  db.pragma("foreign_keys = ON");
  // --- Migraciones / schema (idéntico a tu Server.js) ---
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT,
      created_at TEXT NOT NULL,
      locale TEXT,
      theme TEXT,
      photo_base64 TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      qty INTEGER NOT NULL DEFAULT 1,
      note TEXT,
      done INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS friendships (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_a INTEGER NOT NULL,
      user_b INTEGER NOT NULL,
      status TEXT NOT NULL,
      requested_by INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user_a, user_b),
      FOREIGN KEY (user_a) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (user_b) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS goals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      target_date TEXT,
      is_public INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS feed_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      goal_id INTEGER,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (goal_id) REFERENCES goals(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS feed_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(post_id, user_id),
      FOREIGN KEY (post_id) REFERENCES feed_posts(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS feed_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (post_id) REFERENCES feed_posts(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
  const hasCol = (table, name) => db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === name);
  if (!hasCol("sessions","expires_at")) db.exec(`ALTER TABLE sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'`);
  db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(new Date().toISOString());
  return db;
}

// -------- Queries (idénticas) --------
function queries(db) {
  return {
    qUserByEmail: db.prepare(`SELECT * FROM users WHERE email=?`),
    qUserById: db.prepare(`SELECT id, email, name, created_at, locale, theme, photo_base64 FROM users WHERE id=?`),
    qInsertUser: db.prepare(`INSERT INTO users (email, password_hash, name, created_at) VALUES (@email, @password_hash, @name, @created_at)`),
    qUpdateUserPrefs: db.prepare(`UPDATE users SET name=@name, locale=@locale, theme=@theme WHERE id=@id`),
    qUpdateUserPhoto: db.prepare(`UPDATE users SET photo_base64=@photo WHERE id=@id`),
    qDeleteUser: db.prepare(`DELETE FROM users WHERE id=?`),

    qInsertSession: db.prepare(`INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (@user_id, @token, @created_at, @expires_at)`),
    qFindSession: db.prepare(`SELECT s.token, s.expires_at, u.id as user_id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?`),
    qDeleteSession: db.prepare(`DELETE FROM sessions WHERE token=?`),

    qInsertItem: db.prepare(`INSERT INTO items (user_id, title, qty, note, done, created_at) VALUES (@user_id, @title, @qty, @note, @done, @created_at)`),
    qListItems: db.prepare(`SELECT id, title, qty, note, done, created_at FROM items WHERE user_id=? ORDER BY done ASC, id DESC`),
    qToggleItem: db.prepare(`UPDATE items SET done = CASE WHEN done=1 THEN 0 ELSE 1 END WHERE id=? AND user_id=?`),
    qDeleteItem: db.prepare(`DELETE FROM items WHERE id=? AND user_id=?`),

    canonicalPair: (a,b)=>{ a=+a; b=+b; return a<b ? [a,b] : [b,a]; },
    qFindFriendship: db.prepare(`SELECT * FROM friendships WHERE user_a=? AND user_b=?`),
    qInsertFriendship: db.prepare(`INSERT INTO friendships (user_a, user_b, status, requested_by, created_at) VALUES (@user_a, @user_b, @status, @requested_by, @created_at)`),
    qUpdateFriendshipStatus: db.prepare(`UPDATE friendships SET status=@status WHERE id=@id`),
    qDeleteFriendship: db.prepare(`DELETE FROM friendships WHERE id=?`),
    qListFriendsRaw: db.prepare(`
      SELECT f.id, f.user_a, f.user_b, f.status, f.requested_by,
             CASE WHEN f.user_a = @me THEN f.user_b ELSE f.user_a END as friend_id,
             u.name as friend_name, u.email as friend_email
      FROM friendships f
      JOIN users u ON u.id = CASE WHEN f.user_a = @me THEN f.user_b ELSE f.user_a END
      WHERE (f.user_a = @me OR f.user_b = @me)
      ORDER BY f.id DESC
    `),

    qInsertGoal: db.prepare(`INSERT INTO goals (user_id, title, target_date, is_public, created_at) VALUES (@user_id, @title, @target_date, @is_public, @created_at)`),
    qListGoals: db.prepare(`SELECT id, title, target_date, is_public, created_at FROM goals WHERE user_id=? ORDER BY id DESC`),
    qMakeGoalPublic: db.prepare(`UPDATE goals SET is_public=1 WHERE id=? AND user_id=?`),

    qInsertFeed: db.prepare(`INSERT INTO feed_posts (user_id, goal_id, content, created_at) VALUES (@user_id, @goal_id, @content, @created_at)`),
    qListFeed: db.prepare(`
      SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email,
             (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
             (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
      FROM feed_posts f JOIN users u ON u.id=f.user_id
      ORDER BY f.id DESC LIMIT ? OFFSET ?
    `),
    qListFeedByUser: db.prepare(`
      SELECT f.id, f.user_id, f.content, f.created_at,
             (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
             (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
      FROM feed_posts f
      WHERE f.user_id=? ORDER BY f.id DESC LIMIT ? OFFSET ?
    `),
    qUserLikedPost: db.prepare(`SELECT 1 FROM feed_likes WHERE post_id=? AND user_id=?`),
    qLikePost: db.prepare(`INSERT OR IGNORE INTO feed_likes (post_id, user_id, created_at) VALUES (?, ?, ?)`),
    qUnlikePost: db.prepare(`DELETE FROM feed_likes WHERE post_id=? AND user_id=?`),
    qCountLikes: db.prepare(`SELECT COUNT(*) as c FROM feed_likes WHERE post_id=?`),

    qAddComment: db.prepare(`INSERT INTO feed_comments (post_id, user_id, text, created_at) VALUES (?, ?, ?, ?)`),
    qListComments: db.prepare(`
      SELECT c.id, c.text, c.created_at, u.name, u.email
      FROM feed_comments c JOIN users u ON u.id=c.user_id
      WHERE c.post_id=? ORDER BY c.id ASC
    `),

    qFindUserByEmailPublic: db.prepare(`SELECT id, email, name FROM users WHERE email=?`),
    qFindUserPublicById: db.prepare(`SELECT id, email, name, created_at, photo_base64 FROM users WHERE id=?`),

    qInsertDM: db.prepare(`INSERT INTO dms (sender_id, receiver_id, text, created_at) VALUES (@sender_id, @receiver_id, @text, @created_at)`),
    qListDM: db.prepare(`
      SELECT id, sender_id, receiver_id, text, created_at
      FROM dms
      WHERE (sender_id=@me AND receiver_id=@friend) OR (sender_id=@friend AND receiver_id=@me)
      ORDER BY id DESC LIMIT @limit OFFSET @offset
    `)
  };
}

// -------- Util --------
function writeSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("Permissions-Policy","geolocation=(), microphone=(), camera=()");
  res.setHeader("Content-Security-Policy","default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';");
}
function sendJson(res, code, obj) {
  writeSecurityHeaders(res);
  res.statusCode = code;
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = Buffer.alloc(0), total = 0;
    req.on("data", c => {
      total += c.length;
      if (total > MAX_BODY_BYTES) { reject(new Error("Payload too large")); req.destroy(); return; }
      raw = Buffer.concat([raw,c]);
    });
    req.on("end", () => { if (!raw.length) return resolve({}); try { resolve(JSON.parse(raw.toString("utf8"))); } catch { reject(new Error("Invalid JSON")); } });
  });
}
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function clamp(n, min, max) { n = Number.isFinite(+n) ? +n : min; return Math.min(Math.max(n, min), max); }
function nowISO() { return new Date().toISOString(); }

// Rate limit simple por IP dentro de la invocación (sirve para bursts)
const rlStore = new Map();
function rateLimitOk(ip, isAuthPath) {
  const now = Date.now(); let e = rlStore.get(ip);
  if (!e || now - e.windowStart >= RATE_LIMIT_WINDOW_MS) { e = { windowStart: now, countAuth: 0, countGeneric: 0 }; rlStore.set(ip, e); }
  if (isAuthPath) { e.countAuth++; return e.countAuth <= RATE_LIMIT_MAX_AUTH; }
  e.countGeneric++; return e.countGeneric <= RATE_LIMIT_MAX_GENERIC;
}

// Auth
function authUserFromRequest(req, q) {
  const auth = req.headers["authorization"] || "";
  const m = auth.match(/^Bearer\s+(.+)$/i); if (!m) return null;
  const token = m[1].trim(); const row = q.qFindSession.get(token);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) { q.qDeleteSession.run(token); return null; }
  return { id: row.user_id, email: row.email, name: row.name, token };
}

// Temas (solo para validar prefs)
const THEMES = {
  pastel: { bg:"#0b0c10" }, dark:{}, ocean:{}, forest:{}, rose:{}, mono:{}
};
const THEME_KEYS = Object.keys(THEMES);

// ---------- Handler principal ----------
module.exports = async (req, res) => {
  writeSecurityHeaders(res);

  // path real de la request (sin el prefijo /api/ gracias a rewrite)
  const urlObj = new URL(req.url, "http://local");
  let pathn = urlObj.pathname || "/";
  if (pathn.length > 1 && pathn.endsWith("/")) pathn = pathn.slice(0, -1);

  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const isAuth = pathn.startsWith("/auth/");
  if (!rateLimitOk(ip, isAuth)) return sendJson(res, 429, { ok:false, error:"Too many requests" });

  // DB + queries
  const db = getDb();
  const q = queries(db);

  // --- Rutas (idénticas a tu Server.js) ---

  // root redirige (opcional; en Vercel servimos páginas estáticas por routes)
  if (req.method === "GET" && pathn === "/") {
    // si quisieras replicar el redirect, descomenta:
    // const u = authUserFromRequest(req, q);
    // res.statusCode = 302; res.setHeader("Location", u ? "/app" : "/ui"); return res.end();
    return sendJson(res, 200, { ok:true, hello:"api root" });
  }

  // -------- AUTH --------
  if (req.method === "POST" && pathn === "/auth/register") {
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      const name = (b.name || "").trim();
      const password = b.password || "";
      if (!email || !isValidEmail(email)) return sendJson(res, 400, { ok:false, error:"Invalid email" });
      if (typeof password !== "string" || password.length < PASSWORD_MIN_LEN || password.length > PASSWORD_MAX_LEN) return sendJson(res, 400, { ok:false, error:"Invalid password length" });
      if (q.qUserByEmail.get(email)) return sendJson(res, 409, { ok:false, error:"Email already registered" });
      const password_hash = bcrypt.hashSync(password, 10);
      q.qInsertUser.run({ email, password_hash, name, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  if (req.method === "POST" && pathn === "/auth/login") {
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      const password = b.password || "";
      const invalid = () => sendJson(res, 401, { ok:false, error:"Invalid credentials" });
      if (!email || !isValidEmail(email)) return invalid();
      const u = q.qUserByEmail.get(email); if (!u) return invalid();
      if (!bcrypt.compareSync(password, u.password_hash)) return invalid();
      const token = crypto.randomBytes(32).toString("hex");
      const created_at = nowISO();
      const expires_at = new Date(Date.now()+SESSION_TTL_MS).toISOString();
      q.qInsertSession.run({ user_id: u.id, token, created_at, expires_at });
      return sendJson(res, 200, { ok:true, token });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  if (req.method === "GET" && pathn === "/auth/me") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized (no/invalid/expired token)" });
    const row = q.qUserById.get(u.id); return sendJson(res, 200, { ok:true, user: row });
  }

  if (req.method === "POST" && pathn === "/auth/logout") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    q.qDeleteSession.run(u.token); return sendJson(res, 200, { ok:true });
  }

  // -------- SSE (modo polling-SSE en serverless) --------
  if (req.method === "GET" && pathn === "/events") {
    // token via query
    const token = urlObj.searchParams.get("token") || "";
    const row = q.qFindSession.get(token);
    if (!row || new Date(row.expires_at).getTime() < Date.now()) {
      res.statusCode = 401; res.setHeader("Content-Type","text/plain; charset=utf-8"); return res.end("Unauthorized");
    }
    const userId = row.user_id;
    res.statusCode = 200;
    res.setHeader("Content-Type","text/event-stream");
    res.setHeader("Cache-Control","no-cache");
    res.setHeader("Connection","keep-alive");
    res.setHeader("X-Accel-Buffering","no");
    res.write("event: ping\ndata: {}\n\n");

    const startedAt = Date.now();
    let lastFeedId = db.prepare("SELECT IFNULL(MAX(id),0) AS m FROM feed_posts").get().m || 0;
    let lastDmId = db.prepare("SELECT IFNULL(MAX(id),0) AS m FROM dms").get().m || 0;

    const interval = setInterval(() => {
      try {
        // Feed nuevos (global)
        const newFeed = db.prepare("SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email, (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count, (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count FROM feed_posts f JOIN users u ON u.id=f.user_id WHERE f.id>? ORDER BY f.id ASC").all(lastFeedId);
        for (const p of newFeed) {
          lastFeedId = Math.max(lastFeedId, p.id|0);
          res.write(`event: feed:new\ndata: ${JSON.stringify(p)}\n\n`);
        }
        // DMs nuevos para el usuario
        const newDm = db.prepare("SELECT id, sender_id, receiver_id, text, created_at FROM dms WHERE id>? AND receiver_id=? ORDER BY id ASC").all(lastDmId, userId);
        for (const m of newDm) {
          lastDmId = Math.max(lastDmId, m.id|0);
          res.write(`event: dm:new\ndata: ${JSON.stringify({ sender_id:m.sender_id, text:m.text, created_at:m.created_at })}\n\n`);
        }
        // keepalive
        res.write("event: ping\ndata: {}\n\n");
      } catch {}
      // cortamos a ~55s para respetar timeouts y que el EventSource reconecte
      if (Date.now() - startedAt > 55_000) {
        clearInterval(interval);
        try { res.end(); } catch {}
      }
    }, 2000);

    req.on("close", () => clearInterval(interval));
    return;
  }

  // -------- PREFS / PROFILE --------
  if (req.method === "GET" && pathn === "/prefs") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const row = getDb().prepare(`SELECT name, locale, theme, photo_base64 FROM users WHERE id=?`).get(u.id);
    return sendJson(res, 200, { ok:true, prefs: row });
  }
  if (req.method === "POST" && pathn === "/prefs") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const name = (b.name || "").toString().trim();
      let locale = (b.locale || "auto").toString().trim(); if (!["auto","en","es"].includes(locale)) locale = "auto";
      let theme = (b.theme || "pastel").toString().trim();
      if (!THEME_KEYS.includes(theme)) theme = "pastel";
      q.qUpdateUserPrefs.run({ id: u.id, name, locale, theme });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/photo") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const data = (b.data_url || "").toString();
      if (!data.startsWith("data:image/")) return sendJson(res, 400, { ok:false, error:"Invalid image" });
      if (Buffer.byteLength(data, "utf8") > 500_000) return sendJson(res, 400, { ok:false, error:"Image too large" });
      q.qUpdateUserPhoto.run({ id: u.id, photo: data });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/account/delete") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    q.qDeleteUser.run(u.id); return sendJson(res, 200, { ok:true });
  }

  // -------- ITEMS --------
  if (req.method === "GET" && pathn === "/items") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = q.qListItems.all(u.id);
    return sendJson(res, 200, { ok:true, items: rows });
  }
  if (req.method === "POST" && pathn === "/items") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const qty = Math.max(1, Math.min(9999, parseInt(b.qty || 1, 10) || 1));
      const note = (b.note || "").toString().trim();
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      q.qInsertItem.run({ user_id: u.id, title, qty, note, done: 0, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/items/") && pathn.endsWith("/toggle")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    q.qToggleItem.run(id, u.id); return sendJson(res, 200, { ok:true });
  }
  if (req.method === "DELETE" && pathn.startsWith("/items/")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    q.qDeleteItem.run(id, u.id); return sendJson(res, 200, { ok:true });
  }

  // -------- FRIENDS --------
  if (req.method === "GET" && pathn === "/friends") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = q.qListFriendsRaw.all({ me: u.id }).map(r => ({
      id: r.id, friend_id: r.friend_id, friend_name: r.friend_name, friend_email: r.friend_email,
      status: r.status, requested_by: r.requested_by, can_accept: r.status === "pending" && r.requested_by !== u.id
    }));
    return sendJson(res, 200, { ok:true, friends: rows, friends_ext: rows });
  }
  if (req.method === "POST" && pathn === "/friends/invite") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      if (!email || !isValidEmail(email)) return sendJson(res, 400, { ok:false, error:"Invalid email" });
      const other = q.qFindUserByEmailPublic.get(email);
      if (!other) return sendJson(res, 404, { ok:false, error:"User not found" });
      if (other.id === u.id) return sendJson(res, 400, { ok:false, error:"Cannot invite yourself" });
      const [a, b2] = q.canonicalPair(u.id, other.id);
      const existing = q.qFindFriendship.get(a, b2);
      if (existing) return sendJson(res, 409, { ok:false, error:"Already invited or friends" });
      q.qInsertFriendship.run({ user_a: a, user_b: b2, status: "pending", requested_by: u.id, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/friends/accept") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = getDb().prepare(`SELECT * FROM friendships WHERE id=?`).get(fid);
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      q.qUpdateFriendshipStatus.run({ id: fid, status: "accepted" }); return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && (pathn === "/friends/cancel" || pathn === "/friends/remove")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try{
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = getDb().prepare(`SELECT * FROM friendships WHERE id=?`).get(fid);
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      q.qDeleteFriendship.run(fid);
      return sendJson(res, 200, { ok:true });
    }catch{ return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  // -------- GOALS + FEED --------
  if (req.method === "GET" && pathn === "/goals") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = q.qListGoals.all(u.id);
    return sendJson(res, 200, { ok:true, goals: rows });
  }
  if (req.method === "POST" && pathn === "/goals") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const target_date = (b.target_date || null) ? String(b.target_date) : null;
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      const info = q.qInsertGoal.run({ user_id:u.id, title, target_date, is_public:0, created_at: nowISO() });
      return sendJson(res, 201, { ok:true, goal_id: info.lastInsertRowid });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/goals/") && pathn.endsWith("/publish")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    q.qMakeGoalPublic.run(id, u.id);
    const g = getDb().prepare(`SELECT title FROM goals WHERE id=? AND user_id=?`).get(id, u.id);
    if (g) {
      q.qInsertFeed.run({ user_id: u.id, goal_id: id, content: "New goal: " + g.title, created_at: nowISO() });
    }
    return sendJson(res, 200, { ok:true });
  }

  if (req.method === "GET" && pathn === "/feed") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const limit = clamp(urlObj.searchParams.get("limit"), 1, 50);
    const offset = clamp(urlObj.searchParams.get("offset"), 0, 10_000);
    const rows = q.qListFeed.all(limit, offset);
    return sendJson(res, 200, { ok:true, posts: rows });
  }
  if (req.method === "GET" && pathn.startsWith("/feed/") && !pathn.endsWith("/like") && !pathn.endsWith("/comment")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const comments = q.qListComments.all(pid).map(c => ({ id:c.id, text:c.text, created_at:c.created_at, name:c.name, email:c.email }));
    return sendJson(res, 200, { ok:true, comments });
  }
  if (req.method === "POST" && pathn === "/feed") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const content = (b.content || "").toString().trim();
      if (!content) return sendJson(res, 400, { ok:false, error:"Missing content" });
      q.qInsertFeed.run({ user_id:u.id, goal_id: null, content, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/feed/") && pathn.endsWith("/like")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const liked = !!q.qUserLikedPost.get(pid, u.id);
    if (liked) q.qUnlikePost.run(pid, u.id);
    else q.qLikePost.run(pid, u.id, nowISO());
    const count = q.qCountLikes.get(pid).c|0;
    return sendJson(res, 200, { ok:true, like_count: count, liked: !liked });
  }
  if (req.method === "POST" && pathn.startsWith("/feed/") && pathn.endsWith("/comment")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const b = await readJsonBody(req);
    const text = (b.text || "").toString().trim();
    if (!text) return sendJson(res, 400, { ok:false, error:"Missing text" });
    q.qAddComment.run(pid, u.id, text, nowISO());
    return sendJson(res, 201, { ok:true });
  }

  // -------- DMs --------
  if (req.method === "GET" && pathn === "/dm") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const friend_id = Number(urlObj.searchParams.get("friend_id")||0);
    if (!friend_id) return sendJson(res, 400, { ok:false, error:"Missing friend_id" });
    const [a,b] = q.canonicalPair(u.id, friend_id);
    const f = q.qFindFriendship.get(a, b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const limit = clamp(urlObj.searchParams.get("limit"), 1, 100);
    const offset = clamp(urlObj.searchParams.get("offset"), 0, 1_000_000);
    const rows = q.qListDM.all({ me:u.id, friend:friend_id, limit, offset }).map(m => ({ id:m.id, text:m.text, created_at:m.created_at, mine:m.sender_id===u.id, sender_id:m.sender_id }));
    return sendJson(res, 200, { ok:true, messages: rows });
  }
  if (req.method === "POST" && pathn === "/dm/send") {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const friend_id = Number(b.friend_id || 0);
      const text = (b.text || "").toString().trim();
      if (!friend_id || !text) return sendJson(res, 400, { ok:false, error:"Missing friend_id or text" });
      const [a,bp] = q.canonicalPair(u.id, friend_id);
      const f = q.qFindFriendship.get(a, bp);
      if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
      const created_at = nowISO();
      q.qInsertDM.run({ sender_id:u.id, receiver_id:friend_id, text, created_at });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  // -------- FRIEND PUBLIC PROFILE --------
  if (req.method === "GET" && pathn.startsWith("/users/") && pathn.endsWith("/profile")) {
    const u = authUserFromRequest(req, q); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const [a,b] = q.canonicalPair(u.id, id);
    const f = q.qFindFriendship.get(a,b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const profile = q.qFindUserPublicById.get(id);
    if (!profile) return sendJson(res, 404, { ok:false, error:"User not found" });
    const goals = getDb().prepare(`SELECT id, title, target_date FROM goals WHERE user_id=? AND is_public=1 ORDER BY id DESC LIMIT 10`).all(id);
    const feed = q.qListFeedByUser.all(id, 10, 0);
    return sendJson(res, 200, { ok:true, profile, goals, feed });
  }

  // 404
  res.statusCode = 404;
  res.setHeader("Content-Type","text/plain; charset=utf-8");
  res.end("Not found: " + pathn);
};
