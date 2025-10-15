// Server.js — GroFriends++ (SSE tiempo real, likes/comentarios, sesiones con caducidad)
// Requisitos: node, better-sqlite3, bcryptjs
//   npm i better-sqlite3 bcryptjs
// Ejecuta: node Server.js  -> http://localhost:3000/app

const http = require("http");
const { URL } = require("url");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const PORT = process.env.PORT || 3000;

/* ------------------ Config ------------------ */
const MAX_BODY_BYTES = 256 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_AUTH = 40;
const RATE_LIMIT_MAX_GENERIC = 300;
const PASSWORD_MIN_LEN = 8;
const PASSWORD_MAX_LEN = 72;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días

/* ------------------ DB ------------------ */
const db = new Database("shopping.db");
db.pragma("foreign_keys = ON");
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
  /* NUEVO: likes y comentarios */
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

/* migración menor para sesiones antiguas sin expires_at */
const hasCol = (table, name) => db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === name);
if (!hasCol("sessions","expires_at")) db.exec(`ALTER TABLE sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'`);

/* ------------------ Queries ------------------ */
const qUserByEmail = db.prepare(`SELECT * FROM users WHERE email=?`);
const qUserById    = db.prepare(`SELECT id, email, name, created_at, locale, theme, photo_base64 FROM users WHERE id=?`);
const qInsertUser  = db.prepare(`INSERT INTO users (email, password_hash, name, created_at) VALUES (@email, @password_hash, @name, @created_at)`);
const qUpdateUserPrefs = db.prepare(`UPDATE users SET name=@name, locale=@locale, theme=@theme WHERE id=@id`);
const qUpdateUserPhoto = db.prepare(`UPDATE users SET photo_base64=@photo WHERE id=@id`);
const qDeleteUser  = db.prepare(`DELETE FROM users WHERE id=?`);

const qInsertSession = db.prepare(`INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (@user_id, @token, @created_at, @expires_at)`);
const qFindSession   = db.prepare(`SELECT s.token, s.expires_at, u.id as user_id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?`);
const qDeleteSession = db.prepare(`DELETE FROM sessions WHERE token=?`);
db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(new Date().toISOString()); // limpieza simple al arrancar

const qInsertItem = db.prepare(`INSERT INTO items (user_id, title, qty, note, done, created_at) VALUES (@user_id, @title, @qty, @note, @done, @created_at)`);
const qListItems  = db.prepare(`SELECT id, title, qty, note, done, created_at FROM items WHERE user_id=? ORDER BY done ASC, id DESC`);
const qToggleItem = db.prepare(`UPDATE items SET done = CASE WHEN done=1 THEN 0 ELSE 1 END WHERE id=? AND user_id=?`);
const qDeleteItem = db.prepare(`DELETE FROM items WHERE id=? AND user_id=?`);

function canonicalPair(a, b) { a=+a; b=+b; return a<b ? [a,b] : [b,a]; }
const qFindFriendship = db.prepare(`SELECT * FROM friendships WHERE user_a=? AND user_b=?`);
const qInsertFriendship = db.prepare(`INSERT INTO friendships (user_a, user_b, status, requested_by, created_at) VALUES (@user_a, @user_b, @status, @requested_by, @created_at)`);
const qUpdateFriendshipStatus = db.prepare(`UPDATE friendships SET status=@status WHERE id=@id`);
const qDeleteFriendship = db.prepare(`DELETE FROM friendships WHERE id=?`);
const qListFriendsRaw = db.prepare(`
  SELECT f.id, f.user_a, f.user_b, f.status, f.requested_by,
         CASE WHEN f.user_a = @me THEN f.user_b ELSE f.user_a END as friend_id,
         u.name as friend_name, u.email as friend_email
  FROM friendships f
  JOIN users u ON u.id = CASE WHEN f.user_a = @me THEN f.user_b ELSE f.user_a END
  WHERE (f.user_a = @me OR f.user_b = @me)
  ORDER BY f.id DESC
`);

const qInsertGoal = db.prepare(`INSERT INTO goals (user_id, title, target_date, is_public, created_at) VALUES (@user_id, @title, @target_date, @is_public, @created_at)`);
const qListGoals  = db.prepare(`SELECT id, title, target_date, is_public, created_at FROM goals WHERE user_id=? ORDER BY id DESC`);
const qMakeGoalPublic = db.prepare(`UPDATE goals SET is_public=1 WHERE id=? AND user_id=?`);

const qInsertFeed = db.prepare(`INSERT INTO feed_posts (user_id, goal_id, content, created_at) VALUES (@user_id, @goal_id, @content, @created_at)`);
const qListFeed   = db.prepare(`
  SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email,
         (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
         (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
  FROM feed_posts f JOIN users u ON u.id=f.user_id
  ORDER BY f.id DESC LIMIT ? OFFSET ?
`);
const qListFeedByUser = db.prepare(`
  SELECT f.id, f.user_id, f.content, f.created_at,
         (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
         (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
  FROM feed_posts f
  WHERE f.user_id=? ORDER BY f.id DESC LIMIT ? OFFSET ?
`);
const qUserLikedPost = db.prepare(`SELECT 1 FROM feed_likes WHERE post_id=? AND user_id=?`);
const qLikePost = db.prepare(`INSERT OR IGNORE INTO feed_likes (post_id, user_id, created_at) VALUES (?, ?, ?)`);
const qUnlikePost = db.prepare(`DELETE FROM feed_likes WHERE post_id=? AND user_id=?`);
const qCountLikes = db.prepare(`SELECT COUNT(*) as c FROM feed_likes WHERE post_id=?`);

const qAddComment = db.prepare(`INSERT INTO feed_comments (post_id, user_id, text, created_at) VALUES (?, ?, ?, ?)`);
const qListComments = db.prepare(`
  SELECT c.id, c.text, c.created_at, u.name, u.email
  FROM feed_comments c JOIN users u ON u.id=c.user_id
  WHERE c.post_id=? ORDER BY c.id ASC
`);

const qFindUserByEmailPublic = db.prepare(`SELECT id, email, name FROM users WHERE email=?`);
const qFindUserPublicById = db.prepare(`SELECT id, email, name, created_at, photo_base64 FROM users WHERE id=?`);

const qInsertDM = db.prepare(`INSERT INTO dms (sender_id, receiver_id, text, created_at) VALUES (@sender_id, @receiver_id, @text, @created_at)`);
const qListDM = db.prepare(`
  SELECT id, sender_id, receiver_id, text, created_at
  FROM dms
  WHERE (sender_id=@me AND receiver_id=@friend) OR (sender_id=@friend AND receiver_id=@me)
  ORDER BY id DESC LIMIT @limit OFFSET @offset
`);

/* ------------------ Util ------------------ */
function writeSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy","geolocation=(), microphone=(), camera=()");
  res.setHeader("Content-Security-Policy","default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';");
}
function sendJson(res, code, obj) {
  writeSecurityHeaders(res);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = Buffer.alloc(0), total = 0;
    req.on("data", c => { total += c.length; if (total > MAX_BODY_BYTES) { reject(new Error("Payload too large")); req.destroy(); return; } raw = Buffer.concat([raw,c]); });
    req.on("end", () => { if (!raw.length) return resolve({}); try { resolve(JSON.parse(raw.toString("utf8"))); } catch { reject(new Error("Invalid JSON")); } });
  });
}
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function clamp(n, min, max) { n = Number.isFinite(+n) ? +n : min; return Math.min(Math.max(n, min), max); }
function nowISO() { return new Date().toISOString(); }

/* ------------------ Auth ------------------ */
function authUserFromRequest(req) {
  const auth = req.headers["authorization"] || "";
  const m = auth.match(/^Bearer\s+(.+)$/i); if (!m) return null;
  const token = m[1].trim(); const row = qFindSession.get(token);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) { qDeleteSession.run(token); return null; }
  return { id: row.user_id, email: row.email, name: row.name, token };
}
const rlStore = new Map();
function rateLimitOk(ip, isAuthPath) {
  const now = Date.now(); let e = rlStore.get(ip);
  if (!e || now - e.windowStart >= RATE_LIMIT_WINDOW_MS) { e = { windowStart: now, countAuth: 0, countGeneric: 0 }; rlStore.set(ip, e); }
  if (isAuthPath) { e.countAuth++; return e.countAuth <= RATE_LIMIT_MAX_AUTH; }
  e.countGeneric++; return e.countGeneric <= RATE_LIMIT_MAX_GENERIC;
}

/* ------------------ THEME SYSTEM ------------------ */
const THEMES = {
  pastel: { bg:"#0b0c10", card:"#15171c", ink:"#e6e6e6", muted:"#9aa0a6", acc:"#7dd3fc", acc2:"#a78bfa", ok:"#86efac", err:"#fca5a5", chip:"#0f1116" },
  dark:   { bg:"#000",    card:"#0e0f12", ink:"#e4e4e7", muted:"#9ca3af", acc:"#60a5fa", acc2:"#22d3ee", ok:"#4ade80", err:"#f87171", chip:"#0a0a0b" },
  ocean:  { bg:"#071923", card:"#0c2733", ink:"#e6f6ff", muted:"#9bd1e5", acc:"#38bdf8", acc2:"#34d399", ok:"#86efac", err:"#fda4af", chip:"#0a2230" },
  forest: { bg:"#0b140e", card:"#132017", ink:"#e8f1ea", muted:"#a8bfae", acc:"#86efac", acc2:"#fde047", ok:"#86efac", err:"#fca5a5", chip:"#0f1b14" },
  rose:   { bg:"#1a1014", card:"#24141b", ink:"#ffeef4", muted:"#f4b4c8", acc:"#f472b6", acc2:"#a78bfa", ok:"#86efac", err:"#fca5a5", chip:"#1b0f14" },
  mono:   { bg:"#0e0e0e", card:"#151515", ink:"#ededed", muted:"#9e9e9e", acc:"#ededed", acc2:"#c2c2c2", ok:"#b7f0b4", err:"#f0b4b4", chip:"#0f0f0f" }
};
const THEME_KEYS = Object.keys(THEMES);

/* ------------------ SSE (tiempo real) ------------------ */
const sseClients = new Map(); // userId -> Set(res)
function sseAdd(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);
}
function sseRemove(userId, res) {
  const set = sseClients.get(userId); if (!set) return;
  set.delete(res); if (!set.size) sseClients.delete(userId);
}
function sseSendTo(userId, type, data) {
  const set = sseClients.get(userId); if (!set) return;
  const payload = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) try { res.write(payload); } catch {}
}
function sseBroadcast(type, data) {
  const payload = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const set of sseClients.values()) for (const res of set) { try { res.write(payload); } catch {} }
}

/* ------------------ UI (HTML embebido) ------------------ */
function cssForThemeVars() {
  let out = "";
  for (const [name, t] of Object.entries(THEMES)) {
    out += `[data-theme="${name}"]{--bg:${t.bg};--card:${t.card};--ink:${t.ink};--muted:${t.muted};--acc:${t.acc};--acc2:${t.acc2};--ok:${t.ok};--err:${t.err};--chip:${t.chip};}\n`;
  }
  return out;
}
const BASE_CSS = `
:root{--bg:#0b0c10;--card:#14161b;--ink:#e8e8ea;--muted:#9aa0a6;--acc:#7dd3fc;--acc2:#a78bfa;--ok:#86efac;--err:#fca5a5;--chip:#0f1116;}
${cssForThemeVars()}
*{box-sizing:border-box} body{margin:0;background:linear-gradient(180deg,var(--bg) 0%,#0d1016 100%);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto}
a{color:var(--acc)} input,button,textarea,select{font:inherit}
.app{max-width:1000px;margin:28px auto;padding:0 16px}
.nav{display:flex;gap:8px;position:sticky;top:0;background:rgba(11,12,16,.75);backdrop-filter:blur(8px);padding:12px 0;z-index:2}
.tab{padding:10px 12px;border-radius:12px;border:1px solid #23252c;background:var(--chip);cursor:pointer}
.tab[aria-current="page"]{background:linear-gradient(90deg,rgba(125,211,252,.15),rgba(167,139,250,.15));border-color:#2e3240}
.header{display:flex;gap:10px;align-items:center;margin:20px 0}
.card{background:var(--card);border:1px solid #23252c;border-radius:16px;padding:16px;box-shadow:0 6px 30px rgba(0,0,0,.25)}
.grid{display:grid;gap:12px}
.grid.cols-2{grid-template-columns:1fr 1fr}
.grid.cols-3{grid-template-columns:1fr 1fr 1fr}
h1{font-size:22px;margin:0}
h2{font-size:16px;margin:0 0 8px;color:var(--muted)}
hr{border:none;border-top:1px solid #242832;margin:12px 0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
input[type="text"],input[type="email"],input[type="password"],input[type="date"],textarea,select{
  width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a2e36;background:#0f1116;color:var(--ink)
}
button{padding:10px 12px;border:0;border-radius:10px;background:var(--acc);color:#082431;font-weight:700;cursor:pointer}
button.secondary{background:#2a2e36;color:var(--ink)}
button.ghost{background:transparent;border:1px solid #2a2e36;color:var(--ink)}
.btnbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px;align-items:center}
.list{list-style:none;margin:0;padding:0}
.item{display:flex;justify-content:space-between;align-items:center;padding:10px;border:1px solid #2a2e36;border-radius:12px;background:#0f1116;margin:6px 0}
.badge{padding:4px 8px;border-radius:999px;background:#1a1e27;border:1px solid #2a2e36;color:var(--muted)}
.muted{color:var(--muted)} .ok{color:var(--ok)} .err{color:var(--err)}
.avatar{width:40px;height:40px;border-radius:50%;object-fit:cover;border:1px solid #2a2e36;background:#0f1116}
textarea{min-height:70px}
.spacer{height:8px}
.search{padding:8px 10px;border-radius:10px;border:1px solid #2a2e36;background:#0f1116;color:var(--ink);width:100%}
.like{cursor:pointer;border:0;background:#1a1e27;color:var(--ink);padding:6px 10px;border-radius:999px}
.cmform{display:flex;gap:6px;margin-top:6px}
.cm{background:#0f1116;border:1px solid #2a2e36;border-radius:10px;padding:8px;margin:6px 0}
`;

const PAGE_LOGIN = `<!doctype html><meta charset="utf-8"><title>GroFriends — Login</title>
<style>${BASE_CSS}</style>
<body data-theme="pastel">
<div class="app">
  <div class="header"><h1>GroFriends</h1><span class="badge">Beta</span></div>
  <div class="card grid cols-2">
    <div>
      <h2>Accede</h2>
      <form id="loginForm" class="grid">
        <input id="email" type="email" placeholder="Email" required>
        <input id="password" type="password" placeholder="Password" required minlength="8">
        <div class="btnbar">
          <button>Entrar</button>
          <a class="tab" href="/ui/register">Crear cuenta</a>
        </div>
      </form>
      <div id="msg" class="muted"></div>
    </div>
    <div>
      <h2>Incluye</h2>
      <ul class="list">
        <li class="item"><span>Lista</span><span class="badge">Items</span></li>
        <li class="item"><span>Social</span><span class="badge">Feed + Likes/Comentarios</span></li>
        <li class="item"><span>Amigos + Chat</span><span class="badge">Tiempo real</span></li>
        <li class="item"><span>Metas</span><span class="badge">Públicas/Privadas</span></li>
      </ul>
    </div>
  </div>
</div>
<script>
const $ = s => document.querySelector(s);
document.body.setAttribute("data-theme","pastel");
$("#loginForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); $("#msg").textContent = "Autenticando…";
  try{
    const r = await fetch("/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},
      body: JSON.stringify({email: $("#email").value.trim().toLowerCase(), password: $("#password").value})});
    const j = await r.json();
    if(!j.ok){ $("#msg").innerHTML = '<span class="err">'+(j.error||'Error')+'</span>'; return; }
    localStorage.setItem("token", j.token); location.href="/app";
  }catch(err){ $("#msg").innerHTML = '<span class="err">'+err.message+'</span>'; }
});
</script></body>`;

const PAGE_REGISTER = `<!doctype html><meta charset="utf-8"><title>GroFriends — Registro</title>
<style>${BASE_CSS}</style>
<body data-theme="pastel">
<div class="app">
  <div class="header"><h1>Crear cuenta</h1></div>
  <div class="card">
    <form id="regForm" class="grid">
      <input id="email" type="email" placeholder="Email" required>
      <input id="name" type="text" placeholder="Nombre (opcional)">
      <input id="password" type="password" placeholder="Password (min 8)" required minlength="8">
      <div class="btnbar">
        <button>Registrar</button>
        <a class="tab" href="/ui">Iniciar sesión</a>
      </div>
    </form>
    <div id="msg" class="muted"></div>
  </div>
</div>
<script>
const $ = s => document.querySelector(s);
document.body.setAttribute("data-theme","pastel");
$("#regForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); $("#msg").textContent = "Creando usuario…";
  try{
    const body = { email: $("#email").value.trim().toLowerCase(), name: $("#name").value.trim(), password: $("#password").value };
    const r = await fetch("/auth/register",{method:"POST",headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
    const j = await r.json();
    if(!j.ok){ $("#msg").innerHTML = '<span class="err">'+(j.error||'Error')+'</span>'; return; }
    $("#msg").innerHTML = '<span class="ok">Cuenta creada. Redirigiendo…</span>';
    setTimeout(()=>location.href="/ui",700);
  }catch(err){ $("#msg").innerHTML = '<span class="err">'+err.message+'</span>'; }
});
</script></body>`;

const PAGE_APP = `<!doctype html><meta charset="utf-8"><title>GroFriends — App</title>
<style>${BASE_CSS}</style>
<body data-theme="pastel">
<div class="app">
  <div class="header">
    <img id="mePhoto" class="avatar" alt="">
    <div style="flex:1">
      <div id="me" class="muted">Cargando usuario…</div>
      <div class="muted" id="meSub"></div>
    </div>
    <div class="btnbar">
      <select id="themePicker"></select>
      <button id="logout" class="ghost">Salir</button>
    </div>
  </div>

  <nav class="nav">
    <a class="tab" data-tab="items" href="#items">Items</a>
    <a class="tab" data-tab="feed" href="#feed">Feed</a>
    <a class="tab" data-tab="friends" href="#friends">Amigos</a>
    <a class="tab" data-tab="dms" href="#dms">DMs</a>
    <a class="tab" data-tab="goals" href="#goals">Metas</a>
    <a class="tab" data-tab="profile" href="#profile">Perfil</a>
  </nav>

  <!-- ITEMS -->
  <section id="view-items" class="card" hidden>
    <h2>Tu lista</h2>
    <form id="itemForm" class="row">
      <input id="itemTitle" type="text" placeholder="Nuevo ítem" required>
      <input id="itemQty" type="text" value="1" style="max-width:100px">
      <button>Añadir</button>
    </form>
    <ul id="items" class="list"></ul>
  </section>

  <!-- FEED -->
  <section id="view-feed" class="card" hidden>
    <h2>Feed</h2>
    <form id="postForm" class="row">
      <input id="postText" type="text" placeholder="¿Qué quieres compartir?" required>
      <button>Publicar</button>
    </form>
    <ul id="feed" class="list"></ul>
    <div class="btnbar"><button id="moreFeed" class="secondary">Cargar más</button></div>
  </section>

  <!-- FRIENDS -->
  <section id="view-friends" class="card" hidden>
    <h2>Amigos</h2>
    <div class="grid cols-3">
      <div>
        <h3 class="muted" style="margin:0 0 6px">Invitar</h3>
        <form id="inviteForm" class="row">
          <input id="inviteEmail" type="email" placeholder="Email del amigo" required>
          <button>Invitar</button>
        </form>
        <hr>
        <h3 class="muted" style="margin:0 0 6px">Solicitudes recibidas</h3>
        <ul id="friendsIncoming" class="list"></ul>
      </div>
      <div>
        <h3 class="muted" style="margin:0 0 6px">Enviadas</h3>
        <ul id="friendsOutgoing" class="list"></ul>
      </div>
      <div>
        <h3 class="muted" style="margin:0 0 6px">Tus amigos</h3>
        <ul id="friendsList" class="list"></ul>
      </div>
    </div>
  </section>

  <!-- DMs -->
  <section id="view-dms" class="card" hidden>
    <h2>Mensajes</h2>
    <div class="grid cols-2">
      <div>
        <input id="dmSearch" class="search" type="text" placeholder="Buscar amigo…">
        <ul id="dmFriends" class="list" style="max-height:320px;overflow:auto;margin-top:8px"></ul>
      </div>
      <div>
        <div class="row">
          <span id="dmWith" class="badge">Selecciona un amigo</span>
          <button id="dmLoadMore" class="ghost" style="margin-left:auto">Cargar más</button>
        </div>
        <ul id="dmList" class="list" style="max-height:300px;overflow:auto"></ul>
        <form id="dmForm" class="row">
          <input id="dmText" type="text" placeholder="Escribe un mensaje…" required>
          <button>Enviar</button>
        </form>
      </div>
    </div>
  </section>

  <!-- GOALS -->
  <section id="view-goals" class="card" hidden>
    <h2>Metas</h2>
    <form id="goalForm" class="grid">
      <input id="goalTitle" type="text" placeholder="Título de la meta" required>
      <input id="goalDate" type="date">
      <div class="btnbar"><button>Crear</button></div>
    </form>
    <ul id="goals" class="list"></ul>
  </section>

  <!-- PROFILE -->
  <section id="view-profile" class="card" hidden>
    <h2>Perfil</h2>
    <div class="grid cols-2">
      <div class="grid">
        <div class="kv"><div>Nombre</div><input id="profName" type="text" placeholder="Tu nombre"></div>
        <div class="kv"><div>Idioma</div>
          <select id="profLocale"><option value="auto">Auto</option><option value="es">Español</option><option value="en">English</option></select>
        </div>
        <div class="kv"><div>Tema</div>
          <select id="profTheme"></select>
        </div>
        <div class="btnbar">
          <button id="savePrefs">Guardar</button>
          <button id="delAccount" class="ghost">Borrar cuenta</button>
        </div>
      </div>
      <div>
        <div class="row">
          <img id="profPhoto" class="avatar" alt="">
          <input type="file" id="photoFile" accept="image/*">
        </div>
        <div class="spacer"></div>
        <button id="savePhoto" class="secondary">Actualizar foto</button>
      </div>
    </div>
    <div id="pmsg" class="muted"></div>
  </section>

  <!-- FRIEND PROFILE -->
  <div id="friendModal" class="card" style="position:fixed;right:16px;bottom:16px;max-width:420px;display:none">
    <div class="row">
      <img id="fPhoto" class="avatar" alt="">
      <div>
        <div id="fName"></div>
        <div id="fEmail" class="muted"></div>
      </div>
      <button id="fClose" class="ghost" style="margin-left:auto">Cerrar</button>
    </div>
    <hr>
    <div>
      <h3 class="muted" style="margin:0 0 6px">Metas públicas</h3>
      <ul id="fGoals" class="list"></ul>
      <h3 class="muted" style="margin:10px 0 6px">Feed reciente</h3>
      <ul id="fFeed" class="list"></ul>
    </div>
  </div>

</div>
<script>
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const token = localStorage.getItem("token");
if(!token){ location.href="/ui"; }
function headers(){ return {"Content-Type":"application/json","Authorization":"Bearer "+token}; }
async function api(path, opts={}) {
  const r = await fetch(path, Object.assign({headers: headers()}, opts));
  const ct = r.headers.get("content-type")||"";
  if(ct.includes("application/json")){
    const j = await r.json();
    if(!j.ok) throw new Error(j.error||"Error");
    return j;
  } else { throw new Error("Respuesta no JSON"); }
}

// THEMES
const THEMES = ${JSON.stringify(THEME_KEYS)};
function fillThemePickers(current){
  const sel = $("#themePicker"); const sel2 = $("#profTheme");
  sel.innerHTML = ""; sel2.innerHTML = "";
  for(const t of THEMES){
    const o = document.createElement("option"); o.value=t; o.textContent=t;
    const o2 = document.createElement("option"); o2.value=t; o2.textContent=t;
    sel.append(o); sel2.append(o2);
  }
  sel.value = current; sel2.value = current;
}
function applyTheme(name){
  document.body.setAttribute("data-theme", name);
  localStorage.setItem("theme_override", name);
}

function activate(tab){
  $$(".tab").forEach(t => t.setAttribute("aria-current", t.dataset.tab===tab ? "page":"false"));
  $$("#view-items,#view-feed,#view-friends,#view-dms,#view-goals,#view-profile").forEach(s=>s.hidden=true);
  $("#view-"+tab).hidden = false;
  if(tab==="items") loadItems();
  if(tab==="feed") refreshFeed(true);
  if(tab==="friends") loadFriends();
  if(tab==="dms") { loadDMFriends(); }
  if(tab==="goals") loadGoals();
  if(tab==="profile") loadPrefs();
}
window.addEventListener("hashchange", ()=>{
  const tab = (location.hash||"#items").slice(1);
  activate(tab);
});
activate((location.hash||"#items").slice(1));

async function loadMe(){
  try{
    const j = await api("/auth/me",{method:"GET"});
    $("#me").textContent = j.user.name ? (j.user.name+" — "+j.user.email) : j.user.email;
    $("#meSub").textContent = new Date(j.user.created_at).toLocaleString();
    $("#mePhoto").src = j.user.photo_base64 || "";
    const theme = localStorage.getItem("theme_override") || j.user.theme || "pastel";
    applyTheme(theme);
    fillThemePickers(theme);
    openSSE(); // <- engancha tiempo real tras conocerme
  }catch(e){ localStorage.removeItem("token"); location.href="/ui"; }
}
$("#themePicker").addEventListener("change", async (e)=>{
  const theme = e.target.value;
  applyTheme(theme);
  try{ await api("/prefs",{method:"POST", body: JSON.stringify({name: $("#profName").value||"", locale:"auto", theme})}); }catch{}
});

// ITEMS
async function loadItems(){
  const {items} = await api("/items",{method:"GET"});
  const ul = $("#items"); ul.innerHTML="";
  for(const it of items){
    const li = document.createElement("li"); li.className="item";
    const left = document.createElement("div");
    left.textContent = it.title+" × "+it.qty+" ";
    const meta = document.createElement("span"); meta.className="muted"; meta.textContent = "("+new Date(it.created_at).toLocaleString()+")";
    left.append(meta);
    if(it.done) left.style.textDecoration="line-through";
    const right = document.createElement("div"); right.className="btnbar";
    const b1 = document.createElement("button"); b1.textContent = it.done ? "Desmarcar" : "Hecho";
    b1.onclick = async ()=>{ await api("/items/"+it.id+"/toggle",{method:"POST"}); loadItems(); };
    const b2 = document.createElement("button"); b2.className="secondary"; b2.textContent = "Borrar";
    b2.onclick = async ()=>{ await fetch("/items/"+it.id,{method:"DELETE",headers:headers()}); loadItems(); };
    right.append(b1,b2); li.append(left,right); ul.append(li);
  }
}
$("#itemForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const title = $("#itemTitle").value.trim();
  const qty = parseInt($("#itemQty").value||1,10);
  if(!title) return;
  await api("/items",{method:"POST", body: JSON.stringify({title, qty, note:""})});
  $("#itemTitle").value=""; $("#itemQty").value="1";
  loadItems();
});

// FEED
let feedOffset = 0;
function renderPost(p, ul){
  const li = document.createElement("li"); li.className="item";
  const left = document.createElement("div");
  const strong = document.createElement("strong"); strong.textContent = (p.name||p.email||"") + " ";
  const content = document.createTextNode("— "+p.content);
  const meta = document.createElement("div"); meta.className="muted"; meta.textContent = new Date(p.created_at).toLocaleString();
  const actions = document.createElement("div"); actions.className="row";
  const like = document.createElement("button"); like.className="like"; like.textContent = "♥ "+(p.like_count||0);
  like.onclick = async ()=>{
    try {
      const j = await api("/feed/"+p.id+"/like",{method:"POST"});
      like.textContent = "♥ "+j.like_count;
    } catch(e){}
  };
  const cmForm = document.createElement("form"); cmForm.className="cmform";
  cmForm.innerHTML = '<input type="text" placeholder="Comenta…" style="flex:1"><button class="secondary">Enviar</button>';
  cmForm.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const txt = cmForm.querySelector("input").value.trim(); if(!txt) return;
    await api("/feed/"+p.id+"/comment",{method:"POST", body: JSON.stringify({text: txt})});
    cmForm.querySelector("input").value="";
    // pedir comentarios y re-render block
    const det = await api("/feed/"+p.id,{method:"GET"});
    renderComments(det.comments, cmWrap);
  });
  const cmWrap = document.createElement("div");
  actions.append(like, cmForm);
  left.append(strong, content, meta, actions, cmWrap);
  li.append(left);
  ul.append(li);
  // cargar comentarios lazy
  (async ()=>{ try{ const det = await api("/feed/"+p.id,{method:"GET"}); renderComments(det.comments, cmWrap); }catch{} })();
}
function renderComments(list, wrap){
  wrap.innerHTML="";
  for(const c of list){
    const d = document.createElement("div"); d.className="cm";
    d.textContent = (c.name||c.email)+": "+c.text+" — "+new Date(c.created_at).toLocaleString();
    wrap.append(d);
  }
}
async function refreshFeed(reset=false){
  if(reset){ feedOffset = 0; $("#feed").innerHTML=""; }
  const j = await api("/feed?limit=10&offset="+feedOffset,{method:"GET"});
  const ul = $("#feed");
  for(const p of j.posts){ renderPost(p, ul); }
  feedOffset += j.posts.length;
}
$("#postForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const content = $("#postText").value.trim();
  if(!content) return;
  await api("/feed",{method:"POST", body: JSON.stringify({content})});
  $("#postText").value="";
  // el SSE empuja; por si acaso:
  refreshFeed(true);
});
$("#moreFeed").addEventListener("click", ()=>refreshFeed(false));

// FRIENDS
function splitFriends(rows, meId){
  const incoming = [], outgoing = [], accepted = [];
  for(const f of rows){
    if(f.status==="accepted"){ accepted.push(f); }
    else if(f.status==="pending" && f.requested_by !== meId){ incoming.push(f); }
    else if(f.status==="pending" && f.requested_by === meId){ outgoing.push(f); }
  }
  return {incoming, outgoing, accepted};
}
async function loadFriends(){
  const jMe = await api("/auth/me",{method:"GET"});
  const meId = jMe.user.id;
  const j = await api("/friends",{method:"GET"});
  const incomingEl = $("#friendsIncoming"), outgoingEl = $("#friendsOutgoing"), listEl = $("#friendsList");
  incomingEl.innerHTML=""; outgoingEl.innerHTML=""; listEl.innerHTML="";
  const parts = splitFriends(j.friends_ext || j.friends, meId);
  const mkEmpty = (el, txt) => { const li = document.createElement("li"); li.className="item"; li.innerHTML = '<span class="muted">'+txt+'</span>'; el.append(li); };

  // incoming
  if(!parts.incoming.length) mkEmpty(incomingEl,"No tienes solicitudes.");
  else for(const f of parts.incoming){
    const li = document.createElement("li"); li.className="item";
    li.innerHTML = '<div><strong>'+ (f.friend_name||f.friend_email) +'</strong><div class="muted">'+f.friend_email+'</div></div>';
    const bar = document.createElement("div"); bar.className="btnbar";
    const acc = document.createElement("button"); acc.textContent="Aceptar";
    acc.onclick = async ()=>{ await api("/friends/accept",{method:"POST", body: JSON.stringify({friendship_id:f.id})}); loadFriends(); };
    const rej = document.createElement("button"); rej.className="secondary"; rej.textContent="Rechazar";
    rej.onclick = async ()=>{ await api("/friends/remove",{method:"POST", body: JSON.stringify({friendship_id:f.id})}); loadFriends(); };
    bar.append(acc, rej); li.append(bar); incomingEl.append(li);
  }
  // outgoing
  if(!parts.outgoing.length) mkEmpty(outgoingEl,"No has enviado invitaciones.");
  else for(const f of parts.outgoing){
    const li = document.createElement("li"); li.className="item";
    li.innerHTML = '<div><strong>'+ (f.friend_name||f.friend_email) +'</strong><div class="muted">'+f.friend_email+'</div></div>';
    const cancel = document.createElement("button"); cancel.className="secondary"; cancel.textContent="Cancelar";
    cancel.onclick = async ()=>{ await api("/friends/cancel",{method:"POST", body: JSON.stringify({friendship_id:f.id})}); loadFriends(); };
    li.append(cancel); outgoingEl.append(li);
  }
  // accepted
  if(!parts.accepted.length) mkEmpty(listEl,"Aún no tienes amigos.");
  else for(const f of parts.accepted){
    const li = document.createElement("li"); li.className="item";
    li.innerHTML = '<div><strong>'+ (f.friend_name||f.friend_email) +'</strong><div class="muted">'+f.friend_email+'</div></div>';
    const bar = document.createElement("div"); bar.className="btnbar";
    const prof = document.createElement("button"); prof.textContent="Ver perfil";
    prof.onclick = ()=>openFriendProfile(f.friend_id);
    const chat = document.createElement("button"); chat.className="secondary"; chat.textContent="Chat";
    chat.onclick = ()=>{ location.hash="#dms"; setTimeout(()=>selectDMFriend(f.friend_id, (f.friend_name||f.friend_email)), 0); };
    const rm = document.createElement("button"); rm.className="ghost"; rm.textContent="Eliminar";
    rm.onclick = async ()=>{ await api("/friends/remove",{method:"POST", body: JSON.stringify({friendship_id:f.id})}); loadFriends(); };
    bar.append(prof, chat, rm); li.append(bar); listEl.append(li);
  }
}
$("#inviteForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const email = $("#inviteEmail").value.trim().toLowerCase(); if(!email) return;
  try{ await api("/friends/invite",{method:"POST", body: JSON.stringify({email})}); $("#inviteEmail").value=""; loadFriends(); }
  catch(err){ alert(err.message); }
});

// Friend profile modal
async function openFriendProfile(fid){
  try{
    const j = await api("/users/"+fid+"/profile",{method:"GET"});
    $("#fPhoto").src = j.profile.photo_base64 || "";
    $("#fName").textContent = j.profile.name || j.profile.email;
    $("#fEmail").textContent = j.profile.email;
    const gUl = $("#fGoals"); gUl.innerHTML="";
    for(const g of j.goals){
      const li = document.createElement("li"); li.className="item";
      const d = g.target_date ? new Date(g.target_date).toLocaleDateString() : "—";
      li.textContent = g.title+" (fecha: "+d+")";
      gUl.append(li);
    }
    const fUl = $("#fFeed"); fUl.innerHTML="";
    for(const p of j.feed){
      const li = document.createElement("li"); li.className="item";
      li.textContent = p.content+" — "+new Date(p.created_at).toLocaleString();
      fUl.append(li);
    }
    $("#friendModal").style.display="block";
  }catch(e){ alert(e.message); }
}
$("#fClose").addEventListener("click", ()=>{ $("#friendModal").style.display="none"; });

// DMs (SSE actualiza solo)
let currentDM = null, dmOffset = 0;
$("#dmSearch").addEventListener("input", ()=>loadDMFriends());
async function loadDMFriends(){
  const q = $("#dmSearch").value.trim().toLowerCase();
  const j = await api("/friends",{method:"GET"});
  const ul = $("#dmFriends"); ul.innerHTML="";
  const all = j.friends.filter(x=>x.status==="accepted");
  const filtered = q ? all.filter(f => (f.friend_name||"").toLowerCase().includes(q) || (f.friend_email||"").toLowerCase().includes(q)) : all;
  if(!filtered.length){
    const li = document.createElement("li"); li.className="item";
    li.innerHTML = '<span class="muted">Sin resultados.</span>'; ul.append(li);
  } else {
    for(const f of filtered){
      const li = document.createElement("li"); li.className="item";
      const name = f.friend_name || f.friend_email;
      li.innerHTML = '<div><strong>'+name+'</strong><div class="muted">'+f.friend_email+'</div></div>';
      const btn = document.createElement("button"); btn.textContent="Chat";
      btn.onclick = ()=>selectDMFriend(f.friend_id, name);
      li.append(btn); ul.append(li);
    }
  }
}
async function selectDMFriend(id, name){
  currentDM = id;
  $("#dmWith").textContent = "Hablando con: "+name;
  await loadDMs(true);
}
async function loadDMs(reset=false){
  if(!currentDM) return;
  if(reset){ dmOffset=0; $("#dmList").innerHTML=""; }
  const j = await api("/dm?friend_id="+currentDM+"&limit=20&offset="+dmOffset,{method:"GET"});
  const ul = $("#dmList");
  for(const m of j.messages){
    const li = document.createElement("li"); li.className="item";
    li.style.justifyContent = m.mine ? "flex-end" : "flex-start";
    li.innerHTML = '<div>'+m.text+'<div class="muted">'+new Date(m.created_at).toLocaleString()+'</div></div>';
    ul.append(li);
  }
  dmOffset += j.messages.length;
  ul.scrollTop = ul.scrollHeight;
}
$("#dmForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  if(!currentDM) return;
  const text = $("#dmText").value.trim(); if(!text) return;
  await api("/dm/send",{method:"POST", body: JSON.stringify({friend_id: currentDM, text})});
  $("#dmText").value="";
});

// GOALS
async function loadGoals(){
  const j = await api("/goals",{method:"GET"});
  const ul = $("#goals"); ul.innerHTML="";
  for(const g of j.goals){
    const li = document.createElement("li"); li.className="item";
    const d = g.target_date ? new Date(g.target_date).toLocaleDateString() : "—";
    const left = document.createElement("div");
    left.innerHTML = '<strong>'+g.title+'</strong> · fecha: '+d+' · '+(g.is_public?'<span class="badge">Pública</span>':'<span class="badge">Privada</span>');
    const bar = document.createElement("div"); bar.className="btnbar";
    if(!g.is_public){
      const b = document.createElement("button"); b.textContent="Publicar";
      b.onclick = async ()=>{ await api("/goals/"+g.id+"/publish",{method:"POST"}); loadGoals(); };
      bar.append(b);
    }
    li.append(left, bar); ul.append(li);
  }
}
$("#goalForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const title = $("#goalTitle").value.trim();
  const target_date = $("#goalDate").value ? $("#goalDate").value : null;
  if(!title) return;
  await api("/goals",{method:"POST", body: JSON.stringify({title, target_date})});
  $("#goalTitle").value=""; $("#goalDate").value="";
  loadGoals();
});

// PROFILE
async function loadPrefs(){
  const j = await api("/prefs",{method:"GET"});
  $("#profName").value = j.prefs.name || "";
  $("#profLocale").value = j.prefs.locale || "auto";
  const theme = localStorage.getItem("theme_override") || j.prefs.theme || "pastel";
  fillThemePickers(theme);
  applyTheme(theme);
  $("#profPhoto").src = j.prefs.photo_base64 || "";
}
$("#savePrefs").addEventListener("click", async ()=>{
  const name = $("#profName").value.trim();
  const locale = $("#profLocale").value;
  const theme = $("#profTheme").value;
  await api("/prefs",{method:"POST", body: JSON.stringify({name, locale, theme})});
  localStorage.setItem("theme_override", theme);
  applyTheme(theme);
  $("#pmsg").innerHTML = '<span class="ok">Preferencias guardadas.</span>';
  loadMe();
});
$("#savePhoto").addEventListener("click", async ()=>{
  const f = $("#photoFile").files[0]; if(!f) return alert("Selecciona una imagen");
  const reader = new FileReader();
  reader.onload = async () => {
    const data_url = reader.result.toString();
    try{
      await api("/photo",{method:"POST", body: JSON.stringify({data_url})});
      $("#pmsg").innerHTML = '<span class="ok">Foto actualizada.</span>';
      loadMe(); loadPrefs();
    }catch(err){ $("#pmsg").innerHTML = '<span class="err">'+err.message+'</span>'; }
  };
  reader.readAsDataURL(f);
});
$("#delAccount").addEventListener("click", async ()=>{
  if(!confirm("¿Seguro que quieres borrar tu cuenta?")) return;
  try{ await api("/account/delete",{method:"POST"});}catch{}
  localStorage.removeItem("token"); location.href="/ui";
});

// logout
$("#logout").onclick = async ()=>{
  try{ await api("/auth/logout",{method:"POST"}); }catch{}
  localStorage.removeItem("token"); location.href="/ui";
};

// SSE (tiempo real)
let es=null;
function openSSE(){
  try{
    if(es) es.close();
    es = new EventSource("/events?token="+encodeURIComponent(token));
    es.addEventListener("open", ()=>{/* ok */});
    es.addEventListener("error", ()=>{/* silencioso */});
    es.addEventListener("feed:new", (ev)=>{ try{ const p = JSON.parse(ev.data); const ul=$("#feed"); if(ul) renderPost(p, ul); }catch{} });
    es.addEventListener("feed:update", ()=>{ /* para likes/comentarios si quieres refrescar */ });
    es.addEventListener("dm:new", async (ev)=>{ try{ const m = JSON.parse(ev.data); if(currentDM && +currentDM===+m.sender_id){ await loadDMs(true); } }catch{} });
  }catch{}
}

(async function init(){ await loadMe(); const tab = (location.hash||"#items").slice(1); activate(tab); })();
</script></body>`;

/* ------------------ Servidor HTTP + API ------------------ */
const server = http.createServer(async (req, res) => {
  writeSecurityHeaders(res);

  const ip = req.socket.remoteAddress || "unknown";
  const urlObj = new URL(req.url, `http://localhost:${PORT}`);
  let path = urlObj.pathname || "/";
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

  const isAuth = path.startsWith("/auth/");
  if (!rateLimitOk(ip, isAuth)) return sendJson(res, 429, { ok:false, error:"Too many requests" });

  if (path === "/favicon.ico") { res.writeHead(204); return res.end(); }

  /* UI */
  if (req.method === "GET" && path === "/ui") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(PAGE_LOGIN); }
  if (req.method === "GET" && path === "/ui/register") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(PAGE_REGISTER); }
  if (req.method === "GET" && path === "/app") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(PAGE_APP); }

  /* raíz */
  if (req.method === "GET" && path === "/") {
    const u = authUserFromRequest(req);
    if (u) { res.writeHead(302, { Location: "/app" }); return res.end(); }
    res.writeHead(302, { Location: "/ui" }); return res.end();
  }

  /* -------- AUTH -------- */
  if (req.method === "POST" && path === "/auth/register") {
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      const name = (b.name || "").trim();
      const password = b.password || "";
      if (!email || !isValidEmail(email)) return sendJson(res, 400, { ok:false, error:"Invalid email" });
      if (typeof password !== "string" || password.length < PASSWORD_MIN_LEN || password.length > PASSWORD_MAX_LEN) return sendJson(res, 400, { ok:false, error:"Invalid password length" });
      if (qUserByEmail.get(email)) return sendJson(res, 409, { ok:false, error:"Email already registered" });
      const password_hash = bcrypt.hashSync(password, 10);
      qInsertUser.run({ email, password_hash, name, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  if (req.method === "POST" && path === "/auth/login") {
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      const password = b.password || "";
      const invalid = () => sendJson(res, 401, { ok:false, error:"Invalid credentials" });
      if (!email || !isValidEmail(email)) return invalid();
      const u = qUserByEmail.get(email); if (!u) return invalid();
      if (!bcrypt.compareSync(password, u.password_hash)) return invalid();
      const token = crypto.randomBytes(32).toString("hex");
      const created_at = nowISO();
      const expires_at = new Date(Date.now()+SESSION_TTL_MS).toISOString();
      qInsertSession.run({ user_id: u.id, token, created_at, expires_at });
      return sendJson(res, 200, { ok:true, token });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  if (req.method === "GET" && path === "/auth/me") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized (no/invalid/expired token)" });
    const row = qUserById.get(u.id); return sendJson(res, 200, { ok:true, user: row });
  }

  if (req.method === "POST" && path === "/auth/logout") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    qDeleteSession.run(u.token); return sendJson(res, 200, { ok:true });
  }

  /* -------- SSE -------- */
  if (req.method === "GET" && path === "/events") {
    // token via query (SSE no soporta headers custom fácilmente)
    const token = urlObj.searchParams.get("token") || "";
    const row = qFindSession.get(token);
    if (!row || new Date(row.expires_at).getTime() < Date.now()) {
      res.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Unauthorized");
    }
    const userId = row.user_id;
    res.writeHead(200, {
      "Content-Type":"text/event-stream",
      "Cache-Control":"no-cache",
      "Connection":"keep-alive",
      "X-Accel-Buffering":"no"
    });
    res.write("event: ping\ndata: {}\n\n");
    sseAdd(userId, res);
    req.on("close", ()=>sseRemove(userId, res));
    return; // mantener abierta
  }

  /* -------- PREFS / PROFILE -------- */
  if (req.method === "GET" && path === "/prefs") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const row = db.prepare(`SELECT name, locale, theme, photo_base64 FROM users WHERE id=?`).get(u.id);
    return sendJson(res, 200, { ok:true, prefs: row });
  }
  if (req.method === "POST" && path === "/prefs") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const name = (b.name || "").toString().trim();
      let locale = (b.locale || "auto").toString().trim(); if (!["auto","en","es"].includes(locale)) locale = "auto";
      let theme = (b.theme || "pastel").toString().trim();
      if (!THEME_KEYS.includes(theme)) theme = "pastel";
      qUpdateUserPrefs.run({ id: u.id, name, locale, theme });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path === "/photo") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const data = (b.data_url || "").toString();
      if (!data.startsWith("data:image/")) return sendJson(res, 400, { ok:false, error:"Invalid image" });
      if (Buffer.byteLength(data, "utf8") > 500_000) return sendJson(res, 400, { ok:false, error:"Image too large" });
      qUpdateUserPhoto.run({ id: u.id, photo: data });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path === "/account/delete") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    qDeleteUser.run(u.id); return sendJson(res, 200, { ok:true });
  }

  /* -------- ITEMS -------- */
  if (req.method === "GET" && path === "/items") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = qListItems.all(u.id);
    return sendJson(res, 200, { ok:true, items: rows });
  }
  if (req.method === "POST" && path === "/items") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const qty = Math.max(1, Math.min(9999, parseInt(b.qty || 1, 10) || 1));
      const note = (b.note || "").toString().trim();
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      qInsertItem.run({ user_id: u.id, title, qty, note, done: 0, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path.startsWith("/items/") && path.endsWith("/toggle")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(path.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    qToggleItem.run(id, u.id); return sendJson(res, 200, { ok:true });
  }
  if (req.method === "DELETE" && path.startsWith("/items/")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(path.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    qDeleteItem.run(id, u.id); return sendJson(res, 200, { ok:true });
  }

  /* -------- FRIENDS -------- */
  if (req.method === "GET" && path === "/friends") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = qListFriendsRaw.all({ me: u.id }).map(r => ({
      id: r.id, friend_id: r.friend_id, friend_name: r.friend_name, friend_email: r.friend_email,
      status: r.status, requested_by: r.requested_by, can_accept: r.status === "pending" && r.requested_by !== u.id
    }));
    return sendJson(res, 200, { ok:true, friends: rows, friends_ext: rows });
  }
  if (req.method === "POST" && path === "/friends/invite") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      if (!email || !isValidEmail(email)) return sendJson(res, 400, { ok:false, error:"Invalid email" });
      const other = qFindUserByEmailPublic.get(email);
      if (!other) return sendJson(res, 404, { ok:false, error:"User not found" });
      if (other.id === u.id) return sendJson(res, 400, { ok:false, error:"Cannot invite yourself" });
      const [a, b2] = canonicalPair(u.id, other.id);
      const existing = qFindFriendship.get(a, b2);
      if (existing) return sendJson(res, 409, { ok:false, error:"Already invited or friends" });
      qInsertFriendship.run({ user_a: a, user_b: b2, status: "pending", requested_by: u.id, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path === "/friends/accept") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = db.prepare(`SELECT * FROM friendships WHERE id=?`).get(fid);
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      qUpdateFriendshipStatus.run({ id: fid, status: "accepted" }); return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && (path === "/friends/cancel" || path === "/friends/remove")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try{
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = db.prepare(`SELECT * FROM friendships WHERE id=?`).get(fid);
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      qDeleteFriendship.run(fid);
      return sendJson(res, 200, { ok:true });
    }catch{ return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  /* -------- GOALS + FEED -------- */
  if (req.method === "GET" && path === "/goals") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = qListGoals.all(u.id);
    return sendJson(res, 200, { ok:true, goals: rows });
  }
  if (req.method === "POST" && path === "/goals") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const target_date = (b.target_date || null) ? String(b.target_date) : null;
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      const info = qInsertGoal.run({ user_id:u.id, title, target_date, is_public:0, created_at: nowISO() });
      return sendJson(res, 201, { ok:true, goal_id: info.lastInsertRowid });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path.startsWith("/goals/") && path.endsWith("/publish")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(path.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    qMakeGoalPublic.run(id, u.id);
    const g = db.prepare(`SELECT title FROM goals WHERE id=? AND user_id=?`).get(id, u.id);
    if (g) {
      qInsertFeed.run({ user_id: u.id, goal_id: id, content: "New goal: " + g.title, created_at: nowISO() });
      // broadcast feed
      const post = db.prepare(`SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email,
        (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
        (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
      FROM feed_posts f JOIN users u ON u.id=f.user_id WHERE f.id=?`).get(db.prepare("SELECT last_insert_rowid() as id").get().id);
      sseBroadcast("feed:new", post || {content:"New goal", created_at: nowISO()});
    }
    return sendJson(res, 200, { ok:true });
  }

  if (req.method === "GET" && path === "/feed") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const limit = clamp((new URL(req.url, `http://localhost:${PORT}`)).searchParams.get("limit"), 1, 50);
    const offset = clamp((new URL(req.url, `http://localhost:${PORT}`)).searchParams.get("offset"), 0, 10_000);
    const rows = qListFeed.all(limit, offset);
    return sendJson(res, 200, { ok:true, posts: rows });
  }
  if (req.method === "GET" && path.startsWith("/feed/") && !path.endsWith("/like") && !path.endsWith("/comment")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(path.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const comments = qListComments.all(pid).map(c => ({ id:c.id, text:c.text, created_at:c.created_at, name:c.name, email:c.email }));
    return sendJson(res, 200, { ok:true, comments });
  }
  if (req.method === "POST" && path === "/feed") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const content = (b.content || "").toString().trim();
      if (!content) return sendJson(res, 400, { ok:false, error:"Missing content" });
      const created_at = nowISO();
      const info = qInsertFeed.run({ user_id:u.id, goal_id: null, content, created_at });
      const post = db.prepare(`
        SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email,
               0 as like_count, 0 as comment_count
        FROM feed_posts f JOIN users u ON u.id=f.user_id WHERE f.id=?`).get(info.lastInsertRowid);
      sseBroadcast("feed:new", post);
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && path.startsWith("/feed/") && path.endsWith("/like")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(path.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const liked = !!qUserLikedPost.get(pid, u.id);
    if (liked) qUnlikePost.run(pid, u.id);
    else qLikePost.run(pid, u.id, nowISO());
    const count = qCountLikes.get(pid).c|0;
    sseBroadcast("feed:update", { post_id: pid, like_count: count });
    return sendJson(res, 200, { ok:true, like_count: count, liked: !liked });
  }
  if (req.method === "POST" && path.startsWith("/feed/") && path.endsWith("/comment")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(path.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const b = await readJsonBody(req);
    const text = (b.text || "").toString().trim();
    if (!text) return sendJson(res, 400, { ok:false, error:"Missing text" });
    qAddComment.run(pid, u.id, text, nowISO());
    sseBroadcast("feed:update", { post_id: pid, comment_added: true });
    return sendJson(res, 201, { ok:true });
  }

  /* -------- DMs -------- */
  if (req.method === "GET" && path === "/dm") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const friend_id = Number(url.searchParams.get("friend_id")||0);
    if (!friend_id) return sendJson(res, 400, { ok:false, error:"Missing friend_id" });
    const [a,b] = canonicalPair(u.id, friend_id);
    const f = qFindFriendship.get(a, b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const limit = clamp(url.searchParams.get("limit"), 1, 100);
    const offset = clamp(url.searchParams.get("offset"), 0, 1_000_000);
    const rows = qListDM.all({ me:u.id, friend:friend_id, limit, offset }).map(m => ({ id:m.id, text:m.text, created_at:m.created_at, mine:m.sender_id===u.id, sender_id:m.sender_id }));
    return sendJson(res, 200, { ok:true, messages: rows });
  }
  if (req.method === "POST" && path === "/dm/send") {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const friend_id = Number(b.friend_id || 0);
      const text = (b.text || "").toString().trim();
      if (!friend_id || !text) return sendJson(res, 400, { ok:false, error:"Missing friend_id or text" });
      const [a,bp] = canonicalPair(u.id, friend_id);
      const f = qFindFriendship.get(a, bp);
      if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
      const created_at = nowISO();
      qInsertDM.run({ sender_id:u.id, receiver_id:friend_id, text, created_at });
      // push a ambos
      sseSendTo(friend_id, "dm:new", { sender_id:u.id, text, created_at });
      sseSendTo(u.id, "dm:new", { sender_id:u.id, text, created_at });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  /* -------- FRIEND PUBLIC PROFILE -------- */
  if (req.method === "GET" && path.startsWith("/users/") && path.endsWith("/profile")) {
    const u = authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(path.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const [a,b] = canonicalPair(u.id, id);
    const f = qFindFriendship.get(a,b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const profile = qFindUserPublicById.get(id);
    if (!profile) return sendJson(res, 404, { ok:false, error:"User not found" });
    const goals = db.prepare(`SELECT id, title, target_date FROM goals WHERE user_id=? AND is_public=1 ORDER BY id DESC LIMIT 10`).all(id);
    const feed = qListFeedByUser.all(id, 10, 0);
    return sendJson(res, 200, { ok:true, profile, goals, feed });
  }

  /* 404 */
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found: " + path);
});

server.listen(PORT, () => {
  console.log("Listening on http://localhost:" + PORT + "  -> open /ui to login");
});
