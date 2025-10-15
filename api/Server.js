// api/[...path].js
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { URL } from "url";
import {
  ensureSchema,
  // users/sessions
  userByEmail, userById, insertUser, updateUserPrefs, updateUserPhoto, deleteUser_ as deleteUser,
  insertSession, findSession, deleteSession_ as deleteSession,
  // items
  insertItem_ as insertItem, listItems_ as listItems, toggleItem_ as toggleItem, deleteItem_ as deleteItem,
  // friends
  canonicalPair, findFriendship_ as findFriendship, insertFriendship_ as insertFriendship,
  updateFriendshipStatus_ as updateFriendshipStatus, deleteFriendship_ as deleteFriendship, listFriendsRaw_ as listFriendsRaw,
  // goals + feed
  insertGoal_ as insertGoal, listGoals_ as listGoals, makeGoalPublic_ as makeGoalPublic, insertFeed_ as insertFeed,
  listFeed_ as listFeed, listFeedByUser_ as listFeedByUser,
  userLikedPost_ as userLikedPost, likePost_ as likePost, unlikePost_ as unlikePost, countLikes_ as countLikes,
  addComment_ as addComment, listComments_ as listComments,
  // users public
  findUserByEmailPublic_ as findUserByEmailPublic, findUserPublicById_ as findUserPublicById,
  // dms
  insertDM_ as insertDM, listDM_ as listDM, maxId_ as maxId
} from "./db.js";

// -------- Config --------
const MAX_BODY_BYTES = 256 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_AUTH = 40;
const RATE_LIMIT_MAX_GENERIC = 300;
const PASSWORD_MIN_LEN = 8;
const PASSWORD_MAX_LEN = 72;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días

const THEMES = { pastel:{}, dark:{}, ocean:{}, forest:{}, rose:{}, mono:{} };
const THEME_KEYS = Object.keys(THEMES);

// -------- Utils --------
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
    req.on("data", c => { total += c.length; if (total > MAX_BODY_BYTES) { reject(new Error("Payload too large")); req.destroy(); return; } raw = Buffer.concat([raw,c]); });
    req.on("end", () => { if (!raw.length) return resolve({}); try { resolve(JSON.parse(raw.toString("utf8"))); } catch { reject(new Error("Invalid JSON")); } });
  });
}
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function clamp(n, min, max) { n = Number.isFinite(+n) ? +n : min; return Math.min(Math.max(n, min), max); }
function nowISO() { return new Date().toISOString(); }

const rlStore = new Map();
function rateLimitOk(ip, isAuthPath) {
  const now = Date.now(); let e = rlStore.get(ip);
  if (!e || now - e.windowStart >= RATE_LIMIT_WINDOW_MS) { e = { windowStart: now, countAuth: 0, countGeneric: 0 }; rlStore.set(ip, e); }
  if (isAuthPath) { e.countAuth++; return e.countAuth <= RATE_LIMIT_MAX_AUTH; }
  e.countGeneric++; return e.countGeneric <= RATE_LIMIT_MAX_GENERIC;
}

function authUserFromRequest(req) {
  const auth = req.headers["authorization"] || "";
  const m = auth.match(/^Bearer\s+(.+)$/i); if (!m) return null;
  const token = m[1].trim(); 
  return findSession(token).then(row => {
    if (!row) return null;
    if (new Date(row.expires_at).getTime() < Date.now()) { deleteSession(token); return null; }
    return { id: row.user_id, email: row.email, name: row.name, token };
  });
}

// -------- Handler --------
export default async function handler(req, res) {
  writeSecurityHeaders(res);
  await ensureSchema();

  const urlObj = new URL(req.url, "http://x");
  let pathn = urlObj.pathname || "/";
  if (pathn.length > 1 && pathn.endsWith("/")) pathn = pathn.slice(0, -1);

  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const isAuth = pathn.startsWith("/auth/");
  if (!rateLimitOk(ip, isAuth)) return sendJson(res, 429, { ok:false, error:"Too many requests" });

  // root “ok”
  if (req.method === "GET" && pathn === "/") {
    return sendJson(res, 200, { ok:true });
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
      const u = await userByEmail(email); if (u) return sendJson(res, 409, { ok:false, error:"Email already registered" });
      const password_hash = bcrypt.hashSync(password, 10);
      await insertUser({ email, password_hash, name, created_at: nowISO() });
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
      const u = await userByEmail(email); if (!u) return invalid();
      if (!bcrypt.compareSync(password, u.password_hash)) return invalid();
      const token = crypto.randomBytes(32).toString("hex");
      const created_at = nowISO();
      const expires_at = new Date(Date.now()+SESSION_TTL_MS).toISOString();
      await insertSession({ user_id: u.id, token, created_at, expires_at });
      return sendJson(res, 200, { ok:true, token });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  if (req.method === "GET" && pathn === "/auth/me") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized (no/invalid/expired token)" });
    const row = await userById(u.id); return sendJson(res, 200, { ok:true, user: row });
  }

  if (req.method === "POST" && pathn === "/auth/logout") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    await deleteSession(u.token); return sendJson(res, 200, { ok:true });
  }

  // -------- SSE “polling” --------
  if (req.method === "GET" && pathn === "/events") {
    const token = urlObj.searchParams.get("token") || "";
    const row = await findSession(token);
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

    let lastFeedId = await maxId("feed_posts");
    let lastDmId = await maxId("dms");
    const startedAt = Date.now();

    const interval = setInterval(async () => {
      try {
        const newFeed = await listFeed_(50, 0);
        for (const p of newFeed.filter(p => (p.id|0) > lastFeedId).sort((a,b)=>a.id-b.id)) {
          lastFeedId = Math.max(lastFeedId, p.id|0);
          res.write(`event: feed:new\ndata: ${JSON.stringify(p)}\n\n`);
        }
        const dmRows = await listDM({ me: userId, friend: userId, limit: 50, offset: 0 }); // truco: luego filtramos
        for (const m of dmRows.filter(m => (m.id|0) > lastDmId && m.receiver_id === userId).sort((a,b)=>a.id-b.id)) {
          lastDmId = Math.max(lastDmId, m.id|0);
          res.write(`event: dm:new\ndata: ${JSON.stringify({ sender_id:m.sender_id, text:m.text, created_at:m.created_at })}\n\n`);
        }
        res.write("event: ping\ndata: {}\n\n");
      } catch {}
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
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const row = await userById(u.id);
    const prefs = { name: row?.name || "", locale: row?.locale || "auto", theme: row?.theme || "pastel", photo_base64: row?.photo_base64 || "" };
    return sendJson(res, 200, { ok:true, prefs });
  }
  if (req.method === "POST" && pathn === "/prefs") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const name = (b.name || "").toString().trim();
      let locale = (b.locale || "auto").toString().trim(); if (!["auto","en","es"].includes(locale)) locale = "auto";
      let theme = (b.theme || "pastel").toString().trim();
      if (!THEME_KEYS.includes(theme)) theme = "pastel";
      await updateUserPrefs({ id: u.id, name, locale, theme });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/photo") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const data = (b.data_url || "").toString();
      if (!data.startsWith("data:image/")) return sendJson(res, 400, { ok:false, error:"Invalid image" });
      if (Buffer.byteLength(data, "utf8") > 500_000) return sendJson(res, 400, { ok:false, error:"Image too large" });
      await updateUserPhoto({ id: u.id, photo: data });
      return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/account/delete") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    await deleteUser(u.id); return sendJson(res, 200, { ok:true });
  }

  // -------- ITEMS --------
  if (req.method === "GET" && pathn === "/items") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = await listItems(u.id);
    return sendJson(res, 200, { ok:true, items: rows });
  }
  if (req.method === "POST" && pathn === "/items") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const qty = Math.max(1, Math.min(9999, parseInt(b.qty || 1, 10) || 1));
      const note = (b.note || "").toString().trim();
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      await insertItem({ user_id: u.id, title, qty, note, done: 0, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/items/") && pathn.endsWith("/toggle")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    await toggleItem(id, u.id); return sendJson(res, 200, { ok:true });
  }
  if (req.method === "DELETE" && pathn.startsWith("/items/")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    await deleteItem(id, u.id); return sendJson(res, 200, { ok:true });
  }

  // -------- FRIENDS --------
  if (req.method === "GET" && pathn === "/friends") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = (await listFriendsRaw(u.id)).map(r => ({
      id: r.id, friend_id: r.friend_id, friend_name: r.friend_name, friend_email: r.friend_email,
      status: r.status, requested_by: r.requested_by, can_accept: r.status === "pending" && r.requested_by !== u.id
    }));
    return sendJson(res, 200, { ok:true, friends: rows, friends_ext: rows });
  }
  if (req.method === "POST" && pathn === "/friends/invite") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const email = (b.email || "").trim().toLowerCase();
      if (!email || !isValidEmail(email)) return sendJson(res, 400, { ok:false, error:"Invalid email" });
      const other = await findUserByEmailPublic(email);
      if (!other) return sendJson(res, 404, { ok:false, error:"User not found" });
      if (other.id === u.id) return sendJson(res, 400, { ok:false, error:"Cannot invite yourself" });
      const [a, b2] = canonicalPair(u.id, other.id);
      const existing = await findFriendship(a, b2);
      if (existing) return sendJson(res, 409, { ok:false, error:"Already invited or friends" });
      await insertFriendship({ user_a: a, user_b: b2, status: "pending", requested_by: u.id, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn === "/friends/accept") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = await getOneFriendship(fid); // helper local
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      await updateFriendshipStatus({ id: fid, status: "accepted" }); return sendJson(res, 200, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && (pathn === "/friends/cancel" || pathn === "/friends/remove")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try{
      const b = await readJsonBody(req);
      const fid = Number(b.friendship_id || 0);
      if (!fid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
      const row = await getOneFriendship(fid);
      if (!row) return sendJson(res, 404, { ok:false, error:"Not found" });
      if (row.user_a !== u.id && row.user_b !== u.id) return sendJson(res, 403, { ok:false, error:"Forbidden" });
      await deleteFriendship(fid);
      return sendJson(res, 200, { ok:true });
    }catch{ return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  // -------- GOALS + FEED --------
  if (req.method === "GET" && pathn === "/goals") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const rows = await listGoals(u.id);
    return sendJson(res, 200, { ok:true, goals: rows });
  }
  if (req.method === "POST" && pathn === "/goals") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const title = (b.title || "").toString().trim();
      const target_date = (b.target_date || null) ? String(b.target_date) : null;
      if (!title) return sendJson(res, 400, { ok:false, error:"Missing title" });
      const goal_id = await insertGoal({ user_id:u.id, title, target_date, created_at: nowISO() });
      return sendJson(res, 201, { ok:true, goal_id });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/goals/") && pathn.endsWith("/publish")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    await makeGoalPublic(id, u.id);
    // Añadir post a feed
    const g = await getOneGoalTitle(id, u.id);
    if (g) await insertFeed({ user_id: u.id, goal_id: id, content: "New goal: " + g.title, created_at: nowISO() });
    return sendJson(res, 200, { ok:true });
  }

  if (req.method === "GET" && pathn === "/feed") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const limit = clamp(urlObj.searchParams.get("limit"), 1, 50);
    const offset = clamp(urlObj.searchParams.get("offset"), 0, 10_000);
    const rows = await listFeed(limit, offset);
    return sendJson(res, 200, { ok:true, posts: rows });
  }
  if (req.method === "GET" && pathn.startsWith("/feed/") && !pathn.endsWith("/like") && !pathn.endsWith("/comment")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const comments = await listComments(pid);
    return sendJson(res, 200, { ok:true, comments });
  }
  if (req.method === "POST" && pathn === "/feed") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const content = (b.content || "").toString().trim();
      if (!content) return sendJson(res, 400, { ok:false, error:"Missing content" });
      await insertFeed({ user_id:u.id, goal_id: null, content, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }
  if (req.method === "POST" && pathn.startsWith("/feed/") && pathn.endsWith("/like")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const liked = await userLikedPost(pid, u.id);
    if (liked) await unlikePost(pid, u.id);
    else await likePost(pid, u.id, nowISO());
    const count = await countLikes(pid);
    return sendJson(res, 200, { ok:true, like_count: count, liked: !liked });
  }
  if (req.method === "POST" && pathn.startsWith("/feed/") && pathn.endsWith("/comment")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const pid = Number(pathn.split("/")[2] || 0);
    if (!pid) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const b = await readJsonBody(req);
    const text = (b.text || "").toString().trim();
    if (!text) return sendJson(res, 400, { ok:false, error:"Missing text" });
    await addComment(pid, u.id, text, nowISO());
    return sendJson(res, 201, { ok:true });
  }

  // -------- DMs --------
  if (req.method === "GET" && pathn === "/dm") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const friend_id = Number(urlObj.searchParams.get("friend_id")||0);
    if (!friend_id) return sendJson(res, 400, { ok:false, error:"Missing friend_id" });
    const [a,b] = canonicalPair(u.id, friend_id);
    const f = await findFriendship(a, b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const limit = clamp(urlObj.searchParams.get("limit"), 1, 100);
    const offset = clamp(urlObj.searchParams.get("offset"), 0, 1_000_000);
    const rows = await listDM({ me:u.id, friend:friend_id, limit, offset });
    const mapped = rows.map(m => ({ id:m.id, text:m.text, created_at:m.created_at, mine:m.sender_id===u.id, sender_id:m.sender_id }));
    return sendJson(res, 200, { ok:true, messages: mapped });
  }
  if (req.method === "POST" && pathn === "/dm/send") {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    try {
      const b = await readJsonBody(req);
      const friend_id = Number(b.friend_id || 0);
      const text = (b.text || "").toString().trim();
      if (!friend_id || !text) return sendJson(res, 400, { ok:false, error:"Missing friend_id or text" });
      const [a,bp] = canonicalPair(u.id, friend_id);
      const f = await findFriendship(a, bp);
      if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
      await insertDM({ sender_id:u.id, receiver_id:friend_id, text, created_at: nowISO() });
      return sendJson(res, 201, { ok:true });
    } catch { return sendJson(res, 400, { ok:false, error:"Bad request" }); }
  }

  // -------- Friend public profile --------
  if (req.method === "GET" && pathn.startsWith("/users/") && pathn.endsWith("/profile")) {
    const u = await authUserFromRequest(req); if (!u) return sendJson(res, 401, { ok:false, error:"Unauthorized" });
    const id = Number(pathn.split("/")[2] || 0);
    if (!id) return sendJson(res, 400, { ok:false, error:"Invalid id" });
    const [a,b] = canonicalPair(u.id, id);
    const f = await findFriendship(a,b);
    if (!f || f.status!=="accepted") return sendJson(res, 403, { ok:false, error:"Not friends" });
    const profile = await findUserPublicById(id);
    if (!profile) return sendJson(res, 404, { ok:false, error:"User not found" });
    const goals = await all(`SELECT id, title, target_date FROM goals WHERE user_id=? AND is_public=1 ORDER BY id DESC LIMIT 10`, [id]);
    const feed = await listFeedByUser(id, 10, 0);
    return sendJson(res, 200, { ok:true, profile, goals, feed });
  }

  // 404
  res.statusCode = 404;
  res.setHeader("Content-Type","text/plain; charset=utf-8");
  res.end("Not found: " + pathn);
}

/* -------- helpers privados usados arriba -------- */
async function getOneFriendship(fid){
  return await getOne(`SELECT * FROM friendships WHERE id=?`, [fid]);
}
async function getOneGoalTitle(id, user_id){
  return await getOne(`SELECT title FROM goals WHERE id=? AND user_id=?`, [id, user_id]);
}
async function getOne(sql, params){ // pequeño proxy local para no re-exportar todo
  return await getOneInternal(sql, params);
}
import { getOne as getOneInternal, all as allInternal } from "./sqlite-local.js";
async function all(sql, params){ return await allInternal(sql, params); }
