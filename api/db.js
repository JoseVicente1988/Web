// api/db.js
import { exec, run, all, getOne, openDB } from "./sqlite-local.js";

export async function ensureSchema() {
  await openDB();
  await exec(`
    PRAGMA foreign_keys = ON;
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
    DELETE FROM sessions WHERE expires_at < '${new Date().toISOString()}';
  `);
}

// ---- utils
export function canonicalPair(a, b){ a=+a; b=+b; return a<b ? [a,b] : [b,a]; }

// ---- users
export async function userByEmail(email){ return await getOne(`SELECT * FROM users WHERE email=?`, [email]); }
export async function userById(id){ return await getOne(`SELECT id, email, name, created_at, locale, theme, photo_base64 FROM users WHERE id=?`, [id]); }
export async function insertUser({ email, password_hash, name, created_at }){
  await run(`INSERT INTO users (email, password_hash, name, created_at) VALUES (?,?,?,?)`, [email, password_hash, name, created_at]);
}
export async function updateUserPrefs({ id, name, locale, theme }){
  await run(`UPDATE users SET name=?, locale=?, theme=? WHERE id=?`, [name, locale, theme, id]);
}
export async function updateUserPhoto({ id, photo }){
  await run(`UPDATE users SET photo_base64=? WHERE id=?`, [photo, id]);
}
export async function deleteUser_(id){
  await run(`DELETE FROM users WHERE id=?`, [id]);
}

// ---- sessions
export async function insertSession({ user_id, token, created_at, expires_at }){
  await run(`INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?,?,?,?)`, [user_id, token, created_at, expires_at]);
}
export async function findSession(token){
  return await getOne(`
    SELECT s.token, s.expires_at, u.id as user_id, u.email, u.name
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token=?`, [token]);
}
export async function deleteSession_(token){ await run(`DELETE FROM sessions WHERE token=?`, [token]); }

// ---- items
export async function insertItem_({ user_id, title, qty, note, done, created_at }){
  await run(`INSERT INTO items (user_id, title, qty, note, done, created_at) VALUES (?,?,?,?,?,?)`, [user_id, title, qty, note, done, created_at]);
}
export async function listItems_(user_id){ return await all(`SELECT id, title, qty, note, done, created_at FROM items WHERE user_id=? ORDER BY done ASC, id DESC`, [user_id]); }
export async function toggleItem_(id, user_id){ await run(`UPDATE items SET done = CASE WHEN done=1 THEN 0 ELSE 1 END WHERE id=? AND user_id=?`, [id, user_id]); }
export async function deleteItem_(id, user_id){ await run(`DELETE FROM items WHERE id=? AND user_id=?`, [id, user_id]); }

// ---- friendships
export async function findFriendship_(a, b){ return await getOne(`SELECT * FROM friendships WHERE user_a=? AND user_b=?`, [a,b]); }
export async function insertFriendship_({ user_a, user_b, status, requested_by, created_at }){
  await run(`INSERT INTO friendships (user_a, user_b, status, requested_by, created_at) VALUES (?,?,?,?,?)`, [user_a, user_b, status, requested_by, created_at]);
}
export async function updateFriendshipStatus_({ id, status }){ await run(`UPDATE friendships SET status=? WHERE id=?`, [status, id]); }
export async function deleteFriendship_(id){ await run(`DELETE FROM friendships WHERE id=?`, [id]); }
export async function listFriendsRaw_(me){
  return await all(`
    SELECT f.id, f.user_a, f.user_b, f.status, f.requested_by,
           CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END as friend_id,
           u.name as friend_name, u.email as friend_email
    FROM friendships f
    JOIN users u ON u.id = CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END
    WHERE (f.user_a = ? OR f.user_b = ?)
    ORDER BY f.id DESC
  `, [me, me, me, me]);
}

// ---- goals + feed
export async function insertGoal_({ user_id, title, target_date, created_at }){
  await run(`INSERT INTO goals (user_id, title, target_date, is_public, created_at) VALUES (?,?,?,?,?)`, [user_id, title, target_date, 0, created_at]);
  const row = await getOne(`SELECT last_insert_rowid() AS id`);
  return Number(row?.id || 0);
}
export async function listGoals_(user_id){ return await all(`SELECT id, title, target_date, is_public, created_at FROM goals WHERE user_id=? ORDER BY id DESC`, [user_id]); }
export async function makeGoalPublic_(id, user_id){ await run(`UPDATE goals SET is_public=1 WHERE id=? AND user_id=?`, [id, user_id]); }
export async function insertFeed_({ user_id, goal_id, content, created_at }){
  await run(`INSERT INTO feed_posts (user_id, goal_id, content, created_at) VALUES (?,?,?,?)`, [user_id, goal_id, content, created_at]);
}
export async function listFeed_(limit, offset){
  return await all(`
    SELECT f.id, f.user_id, f.content, f.created_at, u.name, u.email,
           (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
           (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
    FROM feed_posts f JOIN users u ON u.id=f.user_id
    ORDER BY f.id DESC LIMIT ? OFFSET ?
  `, [limit, offset]);
}
export async function listFeedByUser_(uid, limit, offset){
  return await all(`
    SELECT f.id, f.user_id, f.content, f.created_at,
           (SELECT COUNT(*) FROM feed_likes fl WHERE fl.post_id=f.id) as like_count,
           (SELECT COUNT(*) FROM feed_comments fc WHERE fc.post_id=f.id) as comment_count
    FROM feed_posts f WHERE f.user_id=? ORDER BY f.id DESC LIMIT ? OFFSET ?
  `, [uid, limit, offset]);
}
export async function userLikedPost_(post_id, user_id){
  const r = await getOne(`SELECT 1 FROM feed_likes WHERE post_id=? AND user_id=?`, [post_id, user_id]);
  return !!r;
}
export async function likePost_(post_id, user_id, created_at){
  await run(`INSERT OR IGNORE INTO feed_likes (post_id, user_id, created_at) VALUES (?,?,?)`, [post_id, user_id, created_at]);
}
export async function unlikePost_(post_id, user_id){
  await run(`DELETE FROM feed_likes WHERE post_id=? AND user_id=?`, [post_id, user_id]);
}
export async function countLikes_(post_id){
  const r = await getOne(`SELECT COUNT(*) as c FROM feed_likes WHERE post_id=?`, [post_id]);
  return Number(r?.c || 0);
}
export async function addComment_(post_id, user_id, text, created_at){
  await run(`INSERT INTO feed_comments (post_id, user_id, text, created_at) VALUES (?,?,?,?)`, [post_id, user_id, text, created_at]);
}
export async function listComments_(post_id){
  return await all(`
    SELECT c.id, c.text, c.created_at, u.name, u.email
    FROM feed_comments c JOIN users u ON u.id=c.user_id
    WHERE c.post_id=? ORDER BY c.id ASC
  `, [post_id]);
}

// ---- users public
export async function findUserByEmailPublic_(email){ return await getOne(`SELECT id, email, name FROM users WHERE email=?`, [email]); }
export async function findUserPublicById_(id){ return await getOne(`SELECT id, email, name, created_at, photo_base64 FROM users WHERE id=?`, [id]); }

// ---- dms
export async function insertDM_({ sender_id, receiver_id, text, created_at }){
  await run(`INSERT INTO dms (sender_id, receiver_id, text, created_at) VALUES (?,?,?,?)`, [sender_id, receiver_id, text, created_at]);
}
export async function listDM_({ me, friend, limit, offset }){
  return await all(`
    SELECT id, sender_id, receiver_id, text, created_at
    FROM dms
    WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
    ORDER BY id DESC LIMIT ? OFFSET ?
  `, [me, friend, friend, me, limit, offset]);
}
export async function maxId_(table){
  const r = await getOne(`SELECT IFNULL(MAX(id),0) AS m FROM ${table}`);
  return Number(r?.m || 0);
}
