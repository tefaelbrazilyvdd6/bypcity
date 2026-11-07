import { createClient } from "@libsql/client";

export const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

await db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    google_id TEXT UNIQUE,
    telegram_id TEXT UNIQUE,
    email TEXT,
    name TEXT,
    avatar TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

// Migrate existing table: add telegram_id column if it doesn't exist
// NOTE: ALTER TABLE ADD COLUMN ... UNIQUE is invalid in SQLite/libSQL — add the
// column first, then create the unique index separately.
try {
  await db.execute(`ALTER TABLE users ADD COLUMN telegram_id TEXT`);
} catch (_) {}
try {
  await db.execute(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_telegram_id ON users(telegram_id)`);
} catch (_) {}
// Also relax NOT NULL on google_id and email if already created
try {
  await db.execute(`ALTER TABLE users ADD COLUMN _migrated INTEGER DEFAULT 0`);
} catch (_) {}

await db.execute(`
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    filename TEXT NOT NULL,
    mimetype TEXT NOT NULL,
    size INTEGER NOT NULL,
    category TEXT NOT NULL DEFAULT 'OTHER',
    tags TEXT DEFAULT '[]',
    published INTEGER NOT NULL DEFAULT 1,
    cloudinary_url TEXT,
    cloudinary_public_id TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

await db.execute(`
  CREATE TABLE IF NOT EXISTS downloads (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    ip TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// Persistent session store (replaces express-session's default in-memory
// store, which is explicitly unsafe for production: it leaks memory and
// loses every session on each restart/deploy).
await db.execute(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expires INTEGER NOT NULL
  )
`);

export async function getUser(id) {
  const r = await db.execute({ sql: `SELECT * FROM users WHERE id = ?`, args: [id] });
  return r.rows[0] ?? null;
}

export async function getUserByGoogle(google_id) {
  const r = await db.execute({ sql: `SELECT * FROM users WHERE google_id = ?`, args: [google_id] });
  return r.rows[0] ?? null;
}

export async function getUserByTelegram(telegram_id) {
  const r = await db.execute({ sql: `SELECT * FROM users WHERE telegram_id = ?`, args: [String(telegram_id)] });
  return r.rows[0] ?? null;
}

export async function upsertUser({ id, google_id, email, name, avatar }) {
  await db.execute({
    sql: `INSERT INTO users (id, google_id, email, name, avatar)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(google_id) DO UPDATE SET
            email=excluded.email, name=excluded.name, avatar=excluded.avatar`,
    args: [id, google_id, email, name, avatar],
  });
}

export async function upsertTelegramUser({ id, telegram_id, name, avatar }) {
  // google_id and email may be NOT NULL in the live schema (created before Telegram
  // support was added), so supply unique placeholders to satisfy the constraint.
  await db.execute({
    sql: `INSERT INTO users (id, telegram_id, google_id, email, name, avatar)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            telegram_id=excluded.telegram_id,
            name=excluded.name, avatar=excluded.avatar`,
    args: [id, String(telegram_id), `tg_${telegram_id}`, `tg_${telegram_id}@telegram`, name, avatar || ""],
  });
}

// Lets a signed-in user change their own display name from the profile page.
// Does NOT touch email/google_id/telegram_id/role — identity and permissions
// are never editable by the user themselves.
export async function updateUserName(id, name) {
  await db.execute({
    sql: `UPDATE users SET name = ? WHERE id = ?`,
    args: [name, id],
  });
}

export async function getUserDownloads(user_id, limit = 20) {
  const r = await db.execute({
    sql: `SELECT d.id, d.created_at, f.id as file_id, f.name as file_name, f.category
          FROM downloads d JOIN files f ON f.id = d.file_id
          WHERE d.user_id = ?
          ORDER BY d.created_at DESC LIMIT ?`,
    args: [user_id, limit],
  });
  return r.rows;
}

export async function getUserDownloadCount(user_id) {
  const r = await db.execute({
    sql: `SELECT COUNT(*) as c FROM downloads WHERE user_id = ?`,
    args: [user_id],
  });
  return r.rows[0]?.c ?? 0;
}

// ── Session store backing (used by session-store.js) ──────────
export async function getSessionRow(sid) {
  const r = await db.execute({ sql: `SELECT sess, expires FROM sessions WHERE sid = ?`, args: [sid] });
  return r.rows[0] ?? null;
}

export async function setSessionRow(sid, sess, expires) {
  await db.execute({
    sql: `INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
          ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expires=excluded.expires`,
    args: [sid, sess, expires],
  });
}

export async function touchSessionRow(sid, expires) {
  await db.execute({ sql: `UPDATE sessions SET expires = ? WHERE sid = ?`, args: [expires, sid] });
}

export async function destroySessionRow(sid) {
  await db.execute({ sql: `DELETE FROM sessions WHERE sid = ?`, args: [sid] });
}

export async function pruneExpiredSessions() {
  await db.execute({ sql: `DELETE FROM sessions WHERE expires < ?`, args: [Date.now()] });
}

export async function listFiles(limit, offset) {
  const r = await db.execute({
    sql: `SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
          FROM files f WHERE f.published = 1
          ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
    args: [limit, offset],
  });
  return r.rows;
}

export async function searchFiles(q, cat, limit, offset) {
  const like = `%${q}%`;
  const r = await db.execute({
    sql: `SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
          FROM files f WHERE f.published = 1
          AND (f.name LIKE ? OR f.description LIKE ?)
          AND (? = '' OR f.category = ?)
          ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
    args: [like, like, cat, cat, limit, offset],
  });
  return r.rows;
}

export async function getFile(id) {
  const r = await db.execute({
    sql: `SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
          FROM files f WHERE f.id = ? AND f.published = 1`,
    args: [id],
  });
  return r.rows[0] ?? null;
}

export async function getFileAdmin(id) {
  const r = await db.execute({
    sql: `SELECT * FROM files WHERE id = ?`,
    args: [id],
  });
  return r.rows[0] ?? null;
}

export async function getAllFiles() {
  const r = await db.execute(`
    SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
    FROM files f ORDER BY f.created_at DESC
  `);
  return r.rows;
}

export async function insertFile({ id, name, description, filename, mimetype, size, category, tags, cloudinary_url, cloudinary_public_id }) {
  await db.execute({
    sql: `INSERT INTO files (id, name, description, filename, mimetype, size, category, tags, cloudinary_url, cloudinary_public_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [id, name, description, filename, mimetype, size, category, tags, cloudinary_url, cloudinary_public_id],
  });
}

export async function deleteFile(id) {
  await db.execute({ sql: `DELETE FROM files WHERE id = ?`, args: [id] });
}

export async function updateFile({ id, name, description, category, tags, published }) {
  await db.execute({
    sql: `UPDATE files SET name=?, description=?, category=?, tags=?, published=? WHERE id=?`,
    args: [name, description, category, tags, published, id],
  });
}

export async function logDownload(id, file_id, user_id, ip) {
  await db.execute({
    sql: `INSERT INTO downloads (id, file_id, user_id, ip) VALUES (?, ?, ?, ?)`,
    args: [id, file_id, user_id, ip],
  });
}

export async function statsQuery() {
  const r = await db.execute(`
    SELECT
      (SELECT COUNT(*) FROM files WHERE published=1) as total_files,
      (SELECT COUNT(*) FROM downloads) as total_downloads,
      (SELECT COUNT(*) FROM users) as total_users
  `);
  return r.rows[0];
}
