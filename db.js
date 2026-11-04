import { createClient } from "@libsql/client";

export const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

await db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    google_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    avatar TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

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

// helpers — same API shape as before but async
export async function getUser(id) {
  const r = await db.execute({ sql: `SELECT * FROM users WHERE id = ?`, args: [id] });
  return r.rows[0] ?? null;
}

export async function getUserByGoogle(google_id) {
  const r = await db.execute({ sql: `SELECT * FROM users WHERE google_id = ?`, args: [google_id] });
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

export async function listFiles(limit, offset) {
  const r = await db.execute({
    sql: `SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
          FROM files f WHERE f.published = 1
          ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
    args: [limit, offset],
  });
  return r.rows;
}

export async function searchFiles(q, limit, offset) {
  const like = `%${q}%`;
  const r = await db.execute({
    sql: `SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
          FROM files f WHERE f.published = 1
          AND (f.name LIKE ? OR f.description LIKE ? OR f.category = ?)
          ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
    args: [like, like, q, limit, offset],
  });
  return r.rows;
}

export async function getFile(id) {
  const r = await db.execute({
    sql: `SELECT * FROM files WHERE id = ? AND published = 1`,
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
  // delete from cloudinary first — handled in server.js
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
