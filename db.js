import Database from "better-sqlite3";
import { mkdirSync } from "fs";

const DATA_DIR = process.env.DATA_DIR || "./data";
mkdirSync(DATA_DIR, { recursive: true });

export const db = new Database(`${DATA_DIR}/app.db`);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    google_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    avatar TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

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
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS downloads (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    ip TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

export const getUser = db.prepare(`SELECT * FROM users WHERE id = ?`);
export const getUserByGoogle = db.prepare(`SELECT * FROM users WHERE google_id = ?`);
export const upsertUser = db.prepare(`
  INSERT INTO users (id, google_id, email, name, avatar)
  VALUES (@id, @google_id, @email, @name, @avatar)
  ON CONFLICT(google_id) DO UPDATE SET
    email=excluded.email, name=excluded.name, avatar=excluded.avatar
`);

export const listFiles = db.prepare(`
  SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
  FROM files f WHERE f.published = 1
  ORDER BY f.created_at DESC LIMIT ? OFFSET ?
`);
export const searchFiles = db.prepare(`
  SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
  FROM files f WHERE f.published = 1
  AND (f.name LIKE ? OR f.description LIKE ? OR f.category = ?)
  ORDER BY f.created_at DESC LIMIT ? OFFSET ?
`);
export const getFile = db.prepare(`SELECT * FROM files WHERE id = ? AND published = 1`);
export const getAllFiles = db.prepare(`
  SELECT f.*, (SELECT COUNT(*) FROM downloads d WHERE d.file_id = f.id) as dl_count
  FROM files f ORDER BY f.created_at DESC
`);
export const insertFile = db.prepare(`
  INSERT INTO files (id, name, description, filename, mimetype, size, category, tags)
  VALUES (@id, @name, @description, @filename, @mimetype, @size, @category, @tags)
`);
export const deleteFile = db.prepare(`DELETE FROM files WHERE id = ?`);
export const updateFile = db.prepare(`
  UPDATE files SET name=@name, description=@description,
  category=@category, tags=@tags, published=@published WHERE id=@id
`);
export const logDownload = db.prepare(`
  INSERT INTO downloads (id, file_id, user_id, ip) VALUES (?, ?, ?, ?)
`);
export const statsQuery = db.prepare(`
  SELECT
    (SELECT COUNT(*) FROM files WHERE published=1) as total_files,
    (SELECT COUNT(*) FROM downloads) as total_downloads,
    (SELECT COUNT(*) FROM users) as total_users
`);
