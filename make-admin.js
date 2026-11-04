/**
 * Run once after first login to make yourself admin.
 *
 * Usage (on Render Shell or locally):
 *   DATA_DIR=/data node make-admin.js stevenramymaher@gmail.com
 *
 * Or locally (default ./data):
 *   node make-admin.js your@email.com
 */

import Database from "better-sqlite3";
import { mkdirSync } from "fs";

const DATA_DIR = process.env.DATA_DIR || "./data";
mkdirSync(DATA_DIR, { recursive: true });

const email = process.argv[2];
if (!email) {
  console.error("Usage: node make-admin.js <email>");
  process.exit(1);
}

const db = new Database(`${DATA_DIR}/app.db`);
const result = db.prepare("UPDATE users SET role='admin' WHERE email=?").run(email);

if (result.changes === 0) {
  console.error(`✗ User not found: ${email}`);
  console.error("  → Sign in with Google first, then run this script.");
  process.exit(1);
}

const user = db.prepare("SELECT email, role FROM users WHERE email=?").get(email);
console.log(`✓ ${user.email} is now ${user.role.toUpperCase()}`);
db.close();
