/**
 * Usage (on Render Shell):
 *   node make-admin.js stevenramymaher@gmail.com
 */

import { createClient } from "@libsql/client";

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const email = process.argv[2];
if (!email) {
  console.error("Usage: node make-admin.js <email>");
  process.exit(1);
}

const result = await db.execute({
  sql: `UPDATE users SET role='admin' WHERE email=?`,
  args: [email],
});

if (result.rowsAffected === 0) {
  console.error(`✗ User not found: ${email}`);
  console.error("  → Sign in with Google first, then run this script.");
  process.exit(1);
}

const r = await db.execute({
  sql: `SELECT email, role FROM users WHERE email=?`,
  args: [email],
});

const user = r.rows[0];
console.log(`✓ ${user.email} is now ${user.role.toUpperCase()}`);
