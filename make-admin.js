/**
 * Usage (on Render Shell):
 *   node make-admin.js admin@example.com
 *
 * NOTE: this file previously had a real admin email hardcoded in this
 * comment as a usage example. Comments like that get committed, shared, and
 * pasted into chat logs without a second thought — treat even "just an
 * example" PII in source comments as something to avoid.
 */

import { createClient } from "@libsql/client";

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const email = (process.argv[2] || "").trim();
if (!email) {
  console.error("Usage: node make-admin.js <email>");
  process.exit(1);
}

// Case-insensitive match: server.js's own ADMIN_EMAIL check lowercases
// before comparing, and emails returned by Google aren't guaranteed to be
// stored in a consistent case, so match the same way here.
const result = await db.execute({
  sql: `UPDATE users SET role='admin' WHERE lower(email) = lower(?)`,
  args: [email],
});

if (result.rowsAffected === 0) {
  console.error(`✗ User not found: ${email}`);
  console.error("  → Sign in with Google first, then run this script.");
  process.exit(1);
}

const r = await db.execute({
  sql: `SELECT email, role FROM users WHERE lower(email) = lower(?)`,
  args: [email],
});

const user = r.rows[0];
console.log(`✓ ${user.email} is now ${user.role.toUpperCase()}`);
