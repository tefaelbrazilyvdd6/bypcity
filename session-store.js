import session from "express-session";
import {
  getSessionRow, setSessionRow, touchSessionRow, destroySessionRow, pruneExpiredSessions,
} from "./db.js";

const DAY_MS = 24 * 60 * 60 * 1000;

// express-session ships with an in-memory store by default. That store is
// explicitly documented as unsafe for production (unbounded memory growth,
// and every session is lost on restart/redeploy, which forces every signed-in
// user to log in again any time the app restarts — common on Render's free
// tier, which sleeps and respins the process). This store persists sessions
// in the same Turso database the rest of the app already uses, so no extra
// infrastructure or dependency is required.
export class TursoSessionStore extends session.Store {
  constructor({ pruneIntervalMs = 15 * 60_000 } = {}) {
    super();
    if (pruneIntervalMs > 0) {
      this._pruneTimer = setInterval(() => {
        pruneExpiredSessions().catch((e) => console.error("session prune error:", e));
      }, pruneIntervalMs);
      this._pruneTimer.unref?.();
    }
  }

  async get(sid, cb) {
    try {
      const row = await getSessionRow(sid);
      if (!row || row.expires < Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.sess));
    } catch (e) {
      cb(e);
    }
  }

  async set(sid, sessData, cb) {
    try {
      const maxAge = sessData.cookie?.maxAge;
      const expires = Date.now() + (typeof maxAge === "number" ? maxAge : DAY_MS);
      await setSessionRow(sid, JSON.stringify(sessData), expires);
      cb?.(null);
    } catch (e) {
      cb?.(e);
    }
  }

  async touch(sid, sessData, cb) {
    try {
      const maxAge = sessData.cookie?.maxAge;
      const expires = Date.now() + (typeof maxAge === "number" ? maxAge : DAY_MS);
      await touchSessionRow(sid, expires);
      cb?.(null);
    } catch (e) {
      cb?.(e);
    }
  }

  async destroy(sid, cb) {
    try {
      await destroySessionRow(sid);
      cb?.(null);
    } catch (e) {
      cb?.(e);
    }
  }
}
