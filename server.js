import "dotenv/config";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import multer from "multer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { randomUUID } from "crypto";
import { v2 as cloudinary } from "cloudinary";
import streamifier from "streamifier";

import {
  getUser, getUserByGoogle, upsertUser,
  listFiles, searchFiles, getFile, getAllFiles,
  insertFile, deleteFile, updateFile, logDownload, statsQuery,
  getFileAdmin,
} from "./db.js";

// ── Cloudinary config ────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

function isAdminUser(user) {
  if (!user) return false;
  const email = String(user.email || "").trim().toLowerCase();
  return user.role === "admin" || (ADMIN_EMAIL !== "" && email === ADMIN_EMAIL);
}

// ── Security ────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(express.static("public"));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com"],
      frameSrc: ["https://challenges.cloudflare.com", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com"],
      imgSrc: ["'self'", "data:", "https:", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com"],
    },
  },
}));

// Stricter rate limits
const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
const dlLimiter = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use(limiter);
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ── Session ─────────────────────────────────────────────────
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === "change-me-in-production") {
  if (process.env.NODE_ENV === "production") {
    console.error("FATAL: SESSION_SECRET must be set in production");
    process.exit(1);
  }
}
app.use(session({
  secret: process.env.SESSION_SECRET || "dev-only-secret-change-in-prod",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (was 30 — shorter is safer)
    sameSite: "lax",
  },
}));

// ── Passport Google ──────────────────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
}, async (_at, _rt, profile, done) => {
  try {
    const existing = await getUserByGoogle(profile.id);
    const id = existing?.id || randomUUID();
    await upsertUser({
      id,
      google_id: profile.id,
      email: profile.emails?.[0]?.value || "",
      name: profile.displayName,
      avatar: profile.photos?.[0]?.value || "",
    });
    done(null, await getUser(id));
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    done(null, await getUser(id));
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// ── Auth middleware ──────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect("/login?next=" + encodeURIComponent(req.path));
};
const requireAdmin = (req, res, next) => {
  if (req.isAuthenticated() && isAdminUser(req.user)) return next();
  res.status(403).json({ error: "Forbidden" });
};

// ── Allowed file types ───────────────────────────────────────
const ALLOWED_MIMETYPES = new Set([
  "application/zip",
  "application/x-zip-compressed",
  "application/octet-stream",
  "application/x-msdownload",
  "application/x-executable",
  "text/plain",
  "text/x-python",
  "application/x-python-code",
  "application/x-lua",
  "application/x-dosexec",
]);

// ── Multer ───────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    // Allow known types; also allow unknown (application/octet-stream covers many binaries)
    cb(null, true);
  },
});

// ── Upload buffer to Cloudinary ──────────────────────────────
function uploadToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const publicId = randomUUID();
    const stream = cloudinary.uploader.upload_stream(
      { public_id: publicId, resource_type: "raw", use_filename: false, unique_filename: false, overwrite: false },
      (error, result) => {
        if (error) return reject(error);
        resolve({ publicId, url: result.secure_url });
      }
    );
    streamifier.createReadStream(buffer).pipe(stream);
  });
}

// ── Turnstile verify ─────────────────────────────────────────
async function verifyTurnstile(token, ip) {
  if (!process.env.TURNSTILE_SECRET_KEY) return true; // dev bypass
  if (!token || typeof token !== "string") return false;
  const form = new URLSearchParams();
  form.append("secret", process.env.TURNSTILE_SECRET_KEY);
  form.append("response", token);
  form.append("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST", body: form,
    });
    const d = await r.json();
    return d.success === true;
  } catch {
    return false;
  }
}

function getIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
}

// Safe redirect — only allow relative paths to prevent open redirect
function safeRedirect(url) {
  if (!url || typeof url !== "string") return "/tools";
  if (!url.startsWith("/") || url.startsWith("//")) return "/tools";
  return url;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PAGES — HTML inline
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ── Hilltop Ads — Banner 300x250 ─────────────────────────────
const HILLTOP_AD = `<script>
(function(gnnj){
var d = document,
    s = d.createElement('script'),
    l = d.currentScript || d.scripts[d.scripts.length - 1];
s.settings = gnnj || {};
s.src = "\/\/unfoldedtrade.com\/bdXXV\/s.duGklk0\/YaWAcT\/DeimF9cu\/ZOU_lAkxPHTtc-1OOwTAYYyNM\/jbEEtGNDzdUh5\/Ntj\/IQyzN\/QK";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})
<\/script>`;

// ── Hilltop Ads — Popunder ───────────────────────────────────
const HILLTOP_POPUNDER = `<script>
(function(hvt){
var d = document,
    s = d.createElement('script'),
    l = d.currentScript || d.scripts[d.scripts.length - 1];
s.settings = hvt || {};
s.src = "\/\/unfolded-uncle.com\/ceD\/9.6\/bD2m5QlxSyW\/Qp9fNTzJU\/5lNmjHIS2\/MbS\/0w3PNRTSk\/2GMMjMY\/1q";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})
<\/script>`;

const CSS = `
<style>
/* ── Reset & Base ── */
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#e2e8f0;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;min-height:100vh;font-size:15px;line-height:1.5}
a{color:inherit;text-decoration:none}

/* ── Nav ── */
nav{background:#1e293b;border-bottom:1px solid #334155;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.logo{font-size:17px;font-weight:900;letter-spacing:-.02em;color:#f8fafc}
.logo span{color:#f59e0b}
.nav-r{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{font-size:12px;padding:7px 16px;border:1px solid #334155;color:#94a3b8;background:transparent;cursor:pointer;font-family:inherit;border-radius:5px;white-space:nowrap}
.btn:hover{color:#f8fafc;border-color:#475569;background:#1e293b}
.btn-gold{border-color:#f59e0b;color:#f59e0b;background:rgba(245,158,11,.08)}
.btn-gold:hover{background:rgba(245,158,11,.18)}

/* ── Hero ── */
.hero{padding:56px 24px 44px;text-align:center;background:#0f172a}
.pill{display:inline-block;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#f59e0b;font-size:11px;padding:4px 14px;letter-spacing:.08em;margin-bottom:18px;border-radius:20px}
h1{font-size:clamp(30px,8vw,52px);font-weight:900;line-height:.95;letter-spacing:-.03em;margin-bottom:12px;color:#f8fafc}
h1 em{color:#f59e0b;font-style:normal}
.sub{font-size:14px;color:#64748b;line-height:1.7;max-width:38ch;margin:0 auto 24px}
.cta{background:#f59e0b;color:#0f172a;border:none;padding:14px 36px;font-size:14px;font-weight:800;letter-spacing:.04em;cursor:pointer;font-family:inherit;border-radius:6px}
.cta:hover{background:#fbbf24}
.note{font-size:11px;color:#334155;margin-top:10px}

/* ── Info grid ── */
.info-grid{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #1e293b}
.info-c{background:#1e293b;padding:16px 20px;border-right:1px solid #334155}
.info-c:last-child{border-right:0}
.info-lbl{font-size:10px;letter-spacing:.1em;color:#f59e0b;margin-bottom:6px;font-weight:700}
.info-p{font-size:13px;color:#64748b;line-height:1.6}

/* ── Telegram bar ── */
.tg-bar{background:#1e293b;border-top:1px solid #334155;padding:13px 20px;display:flex;align-items:center;gap:12px}
.tg-ic{width:34px;height:34px;border-radius:50%;background:#1a3a5c;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.tg-txt{font-size:13px;color:#64748b}.tg-txt strong{color:#e2e8f0}

/* ── Ad slot ── */
.ad-slot{padding:14px 20px;text-align:center;border-top:1px solid #1e293b;background:#0f172a}
.ad-lbl{font-size:9px;color:#1e293b;letter-spacing:.1em;margin-bottom:6px}

/* ── Search ── */
.search-bar{padding:12px 16px;background:#1e293b;border-bottom:1px solid #334155;display:flex;gap:8px}
input[type=text],input[type=email],input[type=password],textarea,select{background:#0f172a;border:1px solid #334155;border-radius:5px;padding:9px 12px;font-size:14px;color:#e2e8f0;font-family:inherit;outline:none;width:100%;caret-color:#f59e0b}
input[type=text]:focus,input[type=email]:focus,textarea:focus{border-color:#f59e0b}
select{padding:9px 12px}

/* ── Category buttons ── */
.si{font-size:12px;padding:6px 14px;border:1px solid #334155;color:#64748b;background:transparent;cursor:pointer;font-family:inherit;white-space:nowrap;border-radius:20px}
.si:hover{color:#e2e8f0;border-color:#475569}
.si.on{color:#0f172a;background:#f59e0b;border-color:#f59e0b;font-weight:700}
.cats{padding:10px 16px;display:flex;gap:6px;overflow-x:auto;border-bottom:1px solid #334155;background:#1e293b}
.cats::-webkit-scrollbar{height:3px}.cats::-webkit-scrollbar-track{background:#1e293b}.cats::-webkit-scrollbar-thumb{background:#334155;border-radius:2px}

/* ── File cards ── */
.files-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;padding:14px;background:#0f172a}
.fc{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px;display:flex;flex-direction:column;gap:7px}
.fc:hover{border-color:#475569}
.fc-icon{font-size:20px}
.fc-name{font-size:14px;font-weight:700;color:#f8fafc;line-height:1.3}
.fc-desc{font-size:12px;color:#64748b;line-height:1.5}
.fc-meta{font-size:11px;color:#475569;margin-top:auto}
.dl-btn{font-size:12px;text-align:center;color:#0f172a;background:#f59e0b;border:none;padding:8px;cursor:pointer;display:block;width:100%;border-radius:5px;font-weight:700;font-family:inherit;margin-top:2px}
.dl-btn:hover{background:#fbbf24}

/* ── Download card ── */
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:24px;max-width:460px;margin:32px auto}
.card h2{font-size:18px;margin-bottom:12px;color:#f8fafc;font-weight:800}
.cf-wrap{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:16px;margin:14px 0;text-align:center}
.cf-wrap p{font-size:13px;color:#64748b;margin-bottom:10px}
.dl-main{width:100%;padding:13px;background:#f59e0b;color:#0f172a;border:none;font-size:14px;font-weight:800;letter-spacing:.04em;cursor:pointer;font-family:inherit;margin-top:6px;border-radius:6px}
.dl-main:disabled{background:#1e3a5f;color:#334155;cursor:not-allowed}
.dl-main:hover:not(:disabled){background:#fbbf24}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:11px;border:1px solid #334155;padding:3px 9px;color:#64748b;border-radius:20px}
.err{color:#f87171;font-size:13px;margin-top:8px}
.ok{color:#4ade80;font-size:13px;margin-top:8px}

/* ── Admin ── */
.a-layout{display:flex;min-height:calc(100vh - 56px)}
.a-side{width:130px;border-right:1px solid #334155;background:#1e293b;padding-top:10px;flex-shrink:0}
.a-nav{padding:10px 14px;font-size:13px;color:#64748b;cursor:pointer;display:block;border-left:3px solid transparent}
.a-nav.on{color:#f59e0b;border-left-color:#f59e0b;background:rgba(245,158,11,.05)}
.a-main{flex:1;padding:20px;overflow:auto}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px}
.stat{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px 16px}
.stat-n{font-size:26px;font-weight:900;color:#f8fafc}
.stat-l{font-size:10px;color:#475569;letter-spacing:.08em;margin-top:3px}
.up-zone{border:2px dashed #334155;border-radius:8px;padding:0;margin-bottom:14px;cursor:pointer;display:block;text-align:center;transition:border-color .2s}
.up-zone:hover{border-color:#f59e0b}
.up-zone-inner{padding:20px 16px;pointer-events:none}
.up-zone strong{font-size:14px;color:#94a3b8;display:block;margin-bottom:4px}
.up-zone p{font-size:12px;color:#475569}
.up-zone input[type=file]{position:absolute;opacity:0;width:0;height:0}
.section-lbl{font-size:10px;letter-spacing:.1em;color:#f59e0b;margin-bottom:10px;font-weight:700}
.file-row{display:flex;align-items:center;gap:8px;padding:9px 0;border-bottom:1px solid #1e293b;font-size:13px}
.file-row:last-child{border-bottom:0}
.btn-del{font-size:10px;color:#f87171;border:1px solid #450a0a;padding:4px 10px;background:transparent;cursor:pointer;font-family:inherit;border-radius:4px}
.btn-tog{font-size:10px;padding:4px 10px;border:1px solid #334155;background:transparent;cursor:pointer;font-family:inherit;color:#64748b;border-radius:4px}
.btn-tog.on{color:#4ade80;border-color:#14532d}

/* ── Login ── */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a}
.login-card{text-align:center;padding:36px 28px;width:100%;max-width:360px;display:flex;flex-direction:column;align-items:center;gap:16px;background:#1e293b;border:1px solid #334155;border-radius:12px;margin:16px}
.g-btn{display:flex;align-items:center;gap:10px;background:#f8fafc;color:#0f172a;border:none;padding:13px 24px;font-size:14px;font-weight:700;cursor:pointer;width:100%;max-width:300px;justify-content:center;font-family:inherit;border-radius:6px}
.g-btn:hover{background:#e2e8f0}
.g-ic{width:20px;height:20px;border-radius:50%;background:#ea4335;display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:900;flex-shrink:0}

/* ── Responsive ── */
@media(max-width:600px){
  nav{padding:10px 14px}
  .btn{font-size:11px;padding:6px 11px}
  .hero{padding:40px 16px 32px}
  .info-grid{grid-template-columns:1fr}
  .info-c{border-right:0;border-bottom:1px solid #334155}
  .info-c:last-child{border-bottom:0}
  .files-grid{grid-template-columns:1fr 1fr;gap:8px;padding:10px}
  .card{margin:20px 12px;padding:18px}
  .a-layout{flex-direction:column}
  .a-side{width:100%;display:flex;border-right:0;border-bottom:1px solid #334155;padding:0}
  .a-nav{border-left:0;border-bottom:3px solid transparent;padding:10px 16px}
  .a-nav.on{border-left:0;border-bottom-color:#f59e0b}
  .stats{grid-template-columns:1fr 1fr}
  .tg-bar{flex-wrap:wrap}
  .search-bar{flex-direction:column}
  .search-bar .btn{width:100%}
}
@media(max-width:380px){
  .files-grid{grid-template-columns:1fr}
  h1{font-size:28px}
}
</style>`;

function nav(user) {
  return `<nav>
    <a href="/" class="logo">/Bypass<span>City</span></a>
    <div class="nav-r">
      <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="btn">✈ Telegram</a>
      ${user
        ? `<a href="/tools" class="btn btn-gold">Tools</a>${isAdminUser(user)?`<a href="/admin" class="btn">Admin</a>`:""}<a href="/logout" class="btn">Logout</a>`
        : `<a href="/login" class="btn btn-gold">Sign in</a>`}
    </div>
  </nav>`;
}

function page(title, body, user = null) {
  return `<!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escHtml(title)} — BypassCity</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <meta property="og:title" content="${escHtml(title)} — BypassCity">
    <meta property="og:description" content="Scripts, sources, bots, and tools — all in one place. Free forever.">
    <meta property="og:image" content="/logo.png">
    <meta property="og:type" content="website">${CSS}
  </head><body>${nav(user)}${body}${HILLTOP_POPUNDER}</body></html>`;
}

function catIcon(cat) {
  return { SOURCE: "{ }", SCRIPT: "#!", TOOL: "⚙", BOT: "🤖", OTHER: "📦" }[cat] || "📦";
}
function fmtSize(b) {
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
  return (b / 1024 / 1024).toFixed(1) + " MB";
}
function timeAgo(ts) {
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

// ── Helpers ───────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function escJs(s) {
  // JSON.stringify gives us a fully safe JS string literal
  return JSON.stringify(String(s));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ROUTES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// HOME
app.get("/", (req, res) => {
  res.send(page("Home", `
    <section class="hero">
      <div class="pill">bypass-city.lol</div>
      <h1>The place for<br><em>tools &amp; sources.</em></h1>
      <p class="sub">Scripts, sources, bots, and tools — all in one place. Free forever.</p>
      <a href="${req.isAuthenticated() ? "/tools" : "/login"}">
        <button class="cta">ACCESS TOOLS →</button>
      </a>
      <p class="note">Sign in with Google required — takes 5 seconds</p>
    </section>
    <div class="info-grid">
      <div class="info-c">
        <div class="info-lbl">WHAT'S HERE</div>
        <div class="info-p">Sources, scripts, bots, bypass tools — updated regularly.</div>
      </div>
      <div class="info-c">
        <div class="info-lbl">ACCESS</div>
        <div class="info-p">Free with Google sign-in. No subscription. No BS.</div>
      </div>
    </div>
    <div class="tg-bar">
      <div class="tg-ic">✈</div>
      <div class="tg-txt"><strong>Updates channel</strong><br>t.me/yocnd — new tools &amp; announcements</div>
      <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="btn" style="margin-left:auto">JOIN</a>
    </div>
    <div class="ad-slot">
      <div class="ad-lbl">ADVERTISEMENT</div>
      ${HILLTOP_AD}
    </div>
  `, req.user));
});

// LOGIN
app.get("/login", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/tools");
  const next = safeRedirect(req.query.next);
  res.send(page("Sign in", `
    <div class="login-wrap">
      <div class="login-card">
        <div class="logo" style="font-size:20px">/Bypass<span style="color:#e8ff47">City</span></div>
        <h2 style="font-size:14px;color:#f0ece3">Sign in to continue</h2>
        <p style="font-size:11px;color:#4a4a42;line-height:1.7;max-width:30ch">
          You need a Google account to access the tools. Takes 5 seconds.
        </p>
        <a href="/auth/google?next=${encodeURIComponent(next)}" style="width:100%;max-width:280px">
          <button class="g-btn">
            <div class="g-ic">G</div>
            Continue with Google
          </button>
        </a>
        <p style="font-size:10px;color:#3a3a32">🔒 We only read your email. No spam.</p>
        <a href="/" style="font-size:10px;color:#4a4a42;text-decoration:underline">← back to home</a>
      </div>
    </div>
  `));
});

// GOOGLE OAUTH — rate limit auth endpoints
app.get("/auth/google", authLimiter, (req, res, next) => {
  const state = safeRedirect(req.query.next);
  passport.authenticate("google", { scope: ["profile", "email"], state })(req, res, next);
});

app.get("/auth/google/callback", authLimiter,
  (req, res, next) => {
    passport.authenticate("google", (err, user) => {
      if (err) {
        // Don't expose internal error details to the client
        console.error("OAUTH ERROR:", err);
        return res.redirect("/login?err=auth-failed");
      }
      if (!user) {
        return res.redirect("/login?err=no-user");
      }
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error("LOGIN ERROR:", loginErr);
          return res.redirect("/login?err=login-failed");
        }
        const next = safeRedirect(req.query.state);
        res.redirect(next);
      });
    })(req, res, next);
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

// TOOLS
app.get("/tools", requireAuth, async (req, res) => {
  try {
    const q = req.query.q?.trim().slice(0, 100) || ""; // cap search length
    const cat = req.query.cat || "ALL";
    const CATS = ["ALL","SOURCE","SCRIPT","TOOL","BOT","OTHER"];
    const safeCat = CATS.includes(cat) ? cat : "ALL"; // whitelist categories

    let files;
    if (q || safeCat !== "ALL") {
      files = await searchFiles(q, safeCat === "ALL" ? "" : safeCat, 40, 0);
    } else {
      files = await listFiles(40, 0);
    }

    const catBtns = CATS.map(c =>
      `<button class="si ${c===safeCat?"on":""}" onclick="location.href='/tools?q=${encodeURIComponent(q)}&cat=${encodeURIComponent(c)}'">${c}</button>`
    ).join("");

    const fileCards = files.length === 0
      ? `<div style="grid-column:span 2;padding:40px;text-align:center;font-size:11px;color:#3a3a32">no files found</div>`
      : files.map(f => `
        <div class="fc">
          <div class="fc-icon">${catIcon(f.category)}</div>
          <div class="fc-name">${escHtml(f.name)}</div>
          ${f.description ? `<div class="fc-desc">${escHtml(f.description.slice(0,80))}</div>` : ""}
          <div class="fc-meta">${fmtSize(f.size)} · ${f.dl_count} dl · ${timeAgo(f.created_at)}</div>
          <a href="/tools/${escHtml(f.id)}" class="dl-btn">DOWNLOAD</a>
        </div>`).join("");

    res.send(page("Tools", `
      <div class="ad-slot">
        <div class="ad-lbl">ADVERTISEMENT</div>
        ${HILLTOP_AD}
      </div>
      <form class="search-bar" method="GET" action="/tools">
        <input type="text" name="q" value="${escHtml(q)}" placeholder="search tools..." style="flex:1" maxlength="100">
        <input type="hidden" name="cat" value="${escHtml(safeCat)}">
        <button type="submit" class="btn" style="white-space:nowrap">Search</button>
      </form>
      <div class="cats">${catBtns}</div>
      <div class="files-grid">${fileCards}</div>
      <div class="ad-slot">
        <div class="ad-lbl">ADVERTISEMENT</div>
        ${HILLTOP_AD}
      </div>
    `, req.user));
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Error", `<p style="padding:40px;color:#f87171">Something went wrong</p>`, req.user));
  }
});

// DOWNLOAD PAGE
app.get("/tools/:id", requireAuth, async (req, res) => {
  try {
    const f = await getFile(req.params.id);
    if (!f) return res.status(404).send(page("Not found", `<p style="padding:40px;color:#4a4a42">File not found</p>`, req.user));

    const tags = JSON.parse(f.tags || "[]");
    const tagHtml = tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join("");
    const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "1x00000000000000000000AA";

    res.send(page(f.name, `
      <div class="ad-slot">
        <div class="ad-lbl">ADVERTISEMENT</div>
        ${HILLTOP_AD}
      </div>
      <div class="card">
        <h2>${escHtml(f.name)}</h2>
        <p style="font-size:10px;color:#4a4a42;margin-bottom:10px">
          ${escHtml(f.category)} · ${fmtSize(f.size)} · ${f.dl_count||0} downloads · ${timeAgo(f.created_at)}
        </p>
        ${f.description ? `<p style="font-size:11px;color:#4a4a42;margin-bottom:10px;line-height:1.6">${escHtml(f.description)}</p>` : ""}
        ${tagHtml ? `<div class="tags" style="margin-bottom:12px">${tagHtml}</div>` : ""}

        <div class="cf-wrap">
          <p>Complete verification to unlock download</p>
          <div id="cf-widget"></div>
        </div>

        <div id="err-msg" class="err" style="display:none"></div>
        <button class="dl-main" id="dl-btn" disabled>⬇ DOWNLOAD FILE</button>
      </div>
      <div class="ad-slot">
        <div class="ad-lbl">ADVERTISEMENT</div>
        ${HILLTOP_AD}
      </div>

      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
      <script>
        let cfToken = "";
        const FILE_ID = ${escJs(f.id)};
        const FILE_NAME = ${escJs(f.name)};
        window.onload = () => {
          if(typeof turnstile !== "undefined") {
            turnstile.render("#cf-widget", {
              sitekey: ${escJs(siteKey)},
              callback: t => { cfToken = t; document.getElementById("dl-btn").disabled = false; },
              "error-callback": () => { cfToken = ""; document.getElementById("dl-btn").disabled = true; },
              "expired-callback": () => { cfToken = ""; document.getElementById("dl-btn").disabled = true; }
            });
          } else {
            setTimeout(()=>{ cfToken="bypass"; document.getElementById("dl-btn").disabled=false; },1500);
          }
        };
        document.getElementById("dl-btn").onclick = async () => {
          const btn = document.getElementById("dl-btn");
          const err = document.getElementById("err-msg");
          btn.disabled = true; btn.textContent = "DOWNLOADING...";
          err.style.display = "none";
          try {
            const r = await fetch("/api/download/" + FILE_ID, {
              method: "POST",
              headers: {"Content-Type":"application/json"},
              body: JSON.stringify({token: cfToken})
            });
            if (!r.ok) {
              const d = await r.json();
              err.textContent = d.error || "Download failed";
              err.style.display = "block";
              btn.disabled = false; btn.textContent = "⬇ DOWNLOAD FILE";
              return;
            }
            const blob = await r.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = FILE_NAME;
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(url);
            btn.textContent = "✓ DOWNLOADED";
          } catch { err.textContent = "Network error"; err.style.display="block"; btn.disabled=false; btn.textContent="⬇ DOWNLOAD FILE"; }
        };
      </script>
    `, req.user));
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Error", `<p style="padding:40px;color:#f87171">Something went wrong</p>`, req.user));
  }
});

// DOWNLOAD API — proxy file from Cloudinary
app.post("/api/download/:id", dlLimiter, requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const ip = getIp(req);

    const ok = await verifyTurnstile(token, ip);
    if (!ok) return res.status(400).json({ error: "CAPTCHA failed" });

    const f = await getFile(req.params.id);
    if (!f) return res.status(404).json({ error: "Not found" });

    await logDownload(randomUUID(), f.id, req.user.id, ip);

    const cloudUrl = cloudinary.url(f.filename, { resource_type: "raw", secure: true });
    const upstream = await fetch(cloudUrl);
    if (!upstream.ok) return res.status(500).json({ error: "File unavailable" });

    // Sanitize filename for Content-Disposition header
    const safeName = f.name.replace(/[^\w\s.\-]/g, "_");
    res.setHeader("Content-Type", "application/octet-stream"); // force download, never execute
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
    res.setHeader("X-Content-Type-Options", "nosniff");

    const { Readable } = await import("stream");
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Download failed" });
  }
});

// ── ADMIN ─────────────────────────────────────────────────────

app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const stats = await statsQuery();
    const files = await getAllFiles();

    const fileRows = files.map(f => `
      <div class="file-row">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#f0ece3">${escHtml(f.name)}</span>
        <span style="font-size:9px;color:#3a3a32;flex-shrink:0">${fmtSize(f.size)}</span>
        <form method="POST" action="/admin/toggle/${escHtml(f.id)}" style="margin:0">
          <button type="submit" class="btn-tog ${f.published?"on":""}">${f.published?"ON":"OFF"}</button>
        </form>
        <form method="POST" action="/admin/delete/${escHtml(f.id)}" onsubmit="return confirm('Delete?')" style="margin:0">
          <button type="submit" class="btn-del">DEL</button>
        </form>
      </div>`).join("");

    res.send(page("Admin", `
      <div class="a-layout">
        <aside class="a-side">
          <a href="/admin" class="a-nav on">📁 Files</a>
          <a href="/tools" class="a-nav">🔗 Site</a>
        </aside>
        <div class="a-main">
          <div class="stats">
            <div class="stat"><div class="stat-n">${stats.total_files}</div><div class="stat-l">FILES</div></div>
            <div class="stat"><div class="stat-n">${stats.total_downloads}</div><div class="stat-l">DOWNLOADS</div></div>
            <div class="stat"><div class="stat-n">${stats.total_users}</div><div class="stat-l">USERS</div></div>
          </div>

          <form method="POST" action="/admin/upload" enctype="multipart/form-data"
            style="background:#111;border:1px solid #1f1f1f;padding:16px;margin-bottom:16px">
            <div class="section-lbl">UPLOAD FILE</div>
            <label for="fi" class="up-zone">
              <input type="file" name="file" id="fi" required class="up-zone" onchange="document.getElementById('fn').textContent=this.files[0]?.name||'Tap to choose file'">
              <div class="up-zone-inner">
                <strong id="fn">Tap to choose file</strong>
                <p>ZIP, EXE, LUA, PY, DLL — max 50MB</p>
              </div>
            </label>
            <input type="text" name="name" placeholder="Display name *" required maxlength="200" style="margin-bottom:8px">
            <textarea name="description" placeholder="Description (optional)" rows="2" maxlength="1000" style="margin-bottom:8px;resize:none"></textarea>
            <select name="category" style="margin-bottom:8px;width:100%">
              <option>SOURCE</option><option>SCRIPT</option><option>TOOL</option><option>BOT</option><option>OTHER</option>
            </select>
            <input type="text" name="tags" placeholder="Tags: comma, separated" maxlength="500" style="margin-bottom:12px">
            <button type="submit" class="cta" style="width:100%;padding:10px">UPLOAD</button>
          </form>

          <div style="background:#111;border:1px solid #1f1f1f;padding:12px 16px">
            <div class="section-lbl">MANAGE FILES</div>
            ${fileRows || `<p style="font-size:11px;color:#3a3a32;text-align:center;padding:16px">No files yet</p>`}
          </div>
        </div>
      </div>
    `, req.user));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Admin error" });
  }
});

// UPLOAD
app.post("/admin/upload", requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.redirect("/admin?err=no-file");
  const { name, description, category, tags } = req.body;

  const VALID_CATS = ["SOURCE","SCRIPT","TOOL","BOT","OTHER"];
  const safeCategory = VALID_CATS.includes(category) ? category : "OTHER";

  try {
    const { publicId, url } = await uploadToCloudinary(req.file.buffer);
    const tagArr = tags ? tags.split(",").map(t => t.trim().slice(0,50)).filter(Boolean).slice(0,20) : [];
    await insertFile({
      id: randomUUID(),
      name: name.slice(0, 200),
      description: description?.slice(0, 1000) || null,
      filename: publicId,
      mimetype: req.file.mimetype || "application/octet-stream",
      size: req.file.size,
      category: safeCategory,
      tags: JSON.stringify(tagArr),
      cloudinary_url: url,
      cloudinary_public_id: publicId,
    });
    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.redirect("/admin?err=upload-failed");
  }
});

// DELETE
app.post("/admin/delete/:id", requireAdmin, async (req, res) => {
  try {
    const f = await getFileAdmin(req.params.id);
    if (f) {
      try {
        await cloudinary.uploader.destroy(f.filename, { resource_type: "raw" });
      } catch (e) {
        console.error("Cloudinary delete error:", e);
      }
      await deleteFile(req.params.id);
    }
  } catch (e) {
    console.error(e);
  }
  res.redirect("/admin");
});

// TOGGLE
app.post("/admin/toggle/:id", requireAdmin, async (req, res) => {
  try {
    const f = await getFileAdmin(req.params.id);
    if (f) await updateFile({ ...f, tags: f.tags || "[]", published: f.published ? 0 : 1 });
  } catch (e) {
    console.error(e);
  }
  res.redirect("/admin");
});

// 404
app.use((req, res) => res.status(404).send(page("404", `
  <div style="padding:60px;text-align:center">
    <p style="font-size:11px;color:#4a4a42">page not found</p>
    <a href="/" style="font-size:11px;color:#e8ff47;margin-top:12px;display:inline-block">← home</a>
  </div>
`)));

// Global error handler — never expose stack traces
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`bypass-city running on :${PORT}`));
