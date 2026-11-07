import "dotenv/config";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import multer from "multer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { randomUUID, createHash, createHmac } from "crypto";
import { v2 as cloudinary } from "cloudinary";
import streamifier from "streamifier";

import {
  getUser, getUserByGoogle, upsertUser, getUserByTelegram, upsertTelegramUser,
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
      scriptSrc: ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com", "https://fonts.googleapis.com", "https://telegram.org"],
      frameSrc: ["https://challenges.cloudflare.com", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com"],
      imgSrc: ["'self'", "data:", "https:", "https://*.telegram.org", "https://hilltopads.com", "https://*.hilltopads.com", "https://unfoldedtrade.com", "https://unfolded-uncle.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://telegram.org"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
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
    maxAge: 7 * 24 * 60 * 60 * 1000,
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
  if (!process.env.TURNSTILE_SECRET_KEY) return true;
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

function safeRedirect(url) {
  if (!url || typeof url !== "string") return "/tools";
  if (!url.startsWith("/") || url.startsWith("//")) return "/tools";
  return url;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PAGES — HTML inline
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DESIGN SYSTEM — Acid Lime × White × Black
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const CSS = `
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

/* ── Reset & Base ── */
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --lime:#E8FF47;
  --lime-dark:#c8df27;
  --lime-bg:rgba(232,255,71,.08);
  --lime-border:rgba(232,255,71,.2);
  --bg:#FFFFFF;
  --surface:#F7F7F5;
  --surface2:#F0F0EE;
  --border:#EAEAEA;
  --border2:#DEDEDE;
  --txt:#111111;
  --txt2:#555555;
  --txt3:#999999;
  --dark:#0A0A0A;
  --dark2:#141414;
  --dark3:#1E1E1E;
  --green:#16a34a;
  --red:#dc2626;
  --yellow:#ca8a04;
  --radius:12px;
  --radius-sm:8px;
  --radius-lg:16px;
  --radius-pill:100px;
}
html{scroll-behavior:smooth}
body{
  background:var(--bg);
  color:var(--txt);
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  min-height:100vh;
  font-size:15px;
  line-height:1.5;
  -webkit-font-smoothing:antialiased;
}
a{color:inherit;text-decoration:none}
button,input,select,textarea{font-family:inherit}

/* ── Nav ── */
nav{
  background:rgba(255,255,255,.92);
  backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);
  border-bottom:1px solid var(--border);
  padding:0 24px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  position:sticky;
  top:0;
  z-index:100;
  height:60px;
}
.logo{
  font-size:17px;
  font-weight:900;
  letter-spacing:-.04em;
  color:var(--dark);
  display:flex;
  align-items:center;
  gap:9px;
}
.logo-mark{
  width:32px;
  height:32px;
  background:var(--dark);
  border-radius:9px;
  display:flex;
  align-items:center;
  justify-content:center;
  flex-shrink:0;
  position:relative;
  overflow:hidden;
}
.logo-mark::after{
  content:'';
  position:absolute;
  bottom:-4px;
  right:-4px;
  width:14px;
  height:14px;
  background:var(--lime);
  border-radius:3px;
}
.logo-mark svg{position:relative;z-index:1}
.logo-city{color:var(--txt2);font-weight:600}
.nav-links{display:flex;align-items:center;gap:2px;position:absolute;left:50%;transform:translateX(-50%)}
.nav-link{
  font-size:13px;
  font-weight:600;
  padding:7px 14px;
  color:var(--txt2);
  border-radius:var(--radius-sm);
  transition:color .15s,background .15s;
  letter-spacing:-.01em;
}
.nav-link:hover{color:var(--txt);background:var(--surface)}
.nav-link.active{color:var(--txt);background:var(--lime);color:var(--dark)}
.nav-r{display:flex;gap:8px;align-items:center}
.nav-search{
  width:34px;height:34px;
  border:1px solid var(--border);
  background:transparent;
  border-radius:var(--radius-sm);
  display:flex;align-items:center;justify-content:center;
  cursor:pointer;color:var(--txt2);
  transition:all .15s;
}
.nav-search:hover{border-color:var(--border2);color:var(--txt);background:var(--surface)}
.btn-nav{
  font-size:13px;
  font-weight:600;
  padding:8px 16px;
  border:1px solid var(--border2);
  color:var(--txt2);
  background:transparent;
  cursor:pointer;
  border-radius:var(--radius-sm);
  white-space:nowrap;
  transition:all .15s;
}
.btn-nav:hover{color:var(--txt);border-color:var(--border2);background:var(--surface)}
.btn-lime{
  background:var(--lime);
  color:var(--dark);
  border:1px solid var(--lime);
  font-size:13px;
  font-weight:700;
  padding:8px 18px;
  border-radius:var(--radius-sm);
  cursor:pointer;
  transition:all .15s;
  white-space:nowrap;
}
.btn-lime:hover{background:var(--lime-dark);border-color:var(--lime-dark)}
.btn-dark{
  background:var(--dark);
  color:#fff;
  border:1px solid var(--dark);
  font-size:13px;
  font-weight:700;
  padding:8px 18px;
  border-radius:var(--radius-sm);
  cursor:pointer;
  transition:all .15s;
  white-space:nowrap;
}
.btn-dark:hover{background:var(--dark2)}

/* ── Hero ── */
.hero{
  padding:72px 24px 64px;
  max-width:1200px;
  margin:0 auto;
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:48px;
  align-items:center;
}
.hero-left{}
.hero-badge{
  display:inline-flex;
  align-items:center;
  gap:7px;
  background:var(--dark);
  color:#fff;
  font-size:11px;
  font-weight:700;
  padding:5px 12px 5px 8px;
  border-radius:var(--radius-pill);
  margin-bottom:28px;
  letter-spacing:.02em;
}
.hero-badge-dot{
  width:6px;height:6px;
  background:var(--lime);
  border-radius:50%;
}
h1{
  font-size:clamp(44px,6vw,72px);
  font-weight:900;
  line-height:.96;
  letter-spacing:-.05em;
  color:var(--dark);
  margin-bottom:0;
}
h1 .lime-hl{
  display:inline-block;
  background:var(--lime);
  padding:2px 8px;
  border-radius:6px;
  line-height:1.1;
}
.hero-sub-line{
  font-size:clamp(28px,4vw,44px);
  font-weight:900;
  letter-spacing:-.04em;
  color:var(--txt2);
  margin-bottom:20px;
  line-height:1;
}
.hero-desc{
  font-size:15px;
  color:var(--txt2);
  line-height:1.65;
  max-width:38ch;
  margin-bottom:36px;
}
.hero-actions{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.cta-main{
  background:var(--dark);
  color:#fff;
  border:none;
  padding:14px 28px;
  font-size:14px;
  font-weight:700;
  letter-spacing:-.01em;
  cursor:pointer;
  border-radius:var(--radius-sm);
  transition:all .15s;
  display:inline-flex;
  align-items:center;
  gap:9px;
}
.cta-main:hover{background:var(--dark2);transform:translateY(-1px)}
.cta-lime{
  background:var(--lime);
  color:var(--dark);
  border:none;
  padding:14px 28px;
  font-size:14px;
  font-weight:700;
  letter-spacing:-.01em;
  cursor:pointer;
  border-radius:var(--radius-sm);
  transition:all .15s;
  display:inline-flex;
  align-items:center;
  gap:9px;
}
.cta-lime:hover{background:var(--lime-dark);transform:translateY(-1px)}
.cta-ghost{
  background:transparent;
  color:var(--txt);
  border:1px solid var(--border2);
  padding:14px 24px;
  font-size:14px;
  font-weight:600;
  cursor:pointer;
  border-radius:var(--radius-sm);
  transition:all .15s;
  display:inline-flex;
  align-items:center;
  gap:9px;
}
.cta-ghost:hover{border-color:var(--txt);background:var(--surface)}

/* ── City illustration ── */
.hero-right{display:flex;align-items:center;justify-content:center}
.city-wrap{
  position:relative;
  width:100%;
  max-width:460px;
  aspect-ratio:1/0.85;
}
.city-bg{
  position:absolute;
  inset:0;
  background:var(--dark);
  border-radius:24px;
  overflow:hidden;
}
.city-bg::before{
  content:'';
  position:absolute;
  bottom:0;left:50%;
  transform:translateX(-50%);
  width:280px;height:120px;
  background:var(--lime);
  filter:blur(60px);
  opacity:.4;
}
.city-buildings{
  position:absolute;
  bottom:0;left:0;right:0;
  display:flex;
  align-items:flex-end;
  justify-content:center;
  gap:4px;
  padding:0 16px;
}
.bld{background:#1a1a1a;border-radius:3px 3px 0 0;position:relative}
.bld::before{
  content:'';
  position:absolute;
  inset:0;
  border:1px solid rgba(232,255,71,.08);
  border-radius:inherit;
}
.bld-w{
  position:absolute;
  background:var(--lime);
  opacity:.7;
  border-radius:1px;
}
.city-ring{
  position:absolute;
  left:50%;top:52%;
  transform:translate(-50%,-50%);
  width:200px;height:60px;
  border:3px solid var(--lime);
  border-radius:50%;
  box-shadow:0 0 32px rgba(232,255,71,.5), 0 0 60px rgba(232,255,71,.2);
}
.city-crown{
  position:absolute;
  top:16px;left:50%;
  transform:translateX(-50%);
  font-size:36px;
  filter:drop-shadow(0 0 12px var(--lime));
}

/* ── Stats strip ── */
.stats-strip{
  border-top:1px solid var(--border);
  border-bottom:1px solid var(--border);
  display:grid;
  grid-template-columns:repeat(3,1fr);
  background:var(--bg);
}
.stat-cell{
  padding:24px 32px;
  border-right:1px solid var(--border);
  display:flex;
  flex-direction:column;
  gap:4px;
}
.stat-cell:last-child{border-right:0}
.stat-num{font-size:32px;font-weight:900;color:var(--dark);line-height:1;letter-spacing:-.04em}
.stat-lbl{font-size:12px;color:var(--txt2);font-weight:500}

/* ── Info cards ── */
.info-row{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:0;
  border-top:1px solid var(--border);
}
.info-c{
  padding:28px 32px;
  border-right:1px solid var(--border);
  background:var(--bg);
}
.info-c:last-child{border-right:0}
.info-icon-wrap{
  width:40px;height:40px;
  background:var(--dark);
  border-radius:var(--radius-sm);
  display:flex;align-items:center;justify-content:center;
  margin-bottom:14px;
}
.info-lbl{font-size:14px;font-weight:700;color:var(--dark);margin-bottom:7px;letter-spacing:-.02em}
.info-p{font-size:13px;color:var(--txt2);line-height:1.65}

/* ── Telegram bar ── */
.tg-bar{
  background:var(--dark);
  padding:18px 32px;
  display:flex;
  align-items:center;
  gap:16px;
  border-top:1px solid var(--border);
}
.tg-ic{
  width:40px;height:40px;
  border-radius:var(--radius-sm);
  background:#1a4a7a;
  display:flex;align-items:center;justify-content:center;
  font-size:20px;
  flex-shrink:0;
}
.tg-txt{font-size:14px;color:rgba(255,255,255,.6);flex:1}
.tg-txt strong{color:#fff;display:block;margin-bottom:3px;font-size:14px}

/* ── Ad slot ── */
.ad-slot{
  padding:14px 24px;
  text-align:center;
  border-bottom:1px solid var(--border);
  background:var(--surface);
}
.ad-lbl{font-size:9px;color:var(--txt3);letter-spacing:.1em;margin-bottom:6px;text-transform:uppercase;font-weight:600}

/* ── Search bar ── */
.search-section{
  padding:24px;
  background:var(--bg);
  border-bottom:1px solid var(--border);
}
.search-wrap{max-width:640px;margin:0 auto;position:relative}
.search-icon{
  position:absolute;
  left:16px;top:50%;
  transform:translateY(-50%);
  color:var(--txt3);
  pointer-events:none;
}
.search-input{
  width:100%;
  background:var(--surface);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:14px 16px 14px 44px;
  font-size:14px;
  color:var(--txt);
  outline:none;
  transition:border-color .15s,box-shadow .15s;
  caret-color:var(--dark);
}
.search-input::placeholder{color:var(--txt3)}
.search-input:focus{
  border-color:var(--dark);
  box-shadow:0 0 0 3px rgba(17,17,17,.06);
}
.search-btn{
  position:absolute;
  right:8px;top:50%;
  transform:translateY(-50%);
  background:var(--dark);
  color:#fff;
  border:none;
  padding:8px 16px;
  font-size:12px;
  font-weight:700;
  border-radius:var(--radius-sm);
  cursor:pointer;
  transition:background .15s;
  letter-spacing:-.01em;
}
.search-btn:hover{background:var(--dark2)}

/* ── Category pills ── */
.cats{
  padding:14px 24px;
  display:flex;
  gap:8px;
  overflow-x:auto;
  border-bottom:1px solid var(--border);
  background:var(--bg);
  scrollbar-width:none;
}
.cats::-webkit-scrollbar{display:none}
.cat-btn{
  font-size:12px;
  font-weight:700;
  padding:7px 18px;
  border:1.5px solid var(--border2);
  color:var(--txt2);
  background:transparent;
  cursor:pointer;
  white-space:nowrap;
  border-radius:var(--radius-pill);
  transition:all .15s;
  letter-spacing:.01em;
}
.cat-btn:hover{color:var(--txt);border-color:var(--txt);background:var(--surface)}
.cat-btn.on{color:var(--dark);background:var(--lime);border-color:var(--lime)}

/* ── File cards grid ── */
.files-section{
  padding:24px;
  background:var(--bg);
}
.files-grid{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:16px;
  max-width:1200px;
  margin:0 auto;
}
.fc{
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:20px;
  display:flex;
  flex-direction:column;
  gap:10px;
  transition:border-color .2s,transform .2s,box-shadow .2s;
  cursor:pointer;
}
.fc:hover{
  border-color:var(--dark);
  transform:translateY(-3px);
  box-shadow:0 8px 24px rgba(17,17,17,.08);
}
.fc-top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:4px}
.fc-icon{
  width:44px;height:44px;
  border-radius:var(--radius-sm);
  display:flex;align-items:center;justify-content:center;
  font-size:18px;
  flex-shrink:0;
  font-weight:900;
  font-family:'Inter',monospace;
}
.fc-icon.src{background:var(--dark);color:var(--lime)}
.fc-icon.scr{background:#0f2d1f;color:#4ade80}
.fc-icon.tool{background:#1a1200;color:var(--lime)}
.fc-icon.bot{background:#0a1a2d;color:#60a5fa}
.fc-icon.other{background:var(--surface2);color:var(--txt2)}
.fc-cat{
  display:inline-block;
  font-size:10px;
  font-weight:800;
  padding:3px 9px;
  border-radius:var(--radius-pill);
  letter-spacing:.04em;
}
.fc-cat.src{background:var(--dark);color:var(--lime)}
.fc-cat.scr{background:#0f2d1f;color:#4ade80}
.fc-cat.tool{background:var(--lime);color:var(--dark)}
.fc-cat.bot{background:#0a1a2d;color:#60a5fa}
.fc-cat.other{background:var(--surface2);color:var(--txt2)}
.fc-name{font-size:14px;font-weight:800;color:var(--dark);line-height:1.25;letter-spacing:-.02em}
.fc-desc{font-size:12px;color:var(--txt2);line-height:1.55;flex:1}
.fc-meta{font-size:11px;color:var(--txt3);display:flex;gap:8px;flex-wrap:wrap}
.fc-meta-sep{color:var(--border2)}
.dl-btn{
  font-size:12px;
  font-weight:700;
  text-align:center;
  color:var(--dark);
  background:var(--lime);
  border:none;
  padding:10px;
  cursor:pointer;
  display:block;
  width:100%;
  border-radius:var(--radius-sm);
  transition:background .15s,transform .15s;
  margin-top:4px;
  letter-spacing:.01em;
}
.dl-btn:hover{background:var(--lime-dark);transform:translateY(-1px)}

/* ── Empty / no results ── */
.empty-state{
  grid-column:1/-1;
  padding:72px 24px;
  text-align:center;
}
.empty-state-icon{font-size:40px;margin-bottom:16px}
.empty-state h3{font-size:17px;font-weight:800;color:var(--dark);margin-bottom:8px;letter-spacing:-.02em}
.empty-state p{font-size:14px;color:var(--txt2)}

/* ── Download card ── */
.card-wrap{padding:32px 24px;max-width:560px;margin:0 auto}
.card{
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius-lg);
  padding:28px;
  display:flex;
  flex-direction:column;
  gap:18px;
}
.card-header{display:flex;align-items:flex-start;gap:16px}
.card h2{font-size:20px;font-weight:900;color:var(--dark);line-height:1.2;margin-bottom:5px;letter-spacing:-.03em}
.card-meta-row{font-size:12px;color:var(--txt2);display:flex;gap:10px;flex-wrap:wrap}
.cf-wrap{
  background:var(--surface);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:20px;
  text-align:center;
}
.cf-wrap p{font-size:13px;color:var(--txt2);margin-bottom:14px}
.dl-main{
  width:100%;
  padding:16px;
  background:var(--dark);
  color:#fff;
  border:none;
  font-size:15px;
  font-weight:800;
  cursor:pointer;
  border-radius:var(--radius);
  transition:all .15s;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:10px;
  letter-spacing:-.02em;
}
.dl-main:disabled{background:var(--surface2);color:var(--txt3);cursor:not-allowed}
.dl-main:hover:not(:disabled){background:var(--dark2);transform:translateY(-1px)}
.tags{display:flex;gap:7px;flex-wrap:wrap}
.tag{
  font-size:11px;
  font-weight:600;
  border:1.5px solid var(--border2);
  padding:4px 11px;
  color:var(--txt2);
  border-radius:var(--radius-pill);
}
.err{color:var(--red);font-size:13px}
.ok{color:var(--green);font-size:13px}
.divider{height:1px;background:var(--border)}

/* ── Admin ── */
.a-layout{display:flex;min-height:calc(100vh - 60px)}
.a-side{
  width:200px;
  border-right:1.5px solid var(--border);
  background:var(--surface);
  padding:16px 0;
  flex-shrink:0;
}
.a-nav{
  padding:11px 20px;
  font-size:13px;
  font-weight:600;
  color:var(--txt2);
  cursor:pointer;
  display:flex;
  align-items:center;
  gap:9px;
  border-left:3px solid transparent;
  transition:all .15s;
  letter-spacing:-.01em;
}
.a-nav:hover{color:var(--txt);background:var(--surface2)}
.a-nav.on{color:var(--dark);border-left-color:var(--lime);background:var(--lime-bg)}
.a-main{flex:1;padding:28px;overflow:auto;background:var(--bg)}
.a-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:28px}
.stat{
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:20px 24px;
}
.stat-n{font-size:32px;font-weight:900;color:var(--dark);line-height:1;letter-spacing:-.04em}
.stat-l{font-size:11px;color:var(--txt2);margin-top:5px;font-weight:600;letter-spacing:.02em}
.a-section-lbl{
  font-size:11px;
  font-weight:800;
  color:var(--txt3);
  margin-bottom:14px;
  letter-spacing:.08em;
  text-transform:uppercase;
}
/* Upload zone */
.up-block{
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:24px;
  margin-bottom:20px;
}
.up-zone{
  border:2px dashed var(--border2);
  border-radius:var(--radius);
  padding:28px 16px;
  cursor:pointer;
  display:block;
  text-align:center;
  transition:border-color .2s,background .2s;
  position:relative;
  margin-bottom:14px;
}
.up-zone:hover,.up-zone.has-file{border-color:var(--dark);background:var(--surface)}
.up-zone input[type=file]{position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer}
.up-zone-inner{pointer-events:none}
.up-zone-icon{font-size:32px;margin-bottom:10px}
.up-zone strong{font-size:14px;font-weight:700;color:var(--dark);display:block;margin-bottom:5px}
.up-zone p{font-size:12px;color:var(--txt2)}
.up-zone .chosen{font-size:13px;color:var(--dark);font-weight:700;margin-top:6px;word-break:break-all;display:none}
.up-zone.has-file .chosen{display:block}
.up-zone.has-file .default-hint{display:none}
.up-fields{display:flex;flex-direction:column;gap:10px}
input[type=text],input[type=email],input[type=password],textarea,select{
  background:var(--surface);
  border:1.5px solid var(--border);
  border-radius:var(--radius-sm);
  padding:10px 14px;
  font-size:13px;
  color:var(--txt);
  outline:none;
  width:100%;
  transition:border-color .15s,box-shadow .15s;
  caret-color:var(--dark);
}
input:focus,textarea:focus,select:focus{
  border-color:var(--dark);
  box-shadow:0 0 0 3px rgba(17,17,17,.06);
}
select{padding:10px 14px;cursor:pointer}
/* File rows */
.files-block{
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:20px;
}
.file-row{
  display:flex;
  align-items:center;
  gap:12px;
  padding:12px 0;
  border-bottom:1px solid var(--border);
}
.file-row:last-child{border-bottom:0}
.file-row-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;font-weight:600;color:var(--dark)}
.file-row-size{font-size:11px;color:var(--txt3);flex-shrink:0;white-space:nowrap}
.btn-del{
  font-size:11px;
  color:var(--red);
  border:1.5px solid rgba(220,38,38,.2);
  padding:6px 13px;
  background:transparent;
  cursor:pointer;
  border-radius:var(--radius-sm);
  font-weight:700;
  transition:all .15s;
}
.btn-del:hover{background:rgba(220,38,38,.06)}
.btn-tog{
  font-size:11px;
  padding:6px 13px;
  border:1.5px solid var(--border2);
  background:transparent;
  cursor:pointer;
  color:var(--txt2);
  border-radius:var(--radius-sm);
  font-weight:700;
  transition:all .15s;
}
.btn-tog:hover{border-color:var(--border2)}
.btn-tog.on{color:var(--green);border-color:rgba(22,163,74,.35);background:rgba(22,163,74,.06)}
.a-upload-btn{
  width:100%;
  padding:12px;
  background:var(--dark);
  color:#fff;
  border:none;
  font-size:14px;
  font-weight:700;
  cursor:pointer;
  border-radius:var(--radius-sm);
  transition:background .15s;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:8px;
}
.a-upload-btn:hover{background:var(--dark2)}

/* ── Login ── */
.login-wrap{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  background:var(--bg);
  padding:16px;
  position:relative;
  overflow:hidden;
}
.login-wrap::before{
  content:'';
  position:absolute;
  bottom:0;left:0;right:0;
  height:40%;
  background:var(--dark);
  clip-path:polygon(0 40%,100% 0,100% 100%,0 100%);
}
.login-card{
  text-align:center;
  padding:44px 32px;
  width:100%;
  max-width:380px;
  display:flex;
  flex-direction:column;
  align-items:center;
  gap:24px;
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius-lg);
  position:relative;
  z-index:1;
  box-shadow:0 20px 60px rgba(17,17,17,.1);
}
.login-logo{
  font-size:22px;
  font-weight:900;
  letter-spacing:-.04em;
  display:flex;
  align-items:center;
  gap:11px;
  color:var(--dark);
}
.login-logo-mark{
  width:40px;height:40px;
  background:var(--dark);
  border-radius:var(--radius-sm);
  display:flex;align-items:center;justify-content:center;
  font-size:20px;color:var(--lime);font-weight:900;
}
.login-title{font-size:18px;font-weight:900;color:var(--dark);letter-spacing:-.03em;margin-bottom:4px}
.login-sub{font-size:13px;color:var(--txt2);line-height:1.6;max-width:26ch;margin:0 auto}
.g-btn{
  display:flex;
  align-items:center;
  gap:11px;
  background:var(--dark);
  color:#fff;
  border:none;
  padding:14px 24px;
  font-size:14px;
  font-weight:700;
  cursor:pointer;
  width:100%;
  max-width:300px;
  justify-content:center;
  border-radius:var(--radius-sm);
  transition:background .15s;
  letter-spacing:-.01em;
}
.g-btn:hover{background:var(--dark2)}
.g-ic{
  width:22px;height:22px;
  border-radius:50%;
  background:#ea4335;
  display:flex;align-items:center;justify-content:center;
  color:#fff;font-size:11px;font-weight:900;
  flex-shrink:0;
}

/* ── Hamburger / Mobile Menu ── */
.nav-hamburger{
  display:none;
  width:36px;height:36px;
  border:1.5px solid var(--border2);
  background:transparent;
  border-radius:var(--radius-sm);
  cursor:pointer;
  align-items:center;
  justify-content:center;
  flex-direction:column;
  gap:5px;
  padding:0;
  flex-shrink:0;
  transition:border-color .15s,background .15s;
}
.nav-hamburger:hover{border-color:var(--txt2);background:var(--surface)}
.nav-hamburger span{
  display:block;
  width:16px;height:1.5px;
  background:var(--txt);
  border-radius:2px;
  transition:all .2s;
}
.nav-hamburger.open span:nth-child(1){transform:translateY(6.5px) rotate(45deg)}
.nav-hamburger.open span:nth-child(2){opacity:0;transform:scaleX(0)}
.nav-hamburger.open span:nth-child(3){transform:translateY(-6.5px) rotate(-45deg)}

.mobile-menu{
  display:none;
  position:fixed;
  top:60px;left:0;right:0;
  background:rgba(255,255,255,.97);
  backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);
  border-bottom:1.5px solid var(--border);
  z-index:99;
  padding:12px 16px 20px;
  flex-direction:column;
  gap:4px;
  box-shadow:0 8px 32px rgba(17,17,17,.08);
}
.mobile-menu.open{display:flex}
.mob-link{
  font-size:14px;
  font-weight:600;
  color:var(--txt2);
  padding:11px 14px;
  border-radius:var(--radius-sm);
  transition:color .15s,background .15s;
  letter-spacing:-.01em;
}
.mob-link:hover{color:var(--txt);background:var(--surface)}
.mob-link.active{color:var(--dark);background:var(--lime)}
.mob-divider{height:1px;background:var(--border);margin:8px 0}
.mob-btn-row{display:flex;gap:8px;padding:4px 0}
.mob-btn-row .btn-lime,.mob-btn-row .btn-dark,.mob-btn-row .btn-nav{
  flex:1;text-align:center;justify-content:center;
  padding:11px 12px;font-size:13px;
}

/* ── Responsive ── */
@media(max-width:1024px){
  .files-grid{grid-template-columns:repeat(3,1fr)}
  .nav-links{display:none}
}
@media(max-width:768px){
  nav{padding:0 16px}
  .nav-r{display:none}
  .nav-hamburger{display:flex}
  .hero{grid-template-columns:1fr;gap:36px;padding:48px 20px 40px}
  .hero-right{display:none}
  .files-grid{grid-template-columns:repeat(2,1fr);gap:12px}
  .files-section{padding:16px}
  .search-section{padding:16px}
  .cats{padding:12px 16px}
  .stats-strip{grid-template-columns:1fr}
  .stat-cell{border-right:0;border-bottom:1px solid var(--border)}
  .stat-cell:last-child{border-bottom:0}
  .info-row{grid-template-columns:1fr}
  .info-c{border-right:0;border-bottom:1px solid var(--border)}
  .card-wrap{padding:20px 16px}
  .a-layout{flex-direction:column}
  .a-side{width:100%;display:flex;flex-direction:row;border-right:0;border-bottom:1.5px solid var(--border);padding:0;overflow-x:auto}
  .a-nav{border-left:0;border-bottom:3px solid transparent;padding:13px 18px;white-space:nowrap}
  .a-nav.on{border-left:0;border-bottom-color:var(--lime);background:transparent}
  .a-stats{grid-template-columns:1fr 1fr}
  .tg-bar{flex-wrap:wrap;padding:16px 20px}
  .a-main{padding:16px}
}
@media(max-width:480px){
  .files-grid{grid-template-columns:1fr;gap:10px}
  h1{font-size:40px}
  .hero-sub-line{font-size:26px}
  .a-stats{grid-template-columns:1fr}
}
</style>`;

function nav(user, activePage = "") {
  const mobileAuthLinks = user
    ? `<div class="mob-divider"></div>
       <div class="mob-btn-row">
         <a href="/tools" class="btn-dark">⚡ Tools</a>
         ${isAdminUser(user) ? `<a href="/admin" class="btn-nav">Admin</a>` : ""}
         <a href="/logout" class="btn-nav">Logout</a>
       </div>`
    : `<div class="mob-divider"></div>
       <div class="mob-btn-row">
         <a href="/login" class="btn-lime">Sign in →</a>
       </div>`;

  return `<nav>
    <a href="/" class="logo">
      <div class="logo-mark">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 13L8 3L13 13H10L8 9L6 13H3Z" fill="white"/></svg>
      </div>
      <span>Bypass</span><span class="logo-city">City</span>
    </a>
    <div class="nav-links">
      <a href="/" class="nav-link ${activePage==="home"?"active":""}">Home</a>
      <a href="/tools" class="nav-link ${activePage==="tools"?"active":""}">Tools</a>
      <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="nav-link">Guides</a>
      <a href="/" class="nav-link ${activePage==="about"?"active":""}">About</a>
    </div>
    <div class="nav-r">
      <button class="nav-search" aria-label="Search">
        <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 10.5L13.5 13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      </button>
      <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="btn-nav">✈ Telegram</a>
      ${user
        ? `<a href="/tools" class="btn-dark">⚡ Tools</a>${isAdminUser(user)?`<a href="/admin" class="btn-nav">Admin</a>`:""}<a href="/logout" class="btn-nav">Logout</a>`
        : `<a href="/login" class="btn-lime">Sign in</a>`}
    </div>
    <button class="nav-hamburger" id="nav-hbg" aria-label="Menu" aria-expanded="false">
      <span></span><span></span><span></span>
    </button>
  </nav>
  <div class="mobile-menu" id="mobile-menu">
    <a href="/" class="mob-link ${activePage==="home"?"active":""}">Home</a>
    <a href="/tools" class="mob-link ${activePage==="tools"?"active":""}">⚡ Tools</a>
    <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="mob-link">✈ Telegram</a>
    <a href="/" class="mob-link">About</a>
    ${mobileAuthLinks}
  </div>
  <script>
    (function(){
      var btn = document.getElementById('nav-hbg');
      var menu = document.getElementById('mobile-menu');
      if(!btn||!menu) return;
      btn.addEventListener('click', function(){
        var open = menu.classList.toggle('open');
        btn.classList.toggle('open', open);
        btn.setAttribute('aria-expanded', open);
        document.body.style.overflow = open ? 'hidden' : '';
      });
      menu.querySelectorAll('a').forEach(function(a){
        a.addEventListener('click', function(){
          menu.classList.remove('open');
          btn.classList.remove('open');
          btn.setAttribute('aria-expanded','false');
          document.body.style.overflow = '';
        });
      });
    })();
  </script>`;
}

function page(title, body, user = null, activePage = "") {
  return `<!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escHtml(title)} — BypassCity</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <meta property="og:title" content="${escHtml(title)} — BypassCity">
    <meta property="og:description" content="Scripts, sources, bots, and tools — all in one place. Free forever.">
    <meta property="og:image" content="/logo.png">
    <meta property="og:type" content="website">${CSS}
  </head><body>${nav(user, activePage)}${body}${HILLTOP_POPUNDER}</body></html>`;
}

function cityIllustration() {
  return `<div class="city-wrap">
    <div class="city-bg">
      <div class="city-crown">👑</div>
      <div class="city-ring"></div>
      <div class="city-buildings">
        <div class="bld" style="width:22px;height:60px">
          <div class="bld-w" style="width:3px;height:3px;top:8px;left:4px"></div>
          <div class="bld-w" style="width:3px;height:3px;top:8px;right:4px"></div>
          <div class="bld-w" style="width:3px;height:3px;top:18px;left:4px"></div>
        </div>
        <div class="bld" style="width:30px;height:90px">
          <div class="bld-w" style="width:4px;height:4px;top:10px;left:5px"></div>
          <div class="bld-w" style="width:4px;height:4px;top:10px;right:5px"></div>
          <div class="bld-w" style="width:4px;height:4px;top:24px;left:5px"></div>
          <div class="bld-w" style="width:4px;height:4px;top:24px;right:5px"></div>
        </div>
        <div class="bld" style="width:38px;height:130px">
          <div class="bld-w" style="width:5px;height:5px;top:12px;left:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:12px;right:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:28px;left:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:28px;right:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:44px;left:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:44px;right:7px"></div>
        </div>
        <div class="bld" style="width:50px;height:160px">
          <div class="bld-w" style="width:6px;height:6px;top:14px;left:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:14px;right:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:30px;left:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:30px;right:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:46px;left:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:46px;right:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:62px;left:9px"></div>
          <div class="bld-w" style="width:6px;height:6px;top:62px;right:9px"></div>
        </div>
        <div class="bld" style="width:38px;height:120px">
          <div class="bld-w" style="width:5px;height:5px;top:12px;left:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:12px;right:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:28px;left:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:28px;right:7px"></div>
          <div class="bld-w" style="width:5px;height:5px;top:44px;left:7px"></div>
        </div>
        <div class="bld" style="width:28px;height:85px">
          <div class="bld-w" style="width:4px;height:4px;top:10px;left:5px"></div>
          <div class="bld-w" style="width:4px;height:4px;top:10px;right:5px"></div>
          <div class="bld-w" style="width:4px;height:4px;top:24px;left:5px"></div>
        </div>
        <div class="bld" style="width:20px;height:55px">
          <div class="bld-w" style="width:3px;height:3px;top:8px;left:4px"></div>
          <div class="bld-w" style="width:3px;height:3px;top:8px;right:4px"></div>
        </div>
      </div>
    </div>
  </div>`;
}

function catIcon(cat) {
  const icons = { SOURCE:"&lt;/&gt;", SCRIPT:"#!/", TOOL:"⚙", BOT:"◈", OTHER:"◉" };
  return icons[cat] || "◉";
}
function catClass(cat) {
  return { SOURCE:"src", SCRIPT:"scr", TOOL:"tool", BOT:"bot", OTHER:"other" }[cat] || "other";
}
function fmtSize(b) {
  if (!b) return "0 KB";
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
  return (b / 1024 / 1024).toFixed(1) + " MB";
}
function timeAgo(ts) {
  if (!ts) return "";
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function escJs(s) {
  return JSON.stringify(String(s));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ROUTES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// HOME
app.get("/", (req, res) => {
  res.send(page("Home", `
    <section class="hero">
      <div class="hero-left">
        <div class="hero-badge"><span class="hero-badge-dot"></span>bypass-city.lol</div>
        <h1>All Tools.<br><span class="lime-hl">One Place.</span></h1>
        <div class="hero-sub-line">Fast. Free. Powerful.</div>
        <p class="hero-desc">Explore our collection of tools and make the most out of your digital life.</p>
        <div class="hero-actions">
          <a href="${req.isAuthenticated() ? "/tools" : "/login"}">
            <button class="cta-main">Browse Tools →</button>
          </a>
          <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer">
            <button class="cta-ghost">✈ Telegram</button>
          </a>
        </div>
      </div>
      <div class="hero-right">
        ${cityIllustration()}
      </div>
    </section>
    <div class="stats-strip">
      <div class="stat-cell"><div class="stat-num">100%</div><div class="stat-lbl">Free forever</div></div>
      <div class="stat-cell"><div class="stat-num">0</div><div class="stat-lbl">Paywalls</div></div>
      <div class="stat-cell"><div class="stat-num">∞</div><div class="stat-lbl">Tools available</div></div>
    </div>
    <div class="info-row">
      <div class="info-c">
        <div class="info-icon-wrap">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="2" y="2" width="14" height="14" rx="3" fill="#E8FF47"/><path d="M6 9L8 11L12 7" stroke="#0A0A0A" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <div class="info-lbl">What's here</div>
        <div class="info-p">Sources, scripts, bots, bypass tools — updated regularly. Everything you need, nothing you don't.</div>
      </div>
      <div class="info-c">
        <div class="info-icon-wrap">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M9 2L11 7H16L12 10.5L13.5 16L9 12.5L4.5 16L6 10.5L2 7H7L9 2Z" fill="#E8FF47"/></svg>
        </div>
        <div class="info-lbl">Free access</div>
        <div class="info-p">Free with Google sign-in. No subscription, no paywall, no BS. Takes five seconds to unlock everything.</div>
      </div>
    </div>
    <div class="tg-bar">
      <div class="tg-ic">✈</div>
      <div class="tg-txt">
        <strong>Updates &amp; announcements</strong>
        t.me/yocnd — new tools drop here first
      </div>
      <a href="https://t.me/yocnd" target="_blank" rel="noopener noreferrer" class="btn-lime" style="margin-left:auto;flex-shrink:0">Join →</a>
    </div>
    <div class="ad-slot">
      <div class="ad-lbl">Advertisement</div>
      ${HILLTOP_AD}
    </div>
  `, req.user, "home"));
});

// LOGIN
// ── Telegram auth helper ─────────────────────────────────────
function verifyTelegramAuth(data) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) return false;
  const { hash, ...fields } = data;
  if (!hash) return false;
  if (Date.now() / 1000 - Number(fields.auth_date) > 86400) return false;
  const checkString = Object.keys(fields).sort().map(k => `${k}=${fields[k]}`).join("\n");
  const secretKey = createHash("sha256").update(botToken).digest();
  const hmac = createHmac("sha256", secretKey).update(checkString).digest("hex");
  return hmac === hash;
}

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/tools");
  const next = safeRedirect(req.query.next);
  res.send(page("Sign in", `
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">
          <div class="login-logo-mark">B</div>
          BypassCity
        </div>
        <div>
          <div class="login-title">Sign in to continue</div>
          <p class="login-sub">Choose how you want to sign in. Takes 5 seconds.</p>
        </div>
        <a href="/auth/google?next=${encodeURIComponent(next)}" style="width:100%;display:flex;justify-content:center">
          <button class="g-btn">
            <div class="g-ic">G</div>
            Continue with Google
          </button>
        </a>
        <div style="display:flex;align-items:center;gap:10px;width:100%;margin:4px 0">
          <div style="flex:1;height:1px;background:var(--brd)"></div>
          <span style="font-size:11px;color:var(--txt3)">or</span>
          <div style="flex:1;height:1px;background:var(--brd)"></div>
        </div>
        <div style="width:100%;display:flex;justify-content:center">
          <script async src="https://telegram.org/js/telegram-widget.js?22"
            data-telegram-login="BypassCityBot"
            data-size="large"
            data-auth-url="https://bypass-city.lol/auth/telegram/callback?next=${encodeURIComponent(next)}"
            data-request-access="write">
          </script>
        </div>
        <p style="font-size:11px;color:var(--txt3)">🔒 We only read your basic profile. No spam.</p>
        <a href="/" style="font-size:12px;color:var(--txt2)">← Back to home</a>
      </div>
    </div>
  `));
});

// TELEGRAM AUTH CALLBACK
app.get("/auth/telegram/callback", authLimiter, async (req, res) => {
  try {
    const data = { ...req.query };
    const next = safeRedirect(data.next || "/tools");
    delete data.next;

    if (!verifyTelegramAuth(data)) {
      return res.redirect("/login?err=telegram_invalid");
    }

    const existing = await getUserByTelegram(data.id);
    const id = existing?.id || randomUUID();

    await upsertTelegramUser({
      id,
      telegram_id: data.id,
      name: [data.first_name, data.last_name].filter(Boolean).join(" "),
      avatar: data.photo_url || "",
    });

    const user = await getUser(id);
    req.logIn(user, (err) => {
      if (err) {
        console.error("TG LOGIN ERROR:", err);
        return res.redirect("/login?err=telegram_login_failed");
      }
      res.redirect(next);
    });
  } catch (e) {
    console.error("Telegram auth error:", e);
    res.redirect("/login?err=telegram_error");
  }
});

// GOOGLE OAUTH
app.get("/auth/google", authLimiter, (req, res, next) => {
  const state = safeRedirect(req.query.next);
  passport.authenticate("google", { scope: ["profile", "email"], state })(req, res, next);
});

app.get("/auth/google/callback", authLimiter,
  (req, res, next) => {
    passport.authenticate("google", (err, user) => {
      if (err) {
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
    const q = req.query.q?.trim().slice(0, 100) || "";
    const cat = req.query.cat || "ALL";
    const CATS = ["ALL","SOURCE","SCRIPT","TOOL","BOT","OTHER"];
    const safeCat = CATS.includes(cat) ? cat : "ALL";

    let files;
    if (q || safeCat !== "ALL") {
      files = await searchFiles(q, safeCat === "ALL" ? "" : safeCat, 40, 0);
    } else {
      files = await listFiles(40, 0);
    }

    const catBtns = CATS.map(c =>
      `<button class="cat-btn ${c===safeCat?"on":""}" onclick="location.href='/tools?q=${encodeURIComponent(q)}&cat=${encodeURIComponent(c)}'">${c}</button>`
    ).join("");

    const fileCards = files.length === 0
      ? `<div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <h3>No tools found</h3>
          <p>${q ? `No results for "${escHtml(q)}"` : "Nothing in this category yet."}</p>
         </div>`
      : files.map(f => {
          const cc = catClass(f.category);
          return `
        <div class="fc" onclick="location.href='/tools/${escHtml(f.id)}'">
          <div class="fc-top">
            <div class="fc-icon ${cc}">${catIcon(f.category)}</div>
            <span class="fc-cat ${cc}">${escHtml(f.category)}</span>
          </div>
          <div class="fc-name">${escHtml(f.name)}</div>
          ${f.description ? `<div class="fc-desc">${escHtml(f.description.slice(0,100))}</div>` : ""}
          <div class="fc-meta">
            <span>${fmtSize(f.size)}</span>
            <span class="fc-meta-sep">·</span>
            <span>${f.dl_count||0} downloads</span>
            <span class="fc-meta-sep">·</span>
            <span>${timeAgo(f.created_at)}</span>
          </div>
          <a href="/tools/${escHtml(f.id)}" class="dl-btn">↓ Download</a>
        </div>`;
        }).join("");

    res.send(page("Tools", `
      <div class="search-section">
        <form method="GET" action="/tools" class="search-wrap">
          <span class="search-icon">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="7" cy="7" r="4.5" stroke="currentColor" stroke-width="1.5"/><path d="M11 11L14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
          </span>
          <input class="search-input" type="text" name="q" value="${escHtml(q)}" placeholder="Search for a tool..." maxlength="100" autocomplete="off">
          <input type="hidden" name="cat" value="${escHtml(safeCat)}">
          <button type="submit" class="search-btn">Search</button>
        </form>
      </div>
      <div class="cats">${catBtns}</div>
      <div class="files-section">
        <div class="files-grid">${fileCards}</div>
      </div>
      <div class="ad-slot" style="margin:0;border-top:1px solid var(--border);border-bottom:none;padding:20px 24px 24px">
        <div class="ad-lbl">Advertisement</div>
        ${HILLTOP_AD}
      </div>
    `, req.user, "tools"));
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Error", `<div style="padding:60px;text-align:center;color:var(--red)">Something went wrong</div>`, req.user));
  }
});

// DOWNLOAD PAGE
app.get("/tools/:id", requireAuth, async (req, res) => {
  try {
    const f = await getFile(req.params.id);
    if (!f) return res.status(404).send(page("Not found", `
      <div style="padding:80px;text-align:center">
        <div style="font-size:40px;margin-bottom:16px">🔍</div>
        <h2 style="font-size:20px;font-weight:800;color:var(--dark);margin-bottom:8px">File not found</h2>
        <p style="color:var(--txt2);margin-bottom:24px">This file may have been removed or doesn't exist.</p>
        <a href="/tools" class="cta-main" style="display:inline-flex">← Back to Tools</a>
      </div>
    `, req.user));

    const tags = JSON.parse(f.tags || "[]");
    const tagHtml = tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join("");
    const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "1x00000000000000000000AA";
    const dcc = catClass(f.category);

    res.send(page(f.name, `
      <div class="card-wrap">
        <div style="margin-bottom:16px">
          <a href="/tools" style="font-size:13px;color:var(--txt2);display:inline-flex;align-items:center;gap:6px;font-weight:600">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M9 2L4 7L9 12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
            All Tools
          </a>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="fc-icon ${dcc}" style="width:56px;height:56px;border-radius:12px;font-size:22px;flex-shrink:0">${catIcon(f.category)}</div>
            <div style="flex:1;min-width:0">
              <h2>${escHtml(f.name)}</h2>
              <div class="card-meta-row">
                <span class="fc-cat ${dcc}">${escHtml(f.category)}</span>
                <span>${fmtSize(f.size)}</span>
                <span>${f.dl_count||0} downloads</span>
                <span>${timeAgo(f.created_at)}</span>
              </div>
            </div>
          </div>
          ${f.description ? `<p style="font-size:14px;color:var(--txt2);line-height:1.7">${escHtml(f.description)}</p>` : ""}
          ${tagHtml ? `<div class="tags">${tagHtml}</div>` : ""}
          <div class="divider"></div>
          <div class="cf-wrap">
            <p>Complete verification to unlock your download</p>
            <div id="cf-widget"></div>
          </div>
          <div id="err-msg" class="err" style="display:none"></div>
          <button class="dl-main" id="dl-btn" disabled>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2V11M4 8L8 12L12 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 14H14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            Download File
          </button>
        </div>
      </div>
      <div style="max-width:560px;margin:0 auto;padding:0 24px 28px">
        <div class="ad-lbl" style="margin-bottom:8px">Advertisement</div>
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
          btn.disabled = true;
          btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="2" stroke-dasharray="20" stroke-dashoffset="5"/></svg> Downloading...';
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
              btn.disabled = false;
              btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2V11M4 8L8 12L12 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 14H14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> Download File';
              return;
            }
            const blob = await r.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = FILE_NAME;
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(url);
            btn.innerHTML = '✓ Downloaded';
            btn.style.background = 'var(--green)';
          } catch {
            err.textContent = "Network error";
            err.style.display="block";
            btn.disabled=false;
            btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2V11M4 8L8 12L12 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 14H14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> Download File';
          }
        };
      </script>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
    `, req.user, "tools"));
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Error", `<p style="padding:40px;color:var(--red)">Something went wrong</p>`, req.user));
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

    const safeName = f.name.replace(/[^\w\s.\-]/g, "_");
    res.setHeader("Content-Type", "application/octet-stream");
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
        <div class="fc-icon ${catClass(f.category)}" style="width:32px;height:32px;font-size:12px;flex-shrink:0">${catIcon(f.category)}</div>
        <span class="file-row-name">${escHtml(f.name)}</span>
        <span class="file-row-size">${fmtSize(f.size)}</span>
        <form method="POST" action="/admin/toggle/${escHtml(f.id)}" style="margin:0;flex-shrink:0">
          <button type="submit" class="btn-tog ${f.published?"on":""}">${f.published?"LIVE":"DRAFT"}</button>
        </form>
        <form method="POST" action="/admin/delete/${escHtml(f.id)}" onsubmit="return confirm('Delete this file?')" style="margin:0;flex-shrink:0">
          <button type="submit" class="btn-del">Delete</button>
        </form>
      </div>`).join("");

    res.send(page("Admin", `
      <div class="a-layout">
        <aside class="a-side">
          <a href="/admin" class="a-nav on">📁 Files</a>
          <a href="/tools" class="a-nav">⚡ Site</a>
        </aside>
        <div class="a-main">
          <div class="a-stats">
            <div class="stat">
              <div class="stat-n">${stats.total_files}</div>
              <div class="stat-l">Files</div>
            </div>
            <div class="stat">
              <div class="stat-n">${stats.total_downloads}</div>
              <div class="stat-l">Downloads</div>
            </div>
            <div class="stat">
              <div class="stat-n">${stats.total_users}</div>
              <div class="stat-l">Users</div>
            </div>
          </div>

          <div class="up-block">
            <div class="a-section-lbl">Upload file</div>
            <form method="POST" action="/admin/upload" enctype="multipart/form-data" id="upload-form">
              <label class="up-zone" id="up-zone-label">
                <input type="file" name="file" id="fi" required>
                <div class="up-zone-inner">
                  <div class="up-zone-icon">📂</div>
                  <div class="default-hint">
                    <strong>Tap to choose file</strong>
                    <p>ZIP, EXE, LUA, PY, DLL — max 50 MB</p>
                  </div>
                  <div class="chosen" id="fn"></div>
                </div>
              </label>
              <div class="up-fields">
                <input type="text" name="name" placeholder="Display name *" required maxlength="200">
                <textarea name="description" placeholder="Description (optional)" rows="2" maxlength="1000" style="resize:none"></textarea>
                <select name="category">
                  <option>SOURCE</option><option>SCRIPT</option><option>TOOL</option><option>BOT</option><option>OTHER</option>
                </select>
                <input type="text" name="tags" placeholder="Tags: comma, separated" maxlength="500">
                <button type="submit" class="a-upload-btn">↑ Upload File</button>
              </div>
            </form>
          </div>

          <div class="files-block">
            <div class="a-section-lbl">Manage files</div>
            ${fileRows || `<div style="padding:32px;text-align:center;color:var(--txt3);font-size:13px">No files uploaded yet</div>`}
          </div>
        </div>
      </div>
      <script>
        document.getElementById('fi').addEventListener('change', function() {
          var z = document.getElementById('up-zone-label');
          var nm = document.getElementById('fn');
          if (this.files && this.files[0]) {
            nm.textContent = this.files[0].name;
            z.classList.add('has-file');
          } else {
            nm.textContent = '';
            z.classList.remove('has-file');
          }
        });
      </script>
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

// ── Health check (cron-job keep-alive) ───────────────────────
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// 404
app.use((req, res) => res.status(404).send(page("404", `
  <div style="padding:80px 24px;text-align:center">
    <div style="font-size:48px;font-weight:900;color:var(--dark);letter-spacing:-.06em;margin-bottom:12px">404</div>
    <p style="font-size:16px;font-weight:600;color:var(--txt2);margin-bottom:24px">Page not found</p>
    <a href="/" style="display:inline-flex;align-items:center;gap:8px;background:var(--dark);color:#fff;padding:12px 24px;border-radius:var(--radius-sm);font-size:14px;font-weight:700">← Go home</a>
  </div>
`)));

// Global error handler
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`bypass-city running on :${PORT}`));
