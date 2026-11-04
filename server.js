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
import { createRequire } from "module";

import {
  db, getUser, getUserByGoogle, upsertUser,
  listFiles, searchFiles, getFile, getAllFiles,
  insertFile, deleteFile, updateFile, logDownload, statsQuery
} from "./db.js";

const require = createRequire(import.meta.url);

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

  return user.role === "admin" ||
    (ADMIN_EMAIL !== "" && email === ADMIN_EMAIL);
}

// ── Security ────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com"],
      frameSrc: ["https://challenges.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true });
const dlLimiter = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true });
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Session ─────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || "change-me-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    sameSite: "lax",
  },
}));

// ── Passport Google ──────────────────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
}, (_at, _rt, profile, done) => {
  const existing = getUserByGoogle.get(profile.id);
  const id = existing?.id || randomUUID();
  upsertUser.run({
    id,
    google_id: profile.id,
    email: profile.emails?.[0]?.value || "",
    name: profile.displayName,
    avatar: profile.photos?.[0]?.value || "",
  });
  done(null, getUser.get(id));
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, getUser.get(id)));

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

// ── Multer (memory storage — upload buffer to Cloudinary) ────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, true),
});

// ── Upload buffer to Cloudinary ──────────────────────────────
function uploadToCloudinary(buffer, originalname) {
  return new Promise((resolve, reject) => {
    const publicId = randomUUID();
    const stream = cloudinary.uploader.upload_stream(
      {
        public_id: publicId,
        resource_type: "raw",
        use_filename: false,
        unique_filename: false,
        overwrite: false,
      },
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
  const form = new URLSearchParams();
  form.append("secret", process.env.TURNSTILE_SECRET_KEY);
  form.append("response", token);
  form.append("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body: form,
  });
  const d = await r.json();
  return d.success === true;
}

function getIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PAGES — HTML inline
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const CSS = `
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0a;color:#f0ece3;font-family:'Courier New',monospace;min-height:100vh}
a{color:inherit;text-decoration:none}
nav{background:#0a0a0a;border-bottom:1px solid #1f1f1f;padding:10px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.logo{font-size:15px;font-weight:900;letter-spacing:-.02em}.logo span{color:#e8ff47}
.nav-r{display:flex;gap:10px;align-items:center}
.btn{font-size:11px;padding:5px 14px;border:1px solid #3a3a1a;color:#e8ff47;background:rgba(232,255,71,.05);cursor:pointer;font-family:inherit}
.btn:hover{background:rgba(232,255,71,.1)}
.btn-g{border-color:#1f1f1f;color:#4a4a42}
.btn-g:hover{color:#f0ece3;border-color:#3a3a3a}
.hero{padding:50px 20px 36px;text-align:center}
.pill{display:inline-block;background:rgba(232,255,71,.08);border:1px solid rgba(232,255,71,.2);color:#e8ff47;font-size:10px;padding:3px 12px;letter-spacing:.06em;margin-bottom:16px}
h1{font-size:clamp(28px,8vw,48px);font-weight:900;line-height:.95;letter-spacing:-.04em;margin-bottom:10px}
h1 em{color:#e8ff47;font-style:normal}
.sub{font-size:12px;color:#4a4a42;line-height:1.7;max-width:38ch;margin:0 auto 20px}
.cta{background:#e8ff47;color:#000;border:none;padding:12px 32px;font-size:12px;font-weight:900;letter-spacing:.08em;cursor:pointer;font-family:inherit}
.cta:hover{opacity:.88}
.note{font-size:10px;color:#3a3a32;margin-top:8px}
.info-grid{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #1f1f1f}
.info-c{background:#111;padding:14px 18px;border-right:1px solid #1f1f1f}
.info-c:last-child{border-right:0}
.info-lbl{font-size:9px;letter-spacing:.1em;color:#e8ff47;margin-bottom:5px}
.info-p{font-size:11px;color:#4a4a42;line-height:1.6}
.tg-bar{background:#0d0d0d;border-top:1px solid #1f1f1f;padding:11px 18px;display:flex;align-items:center;gap:10px}
.tg-ic{width:30px;height:30px;border-radius:50%;background:#1a2a3a;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.tg-txt{font-size:11px;color:#4a4a42}.tg-txt strong{color:#f0ece3}
.ad-slot{padding:10px 18px;text-align:center;border-top:1px solid #1f1f1f}
.ad-lbl{font-size:9px;color:#2a2a22;letter-spacing:.1em;margin-bottom:4px}
.ad-blk{border:1px dashed #1f1f1f;height:50px;display:flex;align-items:center;justify-content:center;font-size:10px;color:#2a2a22}
.search-bar{padding:10px 16px;background:#0d0d0d;border-bottom:1px solid #1f1f1f;display:flex;gap:8px}
input[type=text],input[type=email],input[type=password],textarea,select{background:transparent;border:0;border-bottom:1px solid #2a2a2a;padding:7px 0;font-size:12px;color:#f0ece3;font-family:inherit;outline:none;width:100%;caret-color:#e8ff47}
select{background:#0d0d0d;border:1px solid #2a2a2a;padding:6px 8px}
.si{font-size:11px;padding:4px 12px;border:1px solid #1f1f1f;color:#4a4a42;background:transparent;cursor:pointer;font-family:inherit;white-space:nowrap}
.si.on{color:#e8ff47;border-color:#3a3a1a;background:rgba(232,255,71,.05)}
.cats{padding:8px 16px;display:flex;gap:6px;overflow-x:auto;border-bottom:1px solid #1f1f1f}
.files-grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:#1f1f1f}
.fc{background:#0d0d0d;padding:12px;display:flex;flex-direction:column;gap:6px}
.fc-icon{font-size:18px}
.fc-name{font-size:12px;font-weight:700;color:#f0ece3;line-height:1.3}
.fc-desc{font-size:10px;color:#4a4a42;line-height:1.5}
.fc-meta{font-size:9px;color:#3a3a32;margin-top:auto}
.dl-btn{font-size:10px;text-align:center;color:#e8ff47;border:1px solid rgba(232,255,71,.2);background:rgba(232,255,71,.05);padding:6px;cursor:pointer;display:block;width:100%}
.dl-btn:hover{background:rgba(232,255,71,.1)}
.card{background:#111;border:1px solid #1f1f1f;padding:20px;max-width:420px;margin:40px auto}
.card h2{font-size:14px;margin-bottom:16px;color:#f0ece3}
.cf-wrap{background:#0d0d0d;border:1px solid #1f1f1f;padding:14px;margin:12px 0;text-align:center}
.cf-wrap p{font-size:10px;color:#4a4a42;margin-bottom:8px}
.dl-main{width:100%;padding:11px;background:#e8ff47;color:#000;border:none;font-size:12px;font-weight:900;letter-spacing:.06em;cursor:pointer;font-family:inherit;margin-top:4px}
.dl-main:disabled{background:#2a2a1a;color:#4a4a32;cursor:not-allowed}
.tags{display:flex;gap:5px;flex-wrap:wrap}
.tag{font-size:9px;border:1px solid #1f1f1f;padding:2px 7px;color:#4a4a42}
.err{color:#f87171;font-size:11px;margin-top:6px}
.ok{color:#4ade80;font-size:11px;margin-top:6px}
/* admin */
.a-layout{display:flex;min-height:calc(100vh - 42px)}
.a-side{width:120px;border-right:1px solid #1f1f1f;background:#0d0d0d;padding-top:8px;flex-shrink:0}
.a-nav{padding:8px 12px;font-size:11px;color:#4a4a42;cursor:pointer;display:block;border-left:2px solid transparent}
.a-nav.on{color:#e8ff47;border-left-color:#e8ff47;background:rgba(232,255,71,.03)}
.a-main{flex:1;padding:16px;overflow:auto}
.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:16px}
.stat{background:#111;border:1px solid #1f1f1f;padding:10px 12px}
.stat-n{font-size:22px;font-weight:900;color:#f0ece3}
.stat-l{font-size:9px;color:#3a3a32;letter-spacing:.08em;margin-top:2px}
.up-zone{border:1.5px dashed #2a2a2a;padding:18px 12px;text-align:center;cursor:pointer;margin-bottom:12px}
.up-zone p{font-size:11px;color:#4a4a42;margin-top:4px}
.up-zone strong{font-size:12px;color:#3a3a32}
.section-lbl{font-size:9px;letter-spacing:.1em;color:#e8ff47;margin-bottom:8px}
.file-row{display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid #1f1f1f;font-size:11px}
.file-row:last-child{border-bottom:0}
.btn-del{font-size:9px;color:#f87171;border:1px solid #450a0a;padding:3px 8px;background:transparent;cursor:pointer;font-family:inherit}
.btn-tog{font-size:9px;padding:3px 8px;border:1px solid #1f1f1f;background:transparent;cursor:pointer;font-family:inherit}
.btn-tog.on{color:#4ade80;border-color:#14532d}
/* login */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{text-align:center;padding:32px 24px;width:100%;max-width:340px;display:flex;flex-direction:column;align-items:center;gap:14px}
.g-btn{display:flex;align-items:center;gap:10px;background:#fff;color:#111;border:none;padding:11px 24px;font-size:12px;font-weight:700;cursor:pointer;width:100%;max-width:280px;justify-content:center;font-family:inherit}
.g-btn:hover{opacity:.88}
.g-ic{width:18px;height:18px;border-radius:50%;background:#ea4335;display:flex;align-items:center;justify-content:center;color:#fff;font-size:10px;font-weight:900;flex-shrink:0}
</style>`;

function nav(user) {
  return `<nav>
    <a href="/" class="logo">/Bypass<span>City</span></a>
    <div class="nav-r">
      <a href="https://t.me/yocnd" target="_blank" class="btn btn-g">✈ t.me/yocnd</a>
      ${user
        ? `<a href="/tools" class="btn">Tools</a>${isAdminUser(user)?`<a href="/admin" class="btn">Admin</a>`:""}<a href="/logout" class="btn btn-g">Logout</a>`
        : `<a href="/login" class="btn">Sign in</a>`}
    </div>
  </nav>`;
}

function page(title, body, user = null) {
  return `<!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${title} — BypassCity</title>${CSS}
  </head><body>${nav(user)}${body}</body></html>`;
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ROUTES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// HOME
app.get("/", (req, res) => {
  res.send(page("Home", `
    <section class="hero">
      <div class="pill">bypass-city.lol</div>
      <h1>The place for<br><em>tools & sources.</em></h1>
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
      <div class="tg-txt"><strong>Updates channel</strong><br>t.me/yocnd — new tools & announcements</div>
      <a href="https://t.me/yocnd" target="_blank" class="btn" style="margin-left:auto">JOIN</a>
    </div>
    <div class="ad-slot">
      <div class="ad-lbl">ADVERTISEMENT</div>
      <div class="ad-blk" id="hilltop-home"><!-- HilltopAds --></div>
    </div>
  `, req.user));
});

// LOGIN
app.get("/login", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/tools");
  const next = req.query.next || "/tools";
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

// GOOGLE OAUTH
app.get("/auth/google", (req, res, next) => {
  const state = req.query.next || "/tools";
  passport.authenticate("google", { scope: ["profile", "email"], state })(req, res, next);
});

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const next = req.query.state || "/tools";
    res.redirect(next.startsWith("/") ? next : "/tools");
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

// TOOLS
app.get("/tools", requireAuth, (req, res) => {
  const q = req.query.q?.trim() || "";
  const cat = req.query.cat || "ALL";
  const CATS = ["ALL","SOURCE","SCRIPT","TOOL","BOT","OTHER"];

  let files;
  if (q || cat !== "ALL") {
    const like = `%${q}%`;
    const catParam = cat === "ALL" ? "" : cat;
    files = searchFiles.all(like, like, catParam || like, 40, 0);
  } else {
    files = listFiles.all(40, 0);
  }

  const catBtns = CATS.map(c =>
    `<button class="si ${c===cat?"on":""}" onclick="location.href='/tools?q=${encodeURIComponent(q)}&cat=${c}'">${c}</button>`
  ).join("");

  const fileCards = files.length === 0
    ? `<div style="grid-column:span 2;padding:40px;text-align:center;font-size:11px;color:#3a3a32">no files found</div>`
    : files.map(f => `
      <div class="fc">
        <div class="fc-icon">${catIcon(f.category)}</div>
        <div class="fc-name">${escHtml(f.name)}</div>
        ${f.description ? `<div class="fc-desc">${escHtml(f.description.slice(0,80))}</div>` : ""}
        <div class="fc-meta">${fmtSize(f.size)} · ${f.dl_count} dl · ${timeAgo(f.created_at)}</div>
        <a href="/tools/${f.id}" class="dl-btn">DOWNLOAD</a>
      </div>`).join("");

  res.send(page("Tools", `
    <div class="ad-slot">
      <div class="ad-lbl">ADVERTISEMENT</div>
      <div class="ad-blk" id="ht-top"><!-- HilltopAds --></div>
    </div>
    <form class="search-bar" method="GET" action="/tools">
      <input type="text" name="q" value="${escHtml(q)}" placeholder="search tools..." style="flex:1">
      <input type="hidden" name="cat" value="${cat}">
      <button type="submit" class="btn" style="white-space:nowrap">Search</button>
    </form>
    <div class="cats">${catBtns}</div>
    <div class="files-grid">${fileCards}</div>
    <div class="ad-slot">
      <div class="ad-lbl">ADVERTISEMENT</div>
      <div class="ad-blk" id="ht-bottom"><!-- HilltopAds --></div>
    </div>
  `, req.user));
});

// DOWNLOAD PAGE
app.get("/tools/:id", requireAuth, (req, res) => {
  const f = getFile.get(req.params.id);
  if (!f) return res.status(404).send(page("Not found", `<p style="padding:40px;color:#4a4a42">File not found</p>`, req.user));

  const tags = JSON.parse(f.tags || "[]");
  const tagHtml = tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join("");
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "1x00000000000000000000AA";

  res.send(page(f.name, `
    <div class="ad-slot">
      <div class="ad-lbl">ADVERTISEMENT</div>
      <div class="ad-blk" id="ht-dl-top"><!-- HilltopAds --></div>
    </div>
    <div class="card">
      <h2>${escHtml(f.name)}</h2>
      <p style="font-size:10px;color:#4a4a42;margin-bottom:10px">
        ${f.category} · ${fmtSize(f.size)} · ${f.dl_count||0} downloads · ${timeAgo(f.created_at)}
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
      <div class="ad-blk" id="ht-dl-bot"><!-- HilltopAds 300x250 --></div>
    </div>

    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async></script>
    <script>
      let cfToken = "";
      window.onload = () => {
        if(typeof turnstile !== "undefined") {
          turnstile.render("#cf-widget", {
            sitekey: "${siteKey}",
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
          const r = await fetch("/api/download/${f.id}", {
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
          a.href = url; a.download = "${escJs(f.name)}";
          document.body.appendChild(a); a.click(); a.remove();
          URL.revokeObjectURL(url);
          btn.textContent = "✓ DOWNLOADED";
        } catch { err.textContent = "Network error"; err.style.display="block"; btn.disabled=false; btn.textContent="⬇ DOWNLOAD FILE"; }
      };
    </script>
  `, req.user));
});

// DOWNLOAD API — proxy file from Cloudinary
app.post("/api/download/:id", dlLimiter, requireAuth, async (req, res) => {
  const { token } = req.body;
  const ip = getIp(req);

  const ok = await verifyTurnstile(token, ip);
  if (!ok) return res.status(400).json({ error: "CAPTCHA failed" });

  const f = getFile.get(req.params.id);
  if (!f) return res.status(404).json({ error: "Not found" });

  logDownload.run(randomUUID(), f.id, req.user.id, ip);

  // Stream file from Cloudinary to client
  try {
    const cloudUrl = cloudinary.url(f.filename, { resource_type: "raw", secure: true });
    const upstream = await fetch(cloudUrl);
    if (!upstream.ok) return res.status(500).json({ error: "File unavailable" });

    res.setHeader("Content-Type", f.mimetype || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${f.name}"`);
    res.setHeader("X-Content-Type-Options", "nosniff");

    const { Readable } = await import("stream");
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Download failed" });
  }
});

// ── ADMIN ─────────────────────────────────────────────────────

app.get("/admin", requireAdmin, (req, res) => {
  const stats = statsQuery.get();
  const files = getAllFiles.all();

  const fileRows = files.map(f => `
    <div class="file-row">
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#f0ece3">${escHtml(f.name)}</span>
      <span style="font-size:9px;color:#3a3a32;flex-shrink:0">${fmtSize(f.size)}</span>
      <form method="POST" action="/admin/toggle/${f.id}" style="margin:0">
        <button type="submit" class="btn-tog ${f.published?"on":""}">${f.published?"ON":"OFF"}</button>
      </form>
      <form method="POST" action="/admin/delete/${f.id}" onsubmit="return confirm('Delete?')" style="margin:0">
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
          <div class="up-zone" onclick="document.getElementById('fi').click()">
            <input type="file" name="file" id="fi" required style="display:none" onchange="document.getElementById('fn').textContent=this.files[0]?.name||''">
            <strong id="fn">Click to choose file</strong>
            <p>ZIP, EXE, LUA, PY, DLL — max 50MB</p>
          </div>
          <input type="text" name="name" placeholder="Display name *" required style="margin-bottom:8px">
          <textarea name="description" placeholder="Description (optional)" rows="2" style="margin-bottom:8px;resize:none"></textarea>
          <select name="category" style="margin-bottom:8px;width:100%">
            <option>SOURCE</option><option>SCRIPT</option><option>TOOL</option><option>BOT</option><option>OTHER</option>
          </select>
          <input type="text" name="tags" placeholder="Tags: comma, separated" style="margin-bottom:12px">
          <button type="submit" class="cta" style="width:100%;padding:10px">UPLOAD</button>
        </form>

        <div style="background:#111;border:1px solid #1f1f1f;padding:12px 16px">
          <div class="section-lbl">MANAGE FILES</div>
          ${fileRows || `<p style="font-size:11px;color:#3a3a32;text-align:center;padding:16px">No files yet</p>`}
        </div>
      </div>
    </div>
  `, req.user));
});

// UPLOAD — stream buffer to Cloudinary
app.post("/admin/upload", requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.redirect("/admin?err=no-file");
  const { name, description, category, tags } = req.body;

  try {
    const { publicId } = await uploadToCloudinary(req.file.buffer, req.file.originalname);
    const tagArr = tags ? tags.split(",").map(t => t.trim()).filter(Boolean) : [];
    insertFile.run({
      id: randomUUID(),
      name: name.slice(0, 200),
      description: description?.slice(0, 1000) || null,
      filename: publicId,                           // store Cloudinary public_id
      mimetype: req.file.mimetype || "application/octet-stream",
      size: req.file.size,
      category: category || "OTHER",
      tags: JSON.stringify(tagArr),
    });
    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.redirect("/admin?err=upload-failed");
  }
});

// DELETE — remove from Cloudinary + DB
app.post("/admin/delete/:id", requireAdmin, async (req, res) => {
  const f = db.prepare("SELECT filename FROM files WHERE id=?").get(req.params.id);
  if (f) {
    try {
      await cloudinary.uploader.destroy(f.filename, { resource_type: "raw" });
    } catch (e) {
      console.error("Cloudinary delete error:", e);
    }
    deleteFile.run(req.params.id);
  }
  res.redirect("/admin");
});

app.post("/admin/toggle/:id", requireAdmin, (req, res) => {
  const f = db.prepare("SELECT published FROM files WHERE id=?").get(req.params.id);
  if (f) db.prepare("UPDATE files SET published=? WHERE id=?").run(f.published ? 0 : 1, req.params.id);
  res.redirect("/admin");
});

// ── Helpers ───────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function escJs(s) {
  return String(s).replace(/\\/g,"\\\\").replace(/"/g,'\\"');
}

// 404
app.use((req, res) => res.status(404).send(page("404", `
  <div style="padding:60px;text-align:center">
    <p style="font-size:11px;color:#4a4a42">page not found</p>
    <a href="/" style="font-size:11px;color:#e8ff47;margin-top:12px;display:inline-block">← home</a>
  </div>
`)));

app.listen(PORT, () => console.log(`bypass-city running on :${PORT}`));
