// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADD THESE IMPORTS at the top of server.js (with other imports)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import crypto from "crypto";
import { getUserByTelegram, upsertTelegramUser } from "./db.js";
// (you already import randomUUID from "crypto" — just add getUserByTelegram, upsertTelegramUser to your existing db.js import)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADD THIS FUNCTION (paste anywhere before the routes)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
function verifyTelegramAuth(data) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) return false;

  const { hash, ...fields } = data;
  if (!hash) return false;

  // Check auth is not older than 1 day
  if (Date.now() / 1000 - Number(fields.auth_date) > 86400) return false;

  const checkString = Object.keys(fields)
    .sort()
    .map(k => `${k}=${fields[k]}`)
    .join("\n");

  const secretKey = crypto.createHash("sha256").update(botToken).digest();
  const hmac = crypto.createHmac("sha256", secretKey).update(checkString).digest("hex");

  return hmac === hash;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADD THIS ROUTE (paste after your Google auth routes)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get("/auth/telegram/callback", authLimiter, async (req, res) => {
  try {
    const data = req.query;

    if (!verifyTelegramAuth(data)) {
      return res.redirect("/login?error=telegram_invalid");
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

    req.login(user, (err) => {
      if (err) return res.redirect("/login?error=telegram_login_failed");
      const next = safeRedirect(req.session.returnTo || "/tools");
      delete req.session.returnTo;
      res.redirect(next);
    });
  } catch (e) {
    console.error("Telegram auth error:", e);
    res.redirect("/login?error=telegram_error");
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UPDATE YOUR LOGIN PAGE — add this Telegram button
// Find your login page HTML in server.js and add this button
// alongside your existing Google button:
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/*
  <script async src="https://telegram.org/js/telegram-widget.js?22"
    data-telegram-login="BypassCityBot"
    data-size="large"
    data-auth-url="https://bypass-city.lol/auth/telegram/callback"
    data-request-access="write">
  </script>
*/

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADD TO YOUR .env file:
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TELEGRAM_BOT_TOKEN=9169279009:AAEkkkmKVAMF7YGK_NUX0eBzFdglugOK8Zo

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ADD TO YOUR helmet CSP scriptSrc (already in your server.js):
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// "https://telegram.org"
// and to imgSrc:
// "https://*.telegram.org"
