/**
 * NoorTube API Worker
 * --------------------
 * Combines the existing R2 file storage routes with a full D1-backed API for
 * users, videos, reels, statuses, comments, likes, follows and monetization.
 *
 * Bindings expected (see wrangler.toml):
 *   env.NOOR_BUCKET   - R2 bucket (file storage, from Phase 0)
 *   env.NOOR_DB       - D1 database (this phase)
 *   env.UPLOAD_SECRET - optional shared secret for file uploads
 */

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Upload-Secret, X-Upload-Token, X-Upload-Expiry, Authorization, X-Anon-Id, Range",
    "Access-Control-Expose-Headers": "Content-Range, Accept-Ranges, Content-Length, ETag",
    "Access-Control-Max-Age": "7200",
  };
}
// Parses a standard "bytes=start-end" Range header against a known total size.
// Handles open-ended ("500-") and suffix ("-500") forms. Returns null if the
// header is missing, malformed, or outside the object's bounds.
function parseRangeHeader(rangeHeader, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader || "");
  if (!m) return null;
  let start = m[1] === "" ? null : parseInt(m[1], 10);
  let end = m[2] === "" ? null : parseInt(m[2], 10);
  if (start === null && end === null) return null;
  if (start === null) {
    const suffixLength = end;
    if (!suffixLength || suffixLength <= 0) return null;
    start = Math.max(0, size - suffixLength);
    end = size - 1;
  } else if (end === null) {
    end = size - 1;
  }
  if (isNaN(start) || isNaN(end) || start > end || start >= size) return null;
  end = Math.min(end, size - 1);
  return { start, end };
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache", ...cors() },
  });
}
function err(message, status = 400) {
  return json({ error: message }, status);
}
function uid(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}
async function addNotification(db, userId, type, title, message, push) {
  await db.prepare("INSERT INTO notifications (id, user_id, type, title, message) VALUES (?,?,?,?,?)")
    .bind(uid("n"), userId, type, title, message).run();
  // Phone push (Android app) only for the notifications that ask for it (nazrana, withdrawals, ad campaigns). Everything else stays in the bell. Never slows or breaks the request.
  if (push === true) {
    try { const p = pushToUser(db, userId, title, message, type).catch(() => {}); if (_ctx && _ctx.waitUntil) _ctx.waitUntil(p); } catch (_) {}
  }
}
// ================= PHONE PUSH (Firebase Cloud Messaging). Does nothing until the FCM_SERVICE_ACCOUNT secret is added to the worker =================
let _pushEnv = null, _pushReady = false, _fcmTok = null;
async function ensurePushTables(db) {
  if (_pushReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS push_tokens (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, platform TEXT, updated_at INTEGER NOT NULL DEFAULT 0)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_push_user ON push_tokens (user_id)").run();
  _pushReady = true;
}
function fcmAccount(env) {
  try {
    const raw = env && env.FCM_SERVICE_ACCOUNT;
    if (!raw) return null;
    const a = typeof raw === "string" ? JSON.parse(raw) : raw;
    return a && a.client_email && a.private_key && a.project_id ? a : null;
  } catch (_) { return null; }
}
function b64url(data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function fcmAccessToken(acc) {
  if (_fcmTok && _fcmTok.exp > Date.now() + 60000) return _fcmTok.t;
  const pem = String(acc.private_key).replace(/\\n/g, "").replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64url(JSON.stringify({ iss: acc.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + head + "." + claim + "." + b64url(sig) });
  const j = await r.json().catch(() => ({}));
  if (!j.access_token) throw new Error("Could not sign in to Firebase");
  _fcmTok = { t: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  return j.access_token;
}
// target is { token: "..." } for one phone, or { topic: "all" } for every phone that joined that topic
async function fcmSend(env, target, title, body, data) {
  const acc = fcmAccount(env);
  if (!acc) return { ok: false, skipped: true };
  try {
    const at = await fcmAccessToken(acc);
    const msg = Object.assign({}, target, { notification: { title: String(title || "NoorTube").slice(0, 100), body: String(body || "").slice(0, 300) }, data: data || {}, android: { priority: "HIGH", notification: { sound: "default" } } });
    const r = await fetch("https://fcm.googleapis.com/v1/projects/" + encodeURIComponent(acc.project_id) + "/messages:send", { method: "POST", headers: { Authorization: "Bearer " + at, "Content-Type": "application/json" }, body: JSON.stringify({ message: msg }) });
    return r.ok ? { ok: true } : { ok: false, gone: r.status === 404, status: r.status };
  } catch (_) { return { ok: false }; }
}
async function pushToUser(db, userId, title, body, type) {
  if (!userId || !fcmAccount(_pushEnv)) return;
  await ensurePushTables(db);
  const rows = await db.prepare("SELECT token FROM push_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5").bind(userId).all();
  for (const x of (rows.results || [])) {
    const r = await fcmSend(_pushEnv, { token: x.token }, title, body, { type: String(type || "info") });
    if (r.gone) { try { await db.prepare("DELETE FROM push_tokens WHERE token = ?").bind(x.token).run(); } catch (_) {} }
  }
}
function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function toB64Url(buf) {
  return toB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Signs "key.expiry" with the server-only UPLOAD_SECRET so the client never
// needs to know the secret itself - it only ever receives a token that is
// valid for one specific file key and expires shortly after issue.
async function signUploadToken(key, expiry, secret) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(`${key}.${expiry}`));
  return toB64Url(sig);
}
async function hashPassword(password, saltB64) {
  const enc = new TextEncoder();
  const salt = saltB64 ? Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0)) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return { hash: toB64(bits), salt: toB64(salt) };
}
async function verifyPassword(password, hash, salt) {
  const { hash: computed } = await hashPassword(password, salt);
  return computed === hash;
}
// ---------- SESSION EXPIRY (30 days, sliding) ----------
// Adds an expires_at column on first use. If that is impossible for any reason, this feature
// switches itself off and sessions behave exactly as before, so login can never break because of it.
const SESSION_MS = 30 * 24 * 3600 * 1000;
let sessionExpiryReady = null;
async function ensureSessionExpiry(db) {
  if (sessionExpiryReady !== null) return sessionExpiryReady;
  try {
    try { await db.prepare("ALTER TABLE sessions ADD COLUMN expires_at INTEGER").run(); } catch (_) { /* column already exists */ }
    await db.prepare("SELECT expires_at FROM sessions LIMIT 1").first();
    try { await db.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions (expires_at)").run(); } catch (_) {}
    sessionExpiryReady = true;
  } catch (_) { sessionExpiryReady = false; }
  return sessionExpiryReady;
}
async function createSession(db, token, userId) {
  if (await ensureSessionExpiry(db)) {
    await db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").bind(token, userId, Date.now() + SESSION_MS).run();
    if (Math.random() < 0.01) {
      try { await db.prepare("DELETE FROM sessions WHERE token IN (SELECT token FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ? LIMIT 200)").bind(Date.now()).run(); } catch (_) {}
    }
  } else {
    await db.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, userId).run();
  }
}

// ---------- UPLOAD RULES ----------
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024; // 200 MB per file
const EXT_TYPES = { mp4: "video/mp4", m4v: "video/mp4", mov: "video/quicktime", webm: "video/webm", mkv: "video/x-matroska", "3gp": "video/3gpp", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" };
function pickUploadType(headerType, key) {
  const ct = String(headerType || "").split(";")[0].trim().toLowerCase();
  if ((ct.startsWith("video/") || ct.startsWith("image/")) && ct !== "image/svg+xml") return ct;
  const ext = (String(key).split(".").pop() || "").toLowerCase();
  return EXT_TYPES[ext] || null;
}

async function currentUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const db = env.NOOR_DB;
  if (await ensureSessionExpiry(db)) {
    const row = await db.prepare(
      "SELECT users.*, sessions.expires_at AS _session_exp FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?"
    ).bind(token).first();
    if (!row) return null;
    const now = Date.now(), exp = row._session_exp;
    if (exp && exp < now) return null; // expired: user must sign in again
    if (!exp || exp - now < SESSION_MS / 2) { // old sessions get an expiry; active users stay signed in
      try { await db.prepare("UPDATE sessions SET expires_at = ? WHERE token = ?").bind(now + SESSION_MS, token).run(); } catch (_) {}
    }
    delete row._session_exp;
    return row;
  }
  const row = await db.prepare(
    "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?"
  ).bind(token).first();
  return row || null;
}
async function lookupGuestIfExists(request, env) {
  const anonId = (request.headers.get("X-Anon-Id") || "").trim();
  if (!anonId) return null;
  return await env.NOOR_DB.prepare(
    "SELECT users.* FROM anon_sessions JOIN users ON users.id = anon_sessions.user_id WHERE anon_sessions.anon_id = ?"
  ).bind(anonId).first();
}
async function currentUserOrGuest(request, env) {
  const real = await currentUser(request, env);
  if (real) return real;
  const anonId = (request.headers.get("X-Anon-Id") || "").trim();
  if (!anonId || anonId.length < 8 || anonId.length > 128) return null;
  const db = env.NOOR_DB;
  const existing = await db.prepare(
    "SELECT users.* FROM anon_sessions JOIN users ON users.id = anon_sessions.user_id WHERE anon_sessions.anon_id = ?"
  ).bind(anonId).first();
  if (existing) return existing;
  const id = uid("guest");
  const email = `${anonId}@guest.noortube.local`;
  const guestNum = 1000 + (Math.abs(anonId.split("").reduce((a, c) => a * 31 + c.charCodeAt(0), 7)) % 9000);
  const guestName = `Guest ${guestNum}`;
  const { hash, salt } = await hashPassword(crypto.randomUUID());
  await db.prepare(
    "INSERT INTO users (id, name, email, password_hash, password_salt, role) VALUES (?,?,?,?,?,'guest')"
  ).bind(id, guestName, email, hash, salt).run();
  await db.prepare("INSERT INTO anon_sessions (anon_id, user_id) VALUES (?, ?)").bind(anonId, id).run();
  return { id, name: guestName, email, avatar_color: "#0d9488", avatar_image: null, role: "guest", suspended: 0, strikes: 0 };
}
// ---------- LOGIN RATE LIMIT ----------
// Only FAILED logins are written to the database, so normal traffic costs one small indexed read.
// If anything in here errors, the limiter "fails open" and login keeps working.
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_PER_EMAIL = 5;   // wrong passwords for one email from one IP
const LOGIN_MAX_PER_IP = 30;     // wrong passwords from one IP across all emails
let loginTableReady = false;
async function ensureLoginTable(db) {
  if (loginTableReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, email TEXT NOT NULL, ts INTEGER NOT NULL)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_ts ON login_attempts (ip, ts)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_login_attempts_ts ON login_attempts (ts)").run();
  loginTableReady = true;
}
async function loginBlocked(db, ip, email) {
  try {
    await ensureLoginTable(db);
    const since = Date.now() - LOGIN_WINDOW_MS;
    const r = await db.prepare(
      "SELECT COUNT(*) AS ip_c, COALESCE(SUM(CASE WHEN email = ? THEN 1 ELSE 0 END), 0) AS em_c FROM login_attempts WHERE ip = ? AND ts > ?"
    ).bind(email, ip, since).first();
    return !!r && (r.em_c >= LOGIN_MAX_PER_EMAIL || r.ip_c >= LOGIN_MAX_PER_IP);
  } catch (_) { return false; }
}
async function recordLoginFailure(db, ip, email) {
  try {
    await ensureLoginTable(db);
    await db.prepare("INSERT INTO login_attempts (ip, email, ts) VALUES (?, ?, ?)").bind(ip, email, Date.now()).run();
    if (Math.random() < 0.02) await db.prepare("DELETE FROM login_attempts WHERE ts < ?").bind(Date.now() - 24 * 3600 * 1000).run();
  } catch (_) {}
}

// ---------- USER BLOCKS (Google Play UGC: users must be able to block other users) ----------
let userBlocksReady = false;
async function ensureUserBlocks(db) {
  if (userBlocksReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS user_blocks (blocker_id TEXT NOT NULL, blocked_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (blocker_id, blocked_id))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON user_blocks (blocker_id)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON user_blocks (blocked_id)").run();
  userBlocksReady = true;
}
async function isBlocked(db, blockerId, blockedId) {
  if (!blockerId || !blockedId || blockerId === blockedId) return false;
  try {
    await ensureUserBlocks(db);
    const r = await db.prepare("SELECT 1 FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?").bind(blockerId, blockedId).first();
    return !!r;
  } catch (_) { return false; }
}
async function blockedIdsFor(db, userId) {
  try {
    await ensureUserBlocks(db);
    const rows = await db.prepare("SELECT blocked_id FROM user_blocks WHERE blocker_id = ?").bind(userId).all();
    return new Set((rows.results || []).map((r) => r.blocked_id));
  } catch (_) { return new Set(); }
}

// ---------- PASSWORD RESET (Forgot password on login) ----------
const RESET_WINDOW_MS = 15 * 60 * 1000;
let passwordResetReady = false;
async function ensurePasswordReset(db) {
  if (passwordResetReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS password_resets (email TEXT PRIMARY KEY, user_id TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent_at INTEGER NOT NULL, hour_start INTEGER NOT NULL DEFAULT 0, hour_count INTEGER NOT NULL DEFAULT 0)").run();
  passwordResetReady = true;
}

// ---------- CREATOR PAYOUTS (rates, creator share, "mark as paid" records) ----------
// Everything is counted in whole cents. Creators only ever receive THEIR share; platform numbers stay admin-only.
const PAYOUT_LIMITS = { vrpm: [0.10, 0.70], rrpm: [0.01, 0.03] }; // allowed $ per 1,000 views. Raise later as the app grows.
const PAYOUT_DEFAULTS = { vrpm: 0.40, rrpm: 0.02, share: 60, inr: 85 };
let payoutTablesReady = false;
async function ensurePayoutTables(db) {
  if (payoutTablesReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS payout_settings (id INTEGER PRIMARY KEY, vrpm REAL NOT NULL, rrpm REAL NOT NULL, share REAL NOT NULL, inr REAL NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS payout_records (user_id TEXT PRIMARY KEY, v_views INTEGER NOT NULL DEFAULT 0, r_views INTEGER NOT NULL DEFAULT 0, paid_cents INTEGER NOT NULL DEFAULT 0, last_paid_at INTEGER)").run();
  payoutTablesReady = true;
}
async function getPayoutSettings(db) {
  await ensurePayoutTables(db);
  const r = await db.prepare("SELECT vrpm, rrpm, share, inr FROM payout_settings WHERE id = 1").first();
  return r ? { vrpm: r.vrpm, rrpm: r.rrpm, share: r.share, inr: r.inr } : { ...PAYOUT_DEFAULTS };
}
function payoutCents(vNew, rNew, S) {
  const gV = Math.round(vNew / 1000 * S.vrpm * 100 + 1e-9), gR = Math.round(rNew / 1000 * S.rrpm * 100 + 1e-9);
  const cV = Math.round(gV * S.share / 100 + 1e-9), cR = Math.round(gR * S.share / 100 + 1e-9);
  return { gV, gR, cV, cR, creator: cV + cR, platform: gV + gR - cV - cR };
}
function payoutFromTotals(totals, rec, S) {
  const vNew = Math.max(0, totals.v - (rec ? rec.v_views : 0)), rNew = Math.max(0, totals.r - (rec ? rec.r_views : 0));
  return { vNew, rNew, c: payoutCents(vNew, rNew, S), paidCents: rec ? rec.paid_cents : 0, lastPaidAt: rec ? rec.last_paid_at : null };
}
async function computeEarnings(db, userId, S) {
  const v = await db.prepare("SELECT COALESCE(SUM(views), 0) AS n FROM videos WHERE owner_id = ? AND monetized = 1 AND removed = 0").bind(userId).first();
  const r = await db.prepare("SELECT COALESCE(SUM(views), 0) AS n FROM reels WHERE owner_id = ?").bind(userId).first();
  const totals = { v: (v && v.n) || 0, r: (r && r.n) || 0 };
  let rec = await db.prepare("SELECT v_views, r_views, paid_cents, last_paid_at FROM payout_records WHERE user_id = ?").bind(userId).first();
  if (rec && (totals.v < rec.v_views || totals.r < rec.r_views)) { // creator deleted content: lower the baseline so new views keep counting
    rec = { ...rec, v_views: Math.min(rec.v_views, totals.v), r_views: Math.min(rec.r_views, totals.r) };
    try { await db.prepare("UPDATE payout_records SET v_views = ?, r_views = ? WHERE user_id = ?").bind(rec.v_views, rec.r_views, userId).run(); } catch (_) {}
  }
  return { totals, ...payoutFromTotals(totals, rec, S) };
}

// ---------- WITHDRAWAL REQUESTS (creator taps "Request Withdrawal", admin pays and marks it) ----------
// Separate table with its own "ready" flag, so the existing payout system above can never be affected by it.
// A request freezes the creator's current unpaid earnings (amount + view totals at that moment).
// Nothing is deducted until the admin marks it Paid.
const WITHDRAW_MIN_CENTS = 10000; // minimum $100.00 to request a withdrawal
let withdrawTableReady = false;
async function ensureWithdrawTable(db) {
  if (withdrawTableReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS withdraw_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, amount_cents INTEGER NOT NULL, v_snap INTEGER NOT NULL, r_snap INTEGER NOT NULL, method TEXT, account_name TEXT, account_number TEXT, routing_code TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at INTEGER NOT NULL, resolved_at INTEGER, note TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_wr_status ON withdraw_requests (status, created_at)").run();
  await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_wr_one_pending ON withdraw_requests (user_id) WHERE status = 'Pending'").run();
  withdrawTableReady = true;
}
// Never throws: if the table is unavailable for any reason it simply reports "no pending request".
async function getPendingWithdraw(db, userId) {
  try {
    await ensureWithdrawTable(db);
    return await db.prepare("SELECT * FROM withdraw_requests WHERE user_id = ? AND status = 'Pending' LIMIT 1").bind(userId).first();
  } catch (_) { return null; }
}

// ================= PLATFORM SETTINGS, SALAH GUARD, HALAL ADS, BROADCASTS, AUDIT LOG, ANALYTICS =================
// ===== Prayer times (astronomical formulas, same approach as praytimes.org). Returns local clock hours (e.g. 5.5 = 5:30). =====
const PRAYER_METHODS = { MWL: { fajr: 18, isha: 17, name: "Muslim World League" }, Karachi: { fajr: 18, isha: 18, name: "Univ. of Islamic Sciences, Karachi" }, ISNA: { fajr: 15, isha: 15, name: "ISNA (North America)" }, Egypt: { fajr: 19.5, isha: 17.5, name: "Egyptian General Authority" }, Makkah: { fajr: 18.5, ishaMin: 90, name: "Umm al-Qura, Makkah" } };
function computePrayerTimes(dateMs, lat, lng, tz, methodKey, hanafi) {
  const R = Math.PI / 180, D = 180 / Math.PI;
  const sin = (d) => Math.sin(d * R), cos = (d) => Math.cos(d * R), tan = (d) => Math.tan(d * R);
  const asin = (x) => D * Math.asin(x), acos = (x) => D * Math.acos(x), atan2 = (y, x) => D * Math.atan2(y, x), acot = (x) => D * Math.atan(1 / x);
  const fixAngle = (a) => { a -= 360 * Math.floor(a / 360); return a; }, fixHour = (h) => { h -= 24 * Math.floor(h / 24); return h; };
  const dt = new Date(dateMs + tz * 3600000); // local calendar date at the location
  let Y = dt.getUTCFullYear(), M = dt.getUTCMonth() + 1; const Dd = dt.getUTCDate();
  if (M <= 2) { Y -= 1; M += 12; }
  const A = Math.floor(Y / 100), B = 2 - A + Math.floor(A / 4);
  const jd0 = Math.floor(365.25 * (Y + 4716)) + Math.floor(30.6001 * (M + 1)) + Dd + B - 1524.5 - lng / (15 * 24);
  const sunPos = (jd) => { const d = jd - 2451545.0, g = fixAngle(357.529 + 0.98560028 * d), q = fixAngle(280.459 + 0.98564736 * d), L = fixAngle(q + 1.915 * sin(g) + 0.020 * sin(2 * g)), e = 23.439 - 0.00000036 * d, RA = fixHour(atan2(cos(e) * sin(L), cos(L)) / 15); return { decl: asin(sin(e) * sin(L)), eqt: q / 15 - RA }; };
  const midDay = (t) => fixHour(12 - sunPos(jd0 + t).eqt);
  const angleTime = (angle, t, ccw) => { const decl = sunPos(jd0 + t).decl, noon = midDay(t), x = (-sin(angle) - sin(decl) * sin(lat)) / (cos(decl) * cos(lat)); if (x < -1 || x > 1) return NaN; const h = acos(x) / 15; return noon + (ccw ? -h : h); };
  const asrTime = (factor, t) => { const decl = sunPos(jd0 + t).decl, angle = -acot(factor + tan(Math.abs(lat - decl))); return angleTime(angle, t, false); };
  const m = PRAYER_METHODS[methodKey] || PRAYER_METHODS.MWL;
  let T = { fajr: 5, sunrise: 6, dhuhr: 12, asr: 13, maghrib: 18, isha: 18 };
  for (let it = 0; it < 2; it++) {
    const t = (h) => h / 24;
    T = {
      fajr: angleTime(m.fajr, t(T.fajr), true), sunrise: angleTime(0.833, t(T.sunrise), true), dhuhr: midDay(t(T.dhuhr)),
      asr: asrTime(hanafi ? 2 : 1, t(T.asr)), maghrib: angleTime(0.833, t(T.maghrib), false),
      isha: m.ishaMin ? NaN : angleTime(m.isha, t(T.isha), false),
    };
    if (m.ishaMin) T.isha = T.maghrib + m.ishaMin / 60;
  }
  const adj = tz - lng / 15, out = {};
  Object.keys(T).forEach((k) => { out[k] = fixHour(T[k] + adj + (k === "dhuhr" ? 2 / 60 : 0)); }); // dhuhr +2 min safety, like most apps
  return out;
}
const PRAYER_ORDER = [["fajr", "Fajr"], ["dhuhr", "Dhuhr"], ["asr", "Asr"], ["maghrib", "Maghrib"], ["isha", "Isha"]];
// Is "now" inside a prayer window? Returns { active, name, untilMs } using the guard length in minutes after each prayer starts.
function salahGuardState(nowMs, cfg) {
  if (!cfg || !cfg.guardOn || !isFinite(cfg.lat) || !isFinite(cfg.lng)) return { active: false };
  const local = new Date(nowMs + cfg.tz * 3600000), startOfDay = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - cfg.tz * 3600000;
  const T = computePrayerTimes(nowMs, cfg.lat, cfg.lng, cfg.tz, cfg.method, cfg.hanafi);
  for (const [k, name] of PRAYER_ORDER) {
    const h = T[k]; if (!isFinite(h)) continue;
    const start = startOfDay + h * 3600000, end = start + cfg.guardMin * 60000;
    if (nowMs >= start && nowMs < end) return { active: true, name, untilMs: end };
  }
  if (cfg.jummah && local.getUTCDay() === 5) { // Jumu'ah: Friday 12:00 to 14:00 local time
    const a = startOfDay + 12 * 3600000, b = startOfDay + 14 * 3600000;
    if (nowMs >= a && nowMs < b) return { active: true, name: "Jumu'ah", untilMs: b };
  }
  return { active: false };
}
let platformReady = false;
async function ensurePlatformTables(db) {
  if (platformReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS ads (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, media_url TEXT NOT NULL, click_url TEXT, placements TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, starts_at INTEGER, ends_at INTEGER, impressions INTEGER NOT NULL DEFAULT 0, clicks INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS broadcasts (id TEXT PRIMARY KEY, admin_id TEXT, title TEXT NOT NULL, message TEXT NOT NULL, audience TEXT NOT NULL, sent_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, admin_id TEXT, admin_name TEXT, action TEXT NOT NULL, method TEXT, path TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts)").run();
  try { await ensureAdVideoCols(db); } catch (_) {}
  platformReady = true;
}
async function getAppSettings(db) {
  const rows = await db.prepare("SELECT k, v FROM app_settings").all();
  const m = {};
  (rows.results || []).forEach((r) => { m[r.k] = r.v; });
  const num = (k, d) => { const n = parseFloat(m[k]); return isFinite(n) ? n : d; };
  return {
    city: m.prayer_city || "Delhi, India", lat: num("prayer_lat", 28.6139), lng: num("prayer_lng", 77.209), tz: num("prayer_tz", 5.5),
    method: PRAYER_METHODS[m.prayer_method] ? m.prayer_method : "Karachi", hanafi: (m.prayer_asr || "hanafi") !== "shafi",
    guardOn: (m.salah_guard == null ? "1" : m.salah_guard) !== "0", jummah: (m.jummah_guard == null ? "1" : m.jummah_guard) !== "0", guardMin: Math.max(1, Math.min(60, Math.round(num("guard_min", 12)))),
  };
}
const AUDIT_LABELS = [
  [/^PATCH \/api\/admin\/users\/[^/]+\/suspend$/, "Deactivated / reactivated a channel"], [/^DELETE \/api\/admin\/users\/[^/]+$/, "Deleted an account"],
  [/^PATCH \/api\/admin\/(videos|reels)\/[^/]+\/hide$/, "Deactivated / reactivated content"], [/^DELETE \/api\/(videos|reels)\/[^/]+$/, "Deleted a video / reel"],
  [/^PATCH \/api\/admin\/reports\/[^/]+$/, "Updated a report"], [/^POST \/api\/admin\/feedback\/[^/]+\/reply$/, "Replied to feedback"],
  [/^PUT \/api\/admin\/payout-settings$/, "Changed payout rates"], [/^POST \/api\/admin\/payouts\/[^/]+\/mark-paid$/, "Marked a creator payout as paid"],
  [/^POST \/api\/admin\/withdraw-requests\/[^/]+\/mark-paid$/, "Marked a withdrawal as paid"], [/^POST \/api\/admin\/withdraw-requests\/[^/]+\/reject$/, "Rejected a withdrawal"],
  [/^PUT \/api\/admin\/vast-settings$/, "Changed video ad network (VAST) settings"],
  [/^PUT \/api\/admin\/sadaqah\/settings$/, "Changed nazrana settings"], [/^POST \/api\/admin\/sadaqah\/donations\/[^/]+\/confirm$/, "Confirmed a nazrana payment"],
  [/^POST \/api\/admin\/sadaqah\/donations\/[^/]+\/reject$/, "Marked a nazrana payment as not received"], [/^POST \/api\/admin\/sadaqah\/requests\/[^/]+\/mark-paid$/, "Marked a nazrana withdrawal as paid"],
  [/^POST \/api\/admin\/sadaqah\/requests\/[^/]+\/reject$/, "Rejected a nazrana withdrawal"], [/^POST \/api\/admin\/ads$/, "Created an ad"], [/^PATCH \/api\/admin\/ads\/[^/]+$/, "Edited / paused an ad"],
  [/^DELETE \/api\/admin\/ads\/[^/]+$/, "Deleted an ad"], [/^POST \/api\/admin\/broadcast$/, "Sent a notification to users"], [/^PUT \/api\/admin\/settings$/, "Changed platform settings"],
  [/^POST \/api\/admin\/scan-duplicates$/, "Ran / applied the duplicate scan"], [/^PUT \/api\/admin\/auto-scan$/, "Turned the hourly duplicate auto-scan on / off"], [/^POST \/api\/admin\/campaigns\/[^/]+\/confirm$/, "Confirmed an ad campaign payment and started the ad"], [/^POST \/api\/admin\/campaigns\/[^/]+\/reject$/, "Rejected an ad campaign"], [/^POST \/api\/admin\/campaigns\/[^/]+\/end$/, "Ended an ad campaign"], [/^PUT \/api\/admin\/campaign-settings$/, "Changed the ad campaign payment settings and prices"], [/^PUT \/api\/admin\/adsense$/, "Changed the Google AdSense settings"], [/^PUT \/api\/admin\/admob$/, "Changed the Google AdMob settings"], [/^POST \/api\/admin\/demo-account$/, "Created / deleted the demo account"],
];
function auditLabel(method, path) {
  const key = method + " " + path;
  for (const [re, label] of AUDIT_LABELS) if (re.test(key)) return label;
  return key;
}
async function adminUser(request, env) { const u = await currentUser(request, env); return u && u.role === "admin" ? u : null; }
const AD_PLACEMENTS = ["home", "watch", "reels", "preroll", "midroll"];
// Video ads (pre-roll = before the video, mid-roll = after N seconds) keep two extra settings on the ad row.
let adVideoColsOk = false;
async function ensureAdVideoCols(db) {
  if (adVideoColsOk) return true;
  const has = async () => { try { await db.prepare("SELECT mid_after, skip_after FROM ads LIMIT 1").first(); return true; } catch (_) { return false; } };
  if (await has()) { adVideoColsOk = true; return true; }
  try { await db.prepare("ALTER TABLE ads ADD COLUMN mid_after INTEGER").run(); } catch (_) {}
  try { await db.prepare("ALTER TABLE ads ADD COLUMN skip_after INTEGER").run(); } catch (_) {}
  adVideoColsOk = await has();
  return adVideoColsOk;
}
const isVideoSlot = (list) => list.includes("preroll") || list.includes("midroll");
function adOut(a) {
  return { id: a.id, name: a.name, type: a.type, mediaUrl: a.media_url, clickUrl: a.click_url || "", placements: String(a.placements || "").split(",").filter(Boolean), active: !!a.active,
    startsAt: a.starts_at || null, endsAt: a.ends_at || null, impressions: a.impressions || 0, clicks: a.clicks || 0, createdAt: a.created_at,
    midAfter: a.mid_after || 30, skipAfter: a.skip_after || 0 };
}

const _adHit = new Map(); // short-lived memory of recent ad impressions/clicks (anti-spam)
// ================= FEED RANKING ("viral algorithm") =================
// base score   = popularity x quality x velocity x freshness x evergreen x safety        (same for everyone, cached ~30 s)
// For You      = base x personal (follows, interests, already-watched) x tiny steady jitter, then creator diversity + "new video" trial slots
// Trending     = base x momentum (views in the last 24 h vs the 24 h before), same for everyone
// The default feed order of /api/videos and /api/reels is NOT changed: add ?rank=1 to get rankFY / rankTR / rankReason on every item.
const RANK_TTL_MS = 30000;
const rankCache = {};
const FEED_SQL = {
  v: "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, users.monetization_enabled as owner_monetized, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.removed = 0 AND videos.hidden = 0",
  r: "SELECT reels.*, users.name as owner_name, users.avatar_color as owner_avatar_color, users.monetization_enabled as owner_monetized, (SELECT COUNT(*) FROM comments WHERE target_type='reel' AND target_id=reels.id) as comment_count FROM reels JOIN users ON users.id = reels.owner_id WHERE reels.hidden = 0",
};
const rkClamp = (x, a, b) => Math.max(a, Math.min(b, x));
// Interest topics of one video/reel: its hashtags (title, description, tags written with #) first, then plain tags. Lower-case, '#' removed.
// Only the first 5 count, so stuffing 15 hashtags gives no extra push. Hashtags never boost a video by themselves: they only help it reach people who already watch that topic.
function rkTopics(row) {
  const out = [], seen = new Set();
  let tags = row && row.tags;
  if (typeof tags === "string") { try { tags = JSON.parse(tags || "[]"); } catch (_) { tags = []; } }
  if (!Array.isArray(tags)) tags = [];
  const add = (t) => { t = String(t || "").replace(/^#/, "").trim().toLowerCase(); if (t && t.length <= 50 && !seen.has(t)) { seen.add(t); out.push(t); } };
  try { for (const h of extractHashtags(row && row.title, row && row.description, tags)) add(h); } catch (_) {}
  for (const t of tags) add(t);
  return out.slice(0, 5);
}
function rkAgeH(s, now) {
  if (!s) return 9999;
  const str = String(s), t = Date.parse(/[TZ]/.test(str) ? str : str.replace(" ", "T") + "Z");
  return isFinite(t) ? Math.max(0, (now - t) / 3600000) : 9999;
}
function rkHash(str) { // 0..1, stable
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return ((h >>> 0) % 100000) / 100000;
}
function rkWilson(up, total) { // lower bound of the true like share, so 1 like out of 1 vote does not look perfect
  if (total <= 0) return 0.7;
  const z = 1.28, p = up / total;
  return (p + z * z / (2 * total) - z * Math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)) / (1 + z * z / total);
}
function rkBase(row, kind, sig, now) {
  const views = Math.max(0, Number(row.views) || 0), likes = Math.max(0, Number(row.likes) || 0), dislikes = Math.max(0, Number(row.dislikes) || 0), comments = Math.max(0, Number(row.comment_count) || 0);
  const ageH = rkAgeH(row.uploaded_at, now), isV = kind === "v";
  const h24 = sig.h24[row.id] || 0, h48 = sig.h48[row.id] || 0, prior24 = Math.max(0, h48 - h24);
  // popularity: bounded, so a 10,000-view video is ~3x (not 100x) a new one
  const popM = 0.8 + 0.22 * Math.log(1 + views);
  // quality: smoothed like rate, comment rate, like/dislike share, and (videos) how much of the video people really watch
  const qLike = rkClamp(((likes + 2) / (views + 40)) / 0.10, 0, 1.5), qCmt = rkClamp(((comments + 0.5) / (views + 80)) / 0.02, 0, 1.5), qRatio = rkWilson(likes, likes + dislikes);
  let watchQ = 1;
  if (isV) {
    const ws = sig.watch[row.id], dur = parseDurSec(row.duration);
    if (ws && ws.sessions >= 5 && dur > 0) { const f = rkClamp(ws.seconds / ws.sessions / dur, 0, 1); watchQ = rkClamp(((f * ws.sessions + 0.4 * 8) / (ws.sessions + 8)) / 0.45, 0.4, 1.6); }
  }
  // reels: how much of the reel people really watch (replays count, up to 1.5x); needs 5+ watch sessions, otherwise the old formula is used
  let rwQ = null;
  if (!isV) { const w = sig.rw[row.id]; if (w && w.sessions >= 5 && w.dur > 0) { const f = rkClamp(w.seconds / w.dur, 0, 1.5); rwQ = rkClamp(((f * w.sessions + 0.5 * 8) / (w.sessions + 8)) / 0.6, 0.4, 1.6); } }
  let quality = isV ? 0.40 * qLike + 0.15 * qCmt + 0.15 * qRatio * 1.4 + 0.30 * watchQ : (rwQ !== null ? 0.40 * qLike + 0.15 * qCmt + 0.20 * qRatio * 1.4 + 0.25 * rwQ : 0.55 * qLike + 0.20 * qCmt + 0.25 * qRatio * 1.4);
  // shares and "subscribed after watching this": only ever ADD to quality, so no data means no change
  const shN = sig.sh[row.id] || 0, sbN = sig.sb[row.id] || 0;
  const qShare = rkClamp((shN / (views + 60)) / 0.01, 0, 1.5), qSub = rkClamp((sbN / (views + 80)) / 0.004, 0, 1.5);
  quality += 0.12 * rkClamp(0.5 * qShare + 0.5 * qSub, 0, 1.2);
  // click-through (videos): of the people who really SAW this video's card, how many opened it. Needs 80+ impressions, otherwise neutral.
  let ctrM = 1;
  if (isV) { const imp = sig.imp[row.id] || 0; if (imp >= 80) { const ctr = (h48 + 2) / (imp + 20); ctrM = rkClamp(0.7 + 0.3 * (ctr / 0.10), 0.7, 1.25); } }
  const engM = 0.6 + 0.8 * rkClamp(quality, 0, 1.6);
  // velocity = how many views in the last 24 h, and is it speeding up compared with the 24 h before
  const accel = rkClamp((h24 + 2) / (prior24 + 2), 0.6, 2.5), momentum = Math.log(1 + h24) * Math.sqrt(accel);
  const velM = rkClamp(0.85 + 0.3 * momentum, 0.85, 2.2);
  // freshness: smooth boost for the first day or two (stronger for reels), then a slow evergreen decay so old good content never vanishes
  // the boost is scaled by quality, so a fresh video nobody likes does not beat a proven one (new creators get trial slots instead)
  const fq = 0.35 + 0.65 * rkClamp(quality, 0, 1.2) / 1.2;
  const fresh = isV ? 1 + 0.9 * fq * Math.exp(-ageH / 20) : 1 + 1.3 * fq * Math.exp(-ageH / 12);
  const evergreen = isV ? 0.65 + 0.35 * Math.exp(-ageH / (30 * 24)) : 0.55 + 0.45 * Math.exp(-ageH / (12 * 24));
  // safety: open reports and copyright claims push content down
  const reports = sig.reports[row.id] || 0, safety = (1 / (1 + 0.6 * reports)) * (isV && row.copyright_status === "claimed" ? 0.5 : 1);
  // satisfaction: once at least 30 people voted, a very high share of dislikes pushes a video down hard, so clickbait cannot ride on views alone.
  // Normal videos (dislikes under ~35% of votes) are not touched at all.
  const votes = likes + dislikes, dShare = votes >= 30 ? dislikes / votes : 0, satisfaction = 1 - 0.65 * rkClamp((dShare - 0.35) / 0.45, 0, 1);
  const base = popM * engM * velM * fresh * evergreen * safety * satisfaction * ctrM;
  return { base, trend: base * (0.5 + momentum), ageH, views, velM, quality, h24 };
}
const _rkInflight = {};
async function rkLoad(db, kind, now) {
  const c = rankCache[kind];
  if (c && now - c.t < RANK_TTL_MS) return c;
  if (_rkInflight[kind]) return await _rkInflight[kind];
  const p = rkLoadRaw(db, kind, now).finally(() => { delete _rkInflight[kind]; });
  _rkInflight[kind] = p;
  return await p;
}
// ================= RANKING SIGNALS: impressions (video cards seen), reel watch time, shares, subscribe-after-watch =================
let _sigReady = false;
async function ensureSignalTables(db) {
  if (_sigReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS impr_daily (kind TEXT NOT NULL, content_id TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, content_id, day))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sig_seen (kind TEXT NOT NULL, content_id TEXT NOT NULL, viewer TEXT NOT NULL, ev TEXT NOT NULL, day TEXT NOT NULL, PRIMARY KEY (kind, content_id, viewer, ev, day))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS engage_daily (kind TEXT NOT NULL, content_id TEXT NOT NULL, day TEXT NOT NULL, shares INTEGER NOT NULL DEFAULT 0, subs INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, content_id, day))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS reel_watch_stats (reel_id TEXT PRIMARY KEY, sessions INTEGER NOT NULL DEFAULT 0, seconds REAL NOT NULL DEFAULT 0, dur REAL NOT NULL DEFAULT 0)").run();
  try { await db.prepare("CREATE INDEX IF NOT EXISTS idx_impr_day ON impr_daily (kind, day)").run(); await db.prepare("CREATE INDEX IF NOT EXISTS idx_engage_day ON engage_daily (kind, day)").run(); } catch (_) {}
  _sigReady = true;
}
// Builds the statements for one batch of signals. Every kind counts once per viewer per day, and never for the owner's own content.
function signalStatements(db, evs, viewer, uid, day) {
  const out = [], idOk = (x) => typeof x === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(x);
  const T = (k) => (k === "r" ? "reels" : "videos");
  const own = uid || "";
  for (const e of evs) {
    if (!e || typeof e !== "object" || !idOk(e.id)) continue;
    const k = e.k === "r" ? "r" : "v", tbl = T(k);
    if (e.t === "imp" && k === "v") {
      out.push(db.prepare("INSERT INTO impr_daily (kind, content_id, day, n) SELECT 'v', t.id, ?, 1 FROM videos t WHERE t.id = ? AND t.removed = 0 AND t.owner_id != ? AND NOT EXISTS (SELECT 1 FROM sig_seen s WHERE s.kind = 'v' AND s.content_id = t.id AND s.viewer = ? AND s.ev = 'imp' AND s.day = ?) ON CONFLICT(kind, content_id, day) DO UPDATE SET n = n + 1").bind(day, e.id, own, viewer, day));
      out.push(db.prepare("INSERT OR IGNORE INTO sig_seen (kind, content_id, viewer, ev, day) SELECT 'v', t.id, ?, 'imp', ? FROM videos t WHERE t.id = ? AND t.removed = 0 AND t.owner_id != ?").bind(viewer, day, e.id, own));
    } else if (e.t === "sh") {
      out.push(db.prepare("INSERT INTO engage_daily (kind, content_id, day, shares, subs) SELECT ?, t.id, ?, 1, 0 FROM " + tbl + " t WHERE t.id = ? AND t.removed = 0 AND t.owner_id != ? AND NOT EXISTS (SELECT 1 FROM sig_seen s WHERE s.kind = ? AND s.content_id = t.id AND s.viewer = ? AND s.ev = 'sh' AND s.day = ?) ON CONFLICT(kind, content_id, day) DO UPDATE SET shares = shares + 1").bind(k, day, e.id, own, k, viewer, day));
      out.push(db.prepare("INSERT OR IGNORE INTO sig_seen (kind, content_id, viewer, ev, day) SELECT ?, t.id, ?, 'sh', ? FROM " + tbl + " t WHERE t.id = ? AND t.removed = 0 AND t.owner_id != ?").bind(k, viewer, day, e.id, own));
    } else if (e.t === "sub" && uid && idOk(e.o)) {
      out.push(db.prepare("INSERT INTO engage_daily (kind, content_id, day, shares, subs) SELECT ?, t.id, ?, 0, 1 FROM " + tbl + " t WHERE t.id = ? AND t.removed = 0 AND t.owner_id = ? AND t.owner_id != ? AND NOT EXISTS (SELECT 1 FROM sig_seen s WHERE s.kind = ? AND s.content_id = t.id AND s.viewer = ? AND s.ev = 'sub' AND s.day = ?) ON CONFLICT(kind, content_id, day) DO UPDATE SET subs = subs + 1").bind(k, day, e.id, e.o, own, k, viewer, day));
      out.push(db.prepare("INSERT OR IGNORE INTO sig_seen (kind, content_id, viewer, ev, day) SELECT ?, t.id, ?, 'sub', ? FROM " + tbl + " t WHERE t.id = ? AND t.removed = 0 AND t.owner_id = ? AND t.owner_id != ?").bind(k, viewer, day, e.id, e.o, own));
    } else if (e.t === "rw") {
      let dur = Number(e.dur), sec = Number(e.sec);
      if (!(dur >= 1 && dur <= 180) || !(sec >= 0.8 && sec <= 900)) continue;
      sec = Math.min(sec, dur * 3); // at most 3 replays count
      const guard = (n) => "EXISTS (SELECT 1 FROM sig_seen s WHERE s.kind = 'r' AND s.content_id = r.id AND s.viewer = ? AND s.ev = '" + n + "' AND s.day = ?)";
      const up = "INSERT INTO reel_watch_stats (reel_id, sessions, seconds, dur) SELECT r.id, 1, ?, ? FROM reels r WHERE r.id = ? AND r.removed = 0 AND r.owner_id != ? AND ";
      const on = " ON CONFLICT(reel_id) DO UPDATE SET sessions = sessions + 1, seconds = seconds + excluded.seconds, dur = dur + excluded.dur";
      const mark = (n, cond) => "INSERT OR IGNORE INTO sig_seen (kind, content_id, viewer, ev, day) SELECT 'r', r.id, ?, '" + n + "', ? FROM reels r WHERE r.id = ? AND r.removed = 0 AND r.owner_id != ? AND " + cond;
      // only the first 2 watch sessions of one viewer per reel per day count (order matters: 2nd, then 1st)
      out.push(db.prepare(up + guard("rw1") + " AND NOT " + guard("rw2") + on).bind(sec, dur, e.id, own, viewer, day, viewer, day));
      out.push(db.prepare(mark("rw2", guard("rw1") + " AND NOT " + guard("rw2"))).bind(viewer, day, e.id, own, viewer, day, viewer, day));
      out.push(db.prepare(up + "NOT " + guard("rw1") + on).bind(sec, dur, e.id, own, viewer, day));
      out.push(db.prepare(mark("rw1", "NOT " + guard("rw1"))).bind(viewer, day, e.id, own, viewer, day));
    }
  }
  return out;
}
let perfIdxDone = false;
// extra indexes for the busiest queries, created once (safe to run again: IF NOT EXISTS)
async function perfIndexes(db) {
  if (perfIdxDone) return;
  perfIdxDone = true;
  try {
    let f = null;
    try { f = await db.prepare("SELECT v FROM auto_tools WHERE k = 'perf_idx_v2'").first(); } catch (_) { try { await ensureAutoToolsTable(db); } catch (__) {} }
    if (f) return;
  } catch (_) {}
  for (const q of [
    "CREATE INDEX IF NOT EXISTS idx_reels_views ON reels (hidden, views)",
    "CREATE INDEX IF NOT EXISTS idx_follows_followee ON follows (followee_id)",
    "CREATE INDEX IF NOT EXISTS idx_videos_owner ON videos (owner_id, uploaded_at)",
    "CREATE INDEX IF NOT EXISTS idx_reels_owner ON reels (owner_id, uploaded_at)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (user_id, created_at)",
  ]) { try { await db.prepare(q).run(); } catch (_) {} }
  try { await setAutoTool(db, "perf_idx_v2", "1"); } catch (_) {}
}
async function rkLoadRaw(db, kind, now) {
  await leanFeedSql(db);
  await perfIndexes(db);
  const c = rankCache[kind];
  if (c && now - c.t < RANK_TTL_MS) return c;
  const tbl = kind === "v" ? "videos" : "reels", sel = FEED_SQL[kind];
  const [newest, top] = await Promise.all([db.prepare(sel + " ORDER BY " + tbl + ".uploaded_at DESC LIMIT 400").all(), db.prepare(sel + " ORDER BY " + tbl + ".views DESC LIMIT 200").all()]);
  const seen = new Set(), rows = [];
  for (const r of [...(newest.results || []), ...(top.results || [])]) { if (!seen.has(r.id)) { seen.add(r.id); rows.push(r); } }
  const sig = { h24: Object.create(null), h48: Object.create(null), watch: Object.create(null), reports: Object.create(null), imp: Object.create(null), sh: Object.create(null), sb: Object.create(null), rw: Object.create(null) };
  try {
    await ensureViewTables(db);
    const q = await db.prepare("SELECT content_id AS id, SUM(CASE WHEN ts > ? THEN 1 ELSE 0 END) AS h24, COUNT(*) AS h48 FROM view_log WHERE kind = ? AND ts > ? GROUP BY content_id").bind(now - 86400000, kind, now - 172800000).all();
    for (const r of q.results || []) { sig.h24[r.id] = r.h24 || 0; sig.h48[r.id] = r.h48 || 0; }
  } catch (_) {}
  if (kind === "v") {
    try { await ensureRetentionTables(db); const q = await db.prepare("SELECT video_id AS id, sessions, seconds FROM video_watch_stats").all(); for (const r of q.results || []) sig.watch[r.id] = { sessions: r.sessions || 0, seconds: r.seconds || 0 }; } catch (_) {}
  }
  try { const q = await db.prepare("SELECT target_id AS id, COUNT(*) AS n FROM reports WHERE status = 'open' AND target_type = ? GROUP BY target_id").bind(kind === "v" ? "video" : "reel").all(); for (const r of q.results || []) sig.reports[r.id] = r.n; } catch (_) {}
  try {
    await ensureSignalTables(db);
    if (kind === "v") { const q = await db.prepare("SELECT content_id AS id, SUM(n) AS n FROM impr_daily WHERE kind = 'v' AND day >= ? GROUP BY content_id").bind(istDay(now - 86400000)).all(); for (const r of q.results || []) sig.imp[r.id] = r.n || 0; }
    const e = await db.prepare("SELECT content_id AS id, SUM(shares) AS sh, SUM(subs) AS sb FROM engage_daily WHERE kind = ? AND day >= ? GROUP BY content_id").bind(kind, istDay(now - 30 * 86400000)).all();
    for (const r of e.results || []) { sig.sh[r.id] = r.sh || 0; sig.sb[r.id] = r.sb || 0; }
    if (kind === "r") { const q = await db.prepare("SELECT reel_id AS id, sessions, seconds, dur FROM reel_watch_stats").all(); for (const r of q.results || []) sig.rw[r.id] = { sessions: r.sessions || 0, seconds: r.seconds || 0, dur: r.dur || 0 }; }
  } catch (_) {}
  const items = rows.map((row) => { const b = rkBase(row, kind, sig, now); return { id: row.id, row, owner: row.owner_id, cat: row.category || null, mix: row.mix_category || null, topics: rkTopics(row), ...b }; });
  const cache = { t: now, items, byId: Object.fromEntries(items.map((x) => [x.id, x])) };
  rankCache[kind] = cache;
  return cache;
}
async function rkPersonal(db, userId, kind) {
  const P = { key: userId ? "u:" + userId : "anon", follows: new Set(), cats: Object.create(null), mix: Object.create(null), topics: Object.create(null), seen: new Set(), has: !!userId };
  if (!userId) return P;
  try { const f = await db.prepare("SELECT followee_id FROM follows WHERE follower_id = ? LIMIT 500").bind(userId).all(); for (const r of f.results || []) P.follows.add(r.followee_id); } catch (_) {}
  try {
    const h = await db.prepare("SELECT watch_history.video_id AS id, videos.category AS cat, videos.mix_category AS mix, videos.title AS title, videos.description AS description, videos.tags AS tags FROM watch_history LEFT JOIN videos ON videos.id = watch_history.video_id WHERE watch_history.user_id = ? ORDER BY watch_history.watched_at DESC LIMIT 200").bind(userId).all();
    (h.results || []).forEach((r, i) => {
      if (kind === "v") P.seen.add(r.id);
      const w = i < 60 ? Math.pow(0.96, i) : 0;
      if (w && r.cat) P.cats[r.cat] = (P.cats[r.cat] || 0) + w;
      if (w && r.mix) P.mix[r.mix] = (P.mix[r.mix] || 0) + w;
      if (w) for (const t of rkTopics(r)) P.topics[t] = (P.topics[t] || 0) + w;
    });
  } catch (_) {}
  return P;
}
function rkPersonalMult(it, P) {
  let m = 1;
  if (P.follows.has(it.owner)) m += 0.45;
  if (it.cat && P.cats[it.cat]) m += 0.30 * Math.min(1, P.cats[it.cat] / 4);
  if (it.mix && P.mix[it.mix]) m += 0.15 * Math.min(1, P.mix[it.mix] / 4);
  if (it.topics && it.topics.length) { let ts = 0; for (const t of it.topics) ts += P.topics[t] || 0; m += 0.20 * Math.min(1, ts / 4); } // hashtags / tags the viewer already watches
  if (P.seen.has(it.id)) m *= 0.45; // already watched: show something new first
  return Math.min(m, 2.2);
}
// greedy re-rank so one creator cannot fill the whole top of the feed
function rkDiversify(list, scoreOf, decay, depth) {
  const head = list.slice(0, depth), tail = list.slice(depth), out = [], cnt = Object.create(null), pool = head.slice();
  while (pool.length) {
    let bi = 0, bs = -1;
    for (let i = 0; i < pool.length; i++) { const s = scoreOf(pool[i]) * Math.pow(decay, cnt[pool[i].owner] || 0); if (s > bs) { bs = s; bi = i; } }
    const it = pool.splice(bi, 1)[0]; cnt[it.owner] = (cnt[it.owner] || 0) + 1; out.push(it);
  }
  return out.concat(tail);
}
// Rank everything for one viewer. Returns { fy: Map(id -> {pos, reason}), tr: Map(id -> pos), order: ids in For You order }
async function rkRanks(db, kind, userId) {
  const now = Date.now(), cache = await rkLoad(db, kind, now), P = await rkPersonal(db, userId, kind), hour = Math.floor(now / 3600000);
  const jit = (it) => 0.97 + 0.06 * rkHash(it.id + "|" + P.key + "|" + hour);
  const sc = new Map(cache.items.map((it) => [it.id, it.base * rkPersonalMult(it, P) * jit(it)]));
  let list = [...cache.items].sort((a, b) => sc.get(b.id) - sc.get(a.id));
  list = rkDiversify(list, (it) => sc.get(it.id), 0.78, 120);
  // trial slots: brand-new content with almost no views gets shown to a few people (positions 3, 8, 13...) so a new creator can take off
  const slots = new Set();
  const trialKey = (it) => it.quality * (1 + 1.2 * Math.exp(-it.ageH / 24)) * (0.9 + 0.2 * rkHash(it.id + P.key + hour)) * (P.follows.has(it.owner) ? 2.5 : 1);
  const pool = cache.items.filter((it) => it.views <= 25 && it.ageH < 72 && !P.seen.has(it.id)).sort((a, b) => trialKey(b) - trialKey(a));
  let pi = 0;
  for (let pos = 2; pos < list.length && pi < pool.length && slots.size < 6; pos += 5) {
    const cand = pool[pi++], from = list.indexOf(cand);
    if (from < 0 || from <= pos) { if (from >= 0 && from <= pos) slots.add(cand.id); continue; }
    list.splice(from, 1); list.splice(pos, 0, cand); slots.add(cand.id);
  }
  const fy = new Map();
  list.forEach((it, i) => {
    let reason = "popular";
    if (P.follows.has(it.owner)) reason = "following";
    else if (slots.has(it.id)) reason = "new";
    else if ((it.cat && P.cats[it.cat]) || (it.mix && P.mix[it.mix]) || (it.topics && it.topics.some((t) => P.topics[t]))) reason = "interest";
    else if (it.velM > 1.4) reason = "trending";
    fy.set(it.id, { pos: i + 1, reason });
  });
  let tl = [...cache.items].sort((a, b) => b.trend - a.trend);
  tl = rkDiversify(tl, (it) => it.trend, 0.85, 40);
  const tr = new Map(tl.map((it, i) => [it.id, i + 1]));
  return { fy, tr, order: list.map((it) => it.id), trOrder: tl.map((it) => it.id), cache };
}
// Adds rankFY / rankTR / rankReason to already-mapped items (the order of the array is untouched).
// Items that were uploaded after the cache was built are treated as brand new: they rank first, newest first.
function rkAttach(out, ranks) {
  let fresh = 0;
  return out.map((o) => {
    const f = ranks.fy.get(o.id);
    if (f) return { ...o, rankFY: f.pos, rankTR: ranks.tr.get(o.id) || f.pos, rankReason: f.reason };
    fresh += 1;
    return { ...o, rankFY: fresh, rankTR: fresh, rankReason: "new" };
  });
}
// "Up next": same creator, same category / mix, shared tags, plus the general quality of the video. Stable (no random shuffling).
async function rkRelated(db, kind, seedId, userId, limit) {
  const now = Date.now(), cache = await rkLoad(db, kind, now), P = await rkPersonal(db, userId, kind);
  let seed = cache.byId[seedId];
  if (!seed) {
    const row = await db.prepare("SELECT * FROM " + (kind === "v" ? "videos" : "reels") + " WHERE id = ?").bind(seedId).first();
    if (!row) return null;
    seed = { id: row.id, row, owner: row.owner_id, cat: row.category || null, mix: row.mix_category || null };
  }
  const tagSet = new Set(rkTopics(seed.row));
  const scored = [];
  for (const it of cache.items) {
    if (it.id === seed.id) continue;
    let aff = 0;
    if (it.owner === seed.owner) aff += 0.9;
    if (seed.cat && it.cat === seed.cat) aff += 0.45;
    if (seed.mix && it.mix === seed.mix) aff += 0.35;
    if (tagSet.size && it.topics) { const tg = it.topics.filter((t) => tagSet.has(t)).length; aff += Math.min(3, tg) * 0.15; }
    let s = it.base * (1 + aff * 1.6) * (aff > 0 ? 1 : 0.5);
    if (P.seen.has(it.id)) s *= 0.45;
    if (P.follows.has(it.owner)) s *= 1.15;
    scored.push({ it, s });
  }
  scored.sort((a, b) => b.s - a.s);
  return scored.slice(0, limit).map((x) => x.it);
}
const rkLimit = (url, d) => { const n = parseInt(url.searchParams.get("limit"), 10); return isFinite(n) ? Math.max(1, Math.min(200, n)) : d; };

// ================= COMMENT LIKES / DISLIKES / REPLIES =================
// If anything here cannot be prepared, comments keep working exactly as before (no likes/replies, nothing breaks).
let _cmExtraP = null;
function ensureCommentExtras(db) {
  if (_cmExtraP) return _cmExtraP;
  _cmExtraP = (async () => {
    try {
      await db.prepare("CREATE TABLE IF NOT EXISTS comment_votes (comment_id TEXT NOT NULL, user_id TEXT NOT NULL, vote INTEGER NOT NULL, created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (comment_id, user_id))").run();
      await db.prepare("CREATE INDEX IF NOT EXISTS idx_comment_votes_c ON comment_votes (comment_id)").run();
      try { await db.prepare("SELECT parent_id FROM comments LIMIT 1").first(); } catch (_) { await db.prepare("ALTER TABLE comments ADD COLUMN parent_id TEXT").run(); }
      await db.prepare("SELECT parent_id FROM comments LIMIT 1").first();
      try { await db.prepare("CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments (parent_id)").run(); } catch (_) {}
      return true;
    } catch (_) { _cmExtraP = null; return false; }
  })();
  return _cmExtraP;
}
async function listComments(db, request, env, type, targetId) {
  const extras = await ensureCommentExtras(db);
  const me = await currentUser(request, env);
  const blocked = me ? await blockedIdsFor(db, me.id) : new Set();
  const base = "comments.*, users.name AS user_name, users.avatar_color AS user_avatar_color";
  const from = " FROM comments JOIN users ON users.id = comments.user_id WHERE target_type = '" + type + "' AND target_id = ? ORDER BY comments.created_at DESC";
  let rows;
  if (extras) {
    rows = await db.prepare("SELECT " + base +
      ", (SELECT COUNT(*) FROM comment_votes cv WHERE cv.comment_id = comments.id AND cv.vote = 1) AS likes" +
      ", (SELECT COUNT(*) FROM comment_votes cv WHERE cv.comment_id = comments.id AND cv.vote = -1) AS dislikes" +
      ", (SELECT cv.vote FROM comment_votes cv WHERE cv.comment_id = comments.id AND cv.user_id = ?) AS my_vote" + from).bind(me ? me.id : "", targetId).all();
  } else {
    rows = await db.prepare("SELECT " + base + from).bind(targetId).all();
  }
  const list = (rows.results || []).filter((c) => !blocked.has(c.user_id));
  return list.map((c) => ({
    id: c.id, userId: c.user_id, userName: c.user_name, avatarColor: c.user_avatar_color, text: c.text, createdAt: c.created_at,
    parentId: c.parent_id || null, likes: c.likes || 0, dislikes: c.dislikes || 0, myVote: c.my_vote || 0, targetType: type, targetId,
  }));
}
// A reply is saved under the top comment (one level, like YouTube); replying to a reply attaches to the same top comment.
async function addComment(db, u, type, targetId, body) {
  const text = body && body.text;
  if (!text || typeof text !== "string" || !text.trim()) return { error: "Comment text is required" };
  if (text.length > 1000) return { error: "Comment is too long (max 1000 characters)" };
  const id = uid("c");
  let parentId = body && typeof body.parentId === "string" && body.parentId ? body.parentId : null;
  if (parentId) {
    if (!(await ensureCommentExtras(db))) return { error: "Replies are not available right now. Please try again later." };
    const par = await db.prepare("SELECT id, parent_id, user_id, target_type, target_id FROM comments WHERE id = ?").bind(parentId).first();
    if (!par || par.target_type !== type || par.target_id !== targetId) return { error: "The comment you are replying to was not found", status: 404 };
    parentId = par.parent_id || par.id;
    await db.prepare("INSERT INTO comments (id, target_type, target_id, user_id, text, parent_id) VALUES (?, ?, ?, ?, ?, ?)").bind(id, type, targetId, u.id, text.trim(), parentId).run();
    // tell the owner of the comment that someone replied (never for own replies, never if they blocked the replier); can never break posting
    try {
      if (par.user_id && par.user_id !== u.id && !(await isBlocked(db, par.user_id, u.id))) {
        const snip = text.trim().length > 80 ? text.trim().slice(0, 80) + "…" : text.trim();
        await addNotification(db, par.user_id, "info", "New reply to your comment", (u.name || "Someone") + " replied: \"" + snip + "\"");
      }
    } catch (_) {}
  } else {
    await db.prepare("INSERT INTO comments (id, target_type, target_id, user_id, text) VALUES (?, ?, ?, ?, ?)").bind(id, type, targetId, u.id, text.trim()).run();
  }
  return { id };
}
// ================= HASHTAGS: unique tags, counts, autocomplete =================
// Everything here runs in the background and swallows its own errors, so a hashtag problem can never break an upload.
let _htReady = false, _htBackfill = false;
const _htMem = new Map(); // suggestion cache (60 s)
async function ensureHashtagTables(db) {
  if (_htReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS hashtags (id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name TEXT NOT NULL UNIQUE, video_count INTEGER NOT NULL DEFAULT 0, channel_count INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS video_hashtags (hashtag_id INTEGER NOT NULL, kind TEXT NOT NULL, content_id TEXT NOT NULL, owner_id TEXT NOT NULL, PRIMARY KEY (hashtag_id, kind, content_id))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vh_content ON video_hashtags (kind, content_id)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_hashtags_count ON hashtags (video_count)").run();
  _htReady = true;
}
const HT_MAX = 15, HT_LEN = 50;
// Hashtags are stored lower-case, once per video (#Naat, #naat and #NAAT are the same tag). Works for Hindi/Urdu/English letters.
function extractHashtags(title, description, tags) {
  const out = [], seen = new Set();
  const add = (raw) => {
    const t = String(raw || "").normalize("NFC").toLowerCase();
    if (!t || t.length > HT_LEN || seen.has(t) || /^[0-9_]+$/.test(t)) return;
    seen.add(t); out.push(t);
  };
  const re = /(?<![\p{L}\p{M}\p{N}_&\/])#([\p{L}\p{M}\p{N}_]{1,50})(?![\p{L}\p{M}\p{N}_])/gu;
  for (const text of [title, description]) {
    if (typeof text !== "string") continue;
    let m; re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) add(m[1]);
  }
  if (Array.isArray(tags)) for (const t of tags) { // only tags the creator wrote with a leading #
    if (typeof t !== "string") continue;
    const x = t.trim();
    if (x[0] === "#" && /^[\p{L}\p{M}\p{N}_]{1,50}$/u.test(x.slice(1))) add(x.slice(1));
  }
  return out.slice(0, HT_MAX);
}
// Live counts: only videos/reels that exist, are not removed and not hidden. Channels = distinct owners.
async function liveHashtagCounts(db, ids) {
  const res = new Map();
  if (!ids.length) return res;
  const ph = ids.map(() => "?").join(",");
  const rows = await db.prepare(
    "SELECT hid, COUNT(*) AS vc, COUNT(DISTINCT oid) AS cc FROM (" +
    "SELECT vh.hashtag_id AS hid, v.owner_id AS oid FROM video_hashtags vh JOIN videos v ON vh.kind = 'v' AND v.id = vh.content_id WHERE v.removed = 0 AND v.hidden = 0 AND vh.hashtag_id IN (" + ph + ") " +
    "UNION ALL " +
    "SELECT vh.hashtag_id AS hid, r.owner_id AS oid FROM video_hashtags vh JOIN reels r ON vh.kind = 'r' AND r.id = vh.content_id WHERE r.hidden = 0 AND vh.hashtag_id IN (" + ph + ")" +
    ") GROUP BY hid"
  ).bind(...ids, ...ids).all();
  for (const r of rows.results || []) res.set(r.hid, { vc: r.vc, cc: r.cc });
  return res;
}
async function recountHashtags(db, ids) {
  if (!ids.length) return;
  const live = await liveHashtagCounts(db, ids), now = Date.now();
  await db.batch(ids.map((id) => { const c = live.get(id) || { vc: 0, cc: 0 }; return db.prepare("UPDATE hashtags SET video_count = ?, channel_count = ?, updated_at = ? WHERE id = ?").bind(c.vc, c.cc, now, id); }));
}
async function indexHashtags(db, kind, contentId, ownerId, title, description, tags) {
  try {
    const list = extractHashtags(title, description, tags);
    if (!list.length) return;
    await ensureHashtagTables(db);
    const now = Date.now();
    await db.batch(list.map((t) => db.prepare("INSERT OR IGNORE INTO hashtags (tag_name, updated_at) VALUES (?, ?)").bind(t, now)));
    const found = await db.prepare("SELECT id FROM hashtags WHERE tag_name IN (" + list.map(() => "?").join(",") + ")").bind(...list).all();
    const ids = (found.results || []).map((r) => r.id);
    await db.batch(ids.map((id) => db.prepare("INSERT OR IGNORE INTO video_hashtags (hashtag_id, kind, content_id, owner_id) VALUES (?, ?, ?, ?)").bind(id, kind, contentId, ownerId)));
    await recountHashtags(db, ids);
    _htMem.clear();
  } catch (_) {}
}
async function unindexHashtags(db, kind, contentId) {
  try {
    await ensureHashtagTables(db);
    const rows = await db.prepare("SELECT hashtag_id FROM video_hashtags WHERE kind = ? AND content_id = ?").bind(kind, contentId).all();
    const ids = (rows.results || []).map((r) => r.hashtag_id);
    if (!ids.length) return;
    await db.prepare("DELETE FROM video_hashtags WHERE kind = ? AND content_id = ?").bind(kind, contentId).run();
    await recountHashtags(db, ids);
    _htMem.clear();
  } catch (_) {}
}
// One-time fill from videos/reels that already exist (runs once, then a flag in auto_tools stops it).
async function backfillHashtags(db) {
  if (_htBackfill) return;
  _htBackfill = true;
  try {
    await ensureHashtagTables(db);
    let done = null;
    try { done = await db.prepare("SELECT v FROM auto_tools WHERE k = 'hashtag_backfill_v1'").first(); } catch (_) { try { await ensureAutoToolsTable(db); } catch (__) {} }
    if (done) return;
    const vids = await db.prepare("SELECT id, owner_id, title, description, tags FROM videos ORDER BY uploaded_at DESC LIMIT 5000").all();
    const rls = await db.prepare("SELECT id, owner_id, title, tags FROM reels ORDER BY uploaded_at DESC LIMIT 5000").all();
    const items = [];
    const parse = (x) => { try { const a = JSON.parse(x || "[]"); return Array.isArray(a) ? a : []; } catch (_) { return []; } };
    for (const v of vids.results || []) items.push(["v", v.id, v.owner_id, extractHashtags(v.title, v.description, parse(v.tags))]);
    for (const r of rls.results || []) items.push(["r", r.id, r.owner_id, extractHashtags(r.title, "", parse(r.tags))]);
    const now = Date.now(), allTags = new Set();
    for (const it of items) for (const t of it[3]) allTags.add(t);
    const tagList = [...allTags];
    for (let i = 0; i < tagList.length; i += 50) await db.batch(tagList.slice(i, i + 50).map((t) => db.prepare("INSERT OR IGNORE INTO hashtags (tag_name, updated_at) VALUES (?, ?)").bind(t, now)));
    const idOf = new Map();
    for (let i = 0; i < tagList.length; i += 50) {
      const part = tagList.slice(i, i + 50);
      const f = await db.prepare("SELECT id, tag_name FROM hashtags WHERE tag_name IN (" + part.map(() => "?").join(",") + ")").bind(...part).all();
      for (const r of f.results || []) idOf.set(r.tag_name, r.id);
    }
    const maps = [];
    for (const [kind, cid, oid, tags] of items) for (const t of tags) if (idOf.has(t)) maps.push(db.prepare("INSERT OR IGNORE INTO video_hashtags (hashtag_id, kind, content_id, owner_id) VALUES (?, ?, ?, ?)").bind(idOf.get(t), kind, cid, oid));
    for (let i = 0; i < maps.length; i += 50) await db.batch(maps.slice(i, i + 50));
    const ids = [...idOf.values()];
    for (let i = 0; i < ids.length; i += 40) await recountHashtags(db, ids.slice(i, i + 40));
    await setAutoTool(db, "hashtag_backfill_v1", "1");
    _htMem.clear();
  } catch (_) { _htBackfill = false; }
}
async function hashtagSuggest(db, url) {
  const q = String(url.searchParams.get("q") || "").normalize("NFC").toLowerCase().replace(/^#+/, "").replace(/[^\p{L}\p{M}\p{N}_]/gu, "").slice(0, HT_LEN);
  const reply = (tags, st) => new Response(JSON.stringify({ tags }), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=30", "X-Suggest-Cache": st, ...cors() } });
  const hit = _htMem.get(q);
  if (hit && Date.now() - hit.t < 60000) return reply(hit.tags, "hit");
  let tags = [];
  try {
    await ensureHashtagTables(db);
    bg(backfillHashtags(db));
    const base = "SELECT id, tag_name FROM hashtags WHERE video_count > 0";
    const cand = q
      ? await db.prepare(base + " AND tag_name >= ? AND tag_name < ? ORDER BY video_count DESC, channel_count DESC, tag_name LIMIT 30").bind(q, q + "\u{10FFFF}").all()
      : await db.prepare(base + " ORDER BY video_count DESC, channel_count DESC, tag_name LIMIT 30").all();
    const rows = cand.results || [], live = await liveHashtagCounts(db, rows.map((r) => r.id));
    tags = rows.map((r) => ({ tag: r.tag_name, videos: (live.get(r.id) || {}).vc || 0, channels: (live.get(r.id) || {}).cc || 0 }))
      .filter((t) => t.videos > 0).sort((a, b) => b.videos - a.videos || b.channels - a.channels || (a.tag < b.tag ? -1 : 1)).slice(0, 10);
  } catch (_) { return reply([], "error"); }
  _htMem.set(q, { t: Date.now(), tags });
  if (_htMem.size > 300) _htMem.delete(_htMem.keys().next().value);
  return reply(tags, "miss");
}
// ================= FAST FEED: memory/edge cache for signed-out visitors, small thumbnails, feed indexes =================
let _origin = "", _ctx = null;
const bg = (p) => { try { if (_ctx) _ctx.waitUntil(p); } catch (_) {} return p; };
const FEED_FRESH_MS = 60000, FEED_STALE_MS = 360000; // "public, max-age=60, stale-while-revalidate=300"
const _feedMem = new Map(), _feedBusy = new Set(), _thumbMem = new Map();
const feedKey = (pathname, params) => pathname + "?" + [...params.entries()].map(([k, v]) => k + "=" + v).sort().join("&");
// Thumbnails that were saved as a huge base64 "data:" string are served from a small cached /thumb URL instead,
// so the feed JSON stays tiny. Normal http(s) thumbnails are returned unchanged.
const tagHash = (s) => { let h = 0; for (const ch of String(s || "")) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return h.toString(36); };
function thumbOut(kind, id, t, row) {
  if (!_origin) return t;
  if (row && row.thumb_inline) return _origin + "/thumb/" + kind + "/" + encodeURIComponent(id) + "?v=" + Number(row.thumb_len || 0).toString(36) + tagHash(row.thumb_tag);
  if (typeof t !== "string" || t.length < 200 || t.slice(0, 11) !== "data:image/") return t;
  return _origin + "/thumb/" + kind + "/" + encodeURIComponent(id) + "?v=" + t.length.toString(36) + tagHash(t.substr(59, 8));
}
// Feed queries used "SELECT videos.*", which dragged every base64 thumbnail (tens of KB each) out of D1 on every rebuild.
// This swaps in the same column list without the thumbnail text (only a flag + length + tag are read). If anything fails, the old query stays.
let _leanP = null;
function leanFeedSql(db) {
  if (_leanP) return _leanP;
  _leanP = Promise.all([["v", "videos"], ["r", "reels"]].map(async ([k, tbl]) => {
    try {
      const info = await db.prepare("PRAGMA table_info(" + tbl + ")").all(), all = (info.results || []).map((c) => c.name);
      const cols = all.filter((n) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(n) && n !== "thumbnail");
      if (cols.length < 5 || all.indexOf("thumbnail") < 0 || FEED_SQL[k].indexOf("SELECT " + tbl + ".*") !== 0) return;
      const T = tbl + ".thumbnail", sel = "SELECT " + cols.map((c) => tbl + "." + c).join(", ") + ", CASE WHEN substr(" + T + ",1,11)='data:image/' THEN NULL ELSE " + T + " END AS thumbnail, (substr(" + T + ",1,11)='data:image/') AS thumb_inline, length(" + T + ") AS thumb_len, substr(" + T + ",60,8) AS thumb_tag";
      const next = FEED_SQL[k].replace("SELECT " + tbl + ".*", sel);
      await db.prepare(next + " ORDER BY " + tbl + ".uploaded_at DESC LIMIT 1").all(); // must work, otherwise keep the old query
      FEED_SQL[k] = next;
    } catch (_) {}
  })).then(() => {});
  return _leanP;
}
let feedIdxDone = false;
async function ensureFeedIndexes(db) {
  if (feedIdxDone) return;
  feedIdxDone = true;
  try {
    let f = null;
    try { f = await db.prepare("SELECT v FROM auto_tools WHERE k = 'feed_idx_v1'").first(); } catch (_) { try { await ensureAutoToolsTable(db); } catch (__) {} }
    if (f) return;
  } catch (_) {}
  for (const q of [
    "CREATE INDEX IF NOT EXISTS idx_videos_feed ON videos (removed, hidden, uploaded_at)",
    "CREATE INDEX IF NOT EXISTS idx_videos_views ON videos (removed, hidden, views)",
    "CREATE INDEX IF NOT EXISTS idx_reels_feed ON reels (hidden, uploaded_at)",
    "CREATE INDEX IF NOT EXISTS idx_comments_target ON comments (target_type, target_id)",
    "CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows (follower_id)",
    "CREATE INDEX IF NOT EXISTS idx_watch_history_user ON watch_history (user_id)",
  ]) { try { await db.prepare(q).run(); } catch (_) {} }
  try { await setAutoTool(db, "feed_idx_v1", "1"); } catch (_) {}
}
function feedReply(body, state) {
  return new Response(body, { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=60, stale-while-revalidate=300", "X-Feed-Cache": state, ...cors() } });
}
// Signed-out visitors all get the same feed, so it is built once and reused for 60 s (and served stale for up to 6 min while it
// refreshes in the background). Signed-in visitors are never cached: their feed is personal.
async function feedCached(db, request, env, url, kind) {
  if (request.headers.get("Authorization")) return await feedResponse(db, request, env, url, kind);
  const key = feedKey(url.pathname, url.searchParams), edgeReq = () => new Request(url.origin + "/__feed" + key), now = Date.now();
  const store = async (body) => {
    _feedMem.set(key, { t: Date.now(), body });
    if (_feedMem.size > 40) _feedMem.delete(_feedMem.keys().next().value);
    try { await caches.default.put(edgeReq(), new Response(body, { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=360", "X-Cached-At": String(Date.now()) } })); } catch (_) {}
  };
  const refresh = async () => {
    if (_feedBusy.has(key)) return;
    _feedBusy.add(key);
    try { const r = await feedResponse(db, request, env, url, kind); if (r.status === 200) await store(await r.text()); } catch (_) {} finally { _feedBusy.delete(key); }
  };
  let e = _feedMem.get(key);
  if (!e) {
    try { const h = await caches.default.match(edgeReq()); if (h) { e = { t: Number(h.headers.get("X-Cached-At")) || 0, body: await h.text() }; _feedMem.set(key, e); } } catch (_) {}
  }
  if (e && e.body && now - e.t < FEED_STALE_MS) {
    const stale = now - e.t >= FEED_FRESH_MS;
    if (stale) bg(refresh());
    return feedReply(e.body, stale ? "stale" : "hit");
  }
  const res = await feedResponse(db, request, env, url, kind);
  if (res.status !== 200) return res;
  const body = await res.text();
  bg(store(body));
  return feedReply(body, "miss");
}
function purgeFeedCache(origin) {
  _feedMem.clear();
  try {
    for (const q of ["/api/videos?rank=1", "/api/reels?rank=1", "/api/videos?limit=24&rank=1&sort=foryou"]) bg(caches.default.delete(new Request(origin + "/__feed" + q)));
  } catch (_) {}
}
async function feedResponse(db, request, env, url, kind) {
  bg(ensureFeedIndexes(db));
  await leanFeedSql(db);
  const key = kind === "v" ? "videos" : "reels", tbl = key, mk = kind === "v" ? videoOut : reelOut;
  const sort = (url.searchParams.get("sort") || "").toLowerCase(), wantRank = url.searchParams.get("rank") === "1";
  if (!sort && !wantRank) { // unchanged default: newest first
    const rows = await db.prepare(FEED_SQL[kind] + " ORDER BY " + tbl + ".uploaded_at DESC LIMIT 200").all();
    return json({ [key]: rows.results.map(mk) });
  }
  const limit = rkLimit(url, 200);
  let me = null;
  try { me = await currentUser(request, env); } catch (_) {}
  const userId = me && me.role !== "guest" ? me.id : null;
  let ranks = null;
  try { ranks = await rkRanks(db, kind, userId); } catch (_) { ranks = null; }
  let blockedOwners = null; // people this viewer blocked: their videos/reels are hidden for this viewer only
  if (userId) { try { const bs = await blockedIdsFor(db, userId); if (bs.size) blockedOwners = bs; } catch (_) {} }
  const keep = (arr) => (blockedOwners ? arr.filter((v) => !blockedOwners.has(v.ownerId)) : arr);
  if ((sort === "trending" || sort === "foryou") && ranks) {
    const ids = sort === "trending" ? ranks.trOrder : ranks.order;
    const out = keep(ids.slice(0, blockedOwners ? ids.length : limit).map((id) => mk(ranks.cache.byId[id].row))).slice(0, limit);
    return json({ [key]: rkAttach(out, ranks), sort });
  }
  const order = sort === "popular" ? tbl + ".views DESC, " + tbl + ".uploaded_at DESC" : tbl + ".uploaded_at DESC";
  const rows = await db.prepare(FEED_SQL[kind] + " ORDER BY " + order + " LIMIT " + limit).all();
  const out = keep(rows.results.map(mk));
  return json({ [key]: ranks ? rkAttach(out, ranks) : out, sort: sort || "latest" });
}

// ================= CREATOR ANALYTICS (real data only) =================
// Daily views: counted in view_daily (above). Audience retention: the app reports which 10% parts of a video a viewer really watched.
const istDay = (ms) => new Date(ms + 19800000).toISOString().slice(0, 10);
let retentionReady = false;
async function ensureRetentionTables(db) {
  if (retentionReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS video_retention (video_id TEXT NOT NULL, bucket INTEGER NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (video_id, bucket))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS video_watch_stats (video_id TEXT PRIMARY KEY, sessions INTEGER NOT NULL DEFAULT 0, seconds INTEGER NOT NULL DEFAULT 0)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS retention_seen (viewer TEXT NOT NULL, video_id TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (viewer, video_id))").run();
  retentionReady = true;
}
function lastDays(n, now) { const out = []; for (let i = n - 1; i >= 0; i--) out.push(istDay(now - i * 86400000)); return out; }

// ================= SADAQAH =================
// Viewers give nazrana under a video by paying the ADMIN's UPI (set in the admin panel). The app cannot see UPI payments, so:
//   1) tapping Nazrana creates a short reference (e.g. NT7K2QX) that goes into the UPI note,
//   2) the donor then tells the app how much they sent ("claimed"),
//   3) the admin checks the UPI statement and confirms ("received"). Only RECEIVED amounts count for the creator.
// Money stays with the admin. A creator can request a withdrawal once their available nazrana reaches the limit (default Rs 5000),
// either the full amount or a custom amount; the admin pays them by UPI/bank and taps Paid. Not linked to monetization at all.
const SADAQAH_UNLOCK_PAISE = 500000;      // Rs 5000 available balance needed before a creator can request a withdrawal
const SADAQAH_MIN_REQUEST_PAISE = 10000;  // smallest custom withdrawal: Rs 100
const SADAQAH_MAX_CLAIM_PAISE = 10000000; // a donor can claim at most Rs 1,00,000 per nazrana
let sadaqahReady = false;
// ----- deductions (tax / platform fee / other): cut from each confirmed nazrana, the creator gets the rest -----
// amount_paise = what the CREATOR gets (net). gross_paise = what the admin received. The cuts are saved on each payment, so old payments never change.
let sdDedOk = false;
const SD_DED_DEFAULTS = [{ key: "tax", name: "Tax" }, { key: "platform", name: "Platform fee" }, { key: "other", name: "Other" }];
async function ensureSadaqahDedCols(db) {
  if (sdDedOk) return true;
  const has = async () => { try { await db.prepare("SELECT gross_paise, tax_paise, platform_paise, other_paise, deduct_json FROM sadaqah_donations LIMIT 1").first(); return true; } catch (_) { return false; } };
  if (await has()) { sdDedOk = true; return true; }
  for (const c of ["gross_paise INTEGER", "tax_paise INTEGER", "platform_paise INTEGER", "other_paise INTEGER", "deduct_json TEXT"]) { try { await db.prepare("ALTER TABLE sadaqah_donations ADD COLUMN " + c).run(); } catch (_) {} }
  sdDedOk = await has();
  return sdDedOk;
}
function parseDeductions(raw) {
  let a = [];
  try { a = JSON.parse(raw || "[]"); } catch (_) {}
  if (!Array.isArray(a)) a = [];
  return SD_DED_DEFAULTS.map((d) => {
    const x = a.find((y) => y && y.key === d.key) || {}, pct = Number(x.pct);
    return { key: d.key, name: String(x.name || "").trim().slice(0, 30) || d.name, pct: isFinite(pct) && pct > 0 && pct <= 50 ? Math.round(pct * 100) / 100 : 0 };
  });
}
function parseDedJson(s) {
  try { const a = JSON.parse(s || "[]"); return Array.isArray(a) ? a.filter((x) => x && Number(x.paise) > 0).map((x) => ({ name: String(x.name || ""), pct: Number(x.pct) || 0, paise: Number(x.paise) || 0 })) : []; } catch (_) { return []; }
}
const sdGross = (a) => { const p = a ? a + "." : ""; return sdDedOk ? "COALESCE(" + p + "gross_paise, " + p + "amount_paise)" : p + "amount_paise"; };
const sdCutCols = (a) => { const p = a ? a + "." : ""; return sdDedOk ? "COALESCE(SUM(CASE WHEN " + p + "status = 'received' THEN " + p + "tax_paise END), 0) AS tax, COALESCE(SUM(CASE WHEN " + p + "status = 'received' THEN " + p + "platform_paise END), 0) AS platform, COALESCE(SUM(CASE WHEN " + p + "status = 'received' THEN " + p + "other_paise END), 0) AS other," : "0 AS tax, 0 AS platform, 0 AS other,"; };
async function sadaqahCutSummary(db, creatorId) {
  if (!sdDedOk) return { grossPaise: 0, taxPaise: 0, platformPaise: 0, otherPaise: 0, netPaise: 0 };
  const r = await db.prepare("SELECT COALESCE(SUM(COALESCE(gross_paise, amount_paise)), 0) AS g, COALESCE(SUM(tax_paise), 0) AS t, COALESCE(SUM(platform_paise), 0) AS p, COALESCE(SUM(other_paise), 0) AS o, COALESCE(SUM(amount_paise), 0) AS n FROM sadaqah_donations WHERE creator_id = ? AND status = 'received'").bind(creatorId).first();
  return { grossPaise: r.g || 0, taxPaise: r.t || 0, platformPaise: r.p || 0, otherPaise: r.o || 0, netPaise: r.n || 0 };
}
function csvCell(v) { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
const csvRow = (a) => a.map(csvCell).join(",");
const istStr = (ms) => (ms ? new Date(Number(ms) + 19800000).toISOString().replace("T", " ").slice(0, 16) : "");
const rupees2 = (p) => ((p || 0) / 100).toFixed(2);
async function ensureSadaqahTables(db) {
  if (sadaqahReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS sadaqah_donations (id TEXT PRIMARY KEY, ref TEXT NOT NULL, video_id TEXT NOT NULL, creator_id TEXT NOT NULL, donor_id TEXT, donor_name TEXT, status TEXT NOT NULL DEFAULT 'initiated', claimed_paise INTEGER, amount_paise INTEGER, utr TEXT, created_at INTEGER NOT NULL, claimed_at INTEGER, resolved_at INTEGER, note TEXT)").run();
  await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_sd_ref ON sadaqah_donations (ref)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sd_creator ON sadaqah_donations (creator_id, status)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sd_status ON sadaqah_donations (status, created_at)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sd_donor ON sadaqah_donations (donor_id, created_at)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sadaqah_requests (id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, amount_paise INTEGER NOT NULL, method TEXT, account_name TEXT, account_number TEXT, routing_code TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at INTEGER NOT NULL, resolved_at INTEGER, note TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sr_status ON sadaqah_requests (status, created_at)").run();
  await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_sr_one_pending ON sadaqah_requests (creator_id) WHERE status = 'Pending'").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS sadaqah_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
  try { await ensureSadaqahDedCols(db); } catch (_) {}
  sadaqahReady = true;
}
async function getSadaqahSettings(db) {
  const rows = await db.prepare("SELECT k, v FROM sadaqah_settings").all();
  const m = {};
  (rows.results || []).forEach((r) => { m[r.k] = r.v; });
  const unlock = parseInt(m.unlock_paise, 10);
  return { enabled: m.enabled !== "0", upiId: m.upi_id || "", payeeName: String(m.payee_name || "NoorTube Nazrana").replace(/sadaqah/gi, "Nazrana"), unlockPaise: unlock >= SADAQAH_MIN_REQUEST_PAISE ? unlock : SADAQAH_UNLOCK_PAISE, minRequestPaise: SADAQAH_MIN_REQUEST_PAISE, deductions: parseDeductions(m.deductions) };
}
async function sadaqahBalance(db, creatorId) {
  const r = await db.prepare(
    "SELECT COALESCE((SELECT SUM(amount_paise) FROM sadaqah_donations WHERE creator_id = ? AND status = 'received'), 0) AS received, " +
    "COALESCE((SELECT COUNT(*) FROM sadaqah_donations WHERE creator_id = ? AND status = 'received'), 0) AS receivedCount, " +
    "COALESCE((SELECT SUM(amount_paise) FROM sadaqah_requests WHERE creator_id = ? AND status = 'Paid'), 0) AS paid, " +
    "COALESCE((SELECT SUM(amount_paise) FROM sadaqah_requests WHERE creator_id = ? AND status = 'Pending'), 0) AS pending, " +
    "COALESCE((SELECT SUM(claimed_paise) FROM sadaqah_donations WHERE creator_id = ? AND status = 'claimed'), 0) AS awaiting"
  ).bind(creatorId, creatorId, creatorId, creatorId, creatorId).first();
  const received = r.received || 0, paid = r.paid || 0, pending = r.pending || 0;
  return { receivedPaise: received, receivedCount: r.receivedCount || 0, paidPaise: paid, pendingPaise: pending, awaitingPaise: r.awaiting || 0, availablePaise: Math.max(0, received - paid - pending) };
}
// Never throws. Removes a deleted creator's nazrana rows (the account and its videos are being deleted too).
async function purgeSadaqah(db, userId) {
  try {
    await ensureSadaqahTables(db);
    await db.batch([
      db.prepare("DELETE FROM sadaqah_donations WHERE creator_id = ?").bind(userId),
      db.prepare("DELETE FROM sadaqah_requests WHERE creator_id = ?").bind(userId),
    ]);
  } catch (_) {}
}
function sadaqahRef() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = crypto.getRandomValues(new Uint8Array(6));
  let s = "NT";
  for (let i = 0; i < 6; i++) s += A[b[i] % A.length];
  return s;
}
function parseRupeesToPaise(v) {
  const n = typeof v === "number" ? v : parseFloat(String(v == null ? "" : v).replace(/,/g, ""));
  if (!isFinite(n) || n <= 0) return null;
  return Math.round(n * 100);
}
const rs2 = (p) => "\u20B9" + ((p || 0) / 100).toFixed(2).replace(/\.00$/, "");
function sadaqahDonationOut(d) {
  return { id: d.id, ref: d.ref, videoId: d.video_id, videoTitle: d.vtitle || "Deleted video", creatorId: d.creator_id, creatorName: d.creator_name || "", donorName: d.donor_name || "Guest",
    status: d.status, claimedPaise: d.claimed_paise, amountPaise: d.amount_paise, grossPaise: d.gross_paise || d.amount_paise, deductions: parseDedJson(d.deduct_json), utr: d.utr || "", createdAt: d.created_at, claimedAt: d.claimed_at, resolvedAt: d.resolved_at, note: d.note || "" };
}

function publicUser(u, withPrivate = false) {
  if (!u) return null;
  if (!withPrivate) {
    // Public view: only what other people legitimately need. No email, payout, strikes etc.
    return { id: u.id, name: u.name, avatarColor: u.avatar_color, avatarImage: u.avatar_image, role: u.role };
  }
  return {
    id: u.id, name: u.name, email: u.email, avatarColor: u.avatar_color, avatarImage: u.avatar_image,
    role: u.role, suspended: !!u.suspended, strikes: u.strikes, monetizationEnabled: !!u.monetization_enabled,
    watchHours: u.watch_hours,
    // payoutInfo (bank/UPI details) is private: only returned to the user themself or an admin
    payoutInfo: u.payout_method ? { method: u.payout_method, accountName: u.payout_account_name, accountNumber: u.payout_account_number, routingCode: u.payout_routing_code } : null,
  };
}
function videoOut(v) {
  return {
    id: v.id, ownerId: v.owner_id, title: v.title, description: v.description, tags: JSON.parse(v.tags || "[]"),
    category: v.category, mixCategory: v.mix_category, sourceType: v.source_type, youtubeId: v.youtube_id,
    fileUrl: v.file_url, thumbnail: thumbOut("v", v.id, v.thumbnail, v), duration: v.duration,
    trimStart: v.trim_start, trimEnd: v.trim_end,
    views: v.views, likes: v.likes, dislikes: v.dislikes, monetized: !!v.monetized,
    copyrightStatus: v.copyright_status, removed: !!v.removed, hidden: !!v.hidden, uploadedAt: v.uploaded_at, earnings: v.earnings,
    channel: v.owner_name, channelAvatar: v.owner_avatar_color, commentCount: v.comment_count || 0,
    channelMonetized: !!v.owner_monetized,
  };
}
function reelOut(r) {
  return {
    id: r.id, ownerId: r.owner_id, title: r.title, tags: JSON.parse(r.tags || "[]"), fileUrl: r.file_url,
    thumbnail: thumbOut("r", r.id, r.thumbnail, r), trimStart: r.trim_start, trimEnd: r.trim_end, views: r.views, likes: r.likes,
    uploadedAt: r.uploaded_at, channel: r.owner_name, channelAvatar: r.owner_avatar_color, commentCount: r.comment_count || 0,
    mixCategory: r.mix_category || null, hidden: !!r.hidden, channelMonetized: !!r.owner_monetized,
  };
}
function statusOut(s) {
  return {
    id: s.id, ownerId: s.owner_id, sourceType: s.source_type, youtubeId: s.youtube_id, fileUrl: s.file_url,
    thumbnail: s.thumbnail, views: s.views, createdAt: s.created_at, channel: s.owner_name, channelAvatar: s.owner_avatar_color,
  };
}

// ================= EMAIL VERIFICATION (needed before monetization can be enabled) =================
// A creator proves the email is real by typing a 6-digit code sent to it. Needs the secrets MAIL_FROM and BREVO_API_KEY (or RESEND_API_KEY).
// Until they are set, asking for a code answers "not set up yet" and nothing else in the app changes.
let emailVerifyReady = false;
async function ensureEmailVerifyTables(db) {
  if (emailVerifyReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS email_verified (user_id TEXT PRIMARY KEY, email TEXT NOT NULL, verified_at INTEGER NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS email_codes (user_id TEXT PRIMARY KEY, email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent_at INTEGER NOT NULL, hour_start INTEGER NOT NULL DEFAULT 0, hour_count INTEGER NOT NULL DEFAULT 0)").run();
  emailVerifyReady = true;
}
async function isEmailVerified(db, u) {
  try {
    await ensureEmailVerifyTables(db);
    const r = await db.prepare("SELECT email FROM email_verified WHERE user_id = ?").bind(u.id).first();
    return !!(r && String(r.email).toLowerCase() === String(u.email || "").toLowerCase());
  } catch (_) { return false; }
}
async function sha256Hex(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function mailConfigured(env) { return !!(env.MAIL_FROM && (env.BREVO_API_KEY || env.RESEND_API_KEY)); }
async function sendMail(env, to, subject, html, text) {
  const fromEmail = env.MAIL_FROM, fromName = env.MAIL_FROM_NAME || "NoorTube";
  try {
    if (env.BREVO_API_KEY) {
      const r = await fetch("https://api.brevo.com/v3/smtp/email", { method: "POST", headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", accept: "application/json" },
        body: JSON.stringify({ sender: { name: fromName, email: fromEmail }, to: [{ email: to }], subject, htmlContent: html, textContent: text }) });
      return r.ok;
    }
    if (env.RESEND_API_KEY) {
      const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ from: fromName + " <" + fromEmail + ">", to: [to], subject, html, text }) });
      return r.ok;
    }
  } catch (_) {}
  return false;
}

// ================= AD CAMPAIGNS: creators buy ads in Studio, the admin checks the payment and starts them =================
// Nothing is open to creators until the admin turns it on, adds at least one way to pay and sets the prices.
let campReady = false;
async function ensureCampTables(db) {
  if (campReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS ad_campaigns (id TEXT PRIMARY KEY, ref TEXT NOT NULL, owner_id TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, media_url TEXT NOT NULL, click_url TEXT, placements TEXT NOT NULL, days INTEGER NOT NULL, mid_after INTEGER, skip INTEGER NOT NULL DEFAULT 0, amount_paise INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'draft', pay_method TEXT, pay_ref TEXT, payer_name TEXT, reject_reason TEXT, ad_id TEXT, created_at INTEGER NOT NULL, submitted_at INTEGER, resolved_at INTEGER, start_at INTEGER, end_at INTEGER)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS ad_pay_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
  try { await db.prepare("SELECT owner_hidden FROM ad_campaigns LIMIT 1").first(); } catch (_) { try { await db.prepare("ALTER TABLE ad_campaigns ADD COLUMN owner_hidden INTEGER NOT NULL DEFAULT 0").run(); } catch (_2) {} }
  try { await db.prepare("SELECT target_impressions, cpm_paise FROM ad_campaigns LIMIT 1").first(); } catch (_) {
    try { await db.prepare("ALTER TABLE ad_campaigns ADD COLUMN target_impressions INTEGER").run(); } catch (_2) {}
    try { await db.prepare("ALTER TABLE ad_campaigns ADD COLUMN cpm_paise INTEGER").run(); } catch (_2) {}
  }
  campReady = true;
}
// Impression-based (CPM) campaigns: the ad row keeps the number of views that were bought. 0 / empty = no limit (admin ads, older day-based campaigns).
let adTargetOk = false;
async function ensureAdTargetCol(db) {
  if (adTargetOk) return true;
  const has = async () => { try { await db.prepare("SELECT target_impressions FROM ads LIMIT 1").first(); return true; } catch (_) { return false; } };
  if (await has()) { adTargetOk = true; return true; }
  try { await db.prepare("ALTER TABLE ads ADD COLUMN target_impressions INTEGER").run(); } catch (_) {}
  adTargetOk = await has();
  return adTargetOk;
}
const CAMP_VIEW_MIN = 1000, CAMP_VIEW_MAX = 1000000;
const CAMP_BANNER_PL = ["home", "watch", "reels"], CAMP_VIDEO_PL = ["preroll", "midroll"];
const CAMP_DAYS = [3, 7, 14, 30];
const CAMP_PRICE_KEYS = ["home", "watch", "reels", "preroll", "midroll"];
async function getCampSettings(db) {
  await ensureCampTables(db);
  const rows = await db.prepare("SELECT k, v FROM ad_pay_settings").all();
  const m = {};
  (rows.results || []).forEach((r) => { m[r.k] = r.v; });
  let prices = {};
  try { prices = JSON.parse(m.prices || "{}"); } catch (_) {}
  const P = {};
  CAMP_PRICE_KEYS.forEach((k) => { const n = Number(prices[k]); P[k] = isFinite(n) && n > 0 && n <= 1000000 ? Math.round(n * 100) / 100 : 0; });
  const s = (k, n) => String(m[k] || "").trim().slice(0, n || 200), usd = Number(m.usd_rate);
  const cpmIn = (k) => { const n = Number(m[k]); return isFinite(n) && n > 0 && n <= 100000 ? Math.round(n * 100) / 100 : 0; };
  const usdR = isFinite(usd) && usd > 0 ? usd : 0, cpmRaw = { banner: cpmIn("cpm_banner"), video: cpmIn("cpm_video") };
  const cpm = { banner: cpmRaw.banner || (usdR ? Math.round(1 * usdR * 100) / 100 : 0), video: cpmRaw.video || (usdR ? Math.round(2.5 * usdR * 100) / 100 : 0) };
  CAMP_BANNER_PL.forEach((k) => { P[k] = cpm.banner; });
  CAMP_VIDEO_PL.forEach((k) => { P[k] = cpm.video; });
  const out = { cpm, cpmRaw, minViews: CAMP_VIEW_MIN, maxViews: CAMP_VIEW_MAX, enabled: m.enabled === "1", upiId: s("upi_id", 80), payee: s("payee", 60), razorpayLink: s("razorpay_link", 300), bankHolder: s("bank_holder", 80), bankAccount: s("bank_account", 40), bankIfsc: s("bank_ifsc", 20), bankName: s("bank_name", 80), intlLink: s("intl_link", 300), intlText: s("intl_text", 600), usdRate: isFinite(usd) && usd > 0 ? usd : 0, prices: P };
  out.methods = { upi: !!out.upiId, razorpay: /^https:\/\//i.test(out.razorpayLink), bank: !!(out.bankAccount && out.bankIfsc), intl: !!(out.intlText || /^https:\/\//i.test(out.intlLink)) };
  out.ready = out.enabled && CAMP_PRICE_KEYS.some((k) => P[k] > 0) && Object.values(out.methods).some(Boolean);
  return out;
}
// ===== Google AdSense (web ads). Off until the admin turns it on and adds the publisher ID from the AdSense account =====
async function getAdsenseCfg(db) {
  try {
    await ensureCampTables(db);
    const rows = await db.prepare("SELECT k, v FROM ad_pay_settings WHERE k LIKE 'adsense_%'").all();
    const m = {};
    (rows.results || []).forEach((r) => { m[r.k] = r.v; });
    const client = /^ca-pub-\d{10,20}$/.test(m.adsense_client || "") ? m.adsense_client : "";
    const slot = (k) => (/^\d{6,20}$/.test(m[k] || "") ? m[k] : "");
    return { switchOn: m.adsense_enabled === "1", enabled: m.adsense_enabled === "1" && !!client, client, slots: { home: slot("adsense_slot_home"), watch: slot("adsense_slot_watch") } };
  } catch (_) { return { switchOn: false, enabled: false, client: "", slots: { home: "", watch: "" } }; }
}
// ===== Muslim Ad Network (MAN): halal display banner ads. Off until the admin turns it on and pastes the banner code MAN gives =====
async function getManCfg(db) {
  const none = { switchOn: false, enabled: false, app: false, home: "", watch: "", heightHome: 100, heightWatch: 100, notes: "" };
  try {
    await ensureCampTables(db);
    const rows = await db.prepare("SELECT k, v FROM ad_pay_settings WHERE k LIKE 'man_%'").all();
    const m = {};
    (rows.results || []).forEach((r) => { m[r.k] = r.v; });
    const h = (k) => { const n = parseInt(m[k], 10); return n >= 30 && n <= 600 ? n : 100; };
    const home = String(m.man_home || ""), watch = String(m.man_watch || "");
    return { switchOn: m.man_enabled === "1", enabled: m.man_enabled === "1" && !!(home.trim() || watch.trim()), app: m.man_app === "1", home, watch, heightHome: h("man_hh"), heightWatch: h("man_hw"), notes: String(m.man_notes || "") };
  } catch (_) { return none; }
}
// ===== Google AdMob (the Android app from the Play Store). The web app calls it through the native shell. Test mode is ON until the admin turns it off =====
async function getAdmobCfg(db) {
  try {
    await ensureCampTables(db);
    const rows = await db.prepare("SELECT k, v FROM ad_pay_settings WHERE k LIKE 'admob_%'").all();
    const m = {};
    (rows.results || []).forEach((r) => { m[r.k] = r.v; });
    const unit = (k) => (/^ca-app-pub-\d{16}\/\d{10}$/.test(m[k] || "") ? m[k] : "");
    const appId = /^ca-app-pub-\d{16}~\d{10}$/.test(m.admob_app_id || "") ? m.admob_app_id : "";
    const num = (k, d, lo, hi) => { const n = parseInt(m[k], 10); return n >= lo && n <= hi ? n : d; };
    const out = { switchOn: m.admob_enabled === "1", test: m.admob_test !== "0", appId, banner: unit("admob_banner"), interstitial: unit("admob_interstitial"), everyVideos: num("admob_every_videos", 3, 1, 20), everyReels: num("admob_every_reels", 7, 2, 50), minGapMin: num("admob_min_gap_min", 4, 1, 60) };
    out.enabled = out.switchOn && (!!out.banner || !!out.interstitial || out.test);
    return out;
  } catch (_) { return { switchOn: false, enabled: false, test: true, appId: "", banner: "", interstitial: "", everyVideos: 3, everyReels: 7, minGapMin: 4 }; }
}
const campRef = () => "NTC" + Array.from(crypto.getRandomValues(new Uint8Array(8))).map((x) => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[x % 32]).join("");
function campOut(c) {
  const now = Date.now();
  let status = c.status;
  if (status === "live" && c.end_at && now > c.end_at) status = "ended";
  const target = c.target_impressions || 0;
  if (target > 0 && status === "ended" && (c.impressions || 0) >= target) status = "completed";
  return { id: c.id, ref: c.ref, name: c.name, type: c.type, mediaUrl: c.media_url, clickUrl: c.click_url || "", placements: String(c.placements || "").split(",").filter(Boolean), days: c.days, midAfter: c.mid_after || 30, skip: !!c.skip, amountPaise: c.amount_paise,
    status, payMethod: c.pay_method || "", payRef: c.pay_ref || "", payerName: c.payer_name || "", rejectReason: c.reject_reason || "", createdAt: c.created_at, submittedAt: c.submitted_at || null, resolvedAt: c.resolved_at || null, startAt: c.start_at || null, endAt: c.end_at || null,
    impressions: c.impressions || 0, clicks: c.clicks || 0, targetImpressions: target, cpmPaise: c.cpm_paise || 0 };
}
const CAMP_SELECT = "SELECT c.*, a.impressions AS impressions, a.clicks AS clicks FROM ad_campaigns c LEFT JOIN ads a ON a.id = c.ad_id ";

// ===== Duplicate scan (shared by the admin button and the hourly auto-scan) =====
async function runDuplicateScan(db, env, apply) {
      // 1) read the storage checksum of older uploads that do not have one yet (small batches, repeat the scan until "remaining" is 0)
      let scanned = 0;
      const todo = [];
      const vOld = await db.prepare("SELECT id, file_url FROM videos WHERE file_etag IS NULL AND file_url IS NOT NULL AND file_url != '' LIMIT 15").all();
      (vOld.results || []).forEach((r) => todo.push({ t: "videos", id: r.id, url: r.file_url }));
      const rOld = await db.prepare("SELECT id, file_url FROM reels WHERE file_etag IS NULL AND file_url IS NOT NULL AND file_url != '' LIMIT 15").all();
      (rOld.results || []).forEach((r) => todo.push({ t: "reels", id: r.id, url: r.file_url }));
      for (const it of todo) {
        const et = await storedFileEtag(env, it.url);
        await db.prepare("UPDATE " + it.t + " SET file_etag = ? WHERE id = ?").bind(et || "-", it.id).run();
        scanned++;
      }
      const remV = await db.prepare("SELECT COUNT(*) AS n FROM videos WHERE file_etag IS NULL AND file_url IS NOT NULL AND file_url != ''").first();
      const remR = await db.prepare("SELECT COUNT(*) AS n FROM reels WHERE file_etag IS NULL AND file_url IS NOT NULL AND file_url != ''").first();
      const remaining = ((remV && remV.n) || 0) + ((remR && remR.n) || 0);
      // 2) group everything that shares a checksum or fingerprint
      const all = await db.prepare(
        "SELECT kind, id, owner_id, title, file_etag, fingerprint, uploaded_at, removed, hidden, name, dup_of FROM (" +
        "SELECT 'v' AS kind, videos.id AS id, videos.owner_id AS owner_id, videos.title AS title, videos.file_etag AS file_etag, videos.fingerprint AS fingerprint, videos.uploaded_at AS uploaded_at, videos.removed AS removed, videos.hidden AS hidden, users.name AS name, videos.dup_of AS dup_of FROM videos JOIN users ON users.id = videos.owner_id " +
        "UNION ALL " +
        "SELECT 'r', reels.id, reels.owner_id, reels.title, reels.file_etag, reels.fingerprint, reels.uploaded_at, 0, reels.hidden, users.name, reels.dup_of FROM reels JOIN users ON users.id = reels.owner_id" +
        ") WHERE (file_etag IS NOT NULL AND file_etag NOT IN ('-', '')) OR fingerprint IS NOT NULL ORDER BY uploaded_at ASC, id ASC LIMIT 5000"
      ).all();
      const rows = all.results || [];
      const found = {}; // id -> { row, original }
      for (const keyName of ["file_etag", "fingerprint"]) {
        const groups = {};
        rows.forEach((r) => { const k = r[keyName]; if (k && k !== "-") (groups[k] = groups[k] || []).push(r); });
        Object.values(groups).forEach((g) => {
          if (g.length < 2) return;
          const orig = g.find((r) => !r.dup_of) || g[0]; // the oldest upload that is not itself a claimed copy is the original
          g.filter((r) => r !== orig).forEach((r) => { if (r.owner_id !== orig.owner_id && !r.removed && !r.hidden && !found[r.kind + r.id]) found[r.kind + r.id] = { row: r, original: orig }; });
        });
      }
      const list = Object.values(found).map((f) => ({ kind: f.row.kind === "v" ? "video" : "reel", id: f.row.id, title: f.row.title, owner: f.row.name, ownerId: f.row.owner_id, originalTitle: f.original.title, originalOwner: f.original.name, originalId: f.original.id }));
      let removedCount = 0;
      if (apply) {
        for (const f of list) {
          if (f.kind === "video") await db.prepare("UPDATE videos SET removed = 1, monetized = 0, copyright_status = 'claimed', dup_of = ? WHERE id = ?").bind(f.originalId, f.id).run();
          else await db.prepare("UPDATE reels SET hidden = 1, dup_of = ? WHERE id = ?").bind(f.originalId, f.id).run();
          try { await addNotification(db, f.ownerId, "copyright", "Duplicate content — " + (f.kind === "video" ? "Video" : "Reel") + " Removed", `Your ${f.kind} "${f.title}" is duplicate content: the same file was already uploaded by another channel ("${f.originalOwner}"), so it was removed automatically.`); } catch (_) {}
          removedCount++;
        }
      }
      return { ok: true, scannedNow: scanned, remaining, duplicates: list, removed: removedCount, applied: apply };
}
// ===== Video ad networks (VAST tags, e.g. Muslim Ad Network). Admin pastes tag links; the app plays them only when no own ad is available. Default: all OFF. =====
let _vastMem = null;
function cleanVastCfg(b) {
  b = b || {};
  const tags = (Array.isArray(b.tags) ? b.tags : []).map((t) => String(t || "").trim()).filter(Boolean).slice(0, 3);
  for (const t of tags) if (!/^https:\/\/[^\s<>"']{4,1990}$/i.test(t)) return { error: "Each ad tag must be a full link starting with https:// (no spaces)." };
  const midAfter = Math.round(Number(b.midAfter === undefined ? 30 : b.midAfter)), gapSec = Math.round(Number(b.gapSec === undefined ? 180 : b.gapSec));
  if (!(midAfter >= 10 && midAfter <= 600)) return { error: "Middle-of-video ad time must be 10 to 600 seconds." };
  if (!(gapSec >= 0 && gapSec <= 3600)) return { error: "Gap between network ads must be 0 to 3600 seconds." };
  return { cfg: { pre: b.pre === true, mid: b.mid === true, native: b.native === true, midAfter, gapSec, tags } };
}
async function getVastCfg(db) {
  if (_vastMem && Date.now() - _vastMem.t < 30000) return _vastMem.cfg;
  let cfg = { pre: false, mid: false, native: false, midAfter: 30, gapSec: 180, tags: [] };
  try {
    await ensureAutoToolsTable(db);
    const r = await db.prepare("SELECT v FROM auto_tools WHERE k = 'vast_cfg'").first();
    if (r) { const c = cleanVastCfg(JSON.parse(r.v)); if (c.cfg) cfg = c.cfg; }
  } catch (_) {}
  _vastMem = { t: Date.now(), cfg };
  return cfg;
}
// ===== Reels: show one full-screen ad after every N reels (admin sets N, default 7) =====
async function getReelAdEvery(db) {
  try {
    await ensureAutoToolsTable(db);
    const r = await db.prepare("SELECT v FROM auto_tools WHERE k = 'reel_ad_every'").first();
    const n = r ? parseInt(r.v, 10) : 7;
    return n >= 1 && n <= 50 ? n : 7;
  } catch (_) { return 7; }
}
// ===== Hourly auto-scan switch (default OFF; the admin turns it on in Tools) =====
async function ensureAutoToolsTable(db) {
  await db.prepare("CREATE TABLE IF NOT EXISTS auto_tools (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
}
async function getAutoTools(db) {
  await ensureAutoToolsTable(db);
  const rows = await db.prepare("SELECT k, v FROM auto_tools").all();
  const o = {}; (rows.results || []).forEach((r) => { o[r.k] = r.v; });
  return { enabled: o.dup_auto === "1", lastRun: Number(o.dup_last_run || 0), lastRemoved: Number(o.dup_last_removed || 0), lastError: o.dup_last_error || "" };
}
async function setAutoTool(db, k, v) {
  await db.prepare("INSERT INTO auto_tools (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, String(v)).run();
}
async function autoDuplicateScan(env) {
  const db = env.NOOR_DB;
  try {
    const st = await getAutoTools(db);
    if (!st.enabled) return;
    if (!(await ensureCopyrightColumns(db))) throw new Error("copyright columns missing");
    for (let i = 0; i < 10; i++) {
      const r = await runDuplicateScan(db, env, false);
      if (!(r.remaining > 0)) break;
    }
    const fin = await runDuplicateScan(db, env, true);
    await setAutoTool(db, "dup_last_run", Date.now());
    await setAutoTool(db, "dup_last_removed", fin.removed || 0);
    await setAutoTool(db, "dup_last_error", "");
  } catch (e) {
    try { await setAutoTool(db, "dup_last_run", Date.now()); await setAutoTool(db, "dup_last_error", String(e && e.message ? e.message : e).slice(0, 200)); } catch (_) {}
  }
}

const WORKER = {
  async fetch(request, env, ctx) {
    try { _pushEnv = env; _ctx = ctx || null; _origin = new URL(request.url).origin; } catch (_) {}
    const res = await WORKER.main(request, env);
    try {
      const m = request.method, p = new URL(request.url).pathname;
      if (m !== "GET" && m !== "HEAD" && m !== "OPTIONS" && res.status < 400 && (/^\/api\/(videos|reels)(\/[^/]+)?$/.test(p) || p.startsWith("/api/admin/"))) purgeFeedCache(new URL(request.url).origin);
      const mutating = m !== "GET" && m !== "HEAD" && m !== "OPTIONS";
      const adminPath = p.startsWith("/api/admin/") || /^\/api\/(videos|reels)\/[^/]+$/.test(p);
      if (mutating && adminPath && res.status < 400) {
        const u = await currentUser(request, env);
        if (u && u.role === "admin") {
          const db = env.NOOR_DB;
          await ensurePlatformTables(db);
          await db.prepare("INSERT INTO audit_log (id, ts, admin_id, admin_name, action, method, path) VALUES (?,?,?,?,?,?,?)").bind(uid("au"), Date.now(), u.id, u.name || "Admin", auditLabel(m, p), m, p).run();
        }
      }
    } catch (_) {}
    return res;
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(autoDuplicateScan(env));
  },
  async main(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return new Response(JSON.stringify({ error: "Server error: " + (e && e.message ? e.message : String(e)) }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...cors() },
      });
    }
  },
};
export default WORKER;

// ================= SECURITY LAYER =================
// 1) Server-side secrets: use the Cloudflare secret if you set one (UPLOAD_SECRET / VIEW_SECRET); otherwise a random
//    secret is created once and kept in the database, so protection is ON even if nothing was configured.
const _secretCache = {};
async function getAppSecret(env, name) {
  const direct = name === "upload" ? env.UPLOAD_SECRET : name === "view" ? env.VIEW_SECRET : null;
  if (direct) return String(direct);
  if (_secretCache[name]) return _secretCache[name];
  const db = env.NOOR_DB;
  await db.prepare("CREATE TABLE IF NOT EXISTS app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)").run();
  let row = await db.prepare("SELECT value FROM app_secrets WHERE name = ?").bind(name).first();
  if (!row) {
    await db.prepare("INSERT OR IGNORE INTO app_secrets (name, value) VALUES (?, ?)").bind(name, toB64Url(crypto.getRandomValues(new Uint8Array(32)))).run();
    row = await db.prepare("SELECT value FROM app_secrets WHERE name = ?").bind(name).first();
  }
  return (_secretCache[name] = row.value);
}
async function hmacB64Url(secret, msg) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toB64Url(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
function safeEq(a, b) { // constant-time string compare
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function b64uEnc(str) { return toB64Url(new TextEncoder().encode(str)); }
function b64uDec(str) {
  let t = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return new TextDecoder().decode(Uint8Array.from(atob(t), (c) => c.charCodeAt(0)));
}
// IPs are never stored in plain text: only a keyed hash is kept.
async function ipKey(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return (await hmacB64Url(await getAppSecret(env, "view"), "ip:" + ip)).slice(0, 22);
}

// 2) Sign-up limit: stops people from mass-creating fake accounts from one network.
const SIGNUP_MAX_PER_IP_HOUR = 10;
let signupTableReady = false;
async function ensureSignupTable(db) {
  if (signupTableReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS signup_log (ip TEXT NOT NULL, ts INTEGER NOT NULL)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_signup_log ON signup_log (ip, ts)").run();
  signupTableReady = true;
}
async function signupBlocked(db, env, request) { // fails open: if anything errors, sign-up keeps working
  try {
    await ensureSignupTable(db);
    const r = await db.prepare("SELECT COUNT(*) AS n FROM signup_log WHERE ip = ? AND ts > ?").bind(await ipKey(request, env), Date.now() - 3600 * 1000).first();
    return !!r && r.n >= SIGNUP_MAX_PER_IP_HOUR;
  } catch (_) { return false; }
}
async function recordSignup(db, env, request) {
  try {
    await ensureSignupTable(db);
    await db.prepare("INSERT INTO signup_log (ip, ts) VALUES (?, ?)").bind(await ipKey(request, env), Date.now()).run();
    if (Math.random() < 0.02) await db.prepare("DELETE FROM signup_log WHERE ts < ?").bind(Date.now() - 24 * 3600 * 1000).run();
  } catch (_) {}
}

// 3) VERIFIED VIEWS. A view only counts when ALL of these are true:
//    - the player first asked the server for a signed "view ticket" when playback started,
//    - enough real time passed since that ticket was issued (the same watch rule as the app: videos 40s/60s, reels 5s/10s),
//    - this viewer has not already got a counted view on this content in the last 24 hours,
//    - this viewer / this network is not over the hourly limit,
//    - the content is visible. The creator's own view of their own content counts exactly ONCE, ever (never again, however long they keep watching).
//    The ticket is signed, so it cannot be forged, edited, or reused for another video, reel or person.
const VIEW_RULE = { v: { base: 40, longBase: 45, longFrom: 300 }, r: { base: 5, longBase: 10, longFrom: 30 } };
const VIEW_TOKEN_TTL_MS = 12 * 3600 * 1000;
const VIEW_COOLDOWN_MS = 24 * 3600 * 1000;       // one counted view per viewer per content per 24h
const VIEW_CAP_VIEWER_HOUR = { v: 60, r: 300 };  // counted views one viewer can make per hour
const VIEW_CAP_IP_HOUR = { v: 240, r: 1200 };    // counted views one network (IP) can make per hour
const VIEW_MAX_SPEED = 2;                        // fastest normal playback speed (2x)
const COUNT_OWNER_VIEWS = true;                  // a creator watching their own content gets ONE view in total (see OWNER marker below)
let viewTablesReady = false;
async function ensureViewTables(db) {
  if (viewTablesReady) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS view_log (id TEXT PRIMARY KEY, kind TEXT NOT NULL, content_id TEXT NOT NULL, viewer TEXT NOT NULL, ip TEXT NOT NULL, ts INTEGER NOT NULL)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vl_content ON view_log (kind, content_id, viewer, ts)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vl_viewer ON view_log (viewer, kind, ts)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vl_ip ON view_log (ip, kind, ts)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vl_ts ON view_log (ts)").run();
  // Daily counted views per video/reel (kept long term, view_log itself is trimmed after 2 days). Day = India time (IST).
  await db.prepare("CREATE TABLE IF NOT EXISTS view_daily (kind TEXT NOT NULL, content_id TEXT NOT NULL, owner_id TEXT NOT NULL, day TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, content_id, day))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_vd_owner ON view_daily (owner_id, day)").run();
  viewTablesReady = true;
}
function parseDurSec(d) {
  if (typeof d === "number") return d > 0 && isFinite(d) ? d : null;
  const t = String(d == null ? "" : d).trim();
  if (!/^\d{1,5}(:\d{1,2}){0,2}$/.test(t)) return null;
  const sec = t.split(":").map(Number).reduce((m, v) => m * 60 + v, 0);
  return sec > 0 ? sec : null;
}
function viewNeedSec(kind, durSec) {
  const R = VIEW_RULE[kind] || VIEW_RULE.v, ok = typeof durSec === "number" && durSec > 0;
  const base = ok && durSec >= R.longFrom ? R.longBase : R.base;
  return ok ? Math.min(base, durSec * 0.8) : base;
}
async function viewWho(request, env) {
  const u = await currentUser(request, env);
  const iph = await ipKey(request, env);
  const anon = (request.headers.get("X-Anon-Id") || "").trim();
  const ident = u ? "u:" + u.id : (anon.length >= 8 && anon.length <= 128 ? "a:" + anon : "x");
  return { u, iph, ident, viewer: u ? "u:" + u.id : "i:" + iph };
}
async function makeViewToken(env, payload) {
  const body = b64uEnc(JSON.stringify(payload));
  return body + "." + (await hmacB64Url(await getAppSecret(env, "view"), body));
}
async function readViewToken(env, tok) {
  if (typeof tok !== "string" || tok.length > 700 || tok.indexOf(".") < 1) return null;
  const [body, sig] = tok.split(".");
  if (!body || !sig) return null;
  if (!safeEq(sig, await hmacB64Url(await getAppSecret(env, "view"), body))) return null;
  try { const p = JSON.parse(b64uDec(body)); return p && typeof p === "object" ? p : null; } catch (_) { return null; }
}
async function handleViewRoute(kind, id, step, request, env, db) {
  const table = kind === "v" ? "videos" : "reels";
  const row = await db.prepare("SELECT * FROM " + table + " WHERE id = ?").bind(id).first();
  if (step === "start") { // playback started: hand out a signed ticket (never breaks playback)
    try {
      if (!row || row.removed || row.hidden) return json({ ok: true, token: null });
      const w = await viewWho(request, env);
      return json({ ok: true, token: await makeViewToken(env, { k: kind, c: id, w: w.ident, t: Date.now(), n: crypto.randomUUID().slice(0, 8) }) });
    } catch (_) { return json({ ok: true, token: null }); }
  }
  // step === "count": the player says the watch rule was met. The server re-checks everything.
  const out = (counted, reason) => json({ ok: true, counted, reason, views: row ? row.views + (counted ? 1 : 0) : null });
  if (!row) return err("Not found", 404);
  if (row.removed || row.hidden) return out(false, "hidden");
  const body = await request.json().catch(() => ({}));
  const w = await viewWho(request, env);
  const tk = await readViewToken(env, body && body.token);
  if (!tk || tk.k !== kind || tk.c !== id || tk.w !== w.ident) return out(false, "no_ticket");
  const now = Date.now(), age = now - Number(tk.t);
  if (!(age >= 0) || age > VIEW_TOKEN_TTL_MS) return out(false, "expired");
  let dur = kind === "v" ? parseDurSec(row.duration) : (row.trim_end > 0 ? row.trim_end - (row.trim_start || 0) : null);
  const need = viewNeedSec(kind, dur);
  const minElapsedMs = Math.max(kind === "v" ? 5000 : 2000, (need / VIEW_MAX_SPEED) * 0.9 * 1000);
  if (age < minElapsedMs) return out(false, "too_fast");
  if (kind === "v" && w.u) { // keep the old "watch history" behaviour for signed-in users
    try { await db.prepare("INSERT OR REPLACE INTO watch_history (user_id, video_id, watched_at) VALUES (?, ?, datetime('now'))").bind(w.u.id, id).run(); } catch (_) {}
  }
  const isOwner = !!(w.u && w.u.id === row.owner_id);
  if (isOwner && !COUNT_OWNER_VIEWS) return out(false, "owner");
  // Owner: the "already counted" window is unlimited (ts > 0 matches every old row) and the log row is marked ip = 'owner' so the cleanup below never deletes it.
  const coolFrom = isOwner ? 0 : now - VIEW_COOLDOWN_MS, logIp = isOwner ? "owner" : w.iph;
  await ensureViewTables(db);
  const vid = uid("vw");
  // One batch = one transaction: the log row is only written if every limit passes, and the counter only moves if that row exists.
  const res = await db.batch([
    db.prepare("INSERT INTO view_log (id, kind, content_id, viewer, ip, ts) SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM view_log WHERE kind = ? AND content_id = ? AND viewer = ? AND ts > ?) AND (SELECT COUNT(*) FROM view_log WHERE viewer = ? AND kind = ? AND ts > ?) < ? AND (SELECT COUNT(*) FROM view_log WHERE ip = ? AND kind = ? AND ts > ?) < ?")
      .bind(vid, kind, id, w.viewer, logIp, now, kind, id, w.viewer, coolFrom, w.viewer, kind, now - 3600000, VIEW_CAP_VIEWER_HOUR[kind], w.iph, kind, now - 3600000, VIEW_CAP_IP_HOUR[kind]),
    db.prepare("UPDATE " + table + " SET views = views + 1 WHERE id = ? AND EXISTS (SELECT 1 FROM view_log WHERE id = ?)").bind(id, vid),
  ]);
  const counted = !!(res && res[1] && res[1].meta && res[1].meta.changes === 1);
  if (counted) {
    try { await db.prepare("INSERT INTO view_daily (kind, content_id, owner_id, day, views) VALUES (?, ?, ?, ?, 1) ON CONFLICT(kind, content_id, day) DO UPDATE SET views = views + 1").bind(kind, id, row.owner_id, istDay(now)).run(); } catch (_) {}
  }
  if (Math.random() < 0.02) { try { await db.prepare("DELETE FROM view_log WHERE ts < ? AND ip != 'owner'").bind(now - 2 * VIEW_COOLDOWN_MS).run(); } catch (_) {} }
  return out(counted, counted ? "counted" : "limit");
}
// ================= END SECURITY LAYER =================

// ================= COPYRIGHT / DUPLICATE CONTENT =================
// Every uploaded video or reel can carry two "fingerprints":
//  - fingerprint : SHA-256 of the ORIGINAL file, calculated by the app before upload (works even if the file is renamed or re-compressed on upload)
//  - file_etag   : the storage's own checksum of the stored file, read by the SERVER (cannot be faked by the uploader)
// If another creator already has content with the same fingerprint, the new upload is a copy.
// Self-migrating: if the extra columns can not be created for any reason, this feature switches itself off and uploads work as before.
let copyrightColsReady = null;
async function ensureCopyrightColumns(db) {
  if (copyrightColsReady !== null) return copyrightColsReady;
  try {
    for (const t of ["videos", "reels"]) {
      for (const c of ["fingerprint", "file_etag", "dup_of"]) {
        try { await db.prepare("ALTER TABLE " + t + " ADD COLUMN " + c + " TEXT").run(); } catch (_) { /* already exists */ }
      }
      await db.prepare("SELECT fingerprint, file_etag, dup_of FROM " + t + " LIMIT 1").first();
      try { await db.prepare("CREATE INDEX IF NOT EXISTS idx_" + t + "_fp ON " + t + " (fingerprint)").run(); } catch (_) {}
      try { await db.prepare("CREATE INDEX IF NOT EXISTS idx_" + t + "_etag ON " + t + " (file_etag)").run(); } catch (_) {}
    }
    copyrightColsReady = true;
  } catch (_) { copyrightColsReady = false; }
  return copyrightColsReady;
}
function cleanFingerprint(x) { return typeof x === "string" && /^fp[fs]_[0-9a-f]{64}$/.test(x) ? x : null; }
const MIN_ETAG_BYTES = 100 * 1024; // tiny files are never compared by checksum
async function storedFileEtag(env, fileUrl) {
  try {
    const m = /\/file\/([^?#]+)$/.exec(String(fileUrl || ""));
    if (!m || !env.NOOR_BUCKET) return null;
    const h = await env.NOOR_BUCKET.head(decodeURIComponent(m[1]));
    return h && h.etag && h.size >= MIN_ETAG_BYTES ? String(h.etag) : null;
  } catch (_) { return null; }
}
// Returns { ownerName } if ANOTHER creator already has the same file as a video or a reel, otherwise null. Never throws.
async function findDuplicateOwner(db, { fingerprint, etag, legacyHash, ownerId }) {
  try {
    const run = async (table, cols) => {
      const conds = [], binds = [];
      if (fingerprint) { conds.push(table + ".fingerprint = ?"); binds.push(fingerprint); }
      if (etag) { conds.push(table + ".file_etag = ?"); binds.push(etag); }
      if (cols.legacy && legacyHash) { conds.push(table + ".content_hash = ?"); binds.push(legacyHash); }
      if (!conds.length) return null;
      // only compare with ORIGINAL uploads: copies that were already claimed never count as "the original"
      const notCopy = table + ".dup_of IS NULL" + (cols.legacy ? " AND (" + table + ".copyright_status IS NULL OR " + table + ".copyright_status != 'claimed')" : "");
      return await db.prepare("SELECT users.name AS owner_name, " + table + ".id AS dup_id FROM " + table + " JOIN users ON users.id = " + table + ".owner_id WHERE " + table + ".owner_id != ? AND " + notCopy + " AND (" + conds.join(" OR ") + ") LIMIT 1").bind(ownerId, ...binds).first();
    };
    const a = await run("videos", { legacy: true });
    if (a) return { ownerName: a.owner_name, id: a.dup_id };
    const b = await run("reels", { legacy: false });
    return b ? { ownerName: b.owner_name, id: b.dup_id } : null;
  } catch (_) { return null; }
}
async function applyCopyrightStrike(db, u, what, title, dupOwnerName) {
  const newStrikes = (u.strikes || 0) + 1, suspended = newStrikes >= 3;
  await db.prepare("UPDATE users SET strikes = ?, suspended = ?, monetization_enabled = CASE WHEN ? = 1 THEN 0 ELSE monetization_enabled END WHERE id = ?")
    .bind(newStrikes, suspended ? 1 : 0, suspended ? 1 : 0, u.id).run();
  await addNotification(db, u.id, "copyright", "Copyright Claim — " + what + " Removed",
    `Your ${what.toLowerCase()} "${title}" was already uploaded by another channel${dupOwnerName ? ` ("${dupOwnerName}")` : ""}. It has been automatically removed and you received a copyright strike (${newStrikes}/3).${suspended ? " Your account has been permanently suspended." : ""}`);
  return suspended;
}
// ================= END COPYRIGHT =================

// The feedback table was created without the columns an admin reply needs; add them once, automatically.
let feedbackColsReady = false;
async function ensureFeedbackColumns(db) {
  if (feedbackColsReady) return;
  for (const c of ["reply", "replied_at"]) {
    try { await db.prepare("ALTER TABLE feedback ADD COLUMN " + c + " TEXT").run(); } catch (_) { /* column already exists */ }
  }
  await db.prepare("SELECT reply, replied_at FROM feedback LIMIT 1").first(); // throws if the columns still do not exist
  feedbackColsReady = true;
}

async function handleRequest(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (method === "OPTIONS") return new Response(null, { headers: cors() });

    // ---------- UPLOAD AUTHORIZATION ----------
    // Signed-in users request a short-lived, single-file token here. The raw
    // UPLOAD_SECRET stays on the server and is never sent to the browser.
    if (method === "POST" && path === "/api/upload-token") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.suspended) return err("Your account is suspended. Uploads are not allowed.", 403);
      const body = await request.json().catch(() => ({}));
      const rawName = (body.filename || "upload").toString().replace(/[^a-zA-Z0-9._-]/g, "_").slice(-150);
      const key = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}_${rawName}`;
      const expiry = Date.now() + 20 * 60 * 1000; // 20 minutes to complete the upload
      const uploadUrl = `${url.origin}/upload/${encodeURIComponent(key)}`;
      const upSecret = await getAppSecret(env, "upload"); // always on, even if UPLOAD_SECRET was never configured
      const token = await signUploadToken(key, expiry, upSecret);
      return json({ key, uploadUrl, token, expiry });
    }

    // ---------- R2 FILE STORAGE (unchanged from Phase 0) ----------
    if (method === "PUT" && path.startsWith("/upload/")) {
      const key = decodeURIComponent(path.replace("/upload/", ""));
      if (!key) return err("Missing filename", 400);
      { // uploads ALWAYS need a valid signed ticket (nobody can write to storage without signing in first)
        const token = request.headers.get("X-Upload-Token");
        const expiry = Number(request.headers.get("X-Upload-Expiry") || 0);
        if (!token || !expiry) return err("Unauthorized", 401);
        if (expiry < Date.now()) return err("Upload authorization expired", 401);
        const expected = await signUploadToken(key, expiry, await getAppSecret(env, "upload"));
        if (!safeEq(token, expected)) return err("Unauthorized", 401);
      }
      const upType = pickUploadType(request.headers.get("Content-Type"), key);
      if (!upType) return err("Only video and image files can be uploaded", 415);
      const declaredSize = Number(request.headers.get("Content-Length") || 0);
      if (declaredSize > MAX_UPLOAD_BYTES) return err("File is too large (max 200 MB)", 413);
      await env.NOOR_BUCKET.put(key, request.body, { httpMetadata: { contentType: upType } });
      if (!declaredSize) { // size was not announced: verify after the fact and remove if too big
        const stored = await env.NOOR_BUCKET.head(key);
        if (stored && stored.size > MAX_UPLOAD_BYTES) { await env.NOOR_BUCKET.delete(key); return err("File is too large (max 200 MB)", 413); }
      }
      return json({ ok: true, key, url: `${url.origin}/file/${encodeURIComponent(key)}` });
    }
    const thumbM = method === "GET" ? path.match(/^\/thumb\/(v|r)\/([^/]+)$/) : null;
    if (thumbM) {
      const tmKey = thumbM[1] + "/" + thumbM[2] + "?" + (url.searchParams.get("v") || ""), tmHit = _thumbMem.get(tmKey);
      if (tmHit) return new Response(tmHit.bytes, { headers: { ...cors(), "Content-Type": tmHit.type, "Cache-Control": "public, max-age=31536000, immutable" } });
      let edgeKey = null;
      try { edgeKey = new Request(url.origin + path + "?v=" + (url.searchParams.get("v") || "")); const hit = await caches.default.match(edgeKey); if (hit) return hit; } catch (_) {}
      let row = null;
      try { row = await env.NOOR_DB.prepare("SELECT thumbnail FROM " + (thumbM[1] === "v" ? "videos" : "reels") + " WHERE id = ?").bind(decodeURIComponent(thumbM[2])).first(); } catch (_) {}
      const t = row && row.thumbnail, mm = typeof t === "string" ? t.match(/^data:(image\/(?:jpeg|png|webp|gif));base64,/) : null;
      if (!mm) return err("Not found", 404);
      let bytes;
      try { const bin = atob(t.slice(mm[0].length)); bytes = new Uint8Array(bin.length); for (let k = 0; k < bin.length; k++) bytes[k] = bin.charCodeAt(k); } catch (_) { return err("Not found", 404); }
      _thumbMem.set(tmKey, { bytes, type: mm[1] });
      if (_thumbMem.size > 80) _thumbMem.delete(_thumbMem.keys().next().value);
      const out = new Response(bytes, { headers: { ...cors(), "Content-Type": mm[1], "Cache-Control": "public, max-age=31536000, immutable" } });
      if (edgeKey) bg(caches.default.put(edgeKey, out.clone()).catch(() => {}));
      return out;
    }
    if (method === "HEAD" && path.startsWith("/file/")) {
      const key = decodeURIComponent(path.replace("/file/", ""));
      const head = await env.NOOR_BUCKET.head(key);
      if (!head) return err("Not found", 404);
      const headers = new Headers(cors());
      head.writeHttpMetadata(headers);
      headers.set("etag", head.httpEtag);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      headers.set("Accept-Ranges", "bytes");
      headers.set("Content-Length", String(head.size));
      return new Response(null, { headers });
    }
    if (method === "GET" && path.startsWith("/file/")) {
      const key = decodeURIComponent(path.replace("/file/", ""));
      const rangeHeader = request.headers.get("Range");
      if (!rangeHeader) {
        const obj = await env.NOOR_BUCKET.get(key);
        if (!obj) return err("Not found", 404);
        const headers = new Headers(cors());
        obj.writeHttpMetadata(headers);
        headers.set("etag", obj.httpEtag);
        headers.set("Cache-Control", "public, max-age=31536000, immutable");
        headers.set("Accept-Ranges", "bytes");
        headers.set("Content-Length", String(obj.size));
        return new Response(obj.body, { headers });
      }
      // A Range header is present (this is how browsers stream/seek video) -
      // look up the object's size first so we can resolve open-ended and
      // suffix ranges, then serve only the requested byte window as 206.
      const head = await env.NOOR_BUCKET.head(key);
      if (!head) return err("Not found", 404);
      const parsed = parseRangeHeader(rangeHeader, head.size);
      if (!parsed) {
        const headers = new Headers(cors());
        headers.set("Content-Range", `bytes */${head.size}`);
        return new Response(null, { status: 416, headers });
      }
      const { start, end } = parsed;
      const obj = await env.NOOR_BUCKET.get(key, { range: { offset: start, length: end - start + 1 } });
      if (!obj) return err("Not found", 404);
      const headers = new Headers(cors());
      obj.writeHttpMetadata(headers);
      headers.set("etag", obj.httpEtag);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      headers.set("Accept-Ranges", "bytes");
      headers.set("Content-Range", `bytes ${start}-${end}/${head.size}`);
      headers.set("Content-Length", String(end - start + 1));
      return new Response(obj.body, { status: 206, headers });
    }
    if (method === "DELETE" && path.startsWith("/file/")) {
      // deleting stored files is admin-only through the server secret; the app itself never needs this route
      if (!env.UPLOAD_SECRET || !safeEq(request.headers.get("X-Upload-Secret") || "", String(env.UPLOAD_SECRET))) return err("Unauthorized", 401);
      const key = decodeURIComponent(path.replace("/file/", ""));
      await env.NOOR_BUCKET.delete(key);
      return json({ ok: true });
    }

    const db = env.NOOR_DB;
    if (!db) return err("Database not configured", 500);

    // ---------- AUTH ----------
    if (method === "POST" && path === "/api/register") {
      const body = await request.json().catch(() => ({}));
      const { name, email, password } = body;
      if (!name || !email || !password) return err("name, email and password are required");
      if (typeof name !== "string" || typeof email !== "string" || typeof password !== "string") return err("Invalid input");
      if (name.trim().length < 1 || name.length > 60) return err("Name must be 1-60 characters");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) return err("Enter a valid email address");
      if (password.length < 6 || password.length > 200) return err("Password must be at least 6 characters");
      if (await signupBlocked(db, env, request)) return err("Too many accounts were created from this network recently. Please try again later.", 429);
      const existing = await db.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
      if (existing) return err("An account with this email already exists");
      const { hash, salt } = await hashPassword(password);
      const id = uid("u");
      await db.prepare("INSERT INTO users (id, name, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)")
        .bind(id, name, email.toLowerCase(), hash, salt).run();
      await recordSignup(db, env, request);
      const token = crypto.randomUUID();
      await createSession(db, token, id);
      const user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
      return json({ ok: true, token, user: publicUser(user, true) });
    }
    if (method === "POST" && path === "/api/login") {
      const { email, password } = await request.json().catch(() => ({}));
      if (!email || !password) return err("email and password are required");
      if (typeof email !== "string" || typeof password !== "string") return err("Invalid input");
      const loginIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const loginEmail = email.toLowerCase().slice(0, 254);
      if (await loginBlocked(db, loginIp, loginEmail)) return err("Too many failed attempts. Please try again in 10 minutes.", 429);
      const user = await db.prepare("SELECT * FROM users WHERE email = ?").bind(loginEmail).first();
      if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) {
        await recordLoginFailure(db, loginIp, loginEmail);
        return err("Invalid email or password", 401);
      }
      const token = crypto.randomUUID();
      await createSession(db, token, user.id);
      return json({ ok: true, token, user: publicUser(user, true) });
    }
    if (method === "POST" && path === "/api/logout") {
      const auth = request.headers.get("Authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
      return json({ ok: true });
    }
    // ----- Forgot password: send 6-digit code to email (same mail stack as verification) -----
    if (method === "POST" && path === "/api/auth/forgot-password") {
      const b = await request.json().catch(() => ({}));
      const email = String((b && b.email) || "").toLowerCase().trim().slice(0, 254);
      const okMsg = { ok: true, message: "If an account exists for that email, a reset code has been sent. Check your inbox." };
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json(okMsg);
      if (!mailConfigured(env)) return err("Password reset is not set up yet. Contact support at noortube09@gmail.com.", 503);
      try { await ensurePasswordReset(db); } catch (_) { return err("Password reset is temporarily unavailable. Try again later.", 503); }
      const user = await db.prepare("SELECT id, name, email, role FROM users WHERE email = ?").bind(email).first();
      if (!user || user.role === "guest") return json(okMsg);
      const now = Date.now();
      const cur = await db.prepare("SELECT sent_at, hour_start, hour_count FROM password_resets WHERE email = ?").bind(email).first();
      let hourStart = now, hourCount = 1;
      if (cur) {
        if (now - cur.sent_at < 60000) return err("Please wait a minute before requesting another code.", 429);
        if (now - cur.hour_start < 3600000) {
          hourStart = cur.hour_start; hourCount = (cur.hour_count || 0) + 1;
          if (hourCount > 5) return err("Too many reset requests. Please try again in an hour.", 429);
        }
      }
      const buf = new Uint32Array(1); crypto.getRandomValues(buf);
      const code = String(buf[0] % 1000000).padStart(6, "0");
      const sent = await sendMail(env, email, "NoorTube password reset code: " + code,
        "<div style=\"font-family:Arial,sans-serif;font-size:15px;color:#111\"><p>Assalamu alaikum " + String(user.name || "").replace(/[<>&\"]/g, "") + ",</p><p>Your NoorTube password reset code is:</p><p style=\"font-size:28px;font-weight:700;letter-spacing:6px\">" + code + "</p><p>This code works for 15 minutes. If you did not request a reset, you can ignore this email — your password will stay the same.</p></div>",
        "Your NoorTube password reset code is " + code + ". It works for 15 minutes. If you did not request a reset, ignore this email.");
      if (!sent) return err("Could not send the email. Please try again in a moment.", 502);
      await db.prepare("INSERT INTO password_resets (email, user_id, code_hash, expires_at, attempts, sent_at, hour_start, hour_count) VALUES (?,?,?,?,0,?,?,?) ON CONFLICT(email) DO UPDATE SET user_id = excluded.user_id, code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0, sent_at = excluded.sent_at, hour_start = excluded.hour_start, hour_count = excluded.hour_count")
        .bind(email, user.id, await sha256Hex(user.id + ":reset:" + code), now + RESET_WINDOW_MS, now, hourStart, hourCount).run();
      return json(okMsg);
    }
    if (method === "POST" && path === "/api/auth/reset-password") {
      const b = await request.json().catch(() => ({}));
      const email = String((b && b.email) || "").toLowerCase().trim().slice(0, 254);
      const code = String((b && b.code) || "").trim();
      const password = String((b && b.password) || "");
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return err("Enter a valid email address");
      if (!/^\d{6}$/.test(code)) return err("Enter the 6-digit code from the email");
      if (password.length < 6 || password.length > 200) return err("Password must be at least 6 characters");
      try { await ensurePasswordReset(db); } catch (_) { return err("Password reset is temporarily unavailable. Try again later.", 503); }
      const row = await db.prepare("SELECT user_id, code_hash, expires_at, attempts FROM password_resets WHERE email = ?").bind(email).first();
      if (!row) return err("Ask for a new reset code first.");
      if (Date.now() > row.expires_at) return err("This code has expired. Request a new one.");
      if ((row.attempts || 0) >= 5) return err("Too many wrong tries. Request a new code.", 429);
      if ((await sha256Hex(row.user_id + ":reset:" + code)) !== row.code_hash) {
        await db.prepare("UPDATE password_resets SET attempts = attempts + 1 WHERE email = ?").bind(email).run();
        return err("Wrong code. Please check and try again.");
      }
      const { hash, salt } = await hashPassword(password);
      await db.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(hash, salt, row.user_id).run();
      await db.prepare("DELETE FROM password_resets WHERE email = ?").bind(email).run();
      try { await db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(row.user_id).run(); } catch (_) {}
      return json({ ok: true, message: "Password updated. You can sign in with your new password." });
    }
    if (method === "GET" && path === "/api/me") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      return json({ user: publicUser(u, true) });
    }
    if (method === "DELETE" && path === "/api/me") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      // 1) remember the uploaded files so they can be removed from storage too
      const fileKeys = [];
      try {
        for (const t of ["videos", "reels", "statuses"]) {
          const r = await db.prepare("SELECT file_url FROM " + t + " WHERE owner_id = ?").bind(u.id).all();
          (r.results || []).forEach((x) => { const f = String(x.file_url || ""); if (f.startsWith(url.origin + "/file/")) fileKeys.push(decodeURIComponent(f.slice((url.origin + "/file/").length))); });
        }
        try { await ensureCampTables(db); const c = await db.prepare("SELECT media_url FROM ad_campaigns WHERE owner_id = ?").bind(u.id).all(); (c.results || []).forEach((x) => { const f = String(x.media_url || ""); if (f.startsWith(url.origin + "/file/")) fileKeys.push(decodeURIComponent(f.slice((url.origin + "/file/").length))); }); } catch (_) {}
      } catch (_) {}
      // 2) money-related and ad records: stop ads, remove personal details, keep only what accounting needs
      const soft = async (sql, ...args) => { try { await db.prepare(sql).bind(...args).run(); } catch (_) {} };
      await soft("UPDATE ads SET active = 0 WHERE id IN (SELECT ad_id FROM ad_campaigns WHERE owner_id = ? AND ad_id IS NOT NULL)", u.id);
      await soft("DELETE FROM ad_campaigns WHERE owner_id = ? AND status IN ('draft', 'cancelled', 'rejected')", u.id);
      await soft("UPDATE ad_campaigns SET owner_id = 'deleted', name = '(deleted)', media_url = '', click_url = NULL, payer_name = NULL WHERE owner_id = ?", u.id);
      await soft("DELETE FROM email_verified WHERE user_id = ?", u.id);
      await soft("DELETE FROM email_codes WHERE user_id = ?", u.id);
      await soft("DELETE FROM password_resets WHERE user_id = ?", u.id);
      await soft("DELETE FROM user_blocks WHERE blocker_id = ? OR blocked_id = ?", u.id, u.id);
      await soft("UPDATE sadaqah_requests SET account_name = NULL, account_number = NULL, routing_code = NULL WHERE creator_id = ?", u.id);
      await soft("UPDATE sadaqah_donations SET donor_id = NULL, donor_name = 'Deleted user' WHERE donor_id = ?", u.id);
      await soft("DELETE FROM reports WHERE reporter_id = ?", u.id);
      await db.batch([
        db.prepare("DELETE FROM comments WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM video_likes WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM reel_likes WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM saved_videos WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM watch_history WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM notifications WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM follows WHERE follower_id = ? OR followee_id = ?").bind(u.id, u.id),
        db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id),
        db.prepare("DELETE FROM videos WHERE owner_id = ?").bind(u.id),
        db.prepare("DELETE FROM reels WHERE owner_id = ?").bind(u.id),
        db.prepare("DELETE FROM statuses WHERE owner_id = ?").bind(u.id),
        db.prepare("DELETE FROM users WHERE id = ?").bind(u.id),
      ]);
      // 3) remove the uploaded files from storage (a failure here never blocks the deletion)
      for (const k of [...new Set(fileKeys)]) { try { await env.NOOR_BUCKET.delete(k); } catch (_) {} }
      return json({ ok: true });
    }
    if (method === "POST" && path === "/api/me/change-password") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const { currentPassword, newPassword } = await request.json().catch(() => ({}));
      if (!currentPassword || !newPassword) return err("Current and new password are required");
      if (typeof newPassword !== "string" || newPassword.length < 6 || newPassword.length > 200) return err("New password must be at least 6 characters");
      if (!(await verifyPassword(currentPassword, u.password_hash, u.password_salt))) return err("Current password is incorrect", 401);
      const { hash, salt } = await hashPassword(newPassword);
      await db.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(hash, salt, u.id).run();
      return json({ ok: true });
    }
    if (method === "GET" && path === "/api/me/following") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const rows = await db.prepare("SELECT followee_id, bell FROM follows WHERE follower_id = ?").bind(u.id).all();
      return json({ following: rows.results.map(r => ({ userId: r.followee_id, bell: !!r.bell })) });
    }
    if (method === "GET" && path === "/api/me/saved") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const rows = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color FROM saved_videos JOIN videos ON videos.id = saved_videos.video_id JOIN users ON users.id = videos.owner_id WHERE saved_videos.user_id = ?"
      ).bind(u.id).all();
      return json({ videos: rows.results.map(videoOut) });
    }
    if (method === "GET" && path === "/api/me/votes") {
      const u = (await currentUser(request, env)) || (await lookupGuestIfExists(request, env));
      if (!u) return json({ videoVotes: {}, reelLikes: [] });
      const vRows = await db.prepare("SELECT video_id, value FROM video_likes WHERE user_id = ?").bind(u.id).all();
      const rRows = await db.prepare("SELECT reel_id FROM reel_likes WHERE user_id = ?").bind(u.id).all();
      const videoVotes = {};
      for (const row of vRows.results) videoVotes[row.video_id] = row.value;
      return json({ videoVotes, reelLikes: rRows.results.map(row => row.reel_id) });
    }
    if (method === "GET" && path === "/api/me/watch-history") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const rows = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color FROM watch_history JOIN videos ON videos.id = watch_history.video_id JOIN users ON users.id = videos.owner_id WHERE watch_history.user_id = ? ORDER BY watch_history.watched_at DESC LIMIT 6"
      ).bind(u.id).all();
      return json({ videos: rows.results.map(videoOut) });
    }
    // ----- phone push: the Android app registers its Firebase token here -----
    if (method === "POST" && path === "/api/me/push-token") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.role === "guest") return err("Sign in to get phone notifications", 403);
      const b = await request.json().catch(() => ({}));
      const token = String(b.token || "").trim();
      if (token.length < 20 || token.length > 4096) return err("Invalid token", 400);
      try {
        await ensurePushTables(db);
        await db.prepare("INSERT INTO push_tokens (token, user_id, platform, updated_at) VALUES (?,?,?,?) ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, platform = excluded.platform, updated_at = excluded.updated_at").bind(token, u.id, String(b.platform || "android").slice(0, 20), Date.now()).run();
        await db.prepare("DELETE FROM push_tokens WHERE user_id = ? AND token NOT IN (SELECT token FROM push_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5)").bind(u.id, u.id).run();
        return json({ ok: true });
      } catch (_) { return err("Could not save", 500); }
    }
    if (method === "POST" && path === "/api/push-token/remove") {
      const b = await request.json().catch(() => ({}));
      const token = String(b.token || "").trim();
      if (token.length >= 20 && token.length <= 4096) { try { await ensurePushTables(db); await db.prepare("DELETE FROM push_tokens WHERE token = ?").bind(token).run(); } catch (_) {} }
      return json({ ok: true });
    }
    if (method === "GET" && path === "/api/me/notifications") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const rows = await db.prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").bind(u.id).all();
      return json({ notifications: rows.results.map(n => ({ id: n.id, type: n.type, title: n.title, message: n.message, read: !!n.read, createdAt: n.created_at })) });
    }
    if (method === "POST" && path === "/api/me/notifications/read") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      await db.prepare("UPDATE notifications SET read = 1 WHERE user_id = ?").bind(u.id).run();
      return json({ ok: true });
    }
    if (method === "DELETE" && path === "/api/me/notifications") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      await db.prepare("DELETE FROM notifications WHERE user_id = ?").bind(u.id).run();
      return json({ ok: true });
    }
    // ----- Google AdSense: public settings (nothing while the Salah guard is active) + ads.txt + admin settings -----
    if (method === "GET" && path === "/api/ads/config") {
      try {
        await ensurePlatformTables(db);
        const A = await getAdsenseCfg(db), g = salahGuardState(Date.now(), await getAppSettings(db));
        const M = await getAdmobCfg(db), N = await getManCfg(db);
        let nazOn = true;
        try { const nz = await db.prepare("SELECT v FROM sadaqah_settings WHERE k = 'enabled'").first(); nazOn = !(nz && nz.v === "0"); } catch (_) {}
        return json({ nazrana: { enabled: nazOn }, man: (!N.enabled || g.active) ? { enabled: false } : { enabled: true, app: N.app, home: N.home, watch: N.watch, hh: N.heightHome, hw: N.heightWatch }, adsense: (!A.enabled || g.active) ? { enabled: false } : { enabled: true, client: A.client, slots: A.slots }, admob: (!M.enabled || g.active) ? { enabled: false } : { enabled: true, test: M.test, banner: M.banner, interstitial: M.interstitial, everyVideos: M.everyVideos, everyReels: M.everyReels, minGapSec: M.minGapMin * 60 } });
      } catch (_) { return json({ adsense: { enabled: false }, admob: { enabled: false } }); }
    }
    if (method === "GET" && path === "/ads.txt") {
      const A = await getAdsenseCfg(db);
      const body = A.client ? "google.com, pub-" + A.client.replace("ca-pub-", "") + ", DIRECT, f08c47fec0942fa0\n" : "";
      return new Response(body, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=300" } });
    }
    if (method === "GET" && path === "/app-ads.txt") {
      const M = await getAdmobCfg(db);
      const body = M.appId ? "google.com, pub-" + M.appId.slice("ca-app-pub-".length, "ca-app-pub-".length + 16) + ", DIRECT, f08c47fec0942fa0\n" : "";
      return new Response(body, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=300" } });
    }
    if ((method === "GET" || method === "PUT") && path === "/api/admin/admob") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      try {
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          const s = (k) => String(b[k] == null ? "" : b[k]).trim();
          const appId = s("appId"), banner = s("banner"), inter = s("interstitial");
          if (appId && !/^ca-app-pub-\d{16}~\d{10}$/.test(appId)) return err("The App ID should look like ca-app-pub-1234567890123456~1234567890", 400);
          if ((banner && !/^ca-app-pub-\d{16}\/\d{10}$/.test(banner)) || (inter && !/^ca-app-pub-\d{16}\/\d{10}$/.test(inter))) return err("An ad unit ID should look like ca-app-pub-1234567890123456/1234567890", 400);
          const iv = (k, d, lo, hi) => { const n = b[k] === "" || b[k] == null ? d : Math.round(Number(b[k])); return n >= lo && n <= hi ? n : null; };
          const ev = iv("everyVideos", 3, 1, 20), er = iv("everyReels", 7, 2, 50), mg = iv("minGapMin", 4, 1, 60);
          if (ev === null || er === null || mg === null) return err("Check the numbers: videos 1-20, reels 2-50, minutes 1-60", 400);
          await ensureCampTables(db);
          const kv = { admob_enabled: b.enabled === true ? "1" : "0", admob_test: b.test === false ? "0" : "1", admob_app_id: appId, admob_banner: banner, admob_interstitial: inter, admob_every_videos: String(ev), admob_every_reels: String(er), admob_min_gap_min: String(mg) };
          await db.batch(Object.keys(kv).map((k) => db.prepare("INSERT INTO ad_pay_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, kv[k])));
        }
        return json({ ok: true, settings: await getAdmobCfg(db) });
      } catch (_) { return err("Could not save", 500); }
    }
    // ranking signals from the app (card seen, reel watch time, share, subscribe-after-watch); small batches, never blocks anything
    if (method === "POST" && path === "/api/signals") {
      const b = await request.json().catch(() => ({}));
      const evs = Array.isArray(b.events) ? b.events.slice(0, 40) : [];
      if (!evs.length) return json({ ok: true });
      try {
        await ensureSignalTables(db);
        const u = await currentUser(request, env).catch(() => null);
        const ip = String(request.headers.get("CF-Connecting-IP") || request.headers.get("x-forwarded-for") || "").slice(0, 64);
        const viewer = u ? "u:" + u.id : "ip:" + ip, day = istDay(Date.now());
        const st = signalStatements(db, evs, viewer, u ? u.id : "", day);
        for (let i = 0; i < st.length; i += 50) await db.batch(st.slice(i, i + 50));
        if (Math.random() < 0.02) { try { await db.prepare("DELETE FROM sig_seen WHERE day < ?").bind(istDay(Date.now() - 3 * 86400000)).run(); await db.prepare("DELETE FROM impr_daily WHERE day < ?").bind(istDay(Date.now() - 10 * 86400000)).run(); await db.prepare("DELETE FROM engage_daily WHERE day < ?").bind(istDay(Date.now() - 40 * 86400000)).run(); } catch (_) {} }
      } catch (_) {}
      return json({ ok: true });
    }
    // admin: test the Firebase key without sending anything to people
    if (method === "GET" && path === "/api/admin/push-status") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      const out = { ok: true, configured: false, authOk: false, sendOk: false, project: "", phones: 0, people: 0, detail: "" };
      try {
        await ensurePushTables(db);
        const c = await db.prepare("SELECT COUNT(*) AS n, COUNT(DISTINCT user_id) AS p FROM push_tokens").first();
        out.phones = (c && c.n) || 0; out.people = (c && c.p) || 0;
      } catch (_) {}
      const acc = fcmAccount(env);
      if (!acc) { out.detail = env.FCM_SERVICE_ACCOUNT ? "The FCM_SERVICE_ACCOUNT secret could not be read. Paste the whole text of the Firebase JSON file." : "The FCM_SERVICE_ACCOUNT secret is not added to the worker yet."; return json(out); }
      out.configured = true; out.project = String(acc.project_id || "");
      let at = "";
      try { _fcmTok = null; at = await fcmAccessToken(acc); out.authOk = true; }
      catch (e) { out.detail = "Could not sign in to Firebase with this key. Make sure you pasted the full JSON of a service account key for this project."; return json(out); }
      try {
        const r = await fetch("https://fcm.googleapis.com/v1/projects/" + encodeURIComponent(acc.project_id) + "/messages:send", { method: "POST", headers: { Authorization: "Bearer " + at, "Content-Type": "application/json" }, body: JSON.stringify({ validate_only: true, message: { topic: "all", notification: { title: "Test", body: "Test" } } }) });
        out.sendOk = r.ok;
        if (!r.ok) { let t = ""; try { t = await r.text(); } catch (_) {} out.detail = ("Firebase answered " + r.status + ". " + t).slice(0, 300); }
      } catch (_) { out.detail = "Could not reach Firebase."; }
      return json(out);
    }
    if ((method === "GET" || method === "PUT") && path === "/api/admin/man") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      try {
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          const t = (v) => String(v == null ? "" : v).trim();
          const home = t(b.home), watch = t(b.watch), notes = t(b.notes).slice(0, 1500);
          if (home.length > 6000 || watch.length > 6000) return err("The ad code is too long (max 6000 characters)", 400);
          const hh = parseInt(b.heightHome, 10), hw = parseInt(b.heightWatch, 10);
          if (!(hh >= 30 && hh <= 600) || !(hw >= 30 && hw <= 600)) return err("Banner height must be a number between 30 and 600", 400);
          await ensureCampTables(db);
          const kv = { man_enabled: b.enabled === true ? "1" : "0", man_app: b.app === true ? "1" : "0", man_home: home, man_watch: watch, man_hh: String(hh), man_hw: String(hw), man_notes: notes };
          await db.batch(Object.keys(kv).map((k) => db.prepare("INSERT INTO ad_pay_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, kv[k])));
        }
        return json({ ok: true, settings: await getManCfg(db) });
      } catch (_) { return err("Could not save", 500); }
    }
    if ((method === "GET" || method === "PUT") && path === "/api/admin/adsense") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      try {
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          const client = String(b.client == null ? "" : b.client).trim(), sh = String(b.slotHome == null ? "" : b.slotHome).trim(), sw = String(b.slotWatch == null ? "" : b.slotWatch).trim();
          if (client && !/^ca-pub-\d{10,20}$/.test(client)) return err("The Publisher ID should look like ca-pub-1234567890123456", 400);
          if ((sh && !/^\d{6,20}$/.test(sh)) || (sw && !/^\d{6,20}$/.test(sw))) return err("An ad slot ID is only numbers (for example 1234567890)", 400);
          await ensureCampTables(db);
          const kv = { adsense_enabled: b.enabled === true ? "1" : "0", adsense_client: client, adsense_slot_home: sh, adsense_slot_watch: sw };
          await db.batch(Object.keys(kv).map((k) => db.prepare("INSERT INTO ad_pay_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, kv[k])));
        }
        return json({ ok: true, settings: await getAdsenseCfg(db) });
      } catch (_) { return err("Could not save", 500); }
    }
    // ----- AD CAMPAIGNS (creators) -----
    if (method === "GET" && path === "/api/campaigns/info") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      try {
        const C = await getCampSettings(db);
        return json({ ok: true, enabled: C.enabled, ready: C.ready, prices: C.prices, durations: CAMP_DAYS, usdRate: C.usdRate, methods: C.methods,
          pay: { upiId: C.upiId, payee: C.payee || "NoorTube", razorpayLink: C.razorpayLink, bankHolder: C.bankHolder, bankAccount: C.bankAccount, bankIfsc: C.bankIfsc, bankName: C.bankName, intlLink: C.intlLink, intlText: C.intlText } });
      } catch (_) { return err("Ad campaigns are temporarily unavailable", 503); }
    }
    // creator removes a finished campaign from their own list (the record stays for the admin's payment history)
    const mDel = path.match(/^\/api\/me\/campaigns\/([^/]+)$/);
    if (method === "DELETE" && mDel) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      try {
        await ensureCampTables(db);
        const c = await db.prepare("SELECT id, status, end_at FROM ad_campaigns WHERE id = ? AND owner_id = ?").bind(mDel[1], u.id).first();
        if (!c) return err("Campaign not found", 404);
        // a live campaign whose end date has passed is shown to the creator as "Ended", so it can be deleted too
        const st = (c.status === "live" && c.end_at && Date.now() > c.end_at) ? "ended" : c.status;
        if (!["ended", "rejected", "cancelled"].includes(st)) return err("Only finished campaigns can be deleted", 409);
        await db.prepare("UPDATE ad_campaigns SET owner_hidden = 1 WHERE id = ? AND owner_id = ?").bind(c.id, u.id).run();
        return json({ ok: true });
      } catch (_) { return err("Could not delete the campaign", 500); }
    }
    if (method === "GET" && path === "/api/me/campaigns") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      try {
        await ensurePlatformTables(db); await ensureCampTables(db);
        let r;
        try { r = await db.prepare(CAMP_SELECT + "WHERE c.owner_id = ? AND COALESCE(c.owner_hidden, 0) = 0 ORDER BY c.created_at DESC LIMIT 100").bind(u.id).all(); }
        catch (_h) { r = await db.prepare(CAMP_SELECT + "WHERE c.owner_id = ? ORDER BY c.created_at DESC LIMIT 100").bind(u.id).all(); }
        return json({ ok: true, campaigns: (r.results || []).map(campOut) });
      } catch (_) { return err("Could not load your campaigns", 500); }
    }
    if (method === "POST" && path === "/api/me/campaigns") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.role === "guest") return err("Please sign in with a real account", 403);
      if (u.suspended) return err("Your account is suspended", 403);
      const b = await request.json().catch(() => ({}));
      try {
        await ensurePlatformTables(db);
        const C = await getCampSettings(db);
        if (!C.ready) return err("Ad campaigns are not open yet", 403);
        const name = String(b.name || "").trim().slice(0, 80);
        if (!name) return err("Give your campaign a name", 400);
        const type = b.type === "video" ? "video" : b.type === "image" ? "image" : "";
        if (!type) return err("Choose an image or a video", 400);
        const media = String(b.mediaUrl || "").trim();
        if (!media.startsWith(url.origin + "/file/")) return err("Please upload your image or video first", 400);
        const click = String(b.clickUrl || "").trim().slice(0, 500);
        if (click && !/^https?:\/\//i.test(click)) return err("The link must start with http:// or https://", 400);
        const places = [...new Set((Array.isArray(b.placements) ? b.placements : []).filter((x) => CAMP_PRICE_KEYS.includes(x) && C.prices[x] > 0))];
        if (!places.length) return err("Choose where your ad should appear", 400);
        if (isVideoSlot(places) && type !== "video") return err("Video start and Video middle need a video file", 400);
        const views = Math.round(Number(b.views) / 1000) * 1000;
        if (!isFinite(views) || views < CAMP_VIEW_MIN || views > CAMP_VIEW_MAX) return err("Choose how many views you want (" + CAMP_VIEW_MIN.toLocaleString("en-US") + " to " + CAMP_VIEW_MAX.toLocaleString("en-US") + ")", 400);
        const isBanner = places.every((x) => CAMP_BANNER_PL.includes(x)), isVid = places.every((x) => CAMP_VIDEO_PL.includes(x));
        if (!isBanner && !isVid) return err("Choose either banner places (Home, Under videos, Reels) or video places (Video start, Video middle), not both in one campaign", 400);
        const cpmRs = isVid ? C.cpm.video : C.cpm.banner;
        if (!(cpmRs > 0)) return err("This kind of ad is not offered right now", 400);
        const open = await db.prepare("SELECT COUNT(*) AS n FROM ad_campaigns WHERE owner_id = ? AND status IN ('draft', 'submitted')").bind(u.id).first();
        if ((open && open.n || 0) >= 5) return err("You already have 5 campaigns waiting. Finish or cancel one first.", 400);
        const cpmPaise = Math.round(cpmRs * 100), amount = Math.round(views / 1000 * cpmPaise);
        if (!(amount > 0)) return err("Could not work out the price", 400);
        const id = uid("camp"), ref = campRef(), midAfter = Math.max(5, Math.min(3600, Math.round(Number(b.midAfter) || 30)));
        await db.prepare("INSERT INTO ad_campaigns (id, ref, owner_id, name, type, media_url, click_url, placements, days, mid_after, skip, amount_paise, status, created_at, target_impressions, cpm_paise) VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'draft', ?, ?, ?)")
          .bind(id, ref, u.id, name, type, media, click || null, places.join(","), 0, midAfter, b.skip ? 1 : 0, amount, Date.now(), views, cpmPaise).run();
        const row = await db.prepare(CAMP_SELECT + "WHERE c.id = ?").bind(id).first();
        return json({ ok: true, campaign: campOut(row) });
      } catch (_) { return err("Could not create the campaign", 500); }
    }
    {
      const m2 = path.match(/^\/api\/me\/campaigns\/([^/]+)\/(submit|cancel)$/);
      if (method === "POST" && m2) {
        const u = await currentUser(request, env);
        if (!u) return err("Sign in required", 401);
        try {
          await ensureCampTables(db);
          const c = await db.prepare("SELECT * FROM ad_campaigns WHERE id = ? AND owner_id = ?").bind(m2[1], u.id).first();
          if (!c) return err("Campaign not found", 404);
          if (c.status !== "draft") return err("This campaign was already sent or finished", 409);
          if (m2[2] === "cancel") {
            await db.prepare("UPDATE ad_campaigns SET status = 'cancelled', resolved_at = ? WHERE id = ? AND status = 'draft'").bind(Date.now(), c.id).run();
            return json({ ok: true });
          }
          const b = await request.json().catch(() => ({}));
          const C = await getCampSettings(db), pm = String(b.method || "");
          if (!["upi", "razorpay", "bank", "intl"].includes(pm) || !C.methods[pm]) return err("Choose how you paid", 400);
          const refText = String(b.reference || "").trim().slice(0, 80);
          if (refText.length < 4) return err("Enter the payment reference or transaction ID", 400);
          const r = await db.prepare("UPDATE ad_campaigns SET status = 'submitted', pay_method = ?, pay_ref = ?, payer_name = ?, submitted_at = ? WHERE id = ? AND status = 'draft'")
            .bind(pm, refText, String(b.payerName || "").trim().slice(0, 60) || null, Date.now(), c.id).run();
          if (!r.meta || r.meta.changes !== 1) return err("This campaign was already sent", 409);
          return json({ ok: true });
        } catch (_) { return err("Could not save", 500); }
      }
    }
    // ----- AD CAMPAIGNS (admin) -----
    if (method === "GET" && path === "/api/admin/campaigns") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      try {
        await ensurePlatformTables(db); await ensureCampTables(db);
        const r = await db.prepare("SELECT c.*, a.impressions AS impressions, a.clicks AS clicks, u.name AS owner_name, u.email AS owner_email FROM ad_campaigns c LEFT JOIN ads a ON a.id = c.ad_id LEFT JOIN users u ON u.id = c.owner_id ORDER BY c.created_at DESC LIMIT 500").all();
        const list = (r.results || []).map((c) => ({ ...campOut(c), ownerName: c.owner_name || "Deleted user", ownerEmail: c.owner_email || "" }));
        const earned = (r.results || []).filter((c) => c.status === "live" || c.status === "ended").reduce((s, c) => s + (c.amount_paise || 0), 0);
        return json({ ok: true, campaigns: list, totals: { earnedPaise: earned, awaiting: list.filter((c) => c.status === "submitted").length, live: list.filter((c) => c.status === "live").length, all: list.length } });
      } catch (_) { return err("Could not load campaigns", 500); }
    }
    {
      const m3 = path.match(/^\/api\/admin\/campaigns\/([^/]+)\/(confirm|reject|end)$/);
      if (method === "POST" && m3) {
        if (!(await adminUser(request, env))) return err("Not allowed", 403);
        try {
          await ensurePlatformTables(db); await ensureCampTables(db);
          const c = await db.prepare("SELECT * FROM ad_campaigns WHERE id = ?").bind(m3[1]).first();
          if (!c) return err("Campaign not found", 404);
          const now = Date.now();
          if (m3[2] === "confirm") {
            if (c.status !== "submitted" && c.status !== "draft") return err("This campaign was already handled", 409);
            const places = String(c.placements || "").split(",").filter(Boolean), tgt = c.target_impressions || 0, end = tgt > 0 ? null : now + c.days * 86400000, adId = uid("ad");
            if (tgt > 0 && !(await ensureAdTargetCol(db))) return err("The server could not prepare view-based ads yet. Please try again.", 500);
            if (isVideoSlot(places) && c.type !== "video") return err("Video start / middle need a video file", 400);
            if (await ensureAdVideoCols(db)) {
              await db.prepare("INSERT INTO ads (id, name, type, media_url, click_url, placements, active, starts_at, ends_at, created_at, mid_after, skip_after) VALUES (?,?,?,?,?,?,1,?,?,?,?,?)")
                .bind(adId, "Campaign: " + c.name, c.type, c.media_url, c.click_url || "", places.join(","), now, end, now, c.mid_after || 30, c.skip ? 5 : 0).run();
            } else {
              if (isVideoSlot(places)) return err("The server could not prepare video ads yet. Please try again.", 500);
              await db.prepare("INSERT INTO ads (id, name, type, media_url, click_url, placements, active, starts_at, ends_at, created_at) VALUES (?,?,?,?,?,?,1,?,?,?)")
                .bind(adId, "Campaign: " + c.name, c.type, c.media_url, c.click_url || "", places.join(","), now, end, now).run();
            }
            if (tgt > 0) { try { await db.prepare("UPDATE ads SET target_impressions = ? WHERE id = ?").bind(tgt, adId).run(); } catch (_) { await db.prepare("DELETE FROM ads WHERE id = ?").bind(adId).run(); return err("Could not start the campaign. Please try again.", 500); } }
            const r = await db.prepare("UPDATE ad_campaigns SET status = 'live', ad_id = ?, start_at = ?, end_at = ?, resolved_at = ? WHERE id = ? AND status IN ('submitted', 'draft')").bind(adId, now, end, now, c.id).run();
            if (!r.meta || r.meta.changes !== 1) { await db.prepare("DELETE FROM ads WHERE id = ?").bind(adId).run(); return err("This campaign was already handled", 409); }
            try { await addNotification(db, c.owner_id, "info", "Your ad campaign is live", "Payment received. Your campaign \"" + c.name + "\" is now live" + (tgt > 0 ? ". It stops by itself after " + tgt.toLocaleString("en-US") + " views." : " for " + c.days + " days.") + " You can see its views and clicks in Studio > Halal Ads.", true); } catch (_) {}
            return json({ ok: true });
          }
          if (m3[2] === "reject") {
            if (c.status !== "submitted" && c.status !== "draft") return err("This campaign was already handled", 409);
            const b = await request.json().catch(() => ({}));
            const reason = String((b && b.reason) || "").trim().slice(0, 200) || "It did not meet the ad rules.";
            const r = await db.prepare("UPDATE ad_campaigns SET status = 'rejected', reject_reason = ?, resolved_at = ? WHERE id = ? AND status IN ('submitted', 'draft')").bind(reason, now, c.id).run();
            if (!r.meta || r.meta.changes !== 1) return err("This campaign was already handled", 409);
            try { await addNotification(db, c.owner_id, "warning", "Ad campaign not accepted", "Your campaign \"" + c.name + "\" was not accepted. Reason: " + reason + (/[.!?]$/.test(reason) ? "" : ".") + " If you already paid, contact us with your reference " + c.ref + ".", true); } catch (_) {}
            return json({ ok: true });
          }
          if (c.status !== "live") return err("Only a live campaign can be ended", 409);
          await db.prepare("UPDATE ad_campaigns SET status = 'ended', end_at = ?, resolved_at = ? WHERE id = ? AND status = 'live'").bind(now, now, c.id).run();
          if (c.ad_id) await db.prepare("UPDATE ads SET active = 0, ends_at = ? WHERE id = ?").bind(now, c.ad_id).run();
          try { await addNotification(db, c.owner_id, "info", "Ad campaign ended", "Your campaign \"" + c.name + "\" has ended.", true); } catch (_) {}
          return json({ ok: true });
        } catch (_) { return err("Could not save", 500); }
      }
    }
    if ((method === "GET" || method === "PUT") && path === "/api/admin/campaign-settings") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      try {
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          const str = (k, n) => String(b[k] == null ? "" : b[k]).trim().slice(0, n);
          const upi = str("upiId", 80), rz = str("razorpayLink", 300), il = str("intlLink", 300), usd = b.usdRate === "" || b.usdRate == null ? 0 : Number(b.usdRate);
          if (upi && !/^[a-zA-Z0-9._-]{2,}@[a-zA-Z][a-zA-Z0-9.-]{1,}$/.test(upi)) return err("The UPI ID does not look right (example: name@bank)", 400);
          if (rz && !/^https:\/\//i.test(rz)) return err("The Razorpay link must start with https://", 400);
          if (il && !/^https:\/\//i.test(il)) return err("The international payment link must start with https://", 400);
          if (!isFinite(usd) || usd < 0 || usd > 1000) return err("The dollar rate is not valid", 400);
          const src = (b.prices && typeof b.prices === "object") ? b.prices : {}, P = {};
          for (const k of CAMP_PRICE_KEYS) {
            const n = src[k] === "" || src[k] == null ? 0 : Number(src[k]);
            if (!isFinite(n) || n < 0 || n > 1000000) return err("A price is not valid. Use a number like 100 (0 means not offered).", 400);
            P[k] = Math.round(n * 100) / 100;
          }
          const cin = b.cpm && typeof b.cpm === "object" ? b.cpm : {}, CP = {};
          for (const k of ["banner", "video"]) {
            const n = cin[k] === "" || cin[k] == null ? 0 : Number(cin[k]);
            if (!isFinite(n) || n < 0 || n > 100000) return err("A rate is not valid. Use a number like 85 (empty = automatic from the dollar rate).", 400);
            CP[k] = Math.round(n * 100) / 100;
          }
          await ensureCampTables(db);
          const kv = { cpm_banner: String(CP.banner || ""), cpm_video: String(CP.video || ""), enabled: b.enabled === true ? "1" : "0", upi_id: upi, payee: str("payee", 60), razorpay_link: rz, bank_holder: str("bankHolder", 80), bank_account: str("bankAccount", 40), bank_ifsc: str("bankIfsc", 20), bank_name: str("bankName", 80), intl_link: il, intl_text: str("intlText", 600), usd_rate: String(usd), prices: JSON.stringify(P) };
          await db.batch(Object.keys(kv).map((k) => db.prepare("INSERT INTO ad_pay_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, kv[k])));
        }
        return json({ ok: true, settings: await getCampSettings(db) });
      } catch (_) { return err("Could not save the settings", 500); }
    }
    // ----- email verification (needed before monetization) -----
    if (method === "GET" && path === "/api/me/email-status") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      return json({ ok: true, email: u.email, verified: await isEmailVerified(db, u) });
    }
    if (method === "POST" && path === "/api/me/email/send-code") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Please sign in with a real account first", 403);
      if (await isEmailVerified(db, u)) return json({ ok: true, verified: true });
      if (!mailConfigured(env)) return err("Email verification is not set up yet. Please try again later.", 503);
      try { await ensureEmailVerifyTables(db); } catch (_) { return err("Email verification is temporarily unavailable. Try again later.", 503); }
      const now = Date.now();
      const cur = await db.prepare("SELECT sent_at, hour_start, hour_count FROM email_codes WHERE user_id = ?").bind(u.id).first();
      let hourStart = now, hourCount = 1;
      if (cur) {
        if (now - cur.sent_at < 60000) return err("Please wait a minute before asking for a new code.", 429);
        if (now - cur.hour_start < 3600000) {
          hourStart = cur.hour_start; hourCount = (cur.hour_count || 0) + 1;
          if (hourCount > 5) return err("Too many codes requested. Please try again in an hour.", 429);
        }
      }
      const buf = new Uint32Array(1); crypto.getRandomValues(buf);
      const code = String(buf[0] % 1000000).padStart(6, "0");
      const email = String(u.email).toLowerCase();
      const sent = await sendMail(env, email, "Your NoorTube verification code: " + code,
        "<div style=\"font-family:Arial,sans-serif;font-size:15px;color:#111\"><p>Assalamu alaikum " + String(u.name || "").replace(/[<>&"]/g, "") + ",</p><p>Your NoorTube email verification code is:</p><p style=\"font-size:28px;font-weight:700;letter-spacing:6px\">" + code + "</p><p>This code works for 10 minutes. If you did not ask for it, you can ignore this email.</p></div>",
        "Your NoorTube email verification code is " + code + ". It works for 10 minutes. If you did not ask for it, ignore this email.");
      if (!sent) return err("Could not send the email. Please try again in a moment.", 502);
      await db.prepare("INSERT INTO email_codes (user_id, email, code_hash, expires_at, attempts, sent_at, hour_start, hour_count) VALUES (?,?,?,?,0,?,?,?) ON CONFLICT(user_id) DO UPDATE SET email = excluded.email, code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0, sent_at = excluded.sent_at, hour_start = excluded.hour_start, hour_count = excluded.hour_count")
        .bind(u.id, email, await sha256Hex(u.id + ":" + code), now + 600000, now, hourStart, hourCount).run();
      return json({ ok: true, sent: true });
    }
    if (method === "POST" && path === "/api/me/email/verify") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Please sign in with a real account first", 403);
      const b = await request.json().catch(() => ({}));
      const code = String((b && b.code) || "").trim();
      if (!/^\d{6}$/.test(code)) return err("Enter the 6-digit code from the email.");
      try { await ensureEmailVerifyTables(db); } catch (_) { return err("Email verification is temporarily unavailable. Try again later.", 503); }
      const row = await db.prepare("SELECT email, code_hash, expires_at, attempts FROM email_codes WHERE user_id = ?").bind(u.id).first();
      if (!row || row.email !== String(u.email).toLowerCase()) return err("Ask for a new code first.");
      if (Date.now() > row.expires_at) return err("This code has expired. Ask for a new code.");
      if ((row.attempts || 0) >= 5) return err("Too many wrong tries. Ask for a new code.", 429);
      if ((await sha256Hex(u.id + ":" + code)) !== row.code_hash) {
        await db.prepare("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = ?").bind(u.id).run();
        return err("Wrong code. Please check and try again.");
      }
      await db.prepare("INSERT INTO email_verified (user_id, email, verified_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET email = excluded.email, verified_at = excluded.verified_at").bind(u.id, row.email, Date.now()).run();
      await db.prepare("DELETE FROM email_codes WHERE user_id = ?").bind(u.id).run();
      return json({ ok: true, verified: true });
    }
    if (method === "PATCH" && path === "/api/me") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      const b = await request.json().catch(() => ({}));
      const fields = [], vals = [];
      if (b.name !== undefined) {
        const nm = String(b.name).trim();
        if (!nm || nm.length > 60) return err("Name must be 1-60 characters");
        fields.push("name = ?"); vals.push(nm);
      }
      if (b.avatarColor !== undefined) { fields.push("avatar_color = ?"); vals.push(b.avatarColor); }
      if (b.avatarImage !== undefined) { fields.push("avatar_image = ?"); vals.push(b.avatarImage); }
      if (b.monetizationEnabled !== undefined) {
        // Turning monetization ON must be earned: the server re-checks the rules so nobody can
        // enable it by calling the API directly. Turning it OFF is always allowed.
        if (b.monetizationEnabled && !u.monetization_enabled && u.role !== "admin") {
          if (u.suspended) return err("Suspended accounts cannot enable monetization", 403);
          const fc = await db.prepare("SELECT COUNT(*) as c FROM follows WHERE followee_id = ?").bind(u.id).first();
          const cutoff = new Date(Date.now() - 62 * 24 * 3600 * 1000).toISOString().slice(0, 10);
          const rv = await db.prepare("SELECT COALESCE(SUM(views), 0) as v FROM reels WHERE owner_id = ? AND uploaded_at >= ?").bind(u.id, cutoff).first();
          // Path A (videos): 1,000 followers + 3,000 watch hours.  Path B (reels): 500 followers + 10 lakh reel views in 62 days.
          const ok = ((fc?.c || 0) >= 1000 && (u.watch_hours || 0) >= 3000) || ((fc?.c || 0) >= 500 && (rv?.v || 0) >= 1000000);
          if (!ok) return err("Monetization requirements not met", 403);
          if (!(await isEmailVerified(db, u))) return err("Please verify your email before enabling monetization.", 403);
        }
        fields.push("monetization_enabled = ?"); vals.push(b.monetizationEnabled ? 1 : 0);
      }
      if (b.payoutInfo !== undefined) {
        const pi = b.payoutInfo;
        if (!pi || typeof pi !== "object" || !["bank", "paypal", "upi", "mobile"].includes(pi.method)) return err("Invalid payout details");
        const clean = (v, n) => String(v == null ? "" : v).trim().slice(0, n);
        fields.push("payout_method = ?", "payout_account_name = ?", "payout_account_number = ?", "payout_routing_code = ?");
        vals.push(pi.method, clean(pi.accountName, 100), clean(pi.accountNumber, 100), clean(pi.routingCode, 50));
      }
      if (!fields.length) return err("Nothing to update");
      vals.push(u.id);
      await db.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...vals).run();
      const updated = await db.prepare("SELECT * FROM users WHERE id = ?").bind(u.id).first();
      return json({ ok: true, user: publicUser(updated, true) });
    }

    // ---------- FOLLOW ----------
    let m;
    if (method === "POST" && (m = path.match(/^\/api\/follow\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const targetId = m[1];
      const existing = await db.prepare("SELECT 1 FROM follows WHERE follower_id = ? AND followee_id = ?").bind(u.id, targetId).first();
      if (existing) await db.prepare("DELETE FROM follows WHERE follower_id = ? AND followee_id = ?").bind(u.id, targetId).run();
      else await db.prepare("INSERT INTO follows (follower_id, followee_id) VALUES (?, ?)").bind(u.id, targetId).run();
      return json({ ok: true, following: !existing });
    }
    if (method === "GET" && (m = path.match(/^\/api\/follow-status\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return json({ following: false, bell: false });
      const row = await db.prepare("SELECT bell FROM follows WHERE follower_id = ? AND followee_id = ?").bind(u.id, m[1]).first();
      return json({ following: !!row, bell: !!(row && row.bell) });
    }
    if (method === "GET" && (m = path.match(/^\/api\/videos\/([^/]+)\/my-vote$/))) {
      const u = await currentUser(request, env);
      if (!u) return json({ value: null });
      const row = await db.prepare("SELECT value FROM video_likes WHERE user_id = ? AND video_id = ?").bind(u.id, m[1]).first();
      return json({ value: row ? row.value : null });
    }
    if (method === "GET" && (m = path.match(/^\/api\/reels\/([^/]+)\/my-vote$/))) {
      const u = await currentUser(request, env);
      if (!u) return json({ liked: false });
      const row = await db.prepare("SELECT 1 FROM reel_likes WHERE user_id = ? AND reel_id = ?").bind(u.id, m[1]).first();
      return json({ liked: !!row });
    }
    if (method === "POST" && (m = path.match(/^\/api\/follow\/([^/]+)\/bell$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const row = await db.prepare("SELECT bell FROM follows WHERE follower_id = ? AND followee_id = ?").bind(u.id, m[1]).first();
      if (!row) return err("Follow the channel first", 400);
      await db.prepare("UPDATE follows SET bell = ? WHERE follower_id = ? AND followee_id = ?").bind(row.bell ? 0 : 1, u.id, m[1]).run();
      return json({ ok: true, bell: !row.bell });
    }
    if (method === "GET" && (m = path.match(/^\/api\/users\/([^/]+)$/))) {
      const user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(m[1]).first();
      if (!user) return err("User not found", 404);
      const followers = await db.prepare("SELECT COUNT(*) as c FROM follows WHERE followee_id = ?").bind(m[1]).first();
      return json({ user: publicUser(user), followerCount: followers.c });
    }
    // ----- creator: my own earnings (creator share only; never rates, share % or platform numbers) -----
    if (method === "GET" && path === "/api/me/earnings") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (!u.monetization_enabled) return json({ enabled: false });
      const S = await getPayoutSettings(db);
      const e = await computeEarnings(db, u.id, S);
      const pend = await getPendingWithdraw(db, u.id);
      let last = null;
      try { last = await db.prepare("SELECT status, amount_cents, resolved_at, note FROM withdraw_requests WHERE user_id = ? AND status != 'Pending' ORDER BY created_at DESC LIMIT 1").bind(u.id).first(); } catch (_) {}
      const pendCents = pend ? pend.amount_cents : 0;
      return json({ enabled: true, videoUsd: e.c.cV / 100, reelsUsd: e.c.cR / 100, totalUsd: e.c.creator / 100, videoViews: e.vNew, reelViews: e.rNew, paidUsd: e.paidCents / 100, lastPaidAt: e.lastPaidAt,
        minWithdrawUsd: WITHDRAW_MIN_CENTS / 100, pendingUsd: pendCents / 100, availableUsd: Math.max(0, e.c.creator - pendCents) / 100,
        hasPayoutInfo: !!(u.payout_method && u.payout_account_number),
        pendingRequest: pend ? { id: pend.id, amountUsd: pend.amount_cents / 100, createdAt: pend.created_at } : null,
        lastRequest: last ? { status: last.status, amountUsd: last.amount_cents / 100, resolvedAt: last.resolved_at, note: last.note || "" } : null });
    }
    // ----- creator: Studio dashboard data (READ-ONLY: one call, only the signed-in creator's OWN content) -----
    // Realtime numbers come from view_log, which already keeps every counted view for 48 hours.
    if (method === "GET" && path === "/api/me/studio") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Sign in to use Studio", 403);
      try {
        const now = Date.now(), H = 3600000;
        const vidsP = db.prepare("SELECT id, title, thumbnail, file_url, views, likes, dislikes, duration, monetized, hidden, copyright_status, uploaded_at, (SELECT COUNT(*) FROM comments WHERE target_type = 'video' AND target_id = videos.id) AS comments, (SELECT COUNT(*) FROM saved_videos WHERE video_id = videos.id) AS saves FROM videos WHERE owner_id = ? AND removed = 0 ORDER BY uploaded_at DESC LIMIT 300").bind(u.id).all();
        const rlsP = db.prepare("SELECT id, title, thumbnail, file_url, views, likes, hidden, uploaded_at, (SELECT COUNT(*) FROM comments WHERE target_type = 'reel' AND target_id = reels.id) AS comments FROM reels WHERE owner_id = ? ORDER BY uploaded_at DESC LIMIT 300").bind(u.id).all();
        const fcP = db.prepare("SELECT COUNT(*) AS c FROM follows WHERE followee_id = ?").bind(u.id).first();
        const cutoff = new Date(now - 62 * 24 * H).toISOString().slice(0, 10);
        const rvP = db.prepare("SELECT COALESCE(SUM(views), 0) AS v FROM reels WHERE owner_id = ? AND uploaded_at >= ?").bind(u.id, cutoff).first();
        let rt = null, daily = null, retention = null;
        const pRt = (async () => { try {
          await ensureViewTables(db);
          const lg = await db.prepare("SELECT kind, content_id, ts, viewer FROM view_log WHERE ts > ? AND ((kind = 'v' AND content_id IN (SELECT id FROM videos WHERE owner_id = ? AND removed = 0)) OR (kind = 'r' AND content_id IN (SELECT id FROM reels WHERE owner_id = ?))) ORDER BY ts DESC LIMIT 30000").bind(now - 48 * H, u.id, u.id).all();
          const mk = () => ({ m60: new Array(60).fill(0), h48: new Array(48).fill(0) });
          const series = { all: mk(), v: mk(), r: mk() }, per = {}, uniq = new Set();
          for (const x of lg.results) {
            const age = now - x.ts;
            if (age < 0) continue;
            const hi = 47 - Math.min(47, Math.floor(age / H));
            const mi = age < H ? 59 - Math.min(59, Math.floor(age / 60000)) : -1;
            const key = x.kind + ":" + x.content_id;
            if (!per[key]) per[key] = mk();
            for (const t of [series.all, series[x.kind], per[key]]) { t.h48[hi]++; if (mi >= 0) t.m60[mi]++; }
            uniq.add(x.viewer);
          }
          rt = { series, perContent: per, uniqueViewers48h: uniq.size };
        } catch (_) { rt = null; } })();
        const pDaily = (async () => { try {
          await ensureViewTables(db);
          const days = lastDays(90, now);
          const dr = await db.prepare("SELECT day, kind, SUM(views) AS n FROM view_daily WHERE owner_id = ? AND day >= ? GROUP BY day, kind").bind(u.id, days[0]).all();
          const ix = {};
          days.forEach((d, i) => { ix[d] = i; });
          const dv = { days, all: new Array(90).fill(0), v: new Array(90).fill(0), r: new Array(90).fill(0), firstDay: null };
          (dr.results || []).forEach((r) => { const i = ix[r.day]; if (i === undefined) return; dv[r.kind === "r" ? "r" : "v"][i] += r.n; dv.all[i] += r.n; });
          const fd = await db.prepare("SELECT MIN(day) AS d FROM view_daily WHERE owner_id = ?").bind(u.id).first();
          dv.firstDay = fd && fd.d ? fd.d : null;
          daily = dv;
        } catch (_) { daily = null; } })();
        const pRet = (async () => { try {
          await ensureRetentionTables(db);
          const st = await db.prepare("SELECT s.video_id AS id, s.sessions AS sessions, s.seconds AS seconds FROM video_watch_stats s WHERE s.video_id IN (SELECT id FROM videos WHERE owner_id = ?)").bind(u.id).all();
          const bk = await db.prepare("SELECT r.video_id AS id, r.bucket AS b, r.n AS n FROM video_retention r WHERE r.video_id IN (SELECT id FROM videos WHERE owner_id = ?)").bind(u.id).all();
          const per = {};
          (st.results || []).forEach((r) => { per[r.id] = { sessions: r.sessions || 0, seconds: r.seconds || 0, n: new Array(10).fill(0) }; });
          (bk.results || []).forEach((r) => { if (per[r.id] && r.b >= 0 && r.b < 10) per[r.id].n[r.b] = r.n; });
          const out = { sessions: 0, seconds: 0, n: new Array(10).fill(0) }, perVideo = {};
          Object.keys(per).forEach((id) => {
            const p = per[id];
            out.sessions += p.sessions; out.seconds += p.seconds; p.n.forEach((x, i) => { out.n[i] += x; });
            perVideo[id] = { sessions: p.sessions, avgSeconds: p.sessions ? Math.round(p.seconds / p.sessions) : 0, curve: p.n.map((x) => (p.sessions ? Math.round(x / p.sessions * 1000) / 10 : 0)) };
          });
          retention = { overall: { sessions: out.sessions, avgSeconds: out.sessions ? Math.round(out.seconds / out.sessions) : 0, curve: out.n.map((x) => (out.sessions ? Math.round(x / out.sessions * 1000) / 10 : 0)) }, perVideo };
        } catch (_) { retention = null; } })();
        const [vids, rls, fc, rv] = await Promise.all([vidsP, rlsP, fcP, rvP]);
        await Promise.all([pRt, pDaily, pRet]);
        const cm = await db.prepare("SELECT comments.id AS id, comments.target_type AS type, comments.target_id AS tid, comments.text AS text, comments.created_at AS at, users.name AS name, users.avatar_color AS color FROM comments JOIN users ON users.id = comments.user_id WHERE comments.user_id != ? AND ((comments.target_type = 'video' AND comments.target_id IN (SELECT id FROM videos WHERE owner_id = ?)) OR (comments.target_type = 'reel' AND comments.target_id IN (SELECT id FROM reels WHERE owner_id = ?))) ORDER BY comments.created_at DESC LIMIT 30").bind(u.id, u.id, u.id).all();
        return json({
          ok: true, now, followers: (fc && fc.c) || 0, watchHours: u.watch_hours || 0, reelViews62d: (rv && rv.v) || 0,
          need: { followers: 1000, watchHours: 3000, reelViews: 1000000, reelFollowers: 500 },
          videos: vids.results.map(v => ({ id: v.id, title: v.title, thumbnail: v.thumbnail, fileUrl: v.file_url, views: v.views || 0, likes: v.likes || 0, dislikes: v.dislikes || 0, duration: v.duration, monetized: !!v.monetized, hidden: !!v.hidden, copyrightStatus: v.copyright_status, uploadedAt: v.uploaded_at, comments: v.comments || 0, saves: v.saves || 0 })),
          reels: rls.results.map(r => ({ id: r.id, title: r.title, thumbnail: r.thumbnail, fileUrl: r.file_url, views: r.views || 0, likes: r.likes || 0, hidden: !!r.hidden, uploadedAt: r.uploaded_at, comments: r.comments || 0 })),
          rt, daily, retention,
          comments: cm.results.map(c => ({ id: c.id, type: c.type, targetId: c.tid, text: c.text, at: c.at, name: c.name, color: c.color })),
        });
      } catch (_) { return err("Studio data unavailable", 500); }
    }
    // ================= PLATFORM routes: ads, settings, broadcast, audit log, analytics =================
    // ----- public: prayer times for THIS device (optional ?lat=&lng=&tz=) or platform default -----
    if (method === "GET" && path === "/api/prayer") {
      try {
        await ensurePlatformTables(db);
        const base = await getAppSettings(db);
        const qLat = parseFloat(url.searchParams.get("lat"));
        const qLng = parseFloat(url.searchParams.get("lng"));
        const qTz = parseFloat(url.searchParams.get("tz"));
        const useUser = isFinite(qLat) && isFinite(qLng) && Math.abs(qLat) <= 90 && Math.abs(qLng) <= 180;
        const cfg = {
          city: useUser ? (String(url.searchParams.get("city") || "").trim().slice(0, 60) || "Your location") : base.city,
          lat: useUser ? qLat : base.lat,
          lng: useUser ? qLng : base.lng,
          tz: useUser && isFinite(qTz) && Math.abs(qTz) <= 14 ? qTz : (useUser ? -new Date().getTimezoneOffset() / 60 : base.tz),
          method: PRAYER_METHODS[url.searchParams.get("method")] ? url.searchParams.get("method") : base.method,
          hanafi: url.searchParams.get("hanafi") === "0" || url.searchParams.get("hanafi") === "false" ? false : base.hanafi,
          guardOn: base.guardOn,
          jummah: base.jummah,
          guardMin: base.guardMin,
        };
        const now = Date.now();
        const g = salahGuardState(now, cfg);
        const T = computePrayerTimes(now, cfg.lat, cfg.lng, cfg.tz, cfg.method, cfg.hanafi);
        const local = new Date(now + cfg.tz * 3600000);
        const startOfDay = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - cfg.tz * 3600000;
        const fmt = (h) => {
          if (!isFinite(h)) return null;
          const m = Math.round(((h % 24) + 24) % 24 * 60), hh = Math.floor(m / 60) % 24, mm = m % 60;
          return String(hh).padStart(2, "0") + ":" + String(mm).padStart(2, "0");
        };
        const times = {};
        for (const [k, name] of PRAYER_ORDER) {
          const h = T[k];
          if (!isFinite(h)) continue;
          const startMs = startOfDay + h * 3600000;
          times[k] = { name, startMs, hm: fmt(h) };
        }
        return json({
          ok: true,
          city: cfg.city,
          lat: cfg.lat,
          lng: cfg.lng,
          tz: cfg.tz,
          method: cfg.method,
          source: useUser ? "device" : "platform",
          guardOn: cfg.guardOn,
          guardMin: cfg.guardMin,
          guard: g.active ? { active: true, name: g.name, untilMs: g.untilMs } : { active: false },
          times,
          serverNow: now,
        });
      } catch (_) {
        return json({ ok: false, times: {}, guard: { active: false }, guardOn: false });
      }
    }
    // ----- public: which ad(s) to show in a placement. Nothing is served while the Salah guard is active. -----
    if (method === "GET" && path === "/api/ads") {
      try {
        await ensurePlatformTables(db);
        const placement = url.searchParams.get("placement") || "";
        if (!AD_PLACEMENTS.includes(placement)) return json({ ads: [] });
        const now = Date.now(), cfg = await getAppSettings(db), g = salahGuardState(now, cfg);
        if (g.active) return json({ ads: [], guard: { active: true, name: g.name, untilMs: g.untilMs } });
        const vOnly = (placement === "preroll" || placement === "midroll") ? " AND type = 'video'" : "";
        const tgtOk = await ensureAdTargetCol(db), tgtSql = tgtOk ? " AND (COALESCE(target_impressions, 0) <= 0 OR impressions < target_impressions)" : "";
        const rows = await db.prepare("SELECT * FROM ads WHERE active = 1" + vOnly + tgtSql + " AND (starts_at IS NULL OR starts_at <= ?) AND (ends_at IS NULL OR ends_at >= ?) AND (',' || placements || ',') LIKE ? ORDER BY RANDOM() LIMIT 3")
          .bind(now, now, "%," + placement + ",%").all();
        return json({ reelEvery: placement === "reels" ? await getReelAdEvery(db) : undefined, ads: (rows.results || []).map((a) => ({ id: a.id, name: a.name, type: a.type, mediaUrl: a.media_url, clickUrl: a.click_url || "", midAfter: a.mid_after || 30, skipAfter: a.skip_after || 0 })), vast: await (async () => { if (placement !== "preroll" && placement !== "midroll") return undefined; const v = await getVastCfg(db); return (placement === "preroll" ? v.pre : v.mid) && v.tags.length ? { tags: v.tags, midAfter: v.midAfter, gapSec: v.gapSec, native: v.native } : undefined; })() });
      } catch (_) { return json({ ads: [] }); }
    }
    if (method === "POST" && (m = path.match(/^\/api\/ads\/([^/]+)\/(impression|click)$/))) {
      try {
        const hk = (request.headers.get("CF-Connecting-IP") || "x") + "|" + m[1] + "|" + m[2], tNow = Date.now(), tLast = _adHit.get(hk);
        if (tLast && tNow - tLast < 15000) return json({ ok: true });
        _adHit.set(hk, tNow);
        if (_adHit.size > 5000) { for (const [k, t] of _adHit) if (tNow - t > 15000) _adHit.delete(k); if (_adHit.size > 5000) _adHit.clear(); }
      } catch (_) {}
      try {
        await ensurePlatformTables(db);
        const col = m[2] === "click" ? "clicks" : "impressions";
        if (col === "impressions" && await ensureAdTargetCol(db)) {
          // one single statement: count the view and, if that was the last bought view, switch the ad off in the same moment (no extra views can slip in)
          const rr = await db.prepare("UPDATE ads SET impressions = impressions + 1, active = CASE WHEN COALESCE(target_impressions, 0) > 0 AND impressions + 1 >= target_impressions THEN 0 ELSE active END WHERE id = ? AND active = 1 AND (COALESCE(target_impressions, 0) <= 0 OR impressions < target_impressions)").bind(m[1]).run();
          if (rr && rr.meta && rr.meta.changes === 1) {
            const row = await db.prepare("SELECT impressions, target_impressions FROM ads WHERE id = ?").bind(m[1]).first();
            if (row && row.target_impressions > 0 && row.impressions >= row.target_impressions) {
              await ensureCampTables(db);
              const nowT = Date.now(), cr = await db.prepare("UPDATE ad_campaigns SET status = 'ended', end_at = ?, resolved_at = ? WHERE ad_id = ? AND status = 'live'").bind(nowT, nowT, m[1]).run();
              if (cr && cr.meta && cr.meta.changes === 1) {
                try { const cc = await db.prepare("SELECT owner_id, name FROM ad_campaigns WHERE ad_id = ?").bind(m[1]).first(); if (cc) await addNotification(db, cc.owner_id, "info", "Your ad campaign is complete", "Your campaign \"" + cc.name + "\" reached all " + Number(row.target_impressions).toLocaleString("en-US") + " views and has stopped. You can see the results in Studio > Halal Ads.", true); } catch (_) {}
              }
            }
          }
        } else {
          await db.prepare("UPDATE ads SET " + col + " = " + col + " + 1 WHERE id = ? AND active = 1").bind(m[1]).run();
        }
      } catch (_) {}
      return json({ ok: true });
    }
    // ----- admin: platform settings (prayer location for the Salah guard + dashboard prayer times) -----
    if (method === "GET" && path === "/api/admin/settings") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const cfg = await getAppSettings(db), g = salahGuardState(Date.now(), cfg);
      return json({ ok: true, settings: cfg, methods: Object.keys(PRAYER_METHODS).map((k) => ({ key: k, name: PRAYER_METHODS[k].name })), guard: g });
    }
    if (method === "PUT" && path === "/api/admin/settings") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const b = await request.json().catch(() => ({}));
      const lat = parseFloat(b.lat), lng = parseFloat(b.lng), tz = parseFloat(b.tz), gm = Math.round(parseFloat(b.guardMin));
      if (!isFinite(lat) || lat < -90 || lat > 90) return err("Latitude must be between -90 and 90", 400);
      if (!isFinite(lng) || lng < -180 || lng > 180) return err("Longitude must be between -180 and 180", 400);
      if (!isFinite(tz) || tz < -12 || tz > 14) return err("Time zone must be between -12 and +14 hours", 400);
      if (!PRAYER_METHODS[b.method]) return err("Choose a calculation method", 400);
      if (!isFinite(gm) || gm < 1 || gm > 60) return err("Guard length must be between 1 and 60 minutes", 400);
      const kv = { prayer_city: String(b.city || "").trim().slice(0, 60), prayer_lat: String(lat), prayer_lng: String(lng), prayer_tz: String(tz), prayer_method: b.method, prayer_asr: b.hanafi === false ? "shafi" : "hanafi", salah_guard: b.guardOn === false ? "0" : "1", jummah_guard: b.jummah === false ? "0" : "1", guard_min: String(gm) };
      await db.batch(Object.keys(kv).map((k) => db.prepare("INSERT INTO app_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, kv[k])));
      const cfg = await getAppSettings(db);
      return json({ ok: true, settings: cfg, guard: salahGuardState(Date.now(), cfg) });
    }
    // ----- admin: halal ads (banners shown on the home page, under videos and on the reels screen) -----
    if (method === "GET" && path === "/api/admin/ads") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const rows = await db.prepare("SELECT * FROM ads ORDER BY created_at DESC LIMIT 300").all();
      const cfg = await getAppSettings(db);
      return json({ ok: true, ads: (rows.results || []).map(adOut), guard: salahGuardState(Date.now(), cfg), guardOn: cfg.guardOn, reelEvery: await getReelAdEvery(db), vast: await getVastCfg(db) });
    }
    if (method === "PUT" && path === "/api/admin/vast-settings") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      const b = await request.json().catch(() => ({}));
      const c = cleanVastCfg(b);
      if (c.error) return err(c.error, 400);
      try { await ensureAutoToolsTable(db); await setAutoTool(db, "vast_cfg", JSON.stringify(c.cfg)); } catch (_) { return err("Could not save", 500); }
      _vastMem = null;
      return json({ ok: true, vast: c.cfg });
    }
    if (method === "PUT" && path === "/api/admin/ads-settings") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      const b = await request.json().catch(() => ({}));
      const n = Math.round(Number(b.reelEvery));
      if (!(n >= 1 && n <= 50)) return err("Enter a number from 1 to 50", 400);
      try { await ensureAutoToolsTable(db); await setAutoTool(db, "reel_ad_every", n); } catch (_) { return err("Could not save", 500); }
      return json({ ok: true, reelEvery: n });
    }
    if (method === "POST" && path === "/api/admin/ads") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const b = await request.json().catch(() => ({}));
      const name = String(b.name || "").trim().slice(0, 80);
      if (!name) return err("Give the ad a name", 400);
      const type = b.type === "video" ? "video" : "image";
      const media = String(b.mediaUrl || "").trim();
      if (!/^https:\/\/[^\s]+$/.test(media)) return err("Upload the ad image or video first", 400);
      let click = String(b.clickUrl || "").trim();
      if (click && !/^https?:\/\/[^\s]+$/.test(click)) return err("The link must start with http:// or https://", 400);
      const places = (Array.isArray(b.placements) ? b.placements : []).filter((p) => AD_PLACEMENTS.includes(p));
      if (!places.length) return err("Choose where the ad should appear", 400);
      const starts = b.startsAt ? Number(b.startsAt) : null, ends = b.endsAt ? Number(b.endsAt) : null;
      if (starts && ends && ends < starts) return err("The end date is before the start date", 400);
      if (isVideoSlot(places) && type !== "video") return err("Pre-roll and mid-roll ads must be a video file (MP4)", 400);
      const id = uid("ad");
      const midAfter = Math.max(5, Math.min(3600, Math.round(Number(b.midAfter) || 30))), skipAfter = b.skip ? 5 : 0;
      if (await ensureAdVideoCols(db)) {
        await db.prepare("INSERT INTO ads (id, name, type, media_url, click_url, placements, active, starts_at, ends_at, created_at, mid_after, skip_after) VALUES (?,?,?,?,?,?,1,?,?,?,?,?)")
          .bind(id, name, type, media, click, [...new Set(places)].join(","), starts || null, ends || null, Date.now(), midAfter, skipAfter).run();
      } else {
        if (isVideoSlot(places)) return err("The server could not prepare video ads yet. Please try again.", 500);
        await db.prepare("INSERT INTO ads (id, name, type, media_url, click_url, placements, active, starts_at, ends_at, created_at) VALUES (?,?,?,?,?,?,1,?,?,?)")
          .bind(id, name, type, media, click, [...new Set(places)].join(","), starts || null, ends || null, Date.now()).run();
      }
      return json({ ok: true, id });
    }
    if ((method === "PATCH" || method === "DELETE") && (m = path.match(/^\/api\/admin\/ads\/([^/]+)$/))) {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const ad = await db.prepare("SELECT * FROM ads WHERE id = ?").bind(m[1]).first();
      if (!ad) return err("Ad not found", 404);
      if (method === "DELETE") { await db.prepare("DELETE FROM ads WHERE id = ?").bind(ad.id).run(); return json({ ok: true }); }
      const b = await request.json().catch(() => ({}));
      const sets = [], vals = [];
      if (b.active !== undefined) { sets.push("active = ?"); vals.push(b.active ? 1 : 0); }
      if (b.name !== undefined) { const n = String(b.name).trim().slice(0, 80); if (!n) return err("Give the ad a name", 400); sets.push("name = ?"); vals.push(n); }
      if (b.clickUrl !== undefined) { const c = String(b.clickUrl || "").trim(); if (c && !/^https?:\/\/[^\s]+$/.test(c)) return err("The link must start with http:// or https://", 400); sets.push("click_url = ?"); vals.push(c); }
      if (b.placements !== undefined) { const p = (Array.isArray(b.placements) ? b.placements : []).filter((x) => AD_PLACEMENTS.includes(x)); if (!p.length) return err("Choose where the ad should appear", 400); sets.push("placements = ?"); vals.push([...new Set(p)].join(",")); }
      if (b.startsAt !== undefined) { sets.push("starts_at = ?"); vals.push(b.startsAt ? Number(b.startsAt) : null); }
      if (b.endsAt !== undefined) { sets.push("ends_at = ?"); vals.push(b.endsAt ? Number(b.endsAt) : null); }
      {
        const finalPlaces = b.placements !== undefined ? (Array.isArray(b.placements) ? b.placements : []).filter((x) => AD_PLACEMENTS.includes(x)) : String(ad.placements || "").split(",").filter(Boolean);
        if (isVideoSlot(finalPlaces) && ad.type !== "video") return err("Pre-roll and mid-roll ads must be a video file (MP4)", 400);
        if (b.midAfter !== undefined || b.skip !== undefined) {
          if (!(await ensureAdVideoCols(db))) return err("The server could not prepare video ads yet. Please try again.", 500);
          if (b.midAfter !== undefined) { sets.push("mid_after = ?"); vals.push(Math.max(5, Math.min(3600, Math.round(Number(b.midAfter) || 30)))); }
          if (b.skip !== undefined) { sets.push("skip_after = ?"); vals.push(b.skip ? 5 : 0); }
        }
      }
      if (!sets.length) return err("Nothing to change", 400);
      await db.prepare("UPDATE ads SET " + sets.join(", ") + " WHERE id = ?").bind(...vals, ad.id).run();
      return json({ ok: true });
    }
    // ----- admin: send an in-app notification to a group of users (shows in their bell) -----
    if (method === "POST" && path === "/api/admin/broadcast") {
      const u = await adminUser(request, env);
      if (!u) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const b = await request.json().catch(() => ({}));
      const title = String(b.title || "").trim().slice(0, 80), message = String(b.message || "").trim().slice(0, 300);
      if (!title || !message) return err("Write a title and a message", 400);
      const where = { all: "", creators: " AND (id IN (SELECT owner_id FROM videos) OR id IN (SELECT owner_id FROM reels))", monetized: " AND monetization_enabled = 1", admins: " AND role = 'admin'" }[b.audience];
      if (where === undefined) return err("Choose who should receive it", 400);
      const r = await db.prepare("INSERT INTO notifications (id, user_id, type, title, message) SELECT 'bc_' || lower(hex(randomblob(8))), id, 'info', ?, ? FROM users WHERE role != 'guest' AND suspended = 0" + where).bind(title, message).run();
      const sent = (r.meta && r.meta.changes) || 0;
      await db.prepare("INSERT INTO broadcasts (id, admin_id, title, message, audience, sent_count, created_at) VALUES (?,?,?,?,?,?,?)").bind(uid("bc"), u.id, title, message, b.audience, sent, Date.now()).run();
      // phone push (Android app) for the same people, only when Firebase is set up
      const push = { configured: !!fcmAccount(env), topic: false, sent: 0 };
      if (push.configured) {
        try {
          await ensurePushTables(db);
          if (b.audience === "all") {
            const r2 = await fcmSend(env, { topic: "all" }, title, message, { type: "info" });
            push.topic = !!r2.ok;
          } else {
            const tk = await db.prepare("SELECT token FROM push_tokens WHERE user_id IN (SELECT id FROM users WHERE role != 'guest' AND suspended = 0" + where + ") LIMIT 40").all();
            const res = await Promise.all((tk.results || []).map(async (x) => {
              const r2 = await fcmSend(env, { token: x.token }, title, message, { type: "info" });
              if (r2.gone) { try { await db.prepare("DELETE FROM push_tokens WHERE token = ?").bind(x.token).run(); } catch (_) {} }
              return r2.ok ? 1 : 0;
            }));
            push.sent = res.reduce((a, c) => a + c, 0);
          }
        } catch (_) {}
      }
      return json({ ok: true, sent, push });
    }
    if (method === "GET" && path === "/api/admin/broadcasts") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const rows = await db.prepare("SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 50").all();
      return json({ ok: true, broadcasts: (rows.results || []).map((x) => ({ id: x.id, title: x.title, message: x.message, audience: x.audience, sent: x.sent_count, createdAt: x.created_at })) });
    }
    // ----- admin: who did what -----
    if (method === "GET" && path === "/api/admin/audit") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const rows = await db.prepare("SELECT * FROM audit_log ORDER BY ts DESC LIMIT 300").all();
      return json({ ok: true, entries: (rows.results || []).map((x) => ({ id: x.id, ts: x.ts, admin: x.admin_name || "Admin", action: x.action, method: x.method, path: x.path })) });
    }
    // ----- admin: platform analytics (real counts only) -----
    if (method === "GET" && path === "/api/admin/analytics") {
      if (!(await adminUser(request, env))) return err("Not allowed", 403);
      await ensurePlatformTables(db);
      const n = url.searchParams.get("days") === "90" ? 90 : url.searchParams.get("days") === "7" ? 7 : 30;
      const now = Date.now(), days = lastDays(n, now), ix = {};
      days.forEach((d, i) => { ix[d] = i; });
      const zero = () => new Array(n).fill(0);
      const out = { days, viewsVideos: zero(), viewsReels: zero(), signups: zero(), uploads: zero(), sadaqahPaise: zero(), firstViewDay: null, hasSignups: false };
      try {
        await ensureViewTables(db);
        const r = await db.prepare("SELECT day, kind, SUM(views) AS n FROM view_daily WHERE day >= ? GROUP BY day, kind").bind(days[0]).all();
        (r.results || []).forEach((x) => { const i = ix[x.day]; if (i !== undefined) out[x.kind === "r" ? "viewsReels" : "viewsVideos"][i] += x.n; });
        const f = await db.prepare("SELECT MIN(day) AS d FROM view_daily").first(); out.firstViewDay = f && f.d ? f.d : null;
      } catch (_) {}
      try {
        const r = await db.prepare("SELECT substr(created_at, 1, 10) AS d, COUNT(*) AS n FROM users WHERE role != 'guest' AND created_at IS NOT NULL AND substr(created_at, 1, 10) >= ? GROUP BY d").bind(days[0]).all();
        (r.results || []).forEach((x) => { const i = ix[x.d]; if (i !== undefined) out.signups[i] += x.n; });
        out.hasSignups = true;
      } catch (_) {}
      try {
        for (const t of ["videos", "reels"]) {
          const r = await db.prepare("SELECT substr(uploaded_at, 1, 10) AS d, COUNT(*) AS n FROM " + t + " WHERE uploaded_at IS NOT NULL AND substr(uploaded_at, 1, 10) >= ? GROUP BY d").bind(days[0]).all();
          (r.results || []).forEach((x) => { const i = ix[x.d]; if (i !== undefined) out.uploads[i] += x.n; });
        }
      } catch (_) {}
      try {
        await ensureSadaqahTables(db);
        const r = await db.prepare("SELECT date(resolved_at / 1000 + 19800, 'unixepoch') AS d, SUM(" + sdGross() + ") AS n FROM sadaqah_donations WHERE status = 'received' AND resolved_at > ? GROUP BY d").bind(now - n * 86400000 - 86400000).all();
        (r.results || []).forEach((x) => { const i = ix[x.d]; if (i !== undefined) out.sadaqahPaise[i] += x.n; });
      } catch (_) {}
      try {
        const c = await db.prepare("SELECT (SELECT COUNT(*) FROM users WHERE role != 'guest') AS users, (SELECT COUNT(*) FROM videos) AS videos, (SELECT COUNT(*) FROM reels) AS reels, (SELECT COALESCE(SUM(views),0) FROM videos) AS vviews, (SELECT COALESCE(SUM(views),0) FROM reels) AS rviews").first();
        out.totals = { users: c.users, videos: c.videos, reels: c.reels, videoViews: c.vviews, reelViews: c.rviews };
      } catch (_) { out.totals = null; }
      try { const tv = await db.prepare("SELECT v.id AS id, v.title AS title, u.name AS channel, v.views AS views FROM videos v LEFT JOIN users u ON u.id = v.owner_id WHERE v.hidden = 0 AND v.removed = 0 ORDER BY v.views DESC LIMIT 5").all(); out.topVideos = tv.results || []; } catch (_) { out.topVideos = []; }
      try { const tr = await db.prepare("SELECT r.id AS id, r.title AS title, u.name AS channel, r.views AS views FROM reels r LEFT JOIN users u ON u.id = r.owner_id WHERE r.hidden = 0 ORDER BY r.views DESC LIMIT 5").all(); out.topReels = tr.results || []; } catch (_) { out.topReels = []; }
      try { const tc = await db.prepare("SELECT u.id AS id, u.name AS name, SUM(v.views) AS views, COUNT(*) AS videos FROM videos v JOIN users u ON u.id = v.owner_id WHERE v.hidden = 0 AND v.removed = 0 GROUP BY u.id ORDER BY views DESC LIMIT 5").all(); out.topCreators = tc.results || []; } catch (_) { out.topCreators = []; }
      try { const a = await db.prepare("SELECT COALESCE(SUM(impressions),0) AS i, COALESCE(SUM(clicks),0) AS c FROM ads").first(); out.ads = { impressions: a.i, clicks: a.c }; } catch (_) {}
      return json({ ok: true, ...out });
    }
    // ================= CREATOR ANALYTICS routes =================
    // ----- viewer's app reports which 10% parts of a video were really watched (feeds Audience Retention in Studio) -----
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/retention$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return json({ ok: true, counted: false });
      try {
        const b = await request.json().catch(() => ({}));
        const segs = Array.isArray(b.segs) && b.segs.length === 10 ? b.segs.map((x) => (x ? 1 : 0)) : null;
        if (!segs || !segs.some((x) => x)) return json({ ok: true, counted: false });
        const v = await db.prepare("SELECT id, owner_id, duration, removed FROM videos WHERE id = ?").bind(m[1]).first();
        if (!v || v.removed || v.owner_id === u.id) return json({ ok: true, counted: false });
        await ensureRetentionTables(db);
        const now = Date.now();
        const recent = await db.prepare("SELECT COUNT(*) AS n FROM retention_seen WHERE viewer = ? AND ts > ?").bind(u.id, now - 3600000).first();
        if (recent && recent.n >= 60) return json({ ok: true, counted: false });
        const seen = await db.prepare("INSERT INTO retention_seen (viewer, video_id, ts) VALUES (?, ?, ?) ON CONFLICT(viewer, video_id) DO UPDATE SET ts = excluded.ts WHERE retention_seen.ts < ?").bind(u.id, v.id, now, now - 6 * 3600000).run();
        if (!seen.meta || seen.meta.changes !== 1) return json({ ok: true, counted: false });
        const dur = parseDurSec(v.duration);
        let secs = Math.round(Number(b.seconds) || 0);
        secs = Math.max(0, Math.min(secs, dur ? Math.round(dur * 2) : 7200));
        const stmts = [db.prepare("INSERT INTO video_watch_stats (video_id, sessions, seconds) VALUES (?, 1, ?) ON CONFLICT(video_id) DO UPDATE SET sessions = sessions + 1, seconds = seconds + excluded.seconds").bind(v.id, secs)];
        segs.forEach((on, i) => { if (on) stmts.push(db.prepare("INSERT INTO video_retention (video_id, bucket, n) VALUES (?, ?, 1) ON CONFLICT(video_id, bucket) DO UPDATE SET n = n + 1").bind(v.id, i)); });
        await db.batch(stmts);
        if (Math.random() < 0.02) { try { await db.prepare("DELETE FROM retention_seen WHERE ts < ?").bind(now - 7 * 86400000).run(); } catch (_) {} }
        return json({ ok: true, counted: true });
      } catch (_) { return json({ ok: true, counted: false }); }
    }
    // ----- creator: daily views of ONE video/reel for the last 90 days -----
    if (method === "GET" && (m = path.match(/^\/api\/me\/content-daily\/(v|r)\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Sign in to use Studio", 403);
      try {
        await ensureViewTables(db);
        const own = await db.prepare("SELECT id FROM " + (m[1] === "v" ? "videos" : "reels") + " WHERE id = ? AND owner_id = ?").bind(m[2], u.id).first();
        if (!own) return err("Not found", 404);
        const now = Date.now(), days = lastDays(90, now);
        const rows = await db.prepare("SELECT day, views FROM view_daily WHERE kind = ? AND content_id = ? AND day >= ?").bind(m[1], m[2], days[0]).all();
        const map = {};
        (rows.results || []).forEach((r) => { map[r.day] = r.views; });
        return json({ ok: true, days, views: days.map((d) => map[d] || 0) });
      } catch (_) { return err("Analytics unavailable", 500); }
    }
    // ================= SADAQAH routes =================
    // ----- donor: tap Nazrana under a video (creates a reference for the UPI note; the amount is entered in the UPI app) -----
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/sadaqah\/start$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Please sign in to give nazrana", 401);
      if (u.suspended) return err("This account cannot give nazrana", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana is temporarily unavailable. Try again later.", 503); }
      const S = await getSadaqahSettings(db);
      if (!S.enabled) return err("Nazrana is switched off right now.", 403);
      if (!S.upiId) return err("Nazrana is not available yet. Please try again later.", 503);
      const v = await db.prepare("SELECT id, owner_id, hidden, removed FROM videos WHERE id = ?").bind(m[1]).first();
      if (!v) return err("Video not found", 404);
      if (v.removed || v.hidden) return err("This video cannot receive nazrana", 400);
      if (v.owner_id === u.id) return err("You cannot give nazrana on your own video", 400);
      const recent = await db.prepare("SELECT COUNT(*) AS n FROM sadaqah_donations WHERE donor_id = ? AND created_at > ?").bind(u.id, Date.now() - 3600000).first();
      if (recent && recent.n >= 20) return err("Too many attempts. Please try again in a while.", 429);
      let ref = "";
      const id = uid("sd");
      for (let i = 0; i < 5 && !ref; i++) {
        const r = sadaqahRef();
        try {
          await db.prepare("INSERT INTO sadaqah_donations (id, ref, video_id, creator_id, donor_id, donor_name, status, created_at) VALUES (?,?,?,?,?,?,'initiated',?)")
            .bind(id, r, v.id, v.owner_id, u.id, u.name || "Guest", Date.now()).run();
          ref = r;
        } catch (_) { ref = ""; }
      }
      if (!ref) return err("Could not start nazrana. Please try again.", 500);
      if (Math.random() < 0.05) { try { await db.prepare("DELETE FROM sadaqah_donations WHERE status = 'initiated' AND created_at < ?").bind(Date.now() - 7 * 86400000).run(); } catch (_) {} }
      return json({ ok: true, ref, upiId: S.upiId, payeeName: S.payeeName });
    }
    // ----- donor: "I sent this much" (the admin still has to confirm it against the UPI statement) -----
    if (method === "POST" && (m = path.match(/^\/api\/sadaqah\/([A-Za-z0-9]+)\/claim$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Please sign in", 401);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana is temporarily unavailable. Try again later.", 503); }
      const b = await request.json().catch(() => ({}));
      const paise = parseRupeesToPaise(b.amount);
      if (!paise || paise < 100 || paise > SADAQAH_MAX_CLAIM_PAISE) return err("Enter the amount you sent, between \u20B91 and \u20B9" + (SADAQAH_MAX_CLAIM_PAISE / 100), 400);
      const utr = String(b.utr || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 30);
      const d = await db.prepare("SELECT id, status, donor_id FROM sadaqah_donations WHERE ref = ?").bind(m[1].toUpperCase()).first();
      if (!d || d.donor_id !== u.id) return err("Not found", 404);
      if (d.status !== "initiated" && d.status !== "claimed") return err("This nazrana was already processed", 409);
      await db.prepare("UPDATE sadaqah_donations SET status = 'claimed', claimed_paise = ?, utr = ?, claimed_at = ?, donor_name = ? WHERE id = ? AND status IN ('initiated', 'claimed')")
        .bind(paise, utr, Date.now(), u.name || "Guest", d.id).run();
      return json({ ok: true, amountPaise: paise });
    }
    // ----- creator: own nazrana numbers for Studio (donor names are never shown to creators) -----
    if (method === "GET" && path === "/api/me/sadaqah") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Sign in to see nazrana", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana data unavailable", 503); }
      const S = await getSadaqahSettings(db), bal = await sadaqahBalance(db, u.id);
      const vids = await db.prepare(
        "SELECT d.video_id AS video_id, v.title AS title, SUM(CASE WHEN d.status = 'received' THEN d.amount_paise ELSE 0 END) AS received, SUM(CASE WHEN d.status = 'received' THEN 1 ELSE 0 END) AS cnt, " +
        "SUM(CASE WHEN d.status = 'claimed' THEN d.claimed_paise ELSE 0 END) AS awaiting FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id " +
        "WHERE d.creator_id = ? AND d.status IN ('received', 'claimed') GROUP BY d.video_id ORDER BY received DESC, awaiting DESC LIMIT 200").bind(u.id).all();
      const recent = await db.prepare(
        "SELECT d.amount_paise, d.resolved_at, v.title AS title" + (sdDedOk ? ", d.gross_paise, d.deduct_json" : "") + " FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id WHERE d.creator_id = ? AND d.status = 'received' ORDER BY d.resolved_at DESC LIMIT 30").bind(u.id).all();
      const pend = await db.prepare("SELECT id, amount_paise, created_at FROM sadaqah_requests WHERE creator_id = ? AND status = 'Pending' LIMIT 1").bind(u.id).first();
      const hist = await db.prepare("SELECT id, amount_paise, status, created_at, resolved_at, note FROM sadaqah_requests WHERE creator_id = ? AND status != 'Pending' ORDER BY created_at DESC LIMIT 10").bind(u.id).all();
      let cuts = { grossPaise: 0, taxPaise: 0, platformPaise: 0, otherPaise: 0, netPaise: 0 };
      try { cuts = await sadaqahCutSummary(db, u.id); } catch (_) {}
      return json({
        ok: true, enabled: !!S.upiId, givingOn: S.enabled, unlockPaise: S.unlockPaise, minRequestPaise: S.minRequestPaise, ...bal, unlocked: bal.availablePaise >= S.unlockPaise,
        hasPayoutInfo: !!(u.payout_method && u.payout_account_number),
        payoutInfo: u.payout_method ? { method: u.payout_method, accountName: u.payout_account_name, accountNumber: u.payout_account_number, routingCode: u.payout_routing_code } : null,
        pending: pend ? { id: pend.id, amountPaise: pend.amount_paise, createdAt: pend.created_at } : null,
        videos: (vids.results || []).map((x) => ({ videoId: x.video_id, title: x.title || "Deleted video", receivedPaise: x.received || 0, count: x.cnt || 0, awaitingPaise: x.awaiting || 0 })),
        recent: (recent.results || []).map((x) => ({ amountPaise: x.amount_paise, grossPaise: x.gross_paise || x.amount_paise, deductions: parseDedJson(x.deduct_json), at: x.resolved_at, title: x.title || "Deleted video" })),
        cuts, rules: S.deductions.filter((x) => x.pct > 0).map((x) => ({ key: x.key, name: x.name, pct: x.pct })), cutNames: { tax: S.deductions[0].name, platform: S.deductions[1].name, other: S.deductions[2].name },
        requests: (hist.results || []).map((x) => ({ id: x.id, amountPaise: x.amount_paise, status: x.status, createdAt: x.created_at, resolvedAt: x.resolved_at, note: x.note || "" })),
      });
    }
    // ----- creator: request a withdrawal of nazrana (full or custom amount; needs the unlock limit + payout details) -----
    if (method === "POST" && path === "/api/me/sadaqah/withdraw") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Sign in to withdraw", 403);
      if (u.suspended) return err("Suspended accounts cannot withdraw", 403);
      if (!u.payout_method || !u.payout_account_number) return err("Add your account / UPI details first", 400);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana is temporarily unavailable. Try again later.", 503); }
      const S = await getSadaqahSettings(db), bal = await sadaqahBalance(db, u.id);
      if (bal.pendingPaise > 0) return err("You already have a withdrawal request pending", 409);
      if (bal.availablePaise < S.unlockPaise) return err("Withdrawals open when your available nazrana reaches " + rs2(S.unlockPaise), 400);
      const b = await request.json().catch(() => ({}));
      const paise = b.full === true || b.amount == null || b.amount === "" ? bal.availablePaise : parseRupeesToPaise(b.amount);
      if (!paise || paise < S.minRequestPaise) return err("The smallest withdrawal is " + rs2(S.minRequestPaise), 400);
      if (paise > bal.availablePaise) return err("You only have " + rs2(bal.availablePaise) + " available", 400);
      const id = uid("sr");
      let res;
      try {
        res = await db.prepare(
          "INSERT INTO sadaqah_requests (id, creator_id, amount_paise, method, account_name, account_number, routing_code, status, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, 'Pending', ? " +
          "WHERE COALESCE((SELECT SUM(amount_paise) FROM sadaqah_donations WHERE creator_id = ? AND status = 'received'), 0) - COALESCE((SELECT SUM(amount_paise) FROM sadaqah_requests WHERE creator_id = ? AND status IN ('Paid', 'Pending')), 0) >= ?")
          .bind(id, u.id, paise, u.payout_method, u.payout_account_name || "", u.payout_account_number, u.payout_routing_code || "", Date.now(), u.id, u.id, paise).run();
      } catch (_) { return err("You already have a withdrawal request pending", 409); }
      if (!res || !res.meta || res.meta.changes !== 1) return err("Your available nazrana changed. Please refresh and try again.", 409);
      return json({ ok: true, id, amountPaise: paise });
    }
    // ----- admin: everything about nazrana (settings, awaiting confirmation, history, per creator, per video, withdrawal requests) -----
    if (method === "GET" && path === "/api/admin/sadaqah") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const S = await getSadaqahSettings(db);
      const T = await db.prepare("SELECT COALESCE(SUM(CASE WHEN status = 'received' THEN " + sdGross() + " END), 0) AS received, COALESCE(SUM(CASE WHEN status = 'received' THEN amount_paise END), 0) AS net, " + sdCutCols() + " COUNT(CASE WHEN status = 'received' THEN 1 END) AS receivedCount, COALESCE(SUM(CASE WHEN status = 'claimed' THEN claimed_paise END), 0) AS awaiting, COUNT(CASE WHEN status = 'claimed' THEN 1 END) AS awaitingCount FROM sadaqah_donations").first();
      const R = await db.prepare("SELECT COALESCE(SUM(CASE WHEN status = 'Paid' THEN amount_paise END), 0) AS paid, COALESCE(SUM(CASE WHEN status = 'Pending' THEN amount_paise END), 0) AS pend, COUNT(CASE WHEN status = 'Pending' THEN 1 END) AS pendCount FROM sadaqah_requests").first();
      const base = "SELECT d.*, v.title AS vtitle, cu.name AS creator_name FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id LEFT JOIN users cu ON cu.id = d.creator_id ";
      const awaiting = await db.prepare(base + "WHERE d.status = 'claimed' ORDER BY d.claimed_at ASC LIMIT 300").all();
      const unclaimed = await db.prepare(base + "WHERE d.status = 'initiated' AND d.created_at > ? ORDER BY d.created_at DESC LIMIT 50").bind(Date.now() - 3 * 86400000).all();
      const history = await db.prepare(base + "WHERE d.status IN ('received', 'rejected') ORDER BY d.resolved_at DESC LIMIT 150").all();
      const cr = await db.prepare("SELECT cu.id AS id, cu.name AS name, cu.email AS email, COALESCE(SUM(CASE WHEN d.status = 'received' THEN d.amount_paise END), 0) AS received, COALESCE(SUM(CASE WHEN d.status = 'received' THEN " + sdGross("d") + " END), 0) AS gross, COUNT(CASE WHEN d.status = 'received' THEN 1 END) AS cnt FROM sadaqah_donations d JOIN users cu ON cu.id = d.creator_id GROUP BY cu.id ORDER BY received DESC LIMIT 300").all();
      const rq = await db.prepare("SELECT creator_id, COALESCE(SUM(CASE WHEN status = 'Paid' THEN amount_paise END), 0) AS paid, COALESCE(SUM(CASE WHEN status = 'Pending' THEN amount_paise END), 0) AS pend FROM sadaqah_requests GROUP BY creator_id").all();
      const rqMap = {};
      (rq.results || []).forEach((x) => { rqMap[x.creator_id] = x; });
      const pv = await db.prepare("SELECT d.video_id AS video_id, v.title AS title, cu.name AS creator, SUM(" + sdGross("d") + ") AS received, COUNT(*) AS cnt FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id LEFT JOIN users cu ON cu.id = d.creator_id WHERE d.status = 'received' GROUP BY d.video_id ORDER BY received DESC LIMIT 100").all();
      const reqBase = "SELECT w.*, users.name AS user_name, users.email AS user_email FROM sadaqah_requests w LEFT JOIN users ON users.id = w.creator_id ";
      const pend = await db.prepare(reqBase + "WHERE w.status = 'Pending' ORDER BY w.created_at ASC").all();
      const done = await db.prepare(reqBase + "WHERE w.status != 'Pending' ORDER BY w.resolved_at DESC LIMIT 25").all();
      const paidAll = await db.prepare(reqBase + "WHERE w.status = 'Paid' ORDER BY w.resolved_at DESC LIMIT 300").all();
      const reqOut = (w) => ({ id: w.id, creatorId: w.creator_id, name: w.user_name || "Deleted user", email: w.user_email || "", amountPaise: w.amount_paise, status: w.status, createdAt: w.created_at, resolvedAt: w.resolved_at, note: w.note || "",
        payoutInfo: w.method ? { method: w.method, accountName: w.account_name, accountNumber: w.account_number, routingCode: w.routing_code } : null });
      const received = T.received || 0, net = T.net || 0, paid = R.paid || 0, pending = R.pend || 0;
      return json({
        ok: true, settings: S,
        totals: { receivedPaise: received, netPaise: net, taxPaise: T.tax || 0, platformPaise: T.platform || 0, otherPaise: T.other || 0, owedPaise: Math.max(0, net - paid), receivedCount: T.receivedCount || 0, paidPaise: paid, pendingRequestPaise: pending, pendingRequestCount: R.pendCount || 0, heldPaise: Math.max(0, received - paid), awaitingPaise: T.awaiting || 0, awaitingCount: T.awaitingCount || 0 },
        awaiting: (awaiting.results || []).map(sadaqahDonationOut), unclaimed: (unclaimed.results || []).map(sadaqahDonationOut), history: (history.results || []).map(sadaqahDonationOut),
        creators: (cr.results || []).map((x) => { const q = rqMap[x.id] || {}; const pd = q.paid || 0, pn = q.pend || 0; return { id: x.id, name: x.name, email: x.email, receivedPaise: x.received || 0, grossPaise: x.gross || x.received || 0, count: x.cnt || 0, paidPaise: pd, pendingPaise: pn, availablePaise: Math.max(0, (x.received || 0) - pd - pn) }; }),
        videos: (pv.results || []).map((x) => ({ videoId: x.video_id, title: x.title || "Deleted video", creator: x.creator || "", receivedPaise: x.received || 0, count: x.cnt || 0 })),
        requests: (pend.results || []).map(reqOut), recentRequests: (done.results || []).map(reqOut), paidList: (paidAll.results || []).map(reqOut),
      });
    }
    // ----- admin: download records as a CSV file (opens in Excel / Google Sheets) -----
    if (method === "GET" && path === "/api/admin/sadaqah/export") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const type = new URL(request.url).searchParams.get("type") === "payouts" ? "payouts" : "donations";
      const rows = [];
      if (type === "payouts") {
        rows.push(csvRow(["Paid on (IST)", "Requested on (IST)", "Creator", "Email", "Amount paid (INR)", "Method", "Account holder", "Account / UPI", "IFSC / code", "Reference"]));
        const r = await db.prepare("SELECT w.*, users.name AS user_name, users.email AS user_email FROM sadaqah_requests w LEFT JOIN users ON users.id = w.creator_id WHERE w.status = 'Paid' ORDER BY w.resolved_at DESC LIMIT 20000").all();
        (r.results || []).forEach((w) => rows.push(csvRow([istStr(w.resolved_at), istStr(w.created_at), w.user_name || "Deleted user", w.user_email || "", rupees2(w.amount_paise), w.method || "", w.account_name || "", w.account_number || "", w.routing_code || "", w.note || ""])));
      } else {
        rows.push(csvRow(["Date (IST)", "Reference", "Status", "Video", "Creator", "Creator email", "Donor", "Amount (INR)", "Tax (INR)", "Platform fee (INR)", "Other (INR)", "Total cut (INR)", "Creator got (INR)", "Cut details", "Donor UTR", "Note"]));
        const r = await db.prepare("SELECT d.*, v.title AS vtitle, cu.name AS creator_name, cu.email AS creator_email FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id LEFT JOIN users cu ON cu.id = d.creator_id WHERE d.status IN ('received', 'rejected') ORDER BY d.resolved_at DESC LIMIT 20000").all();
        (r.results || []).forEach((d) => {
          const ok = d.status === "received", gross = ok ? (d.gross_paise || d.amount_paise) : d.claimed_paise, tax = d.tax_paise || 0, pl = d.platform_paise || 0, ot = d.other_paise || 0;
          rows.push(csvRow([istStr(d.resolved_at), d.ref, ok ? "Received" : "Not received", d.vtitle || "Deleted video", d.creator_name || "", d.creator_email || "", d.donor_name || "Guest", rupees2(gross), ok ? rupees2(tax) : "", ok ? rupees2(pl) : "", ok ? rupees2(ot) : "", ok ? rupees2(tax + pl + ot) : "", ok ? rupees2(d.amount_paise) : "",
            ok ? parseDedJson(d.deduct_json).map((x) => x.name + " " + x.pct + "% = " + rupees2(x.paise)).join("; ") : "", d.utr || "", d.note || ""]));
        });
      }
      return new Response("\uFEFF" + rows.join("\r\n"), { status: 200, headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=\"noortube-nazrana-" + type + ".csv\"", "Cache-Control": "no-store", ...cors() } });
    }
    // ----- admin: UPI id the donors pay + the withdrawal limit -----
    if (method === "PUT" && path === "/api/admin/sadaqah/settings") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const b = await request.json().catch(() => ({}));
      const upiId = String(b.upiId == null ? "" : b.upiId).trim();
      if (upiId && !/^[A-Za-z0-9._\-]{2,64}@[A-Za-z0-9._\-]{2,32}$/.test(upiId)) return err("Enter a valid UPI ID like name@bank", 400);
      const payeeName = String(b.payeeName == null ? "" : b.payeeName).trim().slice(0, 60) || "NoorTube Nazrana";
      const unlock = parseRupeesToPaise(b.unlockRupees);
      if (!unlock || unlock < SADAQAH_MIN_REQUEST_PAISE || unlock > 100000000) return err("The withdrawal limit must be between \u20B9100 and \u20B910,00,000", 400);
      let dedJson = null;
      if (b.deductions !== undefined) {
        const src = Array.isArray(b.deductions) ? b.deductions : [];
        let total = 0;
        const list = [];
        for (const d of SD_DED_DEFAULTS) {
          const x = src.find((y) => y && y.key === d.key) || {};
          const raw = x.pct === "" || x.pct == null ? 0 : Number(x.pct);
          if (!isFinite(raw) || raw < 0 || raw > 50) return err("Each deduction must be between 0% and 50%", 400);
          const pct = Math.round(raw * 100) / 100;
          total += pct;
          list.push({ key: d.key, name: String(x.name == null ? "" : x.name).trim().slice(0, 30) || d.name, pct });
        }
        if (total > 60) return err("The total of all deductions cannot be more than 60%", 400);
        if (total > 0 && !(await ensureSadaqahDedCols(db))) return err("The server could not prepare deductions yet. Please try again.", 500);
        dedJson = JSON.stringify(list);
      }
      await db.batch([
        ...(b.enabled !== undefined ? [db.prepare("INSERT INTO sadaqah_settings (k, v) VALUES ('enabled', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(b.enabled === false || b.enabled === "0" || b.enabled === 0 ? "0" : "1")] : []),
        ...(dedJson !== null ? [db.prepare("INSERT INTO sadaqah_settings (k, v) VALUES ('deductions', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(dedJson)] : []),
        db.prepare("INSERT INTO sadaqah_settings (k, v) VALUES ('upi_id', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(upiId),
        db.prepare("INSERT INTO sadaqah_settings (k, v) VALUES ('payee_name', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(payeeName),
        db.prepare("INSERT INTO sadaqah_settings (k, v) VALUES ('unlock_paise', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(String(unlock)),
      ]);
      return json({ ok: true, settings: await getSadaqahSettings(db) });
    }
    // ----- admin: the money really arrived in your UPI -> count it for the creator (amount can be corrected to what you actually received) -----
    if (method === "POST" && (m = path.match(/^\/api\/admin\/sadaqah\/donations\/([^/]+)\/confirm$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const d = await db.prepare("SELECT d.*, v.title AS vtitle FROM sadaqah_donations d LEFT JOIN videos v ON v.id = d.video_id WHERE d.id = ?").bind(m[1]).first();
      if (!d) return err("Not found", 404);
      if (d.status !== "claimed" && d.status !== "initiated") return err("This nazrana was already handled", 409);
      const b = await request.json().catch(() => ({}));
      const paise = b.amount != null && b.amount !== "" ? parseRupeesToPaise(b.amount) : d.claimed_paise;
      if (!paise || paise < 100 || paise > SADAQAH_MAX_CLAIM_PAISE) return err("Enter the amount you received", 400);
      const S = await getSadaqahSettings(db);
      const parts = sdDedOk ? S.deductions.filter((x) => x.pct > 0).map((x) => ({ key: x.key, name: x.name, pct: x.pct, paise: Math.round(paise * x.pct / 100) })) : [];
      const cutTotal = parts.reduce((s, x) => s + x.paise, 0), net = Math.max(0, paise - cutTotal);
      const cutOf = (k) => parts.filter((x) => x.key === k).reduce((s, x) => s + x.paise, 0);
      const now = Date.now();
      const r = sdDedOk
        ? await db.prepare("UPDATE sadaqah_donations SET status = 'received', amount_paise = ?, gross_paise = ?, tax_paise = ?, platform_paise = ?, other_paise = ?, deduct_json = ?, resolved_at = ? WHERE id = ? AND status IN ('claimed', 'initiated')")
            .bind(net, paise, cutOf("tax"), cutOf("platform"), cutOf("other"), JSON.stringify(parts.map((x) => ({ name: x.name, pct: x.pct, paise: x.paise }))), now, d.id).run()
        : await db.prepare("UPDATE sadaqah_donations SET status = 'received', amount_paise = ?, resolved_at = ? WHERE id = ? AND status IN ('claimed', 'initiated')").bind(paise, now, d.id).run();
      if (!r.meta || r.meta.changes !== 1) return err("This nazrana was already handled", 409);
      try { await addNotification(db, d.creator_id, "info", "Nazrana received", "You received " + rs2(net) + " nazrana on \"" + (d.vtitle || "your video") + "\"." + (parts.length ? " Total " + rs2(paise) + ", minus " + parts.map((x) => x.name + " " + rs2(x.paise)).join(", ") + "." : "") + " Open Studio > Nazrana to see it.", true); } catch (_) {}
      if (d.donor_id) { try { await addNotification(db, d.donor_id, "info", "Nazrana received", "Your nazrana of " + rs2(paise) + " was received. JazakAllahu khayran.", true); } catch (_) {} }
      return json({ ok: true, amountPaise: paise, netPaise: net, deductions: parts });
    }
    if (method === "POST" && (m = path.match(/^\/api\/admin\/sadaqah\/donations\/([^/]+)\/reject$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const b = await request.json().catch(() => ({}));
      const note = String(b.note || "").trim().slice(0, 300);
      const d = await db.prepare("SELECT * FROM sadaqah_donations WHERE id = ?").bind(m[1]).first();
      if (!d) return err("Not found", 404);
      const r = await db.prepare("UPDATE sadaqah_donations SET status = 'rejected', resolved_at = ?, note = ? WHERE id = ? AND status IN ('claimed', 'initiated')").bind(Date.now(), note, d.id).run();
      if (!r.meta || r.meta.changes !== 1) return err("This nazrana was already handled", 409);
      if (d.donor_id && d.claimed_paise) { try { await addNotification(db, d.donor_id, "info", "Nazrana not found", "We could not find your nazrana of " + rs2(d.claimed_paise) + " in our account." + (note ? " " + note : ""), true); } catch (_) {} }
      return json({ ok: true });
    }
    // ----- admin: creator's nazrana withdrawal: after paying them, mark Paid (their available balance drops by that amount) -----
    if (method === "POST" && (m = path.match(/^\/api\/admin\/sadaqah\/requests\/([^/]+)\/mark-paid$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const w = await db.prepare("SELECT * FROM sadaqah_requests WHERE id = ?").bind(m[1]).first();
      if (!w) return err("Request not found", 404);
      const pb = await request.json().catch(() => ({}));
      const payRef = String((pb && pb.reference) || "").trim().slice(0, 60);
      const r = await db.prepare("UPDATE sadaqah_requests SET status = 'Paid', resolved_at = ?, note = ? WHERE id = ? AND status = 'Pending'").bind(Date.now(), payRef ? "Ref: " + payRef : null, w.id).run();
      if (!r.meta || r.meta.changes !== 1) return err("This request was already handled", 409);
      let stmt = "";
      try {
        const cs = await sadaqahCutSummary(db, w.creator_id), SS = await getSadaqahSettings(db), nm = (k) => (SS.deductions.find((x) => x.key === k) || {}).name || k;
        const bits = [[cs.taxPaise, nm("tax")], [cs.platformPaise, nm("platform")], [cs.otherPaise, nm("other")]].filter((x) => x[0] > 0).map((x) => x[1] + " " + rs2(x[0]));
        if (bits.length) stmt = " Your nazrana so far: " + rs2(cs.grossPaise) + " received, minus " + bits.join(", ") + " = " + rs2(cs.netPaise) + " credited to you.";
      } catch (_) {}
      try { await addNotification(db, w.creator_id, "info", "Nazrana withdrawal paid", "Your nazrana withdrawal of " + rs2(w.amount_paise) + " has been paid." + (payRef ? " Payment reference: " + payRef + "." : "") + stmt, true); } catch (_) {}
      return json({ ok: true, paidPaise: w.amount_paise });
    }
    if (method === "POST" && (m = path.match(/^\/api\/admin\/sadaqah\/requests\/([^/]+)\/reject$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureSadaqahTables(db); } catch (_) { return err("Nazrana tables unavailable", 503); }
      const b = await request.json().catch(() => ({}));
      const note = String(b.note || "").trim().slice(0, 300);
      const w = await db.prepare("SELECT * FROM sadaqah_requests WHERE id = ?").bind(m[1]).first();
      if (!w) return err("Request not found", 404);
      const r = await db.prepare("UPDATE sadaqah_requests SET status = 'Rejected', resolved_at = ?, note = ? WHERE id = ? AND status = 'Pending'").bind(Date.now(), note, w.id).run();
      if (!r.meta || r.meta.changes !== 1) return err("This request was already handled", 409);
      try { await addNotification(db, w.creator_id, "info", "Nazrana withdrawal not approved", "Your nazrana withdrawal request of " + rs2(w.amount_paise) + " was not approved." + (note ? " Reason: " + note : " Please check your account / UPI details and request again."), true); } catch (_) {}
      return json({ ok: true });
    }
    // ----- creator: request a withdrawal of the full unpaid balance (needs minimum + payout details) -----
    if (method === "POST" && path === "/api/me/withdraw") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      if (u.role === "guest") return err("Sign in to withdraw", 403);
      if (u.suspended) return err("Suspended accounts cannot withdraw", 403);
      if (!u.monetization_enabled) return err("Monetization is not enabled for your channel", 403);
      if (!u.payout_method || !u.payout_account_number) return err("Add your payout details first", 400);
      const S = await getPayoutSettings(db);
      try { await ensureWithdrawTable(db); } catch (_) { return err("Withdrawals are temporarily unavailable. Try again later.", 503); }
      if (await getPendingWithdraw(db, u.id)) return err("You already have a withdrawal request pending", 409);
      const e = await computeEarnings(db, u.id, S);
      if (e.c.creator < WITHDRAW_MIN_CENTS) return err("Minimum limit not reached. You need at least $" + (WITHDRAW_MIN_CENTS / 100).toFixed(2) + " to withdraw.", 400);
      // The creator may ask for any amount between the minimum and everything available. No amount sent (older app) = everything, exactly as before.
      const body = await request.json().catch(() => ({}));
      let want = e.c.creator;
      if (body && body.amountUsd !== undefined && body.amountUsd !== null && body.amountUsd !== "") {
        const n = Number(body.amountUsd);
        if (!Number.isFinite(n) || n <= 0) return err("Enter a valid amount", 400);
        want = Math.round(n * 100);
        if (Math.abs(n * 100 - want) > 0.0001) return err("Use at most 2 decimals, like 120.50", 400);
        if (want < WITHDRAW_MIN_CENTS) return err("The minimum withdrawal is $" + (WITHDRAW_MIN_CENTS / 100).toFixed(2), 400);
        if (want > e.c.creator) return err("You can withdraw at most $" + (e.c.creator / 100).toFixed(2), 400);
      }
      // Whole balance: freeze today's view totals. Part of it: move the "already paid" view line forward by the same share, so the rest stays in the creator's balance.
      let vSnap = e.totals.v, rSnap = e.totals.r;
      if (want < e.c.creator) {
        const rec = await db.prepare("SELECT v_views, r_views FROM payout_records WHERE user_id = ?").bind(u.id).first();
        const vb = rec ? Math.min(rec.v_views, e.totals.v) : 0, rb = rec ? Math.min(rec.r_views, e.totals.r) : 0, f = want / e.c.creator;
        let vA = Math.floor(e.vNew * f), rA = Math.floor(e.rNew * f);
        // rounding must never cost the creator: do not move the line further than the amount asked for is worth
        for (let k = 0; k < 800 && payoutCents(vA, rA, S).creator > want && (vA > 0 || rA > 0); k++) { if (vA > 0) vA--; if (rA > 0) rA--; }
        vSnap = vb + vA; rSnap = rb + rA;
      }
      const id = uid("wr");
      try {
        await db.prepare("INSERT INTO withdraw_requests (id, user_id, amount_cents, v_snap, r_snap, method, account_name, account_number, routing_code, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,'Pending',?)")
          .bind(id, u.id, want, vSnap, rSnap, u.payout_method, u.payout_account_name || "", u.payout_account_number, u.payout_routing_code || "", Date.now()).run();
      } catch (_) { return err("You already have a withdrawal request pending", 409); }
      return json({ ok: true, id, amountUsd: want / 100 });
    }
    // ----- admin: find (and optionally remove) duplicate uploads that already exist -----
    if (method === "POST" && path === "/api/admin/scan-duplicates") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      if (!(await ensureCopyrightColumns(db))) return err("Could not prepare the database for duplicate scanning", 500);
      const body = await request.json().catch(() => ({}));
      return json(await runDuplicateScan(db, env, !!(body && body.apply === true)));
    }
    // ----- admin: hourly auto-scan on/off + last run -----
    if (path === "/api/admin/auto-scan" && (method === "GET" || method === "PUT")) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try {
        if (method === "PUT") {
          const b = await request.json().catch(() => ({}));
          await ensureAutoToolsTable(db);
          await setAutoTool(db, "dup_auto", b && b.enabled === true ? "1" : "0");
        }
        return json({ ok: true, ...(await getAutoTools(db)) });
      } catch (_) { return err("Could not read or save the auto-scan setting", 500); }
    }
    // ----- admin: create / delete a TEST monetized creator account (random password, shown once) -----
    if (method === "POST" && path === "/api/admin/demo-account") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const body = await request.json().catch(() => ({}));
      const DEMO_EMAIL = "demo.creator@noortube.test";
      await ensurePayoutTables(db);
      try { await ensureWithdrawTable(db); } catch (_) {}
      const old = await db.prepare("SELECT id FROM users WHERE email = ?").bind(DEMO_EMAIL).first();
      if (old) { // remove the previous demo account completely (same clean-up as deleting a user)
        const t = old.id;
        const dels = [
          db.prepare("DELETE FROM comments WHERE user_id = ? OR target_id IN (SELECT id FROM videos WHERE owner_id = ?) OR target_id IN (SELECT id FROM reels WHERE owner_id = ?)").bind(t, t, t),
          db.prepare("DELETE FROM video_likes WHERE user_id = ?").bind(t), db.prepare("DELETE FROM reel_likes WHERE user_id = ?").bind(t),
          db.prepare("DELETE FROM saved_videos WHERE user_id = ?").bind(t), db.prepare("DELETE FROM watch_history WHERE user_id = ?").bind(t),
          db.prepare("DELETE FROM notifications WHERE user_id = ?").bind(t), db.prepare("DELETE FROM follows WHERE follower_id = ? OR followee_id = ?").bind(t, t),
          db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(t), db.prepare("DELETE FROM anon_sessions WHERE user_id = ?").bind(t),
          db.prepare("DELETE FROM videos WHERE owner_id = ?").bind(t), db.prepare("DELETE FROM reels WHERE owner_id = ?").bind(t),
          db.prepare("DELETE FROM statuses WHERE owner_id = ?").bind(t),
          db.prepare("DELETE FROM payout_records WHERE user_id = ?").bind(t), db.prepare("DELETE FROM withdraw_requests WHERE user_id = ?").bind(t),
          db.prepare("DELETE FROM users WHERE id = ?").bind(t),
        ];
        await purgeSadaqah(db, t);
        await db.batch(dels);
      }
      if (body.action === "delete") return json({ ok: true, deleted: !!old });
      const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      const rnd = crypto.getRandomValues(new Uint8Array(12));
      const password = Array.from(rnd, (b) => alphabet[b % alphabet.length]).join("");
      const { hash, salt } = await hashPassword(password);
      const id = uid("u");
      await db.prepare("INSERT INTO users (id, name, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)").bind(id, "Demo Creator (TEST)", DEMO_EMAIL, hash, salt).run();
      await db.prepare("UPDATE users SET monetization_enabled = 1, watch_hours = ?, avatar_color = ?, payout_method = ?, payout_account_name = ?, payout_account_number = ?, payout_routing_code = ? WHERE id = ?")
        .bind(3500, "#0d9488", "upi", "Demo Creator", "democreator@upi", "", id).run();
      const SAMPLE = "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4";
      const vids = [
        ["[DEMO] Surah Ar-Rahman — Beautiful Recitation", "Quran", "Surah/Qirat", 310000, 5200],
        ["[DEMO] The Importance of Salah — Lecture", "Lecture", "Takreer", 180000, 3100],
        ["[DEMO] Story of Prophet Yusuf (AS)", "Stories", "Takreer", 95000, 1900],
      ];
      for (let i = 0; i < vids.length; i++) {
        const [title, cat, mix, views, likes] = vids[i];
        const vid = uid("v");
        await db.prepare(`INSERT INTO videos (id, owner_id, title, description, tags, category, mix_category, source_type, youtube_id, file_url, thumbnail, duration, trim_start, trim_end, monetized, copyright_status, removed, content_hash)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(vid, id, title, "Demo video for testing the monetized creator account. It will be deleted with the demo account.", JSON.stringify(["demo"]), cat, mix, "gallery", null, SAMPLE, `https://picsum.photos/seed/noordemo${i + 1}/640/360`, "0:06", null, null, 1, "clear", 0, null).run();
        await db.prepare("UPDATE videos SET views = ?, likes = ? WHERE id = ?").bind(views, likes, vid).run();
      }
      const rls = [["[DEMO] Short reminder 1", 420000, 6100], ["[DEMO] Short reminder 2", 260000, 3300]];
      for (let i = 0; i < rls.length; i++) {
        const [title, views, likes] = rls[i];
        const rid = uid("r");
        await db.prepare("INSERT INTO reels (id, owner_id, title, tags, file_url, thumbnail, trim_start, trim_end, mix_category) VALUES (?,?,?,?,?,?,?,?,?)")
          .bind(rid, id, title, JSON.stringify(["demo"]), SAMPLE, `https://picsum.photos/seed/noordemoreel${i + 1}/200/350`, null, null, "Naat").run();
        await db.prepare("UPDATE reels SET views = ?, likes = ? WHERE id = ?").bind(views, likes, rid).run();
      }
      const S = await getPayoutSettings(db);
      const e = await computeEarnings(db, id, S);
      return json({ ok: true, email: DEMO_EMAIL, password, name: "Demo Creator (TEST)", videos: vids.length, reels: rls.length, creatorEarningsUsd: e.c.creator / 100, minWithdrawUsd: WITHDRAW_MIN_CENTS / 100 });
    }
    // ----- admin: pending withdrawal requests -----
    if (method === "GET" && path === "/api/admin/withdraw-requests") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      await ensureWithdrawTable(db);
      const rows = await db.prepare("SELECT w.*, users.name AS user_name, users.email AS user_email FROM withdraw_requests w JOIN users ON users.id = w.user_id WHERE w.status = 'Pending' ORDER BY w.created_at ASC").all();
      return json({ minWithdrawUsd: WITHDRAW_MIN_CENTS / 100, requests: (rows.results || []).map((w) => ({
        id: w.id, userId: w.user_id, name: w.user_name, email: w.user_email, amountCents: w.amount_cents, amountUsd: w.amount_cents / 100, createdAt: w.created_at,
        payoutInfo: w.method ? { method: w.method, accountName: w.account_name, accountNumber: w.account_number, routingCode: w.routing_code } : null,
      })) });
    }
    // ----- admin: after paying the creator, mark the request Paid (this also resets their balance by the paid amount) -----
    if (method === "POST" && (m = path.match(/^\/api\/admin\/withdraw-requests\/([^/]+)\/mark-paid$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      await ensureWithdrawTable(db);
      await ensurePayoutTables(db);
      const w = await db.prepare("SELECT * FROM withdraw_requests WHERE id = ?").bind(m[1]).first();
      if (!w) return err("Request not found", 404);
      if (w.status !== "Pending") return err("This request was already handled", 409);
      const rec = await db.prepare("SELECT v_views, r_views FROM payout_records WHERE user_id = ?").bind(w.user_id).first();
      if (rec && (rec.v_views > w.v_snap || rec.r_views > w.r_snap)) return err("This creator's payout record changed after the request was made. Reject this request and ask them to request again.", 409);
      const now = Date.now();
      // One batch (one transaction): the payout record is only written while the request is still Pending, so a double tap can never pay twice.
      const res = await db.batch([
        db.prepare("INSERT INTO payout_records (user_id, v_views, r_views, paid_cents, last_paid_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM withdraw_requests WHERE id = ? AND status = 'Pending') ON CONFLICT(user_id) DO UPDATE SET v_views = excluded.v_views, r_views = excluded.r_views, paid_cents = payout_records.paid_cents + excluded.paid_cents, last_paid_at = excluded.last_paid_at")
          .bind(w.user_id, w.v_snap, w.r_snap, w.amount_cents, now, w.id),
        db.prepare("UPDATE withdraw_requests SET status = 'Paid', resolved_at = ? WHERE id = ? AND status = 'Pending'").bind(now, w.id),
      ]);
      const changed = res && res[1] && res[1].meta ? res[1].meta.changes : 0;
      if (changed !== 1) return err("This request was already handled", 409);
      try { await addNotification(db, w.user_id, "info", "Withdrawal Paid", "Your withdrawal of $" + (w.amount_cents / 100).toFixed(2) + " has been paid.", true); } catch (_) {}
      return json({ ok: true, paidUsd: w.amount_cents / 100 });
    }
    // ----- admin: reject a request (balance stays with the creator, nothing is deducted) -----
    if (method === "POST" && (m = path.match(/^\/api\/admin\/withdraw-requests\/([^/]+)\/reject$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      await ensureWithdrawTable(db);
      const b = await request.json().catch(() => ({}));
      const note = String(b.note || "").trim().slice(0, 300);
      const w = await db.prepare("SELECT * FROM withdraw_requests WHERE id = ?").bind(m[1]).first();
      if (!w) return err("Request not found", 404);
      const r = await db.prepare("UPDATE withdraw_requests SET status = 'Rejected', resolved_at = ?, note = ? WHERE id = ? AND status = 'Pending'").bind(Date.now(), note, w.id).run();
      if (!r.meta || r.meta.changes !== 1) return err("This request was already handled", 409);
      try { await addNotification(db, w.user_id, "info", "Withdrawal Request Rejected", "Your withdrawal request of $" + (w.amount_cents / 100).toFixed(2) + " was not approved." + (note ? " Reason: " + note : " Please check your payout details and request again."), true); } catch (_) {}
      return json({ ok: true });
    }
    // ----- admin: payouts overview -----
    if (method === "GET" && path === "/api/admin/payouts") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const S = await getPayoutSettings(db);
      const users = await db.prepare("SELECT * FROM users WHERE monetization_enabled = 1 AND role != 'guest' ORDER BY created_at DESC").all();
      const vRows = await db.prepare("SELECT owner_id, COALESCE(SUM(views), 0) AS n FROM videos WHERE monetized = 1 AND removed = 0 GROUP BY owner_id").all();
      const rRows = await db.prepare("SELECT owner_id, COALESCE(SUM(views), 0) AS n FROM reels GROUP BY owner_id").all();
      const recRows = await db.prepare("SELECT user_id, v_views, r_views, paid_cents, last_paid_at FROM payout_records").all();
      const pendSet = {};
      try { await ensureWithdrawTable(db); const pr = await db.prepare("SELECT user_id FROM withdraw_requests WHERE status = 'Pending'").all(); (pr.results || []).forEach((x) => { pendSet[x.user_id] = true; }); } catch (_) {}
      const vMap = {}, rMap = {}, recMap = {};
      (vRows.results || []).forEach((x) => { vMap[x.owner_id] = x.n; });
      (rRows.results || []).forEach((x) => { rMap[x.owner_id] = x.n; });
      (recRows.results || []).forEach((x) => { recMap[x.user_id] = x; });
      const rows = (users.results || []).map((usr) => {
        const e = payoutFromTotals({ v: vMap[usr.id] || 0, r: rMap[usr.id] || 0 }, recMap[usr.id] || null, S);
        const pu = publicUser(usr, true);
        return { id: usr.id, name: usr.name, email: usr.email, payoutInfo: pu.payoutInfo, videoViews: e.vNew, reelViews: e.rNew,
          videoRevenueUsd: e.c.gV / 100, reelRevenueUsd: e.c.gR / 100, creatorCents: e.c.creator, creatorUsd: e.c.creator / 100,
          platformUsd: e.c.platform / 100, paidUsd: e.paidCents / 100, lastPaidAt: e.lastPaidAt, hasPendingRequest: !!pendSet[usr.id] };
      });
      return json({ settings: S, limits: PAYOUT_LIMITS, rows, minWithdrawUsd: WITHDRAW_MIN_CENTS / 100 });
    }
    if (method === "PUT" && path === "/api/admin/payout-settings") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const b = await request.json().catch(() => ({}));
      const vrpm = Number(b.vrpm), rrpm = Number(b.rrpm), share = Number(b.share), inr = Number(b.inr);
      if (!(vrpm >= PAYOUT_LIMITS.vrpm[0] && vrpm <= PAYOUT_LIMITS.vrpm[1])) return err("Video rate must be between $" + PAYOUT_LIMITS.vrpm[0].toFixed(2) + " and $" + PAYOUT_LIMITS.vrpm[1].toFixed(2) + " per 1,000 views");
      if (!(rrpm >= PAYOUT_LIMITS.rrpm[0] && rrpm <= PAYOUT_LIMITS.rrpm[1])) return err("Reels rate must be between $" + PAYOUT_LIMITS.rrpm[0].toFixed(2) + " and $" + PAYOUT_LIMITS.rrpm[1].toFixed(2) + " per 1,000 views");
      if (!(share >= 0 && share <= 100)) return err("Creator share must be between 0 and 100");
      if (!(inr > 0 && inr < 1000)) return err("Enter a valid rupee rate");
      await ensurePayoutTables(db);
      await db.prepare("INSERT INTO payout_settings (id, vrpm, rrpm, share, inr) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET vrpm = excluded.vrpm, rrpm = excluded.rrpm, share = excluded.share, inr = excluded.inr").bind(vrpm, rrpm, share, inr).run();
      return json({ ok: true, settings: { vrpm, rrpm, share, inr } });
    }
    if (method === "POST" && (m = path.match(/^\/api\/admin\/payouts\/([^/]+)\/mark-paid$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const b = await request.json().catch(() => ({}));
      const target = await db.prepare("SELECT id, monetization_enabled FROM users WHERE id = ?").bind(m[1]).first();
      if (!target || !target.monetization_enabled) return err("Creator not found or not monetized", 404);
      if (await getPendingWithdraw(db, target.id)) return err("This creator has a pending withdrawal request. Handle it from the Withdrawal Requests list.", 409);
      const S = await getPayoutSettings(db);
      const e = await computeEarnings(db, target.id, S);
      if (e.c.creator <= 0) return err("Nothing to pay right now", 400);
      if (Number(b.expectedCents) !== e.c.creator) return err("Earnings changed since you opened this page. Refresh and check the amount again.", 409);
      await db.prepare("INSERT INTO payout_records (user_id, v_views, r_views, paid_cents, last_paid_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET v_views = excluded.v_views, r_views = excluded.r_views, paid_cents = payout_records.paid_cents + ?, last_paid_at = excluded.last_paid_at")
        .bind(target.id, e.totals.v, e.totals.r, e.c.creator, Date.now(), e.c.creator).run();
      return json({ ok: true, paidUsd: e.c.creator / 100 });
    }
    if (method === "GET" && path === "/api/admin/users") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare("SELECT * FROM users WHERE role != 'guest' ORDER BY created_at DESC").all();
      return json({ users: rows.results.map((r) => publicUser(r, true)) });
    }
    if (method === "PATCH" && (m = path.match(/^\/api\/admin\/users\/([^/]+)\/suspend$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const target = await db.prepare("SELECT id, suspended FROM users WHERE id = ?").bind(m[1]).first();
      if (!target) return err("User not found", 404);
      const nextSuspended = target.suspended ? 0 : 1;
      await db.prepare("UPDATE users SET suspended = ? WHERE id = ?").bind(nextSuspended, m[1]).run();
      if (nextSuspended) {
        await addNotification(db, m[1], "info", "Account Deactivated",
          "Your channel has been deactivated by an admin for review. Please make sure your content follows platform rules. Contact support via Feedback if you believe this is a mistake.");
      } else {
        await addNotification(db, m[1], "info", "Account Reactivated",
          "Your channel has been reactivated. Thank you for your patience.");
      }
      return json({ ok: true, suspended: !!nextSuspended });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/admin\/users\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const targetId = m[1];
      if (targetId === u.id) return err("Use your own account settings to delete your own account", 400);
      await purgeSadaqah(db, targetId);
      await db.batch([
        db.prepare("DELETE FROM comments WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM video_likes WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM reel_likes WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM saved_videos WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM watch_history WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM notifications WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM follows WHERE follower_id = ? OR followee_id = ?").bind(targetId, targetId),
        db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM anon_sessions WHERE user_id = ?").bind(targetId),
        db.prepare("DELETE FROM videos WHERE owner_id = ?").bind(targetId),
        db.prepare("DELETE FROM reels WHERE owner_id = ?").bind(targetId),
        db.prepare("DELETE FROM statuses WHERE owner_id = ?").bind(targetId),
        db.prepare("DELETE FROM users WHERE id = ?").bind(targetId),
      ]);
      return json({ ok: true });
    }
    if (method === "GET" && path === "/api/admin/videos") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, users.monetization_enabled as owner_monetized, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id ORDER BY videos.uploaded_at DESC LIMIT 500"
      ).all();
      return json({ videos: rows.results.map(videoOut) });
    }
    if (method === "PATCH" && (m = path.match(/^\/api\/admin\/videos\/([^/]+)\/hide$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const v = await db.prepare("SELECT id, hidden FROM videos WHERE id = ?").bind(m[1]).first();
      if (!v) return err("Video not found", 404);
      const nextHidden = v.hidden ? 0 : 1;
      await db.prepare("UPDATE videos SET hidden = ? WHERE id = ?").bind(nextHidden, m[1]).run();
      return json({ ok: true, hidden: !!nextHidden });
    }
    if (method === "GET" && path === "/api/admin/reels") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare(
        "SELECT reels.*, users.name as owner_name, users.avatar_color as owner_avatar_color, users.monetization_enabled as owner_monetized, (SELECT COUNT(*) FROM comments WHERE target_type='reel' AND target_id=reels.id) as comment_count FROM reels JOIN users ON users.id = reels.owner_id ORDER BY reels.uploaded_at DESC LIMIT 500"
      ).all();
      return json({ reels: rows.results.map(reelOut) });
    }
    if (method === "PATCH" && (m = path.match(/^\/api\/admin\/reels\/([^/]+)\/hide$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rl = await db.prepare("SELECT id, hidden FROM reels WHERE id = ?").bind(m[1]).first();
      if (!rl) return err("Reel not found", 404);
      const nextHidden = rl.hidden ? 0 : 1;
      await db.prepare("UPDATE reels SET hidden = ? WHERE id = ?").bind(nextHidden, m[1]).run();
      return json({ ok: true, hidden: !!nextHidden });
    }
    if (method === "POST" && path === "/api/feedback") {
      const u = await currentUser(request, env);
      const b = await request.json().catch(() => ({}));
      if (!b.message || !b.message.trim()) return err("Message is required");
      const id = uid("fb");
      await db.prepare("INSERT INTO feedback (id, user_id, name, email, message) VALUES (?,?,?,?,?)")
        .bind(id, u ? u.id : null, b.name || (u ? u.name : null) || null, b.email || (u ? u.email : null) || null, b.message.trim()).run();
      return json({ ok: true });
    }
    if (method === "GET" && path === "/api/admin/feedback") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      try { await ensureFeedbackColumns(db); } catch (_) {}
      const rows = await db.prepare("SELECT * FROM feedback ORDER BY created_at DESC LIMIT 200").all();
      return json({ feedback: rows.results.map(f => ({ id: f.id, userId: f.user_id, name: f.name, email: f.email, message: f.message, reply: f.reply, repliedAt: f.replied_at, createdAt: f.created_at })) });
    }
    if (method === "POST" && (m = path.match(/^\/api\/admin\/feedback\/([^/]+)\/reply$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const { reply } = await request.json().catch(() => ({}));
      if (!reply || !reply.trim()) return err("Reply message is required");
      const fbRow = await db.prepare("SELECT * FROM feedback WHERE id = ?").bind(m[1]).first();
      if (!fbRow) return err("Feedback not found", 404);
      await ensureFeedbackColumns(db);
      await db.prepare("UPDATE feedback SET reply = ?, replied_at = datetime('now') WHERE id = ?").bind(reply.trim(), m[1]).run();
      if (fbRow.user_id) {
        await addNotification(db, fbRow.user_id, "info", "Reply to your feedback", reply.trim());
      }
      return json({ ok: true });
    }

    // ---------- REPORTS + BLOCK (Google Play UGC: report content/users + block users) ----------
    await db.prepare(`CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      reporter_id TEXT,
      reason TEXT NOT NULL,
      status TEXT DEFAULT 'open',
      created_at TEXT DEFAULT (datetime('now'))
    )`).run();

    if (method === "POST" && (m = path.match(/^\/api\/(videos|reels)\/([^/]+)\/report$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const targetType = m[1] === "videos" ? "video" : "reel";
      const targetId = m[2];
      const b = await request.json().catch(() => ({}));
      const reason = (b.reason || "").trim();
      if (!reason) return err("Reason is required");
      const table = targetType === "video" ? "videos" : "reels";
      const exists = await db.prepare(`SELECT id FROM ${table} WHERE id = ?`).bind(targetId).first();
      if (!exists) return err(targetType === "video" ? "Video not found" : "Reel not found", 404);
      const id = uid("rp");
      await db.prepare("INSERT INTO reports (id, target_type, target_id, reporter_id, reason, status) VALUES (?,?,?,?,?,'open')")
        .bind(id, targetType, targetId, u.id, reason).run();
      return json({ ok: true, id });
    }
    if (method === "POST" && (m = path.match(/^\/api\/comments\/([^/]+)\/vote$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role === "guest") return err("Please sign in to like comments", 401);
      if (!(await ensureCommentExtras(db))) return err("Comment likes are not available right now", 503);
      const b = await request.json().catch(() => ({}));
      const v = Number(b.value);
      if (v !== 1 && v !== -1 && v !== 0) return err("Invalid vote");
      const c = await db.prepare("SELECT id FROM comments WHERE id = ?").bind(m[1]).first();
      if (!c) return err("Comment not found", 404);
      if (v === 0) await db.prepare("DELETE FROM comment_votes WHERE comment_id = ? AND user_id = ?").bind(m[1], u.id).run();
      else await db.prepare("INSERT INTO comment_votes (comment_id, user_id, vote, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(comment_id, user_id) DO UPDATE SET vote = excluded.vote").bind(m[1], u.id, v, Date.now()).run();
      const t = await db.prepare("SELECT COALESCE(SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END), 0) AS likes, COALESCE(SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END), 0) AS dislikes FROM comment_votes WHERE comment_id = ?").bind(m[1]).first();
      return json({ ok: true, likes: (t && t.likes) || 0, dislikes: (t && t.dislikes) || 0, myVote: v });
    }
    if (method === "POST" && (m = path.match(/^\/api\/comments\/([^/]+)\/report$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const b = await request.json().catch(() => ({}));
      const reason = (b.reason || "").trim();
      if (!reason) return err("Reason is required");
      const c = await db.prepare("SELECT id, user_id FROM comments WHERE id = ?").bind(m[1]).first();
      if (!c) return err("Comment not found", 404);
      if (c.user_id === u.id) return err("You cannot report your own comment");
      const id = uid("rp");
      await db.prepare("INSERT INTO reports (id, target_type, target_id, reporter_id, reason, status) VALUES (?,?,?,?,?,'open')")
        .bind(id, "comment", m[1], u.id, reason).run();
      return json({ ok: true, id });
    }
    if (method === "POST" && (m = path.match(/^\/api\/users\/([^/]+)\/report$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      if (m[1] === u.id) return err("You cannot report yourself");
      const b = await request.json().catch(() => ({}));
      const reason = (b.reason || "").trim();
      if (!reason) return err("Reason is required");
      const target = await db.prepare("SELECT id, role FROM users WHERE id = ?").bind(m[1]).first();
      if (!target || target.role === "guest") return err("User not found", 404);
      const id = uid("rp");
      await db.prepare("INSERT INTO reports (id, target_type, target_id, reporter_id, reason, status) VALUES (?,?,?,?,?,'open')")
        .bind(id, "user", m[1], u.id, reason).run();
      return json({ ok: true, id });
    }
    if (method === "POST" && (m = path.match(/^\/api\/users\/([^/]+)\/block$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.role === "guest") return err("Please sign in with a real account to block users", 403);
      if (m[1] === u.id) return err("You cannot block yourself");
      const target = await db.prepare("SELECT id, role FROM users WHERE id = ?").bind(m[1]).first();
      if (!target || target.role === "guest") return err("User not found", 404);
      await ensureUserBlocks(db);
      await db.prepare("INSERT INTO user_blocks (blocker_id, blocked_id, created_at) VALUES (?,?,?) ON CONFLICT(blocker_id, blocked_id) DO NOTHING")
        .bind(u.id, m[1], Date.now()).run();
      return json({ ok: true, blocked: true });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/users\/([^/]+)\/block$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      await ensureUserBlocks(db);
      await db.prepare("DELETE FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?").bind(u.id, m[1]).run();
      return json({ ok: true, blocked: false });
    }
    if (method === "GET" && path === "/api/me/blocked") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      await ensureUserBlocks(db);
      const rows = await db.prepare(
        "SELECT user_blocks.blocked_id AS id, users.name, users.avatar_color, user_blocks.created_at FROM user_blocks JOIN users ON users.id = user_blocks.blocked_id WHERE user_blocks.blocker_id = ? ORDER BY user_blocks.created_at DESC LIMIT 200"
      ).bind(u.id).all();
      return json({ blocked: (rows.results || []).map((r) => ({ id: r.id, name: r.name, avatarColor: r.avatar_color, blockedAt: r.created_at })) });
    }
    if (method === "GET" && (m = path.match(/^\/api\/users\/([^/]+)\/block-status$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      return json({ blocked: await isBlocked(db, u.id, m[1]) });
    }
    if (method === "GET" && path === "/api/admin/reports") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare(`
        SELECT reports.*,
          CASE WHEN reports.target_type = 'video' THEN (SELECT title FROM videos WHERE id = reports.target_id)
               WHEN reports.target_type = 'reel' THEN (SELECT title FROM reels WHERE id = reports.target_id)
               WHEN reports.target_type = 'comment' THEN (SELECT substr(text, 1, 80) FROM comments WHERE id = reports.target_id)
               WHEN reports.target_type = 'user' THEN (SELECT name FROM users WHERE id = reports.target_id)
               ELSE NULL END as target_title,
          CASE WHEN reports.target_type = 'video' THEN (SELECT hidden FROM videos WHERE id = reports.target_id)
               WHEN reports.target_type = 'reel' THEN (SELECT hidden FROM reels WHERE id = reports.target_id)
               ELSE 0 END as target_hidden,
          CASE WHEN reports.target_type = 'video' THEN (SELECT removed FROM videos WHERE id = reports.target_id)
               ELSE 0 END as target_removed,
          (SELECT name FROM users WHERE id = reports.reporter_id) as reporter_name
        FROM reports
        ORDER BY CASE WHEN status = 'open' THEN 0 ELSE 1 END, created_at DESC
        LIMIT 300
      `).all();
      return json({
        reports: rows.results.map(r => ({
          id: r.id,
          targetType: r.target_type,
          targetId: r.target_id,
          targetTitle: r.target_title || "(deleted)",
          targetHidden: !!r.target_hidden,
          targetRemoved: !!r.target_removed,
          reporterId: r.reporter_id,
          reporterName: r.reporter_name || "Guest",
          reason: r.reason,
          status: r.status,
          createdAt: r.created_at,
        })),
      });
    }
    if (method === "PATCH" && (m = path.match(/^\/api\/admin\/reports\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const b = await request.json().catch(() => ({}));
      const status = b.status === "resolved" || b.status === "dismissed" ? b.status : null;
      if (!status) return err("status must be 'resolved' or 'dismissed'");
      const row = await db.prepare("SELECT * FROM reports WHERE id = ?").bind(m[1]).first();
      if (!row) return err("Report not found", 404);
      await db.prepare("UPDATE reports SET status = ? WHERE id = ?").bind(status, m[1]).run();
      return json({ ok: true, status });
    }

    // ---------- VIDEOS ----------
    if (method === "GET" && (m = path.match(/^\/api\/(videos|reels)\/([^/]+)\/related$/))) {
      const kind = m[1] === "videos" ? "v" : "r";
      let me = null;
      try { me = await currentUser(request, env); } catch (_) {}
      const items = await rkRelated(db, kind, m[2], me && me.role !== "guest" ? me.id : null, rkLimit(url, 20));
      if (!items) return err("Not found", 404);
      return json({ [m[1]]: items.map((it) => (kind === "v" ? videoOut : reelOut)(it.row)) });
    }
    if (method === "GET" && path === "/api/hashtags/suggest") return await hashtagSuggest(db, url);
    if (method === "GET" && path === "/api/trending-week") {
      try {
        await ensureViewTables(db);
        const since = istDay(Date.now() - 6 * 86400000);
        const rows = await db.prepare("SELECT d.content_id AS id, SUM(d.views) AS n FROM view_daily d JOIN videos v ON v.id = d.content_id WHERE d.kind = 'v' AND d.day >= ? AND v.removed = 0 GROUP BY d.content_id HAVING n > 0 ORDER BY n DESC LIMIT 60").bind(since).all();
        return json({ items: (rows.results || []).map((r) => ({ id: r.id, views7: r.n || 0 })) });
      } catch (_) { return json({ items: [] }); }
    }
    if (method === "GET" && path === "/api/videos") return await feedCached(db, request, env, url, "v");
    if (method === "GET" && (m = path.match(/^\/api\/videos\/([^/]+)$/))) {
      const v = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, users.monetization_enabled as owner_monetized, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.id = ?"
      ).bind(m[1]).first();
      if (!v) return err("Video not found", 404);
      return json({ video: videoOut(v) });
    }
    if (method === "POST" && path === "/api/videos") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.suspended) return err("Your account is suspended. Uploads are not allowed.", 403);
      const b = await request.json().catch(() => ({}));
      if (!b.title) return err("Title is required");
      let removed = 0, monetized = b.monetized ? 1 : 0, copyrightStatus = "clear";
      let dupOwnerName = null;
      if (b.contentHash) {
        const dup = await db.prepare(
          "SELECT videos.owner_id, users.name as owner_name FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.content_hash = ? AND videos.owner_id != ?"
        ).bind(b.contentHash, u.id).first();
        if (dup) { removed = 1; monetized = 0; copyrightStatus = "claimed"; dupOwnerName = dup.owner_name; }
      }
      const crReady = b.sourceType !== "youtube" && await ensureCopyrightColumns(db);
      const vFp = crReady ? cleanFingerprint(b.fingerprint) : null;
      const vEtag = crReady ? await storedFileEtag(env, b.fileUrl) : null;
      let vDupOf = null;
      if (crReady && !removed && (vFp || vEtag)) {
        const d2 = await findDuplicateOwner(db, { fingerprint: vFp, etag: vEtag, ownerId: u.id });
        if (d2) { removed = 1; monetized = 0; copyrightStatus = "claimed"; dupOwnerName = d2.ownerName; vDupOf = d2.id; }
      }
      if (removed && !b.acceptDuplicate) {
        return json({
          error: "This video was already uploaded by another creator" + (dupOwnerName ? (' ("' + dupOwnerName + '")') : "") + ". Uploading it will give you a copyright strike.",
          duplicate: true,
          originalOwner: dupOwnerName || "another creator",
          originalId: vDupOf || null,
        }, 409);
      }
      const id = uid("v");
      await db.prepare(
        `INSERT INTO videos (id, owner_id, title, description, tags, category, mix_category, source_type, youtube_id, file_url, thumbnail, duration, trim_start, trim_end, monetized, copyright_status, removed, content_hash)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(id, u.id, b.title, b.description || "", JSON.stringify(b.tags || []), b.category || null, b.mixCategory || null,
        b.sourceType, b.youtubeId || null, b.fileUrl || null, b.thumbnail || null, b.duration || null,
        b.trimStart ?? null, b.trimEnd ?? null, monetized, copyrightStatus, removed, b.contentHash || null).run();
      bg(indexHashtags(db, "v", id, u.id, b.title, b.description, b.tags));
      if (vFp || vEtag) { try { await db.prepare("UPDATE videos SET fingerprint = ?, file_etag = ?, dup_of = ? WHERE id = ?").bind(vFp, vEtag, vDupOf, id).run(); } catch (_) {} }
      let suspended = false;
      if (removed) {
        const newStrikes = (u.strikes || 0) + 1;
        suspended = newStrikes >= 3;
        await db.prepare(
          "UPDATE users SET strikes = ?, suspended = ?, monetization_enabled = CASE WHEN ? = 1 THEN 0 ELSE monetization_enabled END WHERE id = ?"
        ).bind(newStrikes, suspended ? 1 : 0, suspended ? 1 : 0, u.id).run();
        await addNotification(db, u.id, "copyright", "Copyright Claim — Video Removed",
          `Your video "${b.title}" was already uploaded by another channel${dupOwnerName ? ` ("${dupOwnerName}")` : ""}. It has been automatically removed and you received a copyright strike (${newStrikes}/3).${suspended ? " Your account has been permanently suspended." : ""}`);
      } else {
        const followers = await db.prepare("SELECT follower_id FROM follows WHERE followee_id = ? AND bell = 1").bind(u.id).all();
        for (const f of followers.results) {
          await addNotification(db, f.follower_id, "new_video", `New video from ${u.name}`, `"${b.title}" has just been uploaded.`);
        }
      }
      return json({ ok: true, id, removed: !!removed, suspended });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/videos\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const v = await db.prepare("SELECT owner_id FROM videos WHERE id = ?").bind(m[1]).first();
      if (!v) return err("Video not found", 404);
      if (v.owner_id !== u.id && u.role !== "admin") return err("Not allowed", 403);
      await db.prepare("DELETE FROM videos WHERE id = ?").bind(m[1]).run();
      bg(unindexHashtags(db, "v", m[1]));
      return json({ ok: true });
    }
    if (method === "POST" && (m = path.match(/^\/api\/(videos|reels)\/([^/]+)\/view(-start)?$/))) {
      return await handleViewRoute(m[1] === "videos" ? "v" : "r", m[2], m[3] ? "start" : "count", request, env, db);
    }
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/like$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const { value } = await request.json().catch(() => ({ value: 1 })); // 1 = like, -1 = dislike
      const existing = await db.prepare("SELECT value FROM video_likes WHERE user_id = ? AND video_id = ?").bind(u.id, m[1]).first();
      if (existing && existing.value === value) {
        await db.prepare("DELETE FROM video_likes WHERE user_id = ? AND video_id = ?").bind(u.id, m[1]).run();
        await db.prepare(`UPDATE videos SET ${value === 1 ? "likes = likes - 1" : "dislikes = dislikes - 1"} WHERE id = ?`).bind(m[1]).run();
      } else {
        if (existing) await db.prepare(`UPDATE videos SET ${existing.value === 1 ? "likes = likes - 1" : "dislikes = dislikes - 1"} WHERE id = ?`).bind(m[1]).run();
        await db.prepare("INSERT INTO video_likes (user_id, video_id, value) VALUES (?, ?, ?) ON CONFLICT(user_id, video_id) DO UPDATE SET value = ?").bind(u.id, m[1], value, value).run();
        await db.prepare(`UPDATE videos SET ${value === 1 ? "likes = likes + 1" : "dislikes = dislikes + 1"} WHERE id = ?`).bind(m[1]).run();
      }
      const v = await db.prepare("SELECT likes, dislikes FROM videos WHERE id = ?").bind(m[1]).first();
      return json({ ok: true, likes: v.likes, dislikes: v.dislikes });
    }
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/save$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const existing = await db.prepare("SELECT 1 FROM saved_videos WHERE user_id = ? AND video_id = ?").bind(u.id, m[1]).first();
      if (existing) await db.prepare("DELETE FROM saved_videos WHERE user_id = ? AND video_id = ?").bind(u.id, m[1]).run();
      else await db.prepare("INSERT INTO saved_videos (user_id, video_id) VALUES (?, ?)").bind(u.id, m[1]).run();
      return json({ ok: true, saved: !existing });
    }
    if (method === "PATCH" && (m = path.match(/^\/api\/videos\/([^/]+)\/monetize$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const v = await db.prepare("SELECT owner_id, copyright_status, removed FROM videos WHERE id = ?").bind(m[1]).first();
      if (!v) return err("Video not found", 404);
      if (v.owner_id !== u.id) return err("Not allowed", 403);
      if (v.copyright_status !== "clear" || v.removed) return err("This video cannot be monetized", 400);
      const { monetized } = await request.json().catch(() => ({}));
      await db.prepare("UPDATE videos SET monetized = ? WHERE id = ?").bind(monetized ? 1 : 0, m[1]).run();
      return json({ ok: true, monetized: !!monetized });
    }
    if (method === "GET" && (m = path.match(/^\/api\/videos\/([^/]+)\/comments$/))) {
      return json({ comments: await listComments(db, request, env, "video", m[1]) });
    }
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/comments$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const r = await addComment(db, u, "video", m[1], await request.json().catch(() => ({})));
      if (r.error) return err(r.error, r.status || 400);
      return json({ ok: true, id: r.id });
    }

    // ---------- REELS ----------
    if (method === "GET" && path === "/api/reels") return await feedCached(db, request, env, url, "r");
    if (method === "POST" && path === "/api/reels") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.suspended) return err("Your account is suspended. Uploads are not allowed.", 403);
      const b = await request.json().catch(() => ({}));
      if (!b.title) return err("Title is required");
      const rReady = await ensureCopyrightColumns(db);
      const rFp = rReady ? cleanFingerprint(b.fingerprint) : null;
      const rEtag = rReady ? await storedFileEtag(env, b.fileUrl) : null;
      let rDup = null;
      if (rReady && (rFp || rEtag)) rDup = await findDuplicateOwner(db, { fingerprint: rFp, etag: rEtag, ownerId: u.id });
      if (rDup && !b.acceptDuplicate) {
        return json({
          error: "This reel was already uploaded by another creator" + (rDup.ownerName ? (' ("' + rDup.ownerName + '")') : "") + ". Uploading it will give you a copyright strike.",
          duplicate: true,
          originalOwner: rDup.ownerName || "another creator",
          originalId: rDup.id || null,
        }, 409);
      }
      const id = uid("r");
      await db.prepare("INSERT INTO reels (id, owner_id, title, tags, file_url, thumbnail, trim_start, trim_end, mix_category) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(id, u.id, b.title, JSON.stringify(b.tags || []), b.fileUrl || null, b.thumbnail || null, b.trimStart ?? null, b.trimEnd ?? null, b.mixCategory || null).run();
      bg(indexHashtags(db, "r", id, u.id, b.title, "", b.tags));
      if (rFp || rEtag) { try { await db.prepare("UPDATE reels SET fingerprint = ?, file_etag = ?, dup_of = ? WHERE id = ?").bind(rFp, rEtag, rDup ? rDup.id : null, id).run(); } catch (_) {} }
      let rSuspended = false;
      if (rDup) { // a copy of another creator's reel: hidden right away + strike, same policy as videos
        await db.prepare("UPDATE reels SET hidden = 1 WHERE id = ?").bind(id).run();
        rSuspended = await applyCopyrightStrike(db, u, "Reel", b.title, rDup.ownerName);
      }
      return json({ ok: true, id, removed: !!rDup, suspended: rSuspended });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/reels\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const rl = await db.prepare("SELECT owner_id FROM reels WHERE id = ?").bind(m[1]).first();
      if (!rl) return err("Reel not found", 404);
      if (rl.owner_id !== u.id && u.role !== "admin") return err("Not allowed", 403);
      await db.prepare("DELETE FROM reels WHERE id = ?").bind(m[1]).run();
      bg(unindexHashtags(db, "r", m[1]));
      return json({ ok: true });
    }
    if (method === "POST" && (m = path.match(/^\/api\/reels\/([^/]+)\/like$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const existing = await db.prepare("SELECT 1 FROM reel_likes WHERE user_id = ? AND reel_id = ?").bind(u.id, m[1]).first();
      if (existing) {
        await db.prepare("DELETE FROM reel_likes WHERE user_id = ? AND reel_id = ?").bind(u.id, m[1]).run();
        await db.prepare("UPDATE reels SET likes = likes - 1 WHERE id = ?").bind(m[1]).run();
      } else {
        await db.prepare("INSERT INTO reel_likes (user_id, reel_id) VALUES (?, ?)").bind(u.id, m[1]).run();
        await db.prepare("UPDATE reels SET likes = likes + 1 WHERE id = ?").bind(m[1]).run();
      }
      const rl = await db.prepare("SELECT likes FROM reels WHERE id = ?").bind(m[1]).first();
      return json({ ok: true, likes: rl.likes, liked: !existing });
    }
    if (method === "GET" && (m = path.match(/^\/api\/reels\/([^/]+)\/comments$/))) {
      return json({ comments: await listComments(db, request, env, "reel", m[1]) });
    }
    if (method === "POST" && (m = path.match(/^\/api\/reels\/([^/]+)\/comments$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const r = await addComment(db, u, "reel", m[1], await request.json().catch(() => ({})));
      if (r.error) return err(r.error, r.status || 400);
      return json({ ok: true, id: r.id });
    }

    // ---------- STATUSES ----------
    if (method === "GET" && path === "/api/statuses") {
      const rows = await db.prepare(
        "SELECT statuses.*, users.name as owner_name, users.avatar_color as owner_avatar_color FROM statuses JOIN users ON users.id = statuses.owner_id WHERE statuses.created_at >= datetime('now', '-1 day') ORDER BY statuses.created_at DESC"
      ).all();
      return json({ statuses: rows.results.map(statusOut) });
    }
    if (method === "POST" && path === "/api/statuses") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const b = await request.json().catch(() => ({}));
      const id = uid("st");
      await db.prepare("INSERT INTO statuses (id, owner_id, source_type, youtube_id, file_url, thumbnail) VALUES (?,?,?,?,?,?)")
        .bind(id, u.id, b.sourceType, b.youtubeId || null, b.fileUrl || null, b.thumbnail || null).run();
      return json({ ok: true, id });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/statuses\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const st = await db.prepare("SELECT owner_id FROM statuses WHERE id = ?").bind(m[1]).first();
      if (!st) return err("Status not found", 404);
      if (st.owner_id !== u.id && u.role !== "admin") return err("Not allowed", 403);
      await db.prepare("DELETE FROM statuses WHERE id = ?").bind(m[1]).run();
      return json({ ok: true });
    }
    if (method === "POST" && (m = path.match(/^\/api\/statuses\/([^/]+)\/view$/))) {
      await db.prepare("UPDATE statuses SET views = views + 1 WHERE id = ?").bind(m[1]).run();
      return json({ ok: true });
    }

    return err("Not found", 404);
}
