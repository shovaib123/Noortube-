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
async function addNotification(db, userId, type, title, message) {
  await db.prepare("INSERT INTO notifications (id, user_id, type, title, message) VALUES (?,?,?,?,?)")
    .bind(uid("n"), userId, type, title, message).run();
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
    fileUrl: v.file_url, thumbnail: v.thumbnail, duration: v.duration,
    trimStart: v.trim_start, trimEnd: v.trim_end,
    views: v.views, likes: v.likes, dislikes: v.dislikes, monetized: !!v.monetized,
    copyrightStatus: v.copyright_status, removed: !!v.removed, hidden: !!v.hidden, uploadedAt: v.uploaded_at, earnings: v.earnings,
    channel: v.owner_name, channelAvatar: v.owner_avatar_color, commentCount: v.comment_count || 0,
  };
}
function reelOut(r) {
  return {
    id: r.id, ownerId: r.owner_id, title: r.title, tags: JSON.parse(r.tags || "[]"), fileUrl: r.file_url,
    thumbnail: r.thumbnail, trimStart: r.trim_start, trimEnd: r.trim_end, views: r.views, likes: r.likes,
    uploadedAt: r.uploaded_at, channel: r.owner_name, channelAvatar: r.owner_avatar_color, commentCount: r.comment_count || 0,
    mixCategory: r.mix_category || null, hidden: !!r.hidden,
  };
}
function statusOut(s) {
  return {
    id: s.id, ownerId: s.owner_id, sourceType: s.source_type, youtubeId: s.youtube_id, fileUrl: s.file_url,
    thumbnail: s.thumbnail, views: s.views, createdAt: s.created_at, channel: s.owner_name, channelAvatar: s.owner_avatar_color,
  };
}

export default {
  async fetch(request, env) {
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
      if (!env.UPLOAD_SECRET) return json({ key, uploadUrl, token: null, expiry });
      const token = await signUploadToken(key, expiry, env.UPLOAD_SECRET);
      return json({ key, uploadUrl, token, expiry });
    }

    // ---------- R2 FILE STORAGE (unchanged from Phase 0) ----------
    if (method === "PUT" && path.startsWith("/upload/")) {
      const key = decodeURIComponent(path.replace("/upload/", ""));
      if (!key) return err("Missing filename", 400);
      if (env.UPLOAD_SECRET) {
        const token = request.headers.get("X-Upload-Token");
        const expiry = Number(request.headers.get("X-Upload-Expiry") || 0);
        if (!token || !expiry) return err("Unauthorized", 401);
        if (expiry < Date.now()) return err("Upload authorization expired", 401);
        const expected = await signUploadToken(key, expiry, env.UPLOAD_SECRET);
        if (token !== expected) return err("Unauthorized", 401);
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
      if (env.UPLOAD_SECRET && request.headers.get("X-Upload-Secret") !== env.UPLOAD_SECRET) return err("Unauthorized", 401);
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
      const existing = await db.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
      if (existing) return err("An account with this email already exists");
      const { hash, salt } = await hashPassword(password);
      const id = uid("u");
      await db.prepare("INSERT INTO users (id, name, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)")
        .bind(id, name, email.toLowerCase(), hash, salt).run();
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
    if (method === "GET" && path === "/api/me") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
      return json({ user: publicUser(u, true) });
    }
    if (method === "DELETE" && path === "/api/me") {
      const u = await currentUser(request, env);
      if (!u) return err("Not signed in", 401);
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
          const ok = (fc?.c || 0) >= 1000 && (u.watch_hours || 0) >= 3000 && (rv?.v || 0) >= 2500000;
          if (!ok) return err("Monetization requirements not met", 403);
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
      const id = uid("wr");
      try {
        await db.prepare("INSERT INTO withdraw_requests (id, user_id, amount_cents, v_snap, r_snap, method, account_name, account_number, routing_code, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,'Pending',?)")
          .bind(id, u.id, e.c.creator, e.totals.v, e.totals.r, u.payout_method, u.payout_account_name || "", u.payout_account_number, u.payout_routing_code || "", Date.now()).run();
      } catch (_) { return err("You already have a withdrawal request pending", 409); }
      return json({ ok: true, id, amountUsd: e.c.creator / 100 });
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
      try { await addNotification(db, w.user_id, "info", "Withdrawal Paid", "Your withdrawal of $" + (w.amount_cents / 100).toFixed(2) + " has been paid."); } catch (_) {}
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
      try { await addNotification(db, w.user_id, "info", "Withdrawal Request Rejected", "Your withdrawal request of $" + (w.amount_cents / 100).toFixed(2) + " was not approved." + (note ? " Reason: " + note : " Please check your payout details and request again.")); } catch (_) {}
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
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id ORDER BY videos.uploaded_at DESC LIMIT 500"
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
        "SELECT reels.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='reel' AND target_id=reels.id) as comment_count FROM reels JOIN users ON users.id = reels.owner_id ORDER BY reels.uploaded_at DESC LIMIT 500"
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
      await db.prepare("UPDATE feedback SET reply = ?, replied_at = datetime('now') WHERE id = ?").bind(reply.trim(), m[1]).run();
      if (fbRow.user_id) {
        await addNotification(db, fbRow.user_id, "info", "Reply to your feedback", reply.trim());
      }
      return json({ ok: true });
    }

    // ---------- REPORTS ----------
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
    if (method === "GET" && path === "/api/admin/reports") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare(`
        SELECT reports.*,
          CASE WHEN reports.target_type = 'video' THEN (SELECT title FROM videos WHERE id = reports.target_id)
               WHEN reports.target_type = 'reel' THEN (SELECT title FROM reels WHERE id = reports.target_id)
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
    if (method === "GET" && path === "/api/videos") {
      const rows = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.removed = 0 AND videos.hidden = 0 ORDER BY videos.uploaded_at DESC LIMIT 200"
      ).all();
      return json({ videos: rows.results.map(videoOut) });
    }
    if (method === "GET" && (m = path.match(/^\/api\/videos\/([^/]+)$/))) {
      const v = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.id = ?"
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
      const id = uid("v");
      await db.prepare(
        `INSERT INTO videos (id, owner_id, title, description, tags, category, mix_category, source_type, youtube_id, file_url, thumbnail, duration, trim_start, trim_end, monetized, copyright_status, removed, content_hash)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(id, u.id, b.title, b.description || "", JSON.stringify(b.tags || []), b.category || null, b.mixCategory || null,
        b.sourceType, b.youtubeId || null, b.fileUrl || null, b.thumbnail || null, b.duration || null,
        b.trimStart ?? null, b.trimEnd ?? null, monetized, copyrightStatus, removed, b.contentHash || null).run();
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
      return json({ ok: true });
    }
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/view$/))) {
      await db.prepare("UPDATE videos SET views = views + 1 WHERE id = ?").bind(m[1]).run();
      const u = await currentUser(request, env);
      if (u) await db.prepare("INSERT OR REPLACE INTO watch_history (user_id, video_id, watched_at) VALUES (?, ?, datetime('now'))").bind(u.id, m[1]).run();
      return json({ ok: true });
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
      const rows = await db.prepare(
        "SELECT comments.*, users.name as user_name, users.avatar_color as user_avatar_color FROM comments JOIN users ON users.id = comments.user_id WHERE target_type = 'video' AND target_id = ? ORDER BY comments.created_at DESC"
      ).bind(m[1]).all();
      return json({ comments: rows.results.map(c => ({ id: c.id, userId: c.user_id, userName: c.user_name, avatarColor: c.user_avatar_color, text: c.text, createdAt: c.created_at })) });
    }
    if (method === "POST" && (m = path.match(/^\/api\/videos\/([^/]+)\/comments$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const { text } = await request.json().catch(() => ({}));
      if (!text || typeof text !== "string" || !text.trim()) return err("Comment text is required");
      if (text.length > 1000) return err("Comment is too long (max 1000 characters)");
      const id = uid("c");
      await db.prepare("INSERT INTO comments (id, target_type, target_id, user_id, text) VALUES (?, 'video', ?, ?, ?)").bind(id, m[1], u.id, text.trim()).run();
      return json({ ok: true, id });
    }

    // ---------- REELS ----------
    if (method === "GET" && path === "/api/reels") {
      const rows = await db.prepare(
        "SELECT reels.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='reel' AND target_id=reels.id) as comment_count FROM reels JOIN users ON users.id = reels.owner_id WHERE reels.hidden = 0 ORDER BY reels.uploaded_at DESC LIMIT 200"
      ).all();
      return json({ reels: rows.results.map(reelOut) });
    }
    if (method === "POST" && path === "/api/reels") {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      if (u.suspended) return err("Your account is suspended. Uploads are not allowed.", 403);
      const b = await request.json().catch(() => ({}));
      if (!b.title) return err("Title is required");
      const id = uid("r");
      await db.prepare("INSERT INTO reels (id, owner_id, title, tags, file_url, thumbnail, trim_start, trim_end, mix_category) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(id, u.id, b.title, JSON.stringify(b.tags || []), b.fileUrl || null, b.thumbnail || null, b.trimStart ?? null, b.trimEnd ?? null, b.mixCategory || null).run();
      return json({ ok: true, id });
    }
    if (method === "DELETE" && (m = path.match(/^\/api\/reels\/([^/]+)$/))) {
      const u = await currentUser(request, env);
      if (!u) return err("Sign in required", 401);
      const rl = await db.prepare("SELECT owner_id FROM reels WHERE id = ?").bind(m[1]).first();
      if (!rl) return err("Reel not found", 404);
      if (rl.owner_id !== u.id && u.role !== "admin") return err("Not allowed", 403);
      await db.prepare("DELETE FROM reels WHERE id = ?").bind(m[1]).run();
      return json({ ok: true });
    }
    if (method === "POST" && (m = path.match(/^\/api\/reels\/([^/]+)\/view$/))) {
      await db.prepare("UPDATE reels SET views = views + 1 WHERE id = ?").bind(m[1]).run();
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
      const rows = await db.prepare(
        "SELECT comments.*, users.name as user_name, users.avatar_color as user_avatar_color FROM comments JOIN users ON users.id = comments.user_id WHERE target_type = 'reel' AND target_id = ? ORDER BY comments.created_at DESC"
      ).bind(m[1]).all();
      return json({ comments: rows.results.map(c => ({ id: c.id, userId: c.user_id, userName: c.user_name, avatarColor: c.user_avatar_color, text: c.text, createdAt: c.created_at })) });
    }
    if (method === "POST" && (m = path.match(/^\/api\/reels\/([^/]+)\/comments$/))) {
      const u = await currentUserOrGuest(request, env);
      if (!u) return err("Sign in required", 401);
      const { text } = await request.json().catch(() => ({}));
      if (!text || typeof text !== "string" || !text.trim()) return err("Comment text is required");
      if (text.length > 1000) return err("Comment is too long (max 1000 characters)");
      const id = uid("c");
      await db.prepare("INSERT INTO comments (id, target_type, target_id, user_id, text) VALUES (?, 'reel', ?, ?, ?)").bind(id, m[1], u.id, text.trim()).run();
      return json({ ok: true, id });
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
