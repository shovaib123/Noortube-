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
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Upload-Secret, Authorization, X-Anon-Id",
  };
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
async function currentUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const row = await env.NOOR_DB.prepare(
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
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, name: u.name, email: u.email, avatarColor: u.avatar_color, avatarImage: u.avatar_image,
    role: u.role, suspended: !!u.suspended, strikes: u.strikes, monetizationEnabled: !!u.monetization_enabled,
    watchHours: u.watch_hours,
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
    copyrightStatus: v.copyright_status, removed: !!v.removed, uploadedAt: v.uploaded_at, earnings: v.earnings,
    channel: v.owner_name, channelAvatar: v.owner_avatar_color, commentCount: v.comment_count || 0,
  };
}
function reelOut(r) {
  return {
    id: r.id, ownerId: r.owner_id, title: r.title, tags: JSON.parse(r.tags || "[]"), fileUrl: r.file_url,
    thumbnail: r.thumbnail, trimStart: r.trim_start, trimEnd: r.trim_end, views: r.views, likes: r.likes,
    uploadedAt: r.uploaded_at, channel: r.owner_name, channelAvatar: r.owner_avatar_color, commentCount: r.comment_count || 0,
    mixCategory: r.mix_category || null,
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

    // ---------- R2 FILE STORAGE (unchanged from Phase 0) ----------
    if (method === "PUT" && path.startsWith("/upload/")) {
      if (env.UPLOAD_SECRET && request.headers.get("X-Upload-Secret") !== env.UPLOAD_SECRET) return err("Unauthorized", 401);
      const key = decodeURIComponent(path.replace("/upload/", ""));
      if (!key) return err("Missing filename", 400);
      await env.NOOR_BUCKET.put(key, request.body, { httpMetadata: { contentType: request.headers.get("Content-Type") || "application/octet-stream" } });
      return json({ ok: true, key, url: `${url.origin}/file/${encodeURIComponent(key)}` });
    }
    if (method === "GET" && path.startsWith("/file/")) {
      const key = decodeURIComponent(path.replace("/file/", ""));
      const obj = await env.NOOR_BUCKET.get(key);
      if (!obj) return err("Not found", 404);
      const headers = new Headers(cors());
      obj.writeHttpMetadata(headers);
      headers.set("etag", obj.httpEtag);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      return new Response(obj.body, { headers });
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
      const existing = await db.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
      if (existing) return err("An account with this email already exists");
      const { hash, salt } = await hashPassword(password);
      const id = uid("u");
      await db.prepare("INSERT INTO users (id, name, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)")
        .bind(id, name, email.toLowerCase(), hash, salt).run();
      const token = crypto.randomUUID();
      await db.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, id).run();
      const user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
      return json({ ok: true, token, user: publicUser(user) });
    }
    if (method === "POST" && path === "/api/login") {
      const { email, password } = await request.json().catch(() => ({}));
      if (!email || !password) return err("email and password are required");
      const user = await db.prepare("SELECT * FROM users WHERE email = ?").bind(email.toLowerCase()).first();
      if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) return err("Invalid email or password", 401);
      const token = crypto.randomUUID();
      await db.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, user.id).run();
      return json({ ok: true, token, user: publicUser(user) });
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
      return json({ user: publicUser(u) });
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
      if (b.name !== undefined) { fields.push("name = ?"); vals.push(b.name); }
      if (b.avatarColor !== undefined) { fields.push("avatar_color = ?"); vals.push(b.avatarColor); }
      if (b.avatarImage !== undefined) { fields.push("avatar_image = ?"); vals.push(b.avatarImage); }
      if (b.monetizationEnabled !== undefined) { fields.push("monetization_enabled = ?"); vals.push(b.monetizationEnabled ? 1 : 0); }
      if (b.payoutInfo !== undefined) {
        fields.push("payout_method = ?", "payout_account_name = ?", "payout_account_number = ?", "payout_routing_code = ?");
        vals.push(b.payoutInfo.method, b.payoutInfo.accountName, b.payoutInfo.accountNumber, b.payoutInfo.routingCode);
      }
      if (!fields.length) return err("Nothing to update");
      vals.push(u.id);
      await db.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...vals).run();
      const updated = await db.prepare("SELECT * FROM users WHERE id = ?").bind(u.id).first();
      return json({ ok: true, user: publicUser(updated) });
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
    if (method === "GET" && path === "/api/admin/users") {
      const u = await currentUser(request, env);
      if (!u || u.role !== "admin") return err("Not allowed", 403);
      const rows = await db.prepare("SELECT * FROM users WHERE role != 'guest' ORDER BY created_at DESC").all();
      return json({ users: rows.results.map(publicUser) });
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

    // ---------- VIDEOS ----------
    if (method === "GET" && path === "/api/videos") {
      const rows = await db.prepare(
        "SELECT videos.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='video' AND target_id=videos.id) as comment_count FROM videos JOIN users ON users.id = videos.owner_id WHERE videos.removed = 0 ORDER BY videos.uploaded_at DESC LIMIT 200"
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
      if (!text || !text.trim()) return err("Comment text is required");
      const id = uid("c");
      await db.prepare("INSERT INTO comments (id, target_type, target_id, user_id, text) VALUES (?, 'video', ?, ?, ?)").bind(id, m[1], u.id, text.trim()).run();
      return json({ ok: true, id });
    }

    // ---------- REELS ----------
    if (method === "GET" && path === "/api/reels") {
      const rows = await db.prepare(
        "SELECT reels.*, users.name as owner_name, users.avatar_color as owner_avatar_color, (SELECT COUNT(*) FROM comments WHERE target_type='reel' AND target_id=reels.id) as comment_count FROM reels JOIN users ON users.id = reels.owner_id ORDER BY reels.uploaded_at DESC LIMIT 200"
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
      if (!text || !text.trim()) return err("Comment text is required");
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
