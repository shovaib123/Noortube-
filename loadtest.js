#!/usr/bin/env node
/*
  NoorTube load test (READ-ONLY): it only opens pages the way viewers do. It never signs up,
  never likes, comments, uploads or deletes anything, so it does not change your data.

  Needs Node 18 or newer (check with:  node -v).  Run it from a computer (not from the phone app).

  Examples
    node loadtest.js https://YOUR-WORKER.workers.dev --yes
    node loadtest.js https://YOUR-WORKER.workers.dev --yes --stages 20,50,100,200 --seconds 20
    node loadtest.js https://YOUR-WORKER.workers.dev --yes --token SESSION_TOKEN     (logged-in viewers: the heavy path)
    node loadtest.js https://YOUR-WORKER.workers.dev --yes --stream                  (also fetch the first part of videos)

  Options
    --stages 10,30,60   how many "viewers" at the same time in each round (default 10,30,60)
    --seconds 20        length of each round (default 20)
    --token XYZ         session token of a TEST account (browser: Local Storage after login). Tests the logged-in feed.
    --stream            also request a small piece (first 256 KB) of a video file, like a player does
    --stop-at 20        stop early if more than this % of requests fail with 5xx / timeout (default 20)
    --yes               REQUIRED. Confirms you understand the warning below.

  WARNING
    * Do NOT run this on the Cloudflare FREE plan against your live app. It spends the daily request and
      database limits (free plan: queries fail after the limit, since 1 Sept 2026). Run it on the paid plan,
      or against a separate test copy of the worker + database.
    * Start small (the default stages are small). Watch the Cloudflare dashboard while it runs.
    * Everything runs from ONE internet connection, so very high numbers can be limited by your own wifi/PC.
*/
"use strict";

const args = process.argv.slice(2);
const base = (args.find((a) => /^https?:\/\//.test(a)) || "").replace(/\/+$/, "");
const opt = (n, d) => { const i = args.indexOf("--" + n); return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : d; };
const has = (n) => args.includes("--" + n);

if (!base) { console.log("Usage: node loadtest.js https://YOUR-WORKER.workers.dev --yes   (read the notes at the top of this file)"); process.exit(1); }
if (typeof fetch !== "function") { console.log("Node 18 or newer is needed. Your version:", process.version); process.exit(1); }
if (!has("yes")) {
  console.log("Stopped. Read the WARNING at the top of loadtest.js, then add --yes to start.\n(Do not run on the free plan against the live app.)");
  process.exit(1);
}

const STAGES = String(opt("stages", "10,30,60")).split(",").map((x) => parseInt(x, 10)).filter((n) => n > 0);
const SECONDS = Math.max(5, parseInt(opt("seconds", "20"), 10) || 20);
const TOKEN = opt("token", "");
const STREAM = has("stream");
const STOP_AT = parseFloat(opt("stop-at", "20")) || 20;
const TIMEOUT_MS = 15000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = (a) => a[Math.floor(Math.random() * a.length)];
const pct = (arr, p) => { if (!arr.length) return 0; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]; };

let stats; // per round
function resetStats() { stats = { total: 0, ok: 0, s4: 0, s429: 0, s5: 0, net: 0, lat: [], byEp: {} }; }

async function hit(name, path, extra) {
  const t0 = performance.now();
  const ep = (stats.byEp[name] = stats.byEp[name] || { n: 0, bad: 0, lat: [] });
  const ac = new AbortController();
  const to = setTimeout(() => ac.abort(), TIMEOUT_MS);
  stats.total++; ep.n++;
  try {
    const headers = Object.assign({ "User-Agent": "NoorTubeLoadTest" }, TOKEN ? { Authorization: "Bearer " + TOKEN } : {}, (extra && extra.headers) || {});
    const res = await fetch(base + path, { headers, signal: ac.signal });
    let bodyText = null;
    if (extra && extra.json) bodyText = await res.text(); else if (extra && extra.range) { await res.arrayBuffer(); } else { await res.arrayBuffer(); }
    const ms = performance.now() - t0;
    stats.lat.push(ms); ep.lat.push(ms);
    if (res.status === 429) { stats.s429++; ep.bad++; }
    else if (res.status >= 500) { stats.s5++; ep.bad++; }
    else if (res.status >= 400) { stats.s4++; ep.bad++; }
    else stats.ok++;
    if (extra && extra.json && res.ok) { try { return JSON.parse(bodyText); } catch (_) {} }
    return null;
  } catch (_) {
    stats.net++; ep.bad++; stats.lat.push(TIMEOUT_MS); ep.lat.push(TIMEOUT_MS);
    return null;
  } finally { clearTimeout(to); }
}

// One "viewer": opens the home feed, opens a video, reads comments, sometimes reels / statuses / trending.
async function viewer(until) {
  while (Date.now() < until) {
    const feed = await hit("feed videos", "/api/videos?limit=20", { json: true });
    const list = (feed && (feed.videos || feed)) || [];
    const v = Array.isArray(list) && list.length ? rnd(list.slice(0, 20)) : null;
    if (v && v.id) {
      await sleep(200 + Math.random() * 600);
      await hit("video page", "/api/videos/" + encodeURIComponent(v.id));
      await hit("comments", "/api/videos/" + encodeURIComponent(v.id) + "/comments");
      const furl = STREAM && (v.fileUrl || v.url || v.videoUrl);
      if (furl) {
        const p = String(furl).replace(/^https?:\/\/[^/]+/i, "");
        await hit("video bytes (256KB)", p.startsWith("/") ? p : "/" + p, { range: true, headers: { Range: "bytes=0-262143" } });
      }
    }
    const r = Math.random();
    if (r < 0.35) await hit("feed reels", "/api/reels?limit=20");
    else if (r < 0.55) await hit("statuses", "/api/statuses");
    else if (r < 0.7) await hit("trending", "/api/trending-week");
    else if (r < 0.8) await hit("app config", "/api/ads/config");
    await sleep(400 + Math.random() * 1200); // a real person reads / watches for a moment
  }
}

function report(users, secs) {
  const rps = stats.total / secs, bad = stats.s5 + stats.net, badPct = stats.total ? (bad * 100) / stats.total : 0;
  console.log(`\n=== ${users} viewers at the same time, ${secs}s ===`);
  console.log(`requests: ${stats.total} (${rps.toFixed(1)}/s)  ok: ${stats.ok}  4xx: ${stats.s4}  429(limit): ${stats.s429}  5xx: ${stats.s5}  timeout/network: ${stats.net}`);
  console.log(`speed (ms)  p50: ${pct(stats.lat, 50).toFixed(0)}   p95: ${pct(stats.lat, 95).toFixed(0)}   p99: ${pct(stats.lat, 99).toFixed(0)}   worst: ${Math.max(0, ...stats.lat).toFixed(0)}`);
  console.log("per page:");
  for (const [k, e] of Object.entries(stats.byEp)) console.log(`  ${k.padEnd(22)} n=${String(e.n).padEnd(5)} failed=${String(e.bad).padEnd(4)} p50=${pct(e.lat, 50).toFixed(0)}ms p95=${pct(e.lat, 95).toFixed(0)}ms`);
  const p95 = pct(stats.lat, 95);
  const verdict = badPct > 5 ? "PROBLEM: many failures" : stats.s429 > stats.total * 0.05 ? "NOTE: many 'too many requests' answers (rate limits kicking in)" : p95 > 2500 ? "SLOW: 5% of requests take more than 2.5 s" : p95 > 1200 ? "OK but getting slow" : "GOOD";
  console.log("verdict: " + verdict);
  return badPct;
}

(async () => {
  console.log(`Target: ${base}\nMode: ${TOKEN ? "logged-in viewer" : "guest viewer (feed is edge-cached)"}${STREAM ? " + video bytes" : ""}\nRounds: ${STAGES.join(", ")} viewers, ${SECONDS}s each. Press Ctrl+C to stop.`);
  const pre = await fetch(base + "/api/videos?limit=1", { headers: { "User-Agent": "NoorTubeLoadTest" } }).catch(() => null);
  if (!pre || !pre.ok) { console.log("Cannot reach " + base + "/api/videos (status " + (pre ? pre.status : "no answer") + "). Check the address."); process.exit(1); }
  for (const users of STAGES) {
    resetStats();
    const until = Date.now() + SECONDS * 1000;
    await Promise.all(Array.from({ length: users }, (_, i) => sleep(i * 20).then(() => viewer(until))));
    const badPct = report(users, SECONDS);
    if (badPct > STOP_AT) { console.log(`\nStopped early: more than ${STOP_AT}% failed at ${users} viewers. This is roughly where the app starts to struggle.`); break; }
    await sleep(3000);
  }
  console.log("\nDone. Tip: look at the Cloudflare dashboard (Workers + D1 metrics) for the same time window to see CPU, errors and rows read.");
})();
