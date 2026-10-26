/* NoorTube app-shell service worker.
   What it does: keeps the app's main page on the phone, so the app opens at once (even on a weak network), and refreshes that copy quietly in the background.
   What it never touches: API calls, videos, images, the Studio and Admin pages, and anything that is not a normal page open.
   If anything goes wrong it simply lets the normal network request happen. */
const CACHE = "nt-shell-v1";
const SHELL_KEY = "/__nt_shell";
const MAX_AGE_MS = 5 * 24 * 3600 * 1000; // a saved copy older than 5 days is not used first

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil((async () => { try { await saveShell(); } catch (_) {} })());
});
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    try { for (const k of await caches.keys()) if (k.startsWith("nt-shell-") && k !== CACHE) await caches.delete(k); } catch (_) {}
    try { await self.clients.claim(); } catch (_) {}
  })());
});

async function saveShell() {
  const res = await fetch(new Request(self.location.origin + "/", { cache: "no-cache", credentials: "same-origin" }));
  const type = res.headers.get("content-type") || "";
  if (!res.ok || !/text\/html/i.test(type)) return null;
  const body = await res.clone().arrayBuffer();
  const headers = new Headers(res.headers);
  headers.set("x-nt-saved-at", String(Date.now()));
  const copy = new Response(body, { status: 200, headers });
  const cache = await caches.open(CACHE);
  await cache.put(new Request(self.location.origin + SHELL_KEY), copy);
  return res;
}

const SKIP = /^\/(noortube-(studio|admin)\.html|index-22-7\.html|sw\.js|manifest\.json|app-ads\.txt|ads\.txt|robots\.txt|sitemap\.xml)$/;

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" || req.mode !== "navigate") return;
  let url;
  try { url = new URL(req.url); } catch (_) { return; }
  if (url.origin !== self.location.origin || SKIP.test(url.pathname) || url.searchParams.has("fresh")) return;
  event.respondWith(answer(event));
});

async function answer(event) {
  const req = event.request;
  let cached = null;
  try {
    const cache = await caches.open(CACHE);
    cached = await cache.match(new Request(self.location.origin + SHELL_KEY));
  } catch (_) {}
  const age = cached ? Date.now() - (Number(cached.headers.get("x-nt-saved-at")) || 0) : Infinity;
  if (cached && age < MAX_AGE_MS) {
    event.waitUntil(saveShell().catch(() => null)); // refresh quietly for next time
    return cached;
  }
  try { // first visit, or the saved copy is old: ask the network first
    const res = await saveShell();
    if (res) return res;
  } catch (_) {}
  try { return await fetch(req); } catch (e) { if (cached) return cached; throw e; }
}
