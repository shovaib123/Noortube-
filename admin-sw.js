/* NoorTube Admin service worker.
   Scope is limited to /noortube-admin.html so it can NEVER touch the main NoorTube app,
   its API calls, uploads or video streaming. */
const VERSION = 'admin-v1';
const PAGE = '/noortube-admin.html';
const CORE = [PAGE, '/admin-manifest.json', '/admin-icon-192.png', '/admin-icon-512.png'];
const CDN_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(VERSION).then((c) => Promise.all(CORE.map((u) => c.add(u).catch(() => {})))).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('admin-') && k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Page itself: network first (always fresh), cached copy only when offline
  if (req.mode === 'navigate' && url.origin === self.location.origin) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(PAGE, copy)); }
          return res;
        })
        .catch(() => caches.match(PAGE).then((r) => r || Response.error()))
    );
    return;
  }

  // Admin files + the CDN libraries it needs: serve cached, refresh in background
  const isAdminFile = url.origin === self.location.origin && (url.pathname === PAGE || url.pathname.startsWith('/admin-'));
  if (isAdminFile || CDN_HOSTS.includes(url.hostname)) {
    e.respondWith(
      caches.open(VERSION).then(async (cache) => {
        const hit = await cache.match(req);
        const net = fetch(req)
          .then((res) => { if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone()); return res; })
          .catch(() => hit || Response.error());
        return hit || net;
      })
    );
  }
});
