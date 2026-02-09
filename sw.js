/* Sigilo A33 — SW (Etapa 9B) */
// HARDENING: nunca devolver index.html a requests de assets (.js/.css/.png/etc)
// para evitar que el navegador reciba HTML como si fuera JS (típico "QR en blanco" en iPad/PWA).
const CACHE = "sigilo-a33-v0.2.2-9b";
const ASSETS = [
  "./",
  "./index.html",
  "./styles.css",
  "./app.js",
  "./manifest.json",
  "./qrcode-generator.js",
  "./assets/sigilo-a33-logo.png",
  "./assets/logo.png",
  "./assets/icon-192.png",
  "./assets/icon-512.png",
  "./assets/icon-512-maskable.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((k) => (k === CACHE ? null : caches.delete(k))))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin GET
  if (req.method !== "GET" || url.origin !== self.location.origin) return;

  const isNavigate = (req.mode === "navigate") || (req.destination === "document");

  // NAVIGATION (HTML/document): permitir fallback a index.html
  if (isNavigate) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          // Cache navigation responses opportunistically (best-effort)
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() =>
          caches.match(req).then((cached) => cached || caches.match("./index.html"))
        )
    );
    return;
  }

  // ASSETS (JS/CSS/IMGS/JSON/etc): NUNCA devolver index.html.
  // Cache-first; si no hay cache y falla red, devolver error de red (pero no HTML).
  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          // Solo cachear respuestas OK. (Evita guardar errores intermedios)
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => new Response("", { status: 504, statusText: "Offline" }));
    })
  );
});
