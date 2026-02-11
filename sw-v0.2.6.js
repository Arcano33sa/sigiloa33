/* Sigilo A33 — SW versionado (Etapa 8F)
   OBJETIVO: evitar "SW viejo pegado" usando un archivo distinto.
   HARDENING: fallback a index.html SOLO navegación; assets JAMÁS reciben HTML. */

const BUILD_ID = "v0.2.6-20260210T1553Z";
const CACHE_PREFIX = "sigilo-a33-";
const CACHE = `${CACHE_PREFIX}${BUILD_ID}`;

const ASSETS = [
  "./",
  "./index.html",
  "./styles.css",
  "./app.js",
  "./manifest.json",
  "./assets/sigilo-a33-logo.png",
  "./assets/logo.png",
  "./assets/icon-192.png",
  "./assets/icon-512.png",
  "./assets/icon-512-maskable.png"
];

// Diagnóstico: responder cache/build/script al cliente (sin consola)
self.addEventListener("message", (event) => {
  const data = event && event.data ? event.data : null;
  if (!data || typeof data !== "object") return;

  if (data.type === "SKIP_WAITING") {
    try{ self.skipWaiting(); }catch(_e){}
    return;
  }

  if (data.type !== "GET_SW_INFO") return;

  const payload = {
    type: "SW_INFO",
    cache: CACHE,
    build: BUILD_ID,
    script: (self.location && self.location.href) ? String(self.location.href) : ""
  };

  try{
    if (event.ports && event.ports[0]){
      event.ports[0].postMessage(payload);
      return;
    }
  }catch(_e){}

  try{
    event.source && event.source.postMessage && event.source.postMessage(payload);
  }catch(_e){}
});

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    try{
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((k) => String(k || "").startsWith(CACHE_PREFIX) && k !== CACHE)
          .map((k) => caches.delete(k))
      );
    }catch(_e){}

    try{ await self.clients.claim(); }catch(_e){}
  })());
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
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() =>
          caches.match(req, { ignoreSearch: true })
            .then((cached) => cached || caches.match("./index.html"))
        )
    );
    return;
  }

  // ASSETS (JS/CSS/IMGS/JSON/etc): NUNCA devolver index.html.
  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
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
