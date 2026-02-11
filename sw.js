/* Sigilo A33 — SW puente (Etapa 8F)
   Propósito: clientes con SW viejo pegado terminan migrando al SW versionado.
   - NO intercepta fetch (evita HTML-as-asset).
   - Notifica al cliente para que registre el SW versionado.
   - Fuerza 1 recarga con cache-bust (best-effort) para sacar al cliente del estado raro.
*/

const BRIDGE_BUILD_ID = "v0.3.4-20260211T2013Z";
const TARGET_SW = "./sw-v0.3.4.js";
const CACHE_PREFIX = "sigilo-a33-";

function postInfo(ev){
  const payload = {
    type: "SW_INFO",
    cache: "(bridge)",
    build: BRIDGE_BUILD_ID,
    script: (self.location && self.location.href) ? String(self.location.href) : ""
  };
  try{
    if (ev && ev.ports && ev.ports[0]){
      ev.ports[0].postMessage(payload);
      return;
    }
  }catch(_e){}
  try{ ev && ev.source && ev.source.postMessage && ev.source.postMessage(payload); }catch(_e){}
}

self.addEventListener("message", (event) => {
  const data = event && event.data ? event.data : null;
  if (!data || typeof data !== "object") return;
  if (data.type === "SKIP_WAITING"){
    try{ self.skipWaiting(); }catch(_e){}
    return;
  }
  if (data.type === "GET_SW_INFO"){
    postInfo(event);
  }
});

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    try{ await self.skipWaiting(); }catch(_e){}
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    // Limpieza best-effort de caches viejos (solo Sigilo)
    try{
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((k) => String(k || "").startsWith(CACHE_PREFIX))
          .map((k) => caches.delete(k))
      );
    }catch(_e){}

    try{ await self.clients.claim(); }catch(_e){}

    // Avisar + recargar una vez (cache-bust) para salir del SW viejo pegado.
    try{
      const list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of list){
        try{
          client.postMessage({
            type: "SW_BRIDGE_TO_VERSIONED",
            target: TARGET_SW,
            build: BRIDGE_BUILD_ID,
            script: (self.location && self.location.href) ? String(self.location.href) : ""
          });
        }catch(_e){}

        try{
          const u = new URL(client.url);
          // Evitar loop: solo si no existe el param.
          if (!u.searchParams.has("swfix")){
            u.searchParams.set("swfix", String(Date.now()));
            await client.navigate(u.toString());
          }
        }catch(_e){}
      }
    }catch(_e){}
  })());
});
