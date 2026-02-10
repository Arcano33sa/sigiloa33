(() => {
  const SCREENS = ["encrypt","decrypt","contacts","profile"];

  // Build stamp (Etapa 8E): visible para diagnóstico anti-caché/SW
  const BUILD_ID = "v0.2.11-20260210T1842Z";

  // Service Worker versionado por archivo (Etapa 8F)
  const SW_VERSIONED_FILE = "./sw-v0.2.11.js";
  const SW_BRIDGE_FILE = "./sw.js";

  // Mi QR — guardado (Etapa 1B)
  const SIGILOA33_QR_IDENTITY_SVG_V1 = "SIGILOA33_QR_IDENTITY_SVG_V1";
  const SIGILOA33_QR_IDENTITY_PNG_V1 = "SIGILOA33_QR_IDENTITY_PNG_V1";
  const SIGILOA33_QR_IDENTITY_META_V1 = "SIGILOA33_QR_IDENTITY_META_V1";

  // Sigilo A33 — Identidad local (Etapa 2)
  const DB_NAME = "sigilo-a33";
  const DB_VER = 2;
  const STORE_IDENTITY = "identity";
  const STORE_CONTACTS = "contacts";
  const IDX_CONTACT_HUELLA = "byHuella";
  const IDENTITY_ID = "me";
  const LS_KEY = "sigilo_a33_identity_v1";
  const LS_KEY_CONTACTS = "sigilo_a33_contacts_v1";

  let _storage = null; // { mode, getIdentity, setIdentity, getContacts, addContact, deleteContact, findContactByHuella }
  let _identity = null; // loaded identity record
  let _contacts = []; // cached contacts

  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  const screens = $$(".screen");
  const tabs = $$(".tab");

  const toastEl = $("#toast");
  let toastTimer = null;
  function toast(msg){
    if (!msg) return;
    if (!toastEl){
      alert(msg);
      return;
    }
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove("show"), 1600);
  }

  function setActive(screenKey){
    if (!SCREENS.includes(screenKey)) screenKey = "encrypt";

    screens.forEach(s => {
      const on = s.dataset.screen === screenKey;
      s.classList.toggle("active", on);
      s.setAttribute("aria-hidden", on ? "false" : "true");
    });

    tabs.forEach(t => {
      const on = t.dataset.tab === screenKey;
      t.classList.toggle("active", on);
      t.setAttribute("aria-current", on ? "page" : "false");
    });

    // Update hash without scrolling jumps
    const newHash = `#/${screenKey}`;
    if (location.hash !== newHash) history.replaceState(null, "", newHash);
  }

  function parseRoute(){
    const h = (location.hash || "").trim();
    const m = h.match(/^#\/(encrypt|decrypt|contacts|profile)$/);
    return m ? m[1] : "encrypt";
  }


  // ---------- Diagnóstico SW (Etapa 8E) ----------
  const swYesNo = (v) => (v ? "sí" : "no");
  let _swDiag = { supported:false, registered:false, active:false, controlling:false, state:"-", cache:"-", script:"-", build:"-" };
  let _myQrLastDiag = null;

  function swSnapshot(){
    const supported = ("serviceWorker" in navigator);
    const controlling = supported ? !!navigator.serviceWorker.controller : false;
    _swDiag = { ..._swDiag, supported, controlling };
    return _swDiag;
  }

  async function swRequestInfo(timeoutMs=650){
    if (!("serviceWorker" in navigator)) return null;
    try{
      const reg = await navigator.serviceWorker.getRegistration();
      const sw = (navigator.serviceWorker.controller || reg?.active || reg?.waiting || reg?.installing);
      if (!sw || typeof sw.postMessage !== "function") return null;

      return await new Promise((resolve) => {
        const ch = new MessageChannel();
        const t = setTimeout(() => resolve(null), timeoutMs);
        ch.port1.onmessage = (ev) => {
          clearTimeout(t);
          resolve(ev?.data || null);
        };
        try{
          sw.postMessage({ type: "GET_SW_INFO" }, [ch.port2]);
        }catch(_e){
          clearTimeout(t);
          resolve(null);
        }
      });
    }catch(_e){
      return null;
    }
  }

  async function refreshSwDiag(){
    const out = { supported:false, registered:false, active:false, controlling:false, state:"-", cache:"-", script:"-", build:"-" };
    if (!("serviceWorker" in navigator)){
      _swDiag = out;
      return out;
    }

    out.supported = true;
    out.controlling = !!navigator.serviceWorker.controller;

    try{
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg){
        out.registered = true;
        out.active = !!reg.active;
        out.state = String(reg.active?.state || reg.waiting?.state || reg.installing?.state || "-");

        // Best-effort: obtener scriptURL aunque aún no esté "controlando".
        const s0 = reg.active?.scriptURL || reg.waiting?.scriptURL || reg.installing?.scriptURL || "";
        if (s0){
          try{ out.script = new URL(String(s0), location.href).pathname.split("/").pop() || "-"; }catch(_e){ out.script = String(s0); }
        }
      }
    }catch(_e){}

    const info = await swRequestInfo(650);
    if (info && typeof info === "object"){
      const c = info.cache || info.cacheName || info.CACHE || "";
      if (c) out.cache = String(c);
      const b = info.build || info.BUILD_ID || info.BUILD || "";
      if (b) out.build = String(b);
      const s = info.script || info.scriptURL || info.url || "";
      if (s){
        try{ out.script = new URL(String(s), location.href).pathname.split("/").pop() || "-"; }catch(_e){ out.script = String(s); }
      }
    }

    _swDiag = out;
    // Si el modal está abierto, refrescar Detalles sin depender de consola.
    if (typeof updateMyQrDiagUI === "function"){
      try{ updateMyQrDiagUI(true); }catch(_e){}
    }
    return out;
  }

  
  // ---------- Salida de emergencia: Reparar caché/SW (Etapa 8F) ----------
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  async function repairCacheRescue(){
    // No toca identidad/contactos (IndexedDB/localStorage).
    // Solo SW + Cache Storage.

    const online = (typeof navigator.onLine === "boolean") ? navigator.onLine : true;
    if (!online){
      // Sin internet igual sirve para soltar SW/caches; la recarga puede depender de red.
      toast("Sin internet: se limpiará caché, pero la recarga podría fallar");
    }

    const ok = confirm("Reparar caché y recargar? (no borra tu identidad ni contactos)");
    if (!ok) return;

    toast("Reparando caché…");

    const scopeUrl = (() => {
      try{ return new URL("./", location.href).href; }catch(_e){ return ""; }
    })();

    // 1) Update/skip waiting (best-effort)
    if ("serviceWorker" in navigator){
      try{
        const regs = await navigator.serviceWorker.getRegistrations();
        for (const reg of regs){
          try{ await reg.update(); }catch(_e){}
          try{ reg.waiting && reg.waiting.postMessage && reg.waiting.postMessage({ type: "SKIP_WAITING" }); }catch(_e){}
        }
      }catch(_e){}
    }

    // 2) Unregister SW for this app scope (best-effort)
    if ("serviceWorker" in navigator){
      try{
        const regs = await navigator.serviceWorker.getRegistrations();
        for (const reg of regs){
          try{
            const sc = String(reg.scope || "");
            const mine = scopeUrl && sc && sc.startsWith(scopeUrl);
            if (mine){
              await reg.unregister();
            }
          }catch(_e){}
        }
      }catch(_e){}
    }

    // 3) Delete app caches (Cache Storage)
    if ("caches" in window){
      try{
        const keys = await caches.keys();
        const del = [];
        for (const k of keys){
          const ks = String(k || "");
          if (!ks) continue;
          // Borrado amplio pero acotado a Sigilo
          if (ks.startsWith("sigilo-a33-") || ks.includes("sigilo") || ks.includes("SIGILO")){
            del.push(caches.delete(k));
          }
        }
        await Promise.all(del);
      }catch(_e){}
    }

    // 4) Force reload with cache-bust param (keep hash)
    await sleep(120);
    try{
      const h = String(location.hash || "");
      const u = new URL(location.href);
      u.searchParams.set("r", String(Date.now()));
      u.hash = h;
      location.replace(u.toString());
    }catch(_e){
      location.reload();
    }
  }

// ---------- Storage (IndexedDB con fallback localStorage) ----------
  function openDB(){
    return new Promise((resolve, reject) => {
      if (!("indexedDB" in window)) return reject(new Error("IndexedDB no disponible"));

      const req = indexedDB.open(DB_NAME, DB_VER);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_IDENTITY)){
          db.createObjectStore(STORE_IDENTITY, { keyPath: "id" });
        }

        // Contactos (Etapa 4)
        if (!db.objectStoreNames.contains(STORE_CONTACTS)){
          const st = db.createObjectStore(STORE_CONTACTS, { keyPath: "id" });
          st.createIndex(IDX_CONTACT_HUELLA, "huella", { unique: true });
        } else {
          // Backfill de index si existe store sin index (upgrade safe)
          const tx = req.transaction;
          if (tx){
            const st = tx.objectStore(STORE_CONTACTS);
            if (st && !st.indexNames.contains(IDX_CONTACT_HUELLA)){
              st.createIndex(IDX_CONTACT_HUELLA, "huella", { unique: true });
            }
          }
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error("Fallo al abrir IndexedDB"));
      req.onblocked = () => reject(new Error("IndexedDB bloqueado"));
    });
  }

  function idbGet(db, storeName, key){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const st = tx.objectStore(storeName);
      const req = st.get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error("Fallo al leer"));
    });
  }

  function idbPut(db, storeName, val){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const st = tx.objectStore(storeName);
      const req = st.put(val);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error || new Error("Fallo al guardar"));
    });
  }

  function idbAdd(db, storeName, val){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const st = tx.objectStore(storeName);
      const req = st.add(val);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error || new Error("Fallo al agregar"));
    });
  }

  function idbDelete(db, storeName, key){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const st = tx.objectStore(storeName);
      const req = st.delete(key);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error || new Error("Fallo al eliminar"));
    });
  }

  function idbGetAll(db, storeName){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const st = tx.objectStore(storeName);
      const req = st.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error || new Error("Fallo al listar"));
    });
  }

  function idbGetByIndex(db, storeName, indexName, value){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const st = tx.objectStore(storeName);
      const idx = st.index(indexName);
      const req = idx.get(value);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error("Fallo al buscar"));
    });
  }

  function idbClear(db, storeName){
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const st = tx.objectStore(storeName);
      const req = st.clear();
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error || new Error("Fallo al limpiar"));
    });
  }

  function idbReplaceAll(db, storeName, vals){
    const list = Array.isArray(vals) ? vals : [];
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const st = tx.objectStore(storeName);

      const reqClear = st.clear();
      reqClear.onerror = () => reject(reqClear.error || new Error("Fallo al limpiar"));
      reqClear.onsuccess = () => {
        try{
          for (const v of list){
            st.put(v);
          }
        }catch(e){
          reject(e);
        }
      };

      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error || new Error("Fallo al restaurar"));
      tx.onabort = () => reject(tx.error || new Error("Restauración abortada"));
    });
  }


  async function initStorage(){
    // Preferir IndexedDB. Si no se puede (Safari privado, etc.), fallback a localStorage.
    try{
      const db = await openDB();
      _storage = {
        mode: "idb",
        getIdentity: () => idbGet(db, STORE_IDENTITY, IDENTITY_ID),
        setIdentity: (rec) => idbPut(db, STORE_IDENTITY, rec),

        // Contactos (Etapa 4)
        getContacts: () => idbGetAll(db, STORE_CONTACTS),
        findContactByHuella: (huella) => idbGetByIndex(db, STORE_CONTACTS, IDX_CONTACT_HUELLA, huella),
        addContact: (rec) => idbAdd(db, STORE_CONTACTS, rec),
        deleteContact: (id) => idbDelete(db, STORE_CONTACTS, id),

        // Backup/Restore (Etapa 8)
        clearIdentity: () => idbDelete(db, STORE_IDENTITY, IDENTITY_ID),
        clearContacts: () => idbClear(db, STORE_CONTACTS),
        replaceContacts: (arr) => idbReplaceAll(db, STORE_CONTACTS, arr)
      };
      return;
    }catch(_e){
      // fallback
    }

    try{
      const ls = window.localStorage;
      _storage = {
        mode: "ls",
        getIdentity: () => {
          const raw = ls.getItem(LS_KEY);
          if (!raw) return Promise.resolve(null);
          try{ return Promise.resolve(JSON.parse(raw)); }
          catch{ return Promise.resolve(null); }
        },
        setIdentity: (rec) => {
          ls.setItem(LS_KEY, JSON.stringify(rec));
          return Promise.resolve(true);
        },

        // Contactos (Etapa 4)
        getContacts: () => {
          const raw = ls.getItem(LS_KEY_CONTACTS);
          if (!raw) return Promise.resolve([]);
          try{
            const arr = JSON.parse(raw);
            return Promise.resolve(Array.isArray(arr) ? arr : []);
          }catch{
            return Promise.resolve([]);
          }
        },
        findContactByHuella: async (huella) => {
          const arr = await _storage.getContacts();
          return arr.find(c => c && c.huella === huella) || null;
        },
        addContact: async (rec) => {
          const arr = await _storage.getContacts();
          // evitar duplicados por huella
          if (arr.some(c => c && c.huella === rec.huella)){
            const err = new DOMException("ConstraintError", "ConstraintError");
            throw err;
          }
          arr.push(rec);
          ls.setItem(LS_KEY_CONTACTS, JSON.stringify(arr));
          return true;
        },
        deleteContact: async (id) => {
          const arr = await _storage.getContacts();
          const next = arr.filter(c => c && c.id !== id);
          ls.setItem(LS_KEY_CONTACTS, JSON.stringify(next));
          return true;
        },

        // Backup/Restore (Etapa 8)
        clearIdentity: () => {
          ls.removeItem(LS_KEY);
          return Promise.resolve(true);
        },
        clearContacts: () => {
          ls.removeItem(LS_KEY_CONTACTS);
          return Promise.resolve(true);
        },
        replaceContacts: (arr) => {
          ls.setItem(LS_KEY_CONTACTS, JSON.stringify(Array.isArray(arr) ? arr : []));
          return Promise.resolve(true);
        }
      };
    }catch(e){
      throw new Error("Sin almacenamiento persistente (IndexedDB y localStorage fallaron)");
    }
  }

  // ---------- Crypto helpers ----------
  function stableStringify(obj){
    if (obj === null || obj === undefined) return String(obj);
    if (typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
    const keys = Object.keys(obj).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
  }

  async function sha256Hex(text){
    const data = new TextEncoder().encode(String(text));
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = new Uint8Array(digest);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return hex;
  }

  function shortFingerprintFromHex(hex){
    const h = (hex || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
    const short = h.slice(0, 12) || "";
    return short ? `${short.slice(0,4)} ${short.slice(4,8)} ${short.slice(8,12)}` : "—";
  }

  async function createIdentity(){
    if (!(window.crypto && crypto.subtle)){
      throw new Error("WebCrypto no disponible en este navegador");
    }

    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1,0,1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt","decrypt"]
    );

    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    const fpHex = await sha256Hex(stableStringify(publicJwk));
    const fpShort = shortFingerprintFromHex(fpHex);

    const now = Date.now();
    return {
      id: IDENTITY_ID,
      createdAt: now,
      updatedAt: now,
      profile: { name: "", last: "", alias: "" },
      keys: { publicJwk, privateJwk },
      fingerprint: { hex: fpHex, short: fpShort },
      meta: { storagePreferred: "idb", v: 1 }
    };
  }

  async function ensureIdentity(){
    if (!_storage) await initStorage();

    const existing = await _storage.getIdentity();
    if (!existing){
      const rec = await createIdentity();
      await _storage.setIdentity(rec);
      _identity = rec;
      return;
    }

    // Idempotencia dura: si existe, NO regenerar.
    const ok = existing?.keys?.publicJwk && existing?.keys?.privateJwk;
    if (!ok){
      throw new Error("Identidad existente pero incompleta/corrupta (no se regeneró)");
    }

    // Backfill fingerprint si falta (sin tocar llaves)
    if (!existing.fingerprint || !existing.fingerprint.hex){
      const fpHex = await sha256Hex(stableStringify(existing.keys.publicJwk));
      existing.fingerprint = { hex: fpHex, short: shortFingerprintFromHex(fpHex) };
      existing.updatedAt = Date.now();
      await _storage.setIdentity(existing);
    }else if (!existing.fingerprint.short){
      existing.fingerprint.short = shortFingerprintFromHex(existing.fingerprint.hex);
      existing.updatedAt = Date.now();
      await _storage.setIdentity(existing);
    }

    // Backfill profile
    if (!existing.profile) existing.profile = { name: "", last: "", alias: "" };

    _identity = existing;
  }

  function candadoPayload(){
    if (!_identity?.keys?.publicJwk) return "";
    const obj = {
      t: "sigilo-a33-candado-v1",
      alg: "RSA-OAEP-256",
      fp: _identity?.fingerprint?.short || "",
      pub: _identity.keys.publicJwk
    };
    return JSON.stringify(obj);
  }

  function candadoPreview(str){
    if (!str) return "—";
    if (str.length <= 160) return str;
    return str.slice(0, 160) + "…";
  }

  async function copyToClipboard(text){
    const t = String(text || "");
    if (!t) throw new Error("Nada para copiar");
    if (navigator.clipboard?.writeText){
      await navigator.clipboard.writeText(t);
      return;
    }
    // Fallback
    const ta = document.createElement("textarea");
    ta.value = t;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand("copy");
    document.body.removeChild(ta);
    if (!ok) throw new Error("Clipboard no disponible");
  }



  // ---------- Mensajes 1-a-1 (Etapa 7) ----------
  const SIGILO_MSG_PREFIX = "SIGILOA33:MSG";
  const SIGILO_MSG_VERSION = 1;
  const SIGILO_MSG_INFO = "SigiloA33:MSG:1";

  let _myPrivKey = null; // CryptoKey RSA-OAEP (decrypt)
  const _pubKeyCache = new Map(); // huellaHex -> CryptoKey RSA-OAEP (encrypt)

  function isHex64(v){ return /^[0-9a-f]{64}$/i.test(String(v||"")); }

  function buildMsgAad(toFp, fromFp){
    const t = String(toFp||"").toLowerCase();
    const f = String(fromFp||"").toLowerCase();
    return new TextEncoder().encode(`${SIGILO_MSG_PREFIX}:${SIGILO_MSG_VERSION}|to=${t}|from=${f}`);
  }

  function concatBytes(a,b){
    const A = (a instanceof Uint8Array) ? a : new Uint8Array(a);
    const B = (b instanceof Uint8Array) ? b : new Uint8Array(b);
    const out = new Uint8Array(A.length + B.length);
    out.set(A,0); out.set(B,A.length);
    return out;
  }

  function splitCipherAndTag(buf, tagLen=16){
    const u = new Uint8Array(buf);
    if (u.length < tagLen + 1) throw new Error("Formato inválido");
    return {
      cipher: u.slice(0, u.length - tagLen),
      tag: u.slice(u.length - tagLen)
    };
  }

  function randBytes(n){
    const u = new Uint8Array(n);
    crypto.getRandomValues(u);
    return u;
  }

  async function importMyPrivateKey(){
    if (_myPrivKey) return _myPrivKey;
    const jwk = _identity?.keys?.privateJwk;
    if (!jwk) throw new Error("Identidad no lista");
    try{
      _myPrivKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
      );
      return _myPrivKey;
    }catch(e){
      throw new Error("No se pudo importar llave privada");
    }
  }

  async function importContactPublicKey(contact){
    const fp = String(contact?.huella||"").toLowerCase();
    if (!isHex64(fp)) throw new Error("Contacto inválido");
    if (_pubKeyCache.has(fp)) return _pubKeyCache.get(fp);

    const candadoObj = parseJsonMaybe(contact?.candadoPublico || "");
    const pubJwk = candadoObj?.pub;
    const schemaOk = (candadoObj?.t === "sigilo-a33-candado-v1" && candadoObj?.alg === "RSA-OAEP-256");
    if (!schemaOk || !pubJwk) throw new Error("Contacto sin candado válido");

    try{
      const key = await crypto.subtle.importKey(
        "jwk",
        pubJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
      _pubKeyCache.set(fp, key);
      return key;
    }catch(e){
      throw new Error("No se pudo importar candado del contacto");
    }
  }

  async function hkdfToAesKey(keyMaterialBytes, saltBytes){
    // keyMaterialBytes: 32 bytes random (raw)
    const km = (keyMaterialBytes instanceof Uint8Array) ? keyMaterialBytes : new Uint8Array(keyMaterialBytes);
    const salt = (saltBytes instanceof Uint8Array) ? saltBytes : new Uint8Array(saltBytes);

    try{
      const ikm = await crypto.subtle.importKey("raw", km, "HKDF", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(SIGILO_MSG_INFO) },
        ikm,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt","decrypt"]
      );
    }catch(e){
      // Fallback ultra simple (si HKDF no está): usar km directamente como AES-GCM 256.
      try{
        return await crypto.subtle.importKey("raw", km, { name: "AES-GCM" }, false, ["encrypt","decrypt"]);
      }catch{
        throw new Error("WebCrypto no soporta HKDF/AES-GCM");
      }
    }
  }

  function buildMsgPackage(payloadObj){
    const b64 = base64UrlEncodeJson(payloadObj);
    return `${SIGILO_MSG_PREFIX}:${SIGILO_MSG_VERSION}:${b64}`;
  }

  function parseMsgPackage(text){
    const raw = String(text||"").trim();
    const re = new RegExp(`^${SIGILO_MSG_PREFIX}:(\\d+):([A-Za-z0-9_-]+)$`);
    const m = raw.match(re);
    if (!m) throw new Error("Formato inválido");
    const ver = Number(m[1]);
    if (ver !== SIGILO_MSG_VERSION) throw new Error("Formato inválido");
    let obj;
    try{ obj = base64UrlDecodeJson(m[2]); }
    catch{ throw new Error("Formato inválido"); }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw new Error("Formato inválido");
    return obj;
  }

  async function encrypt1to1(contactId, message){
    if (!_identity) throw new Error("Identidad no lista");
    const ct = _contacts.find(c => c && c.id === contactId);
    if (!ct) throw new Error("Contacto inválido");

    const toFingerprint = String(ct.huella||"").toLowerCase();
    if (!isHex64(toFingerprint)) throw new Error("Contacto inválido");

    const fromFingerprint = String(_identity?.fingerprint?.hex || "").toLowerCase();

    const pubKey = await importContactPublicKey(ct);

    // Key material + salt + nonce
    const keyMaterial = randBytes(32);
    const salt = randBytes(16);
    const nonce = randBytes(12);

    const aesKey = await hkdfToAesKey(keyMaterial, salt);
    const aad = buildMsgAad(toFingerprint, fromFingerprint);

    const plainBytes = new TextEncoder().encode(String(message||""));
    const enc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      aesKey,
      plainBytes
    );
    const parts = splitCipherAndTag(enc, 16);

    // Wrap keyMaterial with RSA-OAEP
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, keyMaterial);

    const payload = {
      toFingerprint,
      fromFingerprint: fromFingerprint || undefined,
      nonce: base64UrlEncodeBytes(nonce),
      salt: base64UrlEncodeBytes(salt),
      params: {
        kdf: { name: "HKDF", hash: "SHA-256", info: SIGILO_MSG_INFO },
        aead: { name: "AES-GCM", tagLength: 128 },
        keywrap: { name: "RSA-OAEP", hash: "SHA-256", wrappedKey: base64UrlEncodeBytes(new Uint8Array(wrapped)) }
      },
      ciphertext: base64UrlEncodeBytes(parts.cipher),
      tag: base64UrlEncodeBytes(parts.tag)
    };

    // Limpieza: no dejar undefined en JSON
    if (!payload.fromFingerprint) delete payload.fromFingerprint;

    return buildMsgPackage(payload);
  }

  async function decrypt1to1(pkgText){
    if (!_identity) throw new Error("Identidad no lista");

    const obj = parseMsgPackage(pkgText);

    const toFp = String(obj.toFingerprint||"").toLowerCase();
    const fromFp = String(obj.fromFingerprint||"").toLowerCase();
    if (!isHex64(toFp)) throw new Error("Formato inválido");

    const myFp = String(_identity?.fingerprint?.hex || "").toLowerCase();
    if (!isHex64(myFp)) throw new Error("Identidad no lista");
    if (toFp !== myFp) throw new Error("Este mensaje no es para ti");

    const nonceB = obj.nonce;
    const saltB = obj.salt;
    const ctB = obj.ciphertext;
    const tagB = obj.tag;

    if (!nonceB || !saltB || !ctB || !tagB) throw new Error("Formato inválido");

    const wrappedKeyB64 = obj?.params?.keywrap?.wrappedKey || obj?.wrappedKey;
    if (!wrappedKeyB64) throw new Error("Formato inválido");

    let nonce, salt, cipher, tag, wrappedKey;
    try{
      nonce = base64UrlDecodeToBytes(nonceB);
      salt = base64UrlDecodeToBytes(saltB);
      cipher = base64UrlDecodeToBytes(ctB);
      tag = base64UrlDecodeToBytes(tagB);
      wrappedKey = base64UrlDecodeToBytes(wrappedKeyB64);
    }catch{
      throw new Error("Formato inválido");
    }

    const aad = buildMsgAad(toFp, fromFp);

    let keyMaterial;
    try{
      const priv = await importMyPrivateKey();
      const kmBuf = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, wrappedKey);
      keyMaterial = new Uint8Array(kmBuf);
    }catch{
      throw new Error("Clave incorrecta o mensaje alterado");
    }

    const aesKey = await hkdfToAesKey(keyMaterial, salt);

    const data = concatBytes(cipher, tag);

    let plainBuf;
    try{
      plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        data
      );
    }catch{
      throw new Error("Clave incorrecta o mensaje alterado");
    }

    const text = new TextDecoder().decode(new Uint8Array(plainBuf));
    return { text, fromFingerprint: fromFp || null };
  }

  // ---------- QR (Etapa 5) ----------
  const SIGILO_QR_PREFIX = "SIGILOA33";
  const SIGILO_QR_VERSION = 1;
  // Error correction: we auto-pick between L and M to reduce density while keeping scan reliability.
  const SIGILO_QR_EC_LEVEL_FALLBACK = "M";
  const SIGILO_QR_WARN_THRESHOLD = 350; // chars

  function base64UrlEncodeBytes(bytes){
    let bin = "";
    for (let i=0; i<bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlDecodeToBytes(b64url){
    let b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i=0; i<bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function base64UrlEncodeJson(obj){
    const json = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(json);
    return base64UrlEncodeBytes(bytes);
  }

  function base64UrlDecodeJson(b64url){
    const bytes = base64UrlDecodeToBytes(b64url);
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
  }

  function buildSigiloQrPayload(obj){
    return `${SIGILO_QR_PREFIX}:${SIGILO_QR_VERSION}:${base64UrlEncodeJson(obj)}`;
  }

  async function parseSigiloQrPayload(text){
    const raw = String(text || "").trim();
    const re = new RegExp(`^${SIGILO_QR_PREFIX}:(\\d+):([A-Za-z0-9_-]+)$`);
    const m = raw.match(re);
    if (!m) throw new Error("Formato QR inválido. Debe ser SIGILOA33:1:<base64url-json>");
    const ver = Number(m[1]);
    if (ver !== SIGILO_QR_VERSION) throw new Error(`Versión QR no soportada (${m[1]}).`);

    let obj;
    try{
      obj = base64UrlDecodeJson(m[2]);
    }catch{
      throw new Error("QR corrupto: no se pudo decodificar.");
    }

    if (!obj || typeof obj !== "object" || Array.isArray(obj))
      throw new Error("QR inválido: JSON no es un objeto.");

    const allowed = new Set(["candadoPublico","alias","huella","nombre","apellidos"]);
    for (const k of Object.keys(obj)){
      if (!allowed.has(k)) throw new Error("QR inválido: contiene campos desconocidos.");
    }

    const candadoPublico = String(obj.candadoPublico || "").trim();
    const huella = String(obj.huella || "").trim().toLowerCase();
    if (!candadoPublico) throw new Error("QR inválido: falta candadoPublico.");
    if (!/^[0-9a-f]{64}$/.test(huella)) throw new Error("QR inválido: huella no válida.");

    const alias = (typeof obj.alias === "string") ? normalizeAlias(obj.alias) : "";
    const nombre = (typeof obj.nombre === "string") ? obj.nombre.trim() : "";
    const apellidos = (typeof obj.apellidos === "string") ? obj.apellidos.trim() : "";

    const candadoObj = parseJsonMaybe(candadoPublico);
    if (!candadoObj || !candadoObj.pub) throw new Error("QR inválido: candadoPublico no es JSON válido.");

    const schemaOk = (candadoObj.t === "sigilo-a33-candado-v1" && candadoObj.alg === "RSA-OAEP-256");
    if (!schemaOk) throw new Error("QR inválido: candadoPublico no es de Sigilo A33.");

    const fpHex = await sha256Hex(stableStringify(candadoObj.pub));
    if (fpHex !== huella) throw new Error("QR inválido: huella no coincide con el candado.");

    return { candadoPublico, huella, alias, nombre, apellidos };
  }

  function buildMyQrText(){
    if (!_identity) return "";
    const p = _identity.profile || { name:"", last:"", alias:"" };
    const obj = {
      candadoPublico: candadoPayload(),
      huella: _identity?.fingerprint?.hex || ""
    };
    const a = normalizeAlias(p.alias || "");
    if (a) obj.alias = a;
    const n = (p.name || "").trim();
    const l = (p.last || "").trim();
    if (n) obj.nombre = n;
    if (l) obj.apellidos = l;
    return buildSigiloQrPayload(obj);
  }

  function lsGetSafe(key){
    try{ return window.localStorage ? window.localStorage.getItem(key) : null; }catch(_e){ return null; }
  }

  function lsSetSafe(key, value){
    try{ if (window.localStorage) window.localStorage.setItem(key, value); }catch(_e){ /* ignore */ }
  }

  function hash8(hex){
    const h = String(hex || "").trim().toLowerCase().replace(/[^0-9a-f]/g, "");
    return h ? h.slice(0, 8) : "-";
  }


  function parseQrMeta(){
    const raw = lsGetSafe(SIGILOA33_QR_IDENTITY_META_V1);
    if (!raw) return null;
    try{
      const j = JSON.parse(String(raw));
      const ts = Number(j?.ts || 0) || 0;
      const build = String(j?.build || "").trim();
      const payloadLen = Number(j?.payloadLen || 0) || 0;
      const payloadHash = String(j?.payloadHash || "").trim().toLowerCase();
      const lastGenOk = (j && typeof j.lastGenOk === "boolean") ? j.lastGenOk : null;
      const lastErrCode = String(j?.lastErrCode || "").trim();
      return {
        ts,
        build: build || "-",
        payloadLen,
        payloadHash: payloadHash ? payloadHash.replace(/[^0-9a-f]/g, "") : "",
        lastGenOk,
        lastErrCode: lastErrCode || ""
      };
    }catch{ return null; }
  }


  // Guardar meta del QR (hash/len) junto con ts/build.
  // Nota: NO genera QR; solo persiste meta cuando un flujo de guardado lo invoque.
  async function saveMyQrMetaForPayload(payloadText, opts={}){
    const t = String(payloadText || "");
    const payloadLen = t.length;
    let payloadHash = "";
    try{ payloadHash = payloadLen ? await sha256Hex(t) : ""; }catch(_e){ payloadHash = ""; }

    const ok = (opts && typeof opts.ok === "boolean") ? opts.ok : null;
    const errCodeIn = String((opts && opts.errCode) ? opts.errCode : "").trim();

    const prev = parseQrMeta();
    const meta = {
      ts: Number(prev?.ts || 0) || 0,
      build: String(prev?.build || "-").trim() || "-",
      payloadLen: Number(prev?.payloadLen || 0) || 0,
      payloadHash: String(prev?.payloadHash || "").trim().toLowerCase().replace(/[^0-9a-f]/g, ""),
      lastGenOk: (prev && typeof prev.lastGenOk === "boolean") ? prev.lastGenOk : null,
      lastErrCode: String(prev?.lastErrCode || "").trim()
    };

    if (ok === false){
      // NO tocar ts/build/payloadLen/payloadHash (mantener QR previo si existe)
      meta.lastGenOk = false;
      meta.lastErrCode = errCodeIn || "QR_GEN_FAIL_1";
      if (!prev){
        // Sin meta previa: al menos marcar build para diagnóstico.
        meta.build = BUILD_ID;
      }
    }else{
      // Éxito (o compat): actualizar sello y hash
      meta.ts = Date.now();
      meta.build = BUILD_ID;
      meta.payloadLen = payloadLen;
      meta.payloadHash = payloadHash;
      if (ok === true){
        meta.lastGenOk = true;
        meta.lastErrCode = "";
      }
      if (ok === null){
        // Compat: no tocar status fields si no se especifica ok
        meta.lastGenOk = (prev && typeof prev.lastGenOk === "boolean") ? prev.lastGenOk : null;
        meta.lastErrCode = String(prev?.lastErrCode || "").trim();
      }
    }

    lsSetSafe(SIGILOA33_QR_IDENTITY_META_V1, JSON.stringify(meta));
    return meta;
  }

  function fmtTs(ts){
    const n = Number(ts || 0) || 0;
    if (!n) return "-";
    const d = new Date(n);
    if (isNaN(d.getTime())) return "-";
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function readSavedMyQr(){
    const svgRaw = String(lsGetSafe(SIGILOA33_QR_IDENTITY_SVG_V1) || "").trim();
    const pngRaw = String(lsGetSafe(SIGILOA33_QR_IDENTITY_PNG_V1) || "").trim();
    const meta = parseQrMeta();

    const svgOk = !!(svgRaw && /<svg[\s>]/i.test(svgRaw));
    const pngOk = !!(pngRaw && /^data:image\/png/i.test(pngRaw));

    if (svgOk) return { ok:true, kind:"svg", data: svgRaw, meta };
    if (pngOk) return { ok:true, kind:"png", data: pngRaw, meta };
    return { ok:false, kind:"-", data:"", meta };
  }

  function buildQrInstance(text, ecLevel){
    const level = (ecLevel || SIGILO_QR_EC_LEVEL_FALLBACK);
    const qr = qrcode(0, level); // typeNumber auto
    qr.addData(String(text || "").trim());
    qr.make();
    return qr;
  }

  function isQrLibOk(){
    return (typeof qrcode === "function");
  }

  function isQrCapacityError(err){
    const msg = (err && err.message) ? String(err.message) : String(err || "");
    return /overflow|too long|data too long|code length/i.test(msg);
  }

  function qrCauseLabel(code){
    if (code === "A") return "A) Librería QR no cargó (probable caché/SW viejo)";
    if (code === "B") return "B) Texto QR demasiado largo para QR";
    if (code === "C") return "C) Error interno al renderizar";
    return "";
  }

  function setMyQrWarnMsg(msg, danger){
    if (!myQrWarn) return;
    const m = String(msg || "").trim();
    myQrWarn.textContent = m;
    myQrWarn.hidden = !m;
    if (danger) myQrWarn.classList.add("danger");
    else myQrWarn.classList.remove("danger");
  }

  function setMyQrStatusMsg(ok){
    if (!myQrStatus) return;
    if (ok){
      myQrStatus.textContent = "✓ Listo para escanear";
      myQrStatus.hidden = false;
    }else{
      myQrStatus.hidden = true;
    }
  }

  function setMyQrStaleUI(stale){
    if (!myQrStaleRow) return;
    myQrStaleRow.hidden = !stale;
    if (myQrStaleBadge){
      myQrStaleBadge.textContent = stale ? "QR desactualizado" : "";
    }
  }

  function setMyQrDetailsInfo(info){
    if (!myQrDetails || !myQrDetailsBody) return;
    const lines = Array.isArray(info) ? info : [];
    myQrDetailsBody.textContent = lines.filter(Boolean).join("\n");
  }

  function setMyQrPlaceholder(code){
    if (!myQrSvg) return;
    const cause = qrCauseLabel(code);
    myQrSvg.hidden = false;
    myQrSvg.innerHTML = `
      <div class="qr-placeholder">
        <div class="qr-ph-title">QR no disponible</div>
        <div class="qr-ph-cause">${cause || ""}</div>
      </div>`;
    if (myQrCanvas) myQrCanvas.hidden = true;
  }

  function setMyQrNoSavedPlaceholder(){
    if (!myQrSvg) return;
    myQrSvg.hidden = false;
    myQrSvg.innerHTML = `
      <div class="qr-placeholder">
        <div class="qr-ph-title">Aún no has generado tu QR</div>
      </div>`;
    if (myQrCanvas) myQrCanvas.hidden = true;
  }

  function renderMyQrFromSaved(){
    const saved = readSavedMyQr();
    if (myQrGenRow) myQrGenRow.hidden = !!saved.ok;

    if (saved.ok){
      clearMyQrPlaceholder();
      if (myQrSvg){
        myQrSvg.hidden = false;
        if (saved.kind === "svg"){
          myQrSvg.innerHTML = saved.data;
        }else{
          myQrSvg.innerHTML = "";
          const img = document.createElement("img");
          img.className = "qr-img";
          img.alt = "Mi QR";
          img.src = saved.data;
          myQrSvg.appendChild(img);
        }
      }
      if (myQrCanvas) myQrCanvas.hidden = true;
      setMyQrStatusMsg(true);
      setMyQrWarnMsg("", false);
    }else{
      setMyQrStatusMsg(false);
      setMyQrWarnMsg("", false);
      setMyQrNoSavedPlaceholder();
    }
    return saved;
  }

  function clearMyQrPlaceholder(){
    if (myQrSvg) myQrSvg.innerHTML = "";
  }

  function composeMyQrDetailsLines(diag){
    const d = diag || {};
    const payloadLen = Number(d.payloadLen || d.len || 0) || 0;
    const payloadHash = String(d.payloadHash || "").trim();
    const savedPayloadLen = Number(d.savedPayloadLen || 0) || 0;
    const savedPayloadHash = String(d.savedPayloadHash || "").trim();
    const stale = !!d.stale;
    const libOk = !!d.libOk;
    const attempted = Array.isArray(d.attempted) ? d.attempted : [];
    const usedRenderer = String(d.usedRenderer || "-");
    const ecUsed = String(d.ecUsed || "-");
    const errMsg = String(d.errMsg || "").trim();

    const sw = _swDiag || swSnapshot();
    const swLine = sw.supported
      ? `SW: reg ${swYesNo(sw.registered)} | activo ${swYesNo(sw.active)} | controlando ${swYesNo(sw.controlling)}${sw.state && sw.state !== "-" ? ` | ${sw.state}` : ""}`
      : "SW: no soportado";
    const swCache = sw.supported ? `SW cache: ${String(sw.cache || "-")}` : "";

    const qrSaved = !!d.qrSaved;
    const qrTs = Number(d.qrTs || 0) || 0;

    const out = [
      `Build: ${BUILD_ID}`,
      `QR guardado: ${qrSaved ? "sí" : "no"}`,
      `QR ts: ${qrTs ? fmtTs(qrTs) : "-"}`,
      `payloadLen: ${payloadLen}`,
      `payloadHash: ${hash8(payloadHash)}`,
      `savedLen: ${savedPayloadLen || "-"}`,
      `savedHash: ${hash8(savedPayloadHash)}`,
      `stale: ${stale ? "Sí" : "No"}`,
      `Lib: ${libOk ? "OK" : "NO"}` ,
      `Gen: ${d.genOk === true ? "OK" : (d.genOk === false ? "FAIL" : "-")}` ,
      `ErrCode: ${String(d.errCode || "-") || "-"}` ,
      swLine,
      swCache,
      (sw.supported && sw.build && sw.build !== "-" ? `SW build: ${sw.build}` : ""),
      (sw.supported && sw.script && sw.script !== "-" ? `SW file: ${sw.script}` : ""),
      `Renderer: ${attempted.join(" → ") || "-"}`,
      `Usado: ${usedRenderer || "-"}`,
      `EC: ${ecUsed || "-"}`,
    ];
    if (errMsg) out.push(`Err: ${errMsg}`);
    return out.filter(Boolean);
  }

  function updateMyQrDiagUI(force){
    if (!myQrModal || myQrModal.hidden) return;
    if (force) renderBuildStamps();
    if (!_myQrLastDiag) return;
    setMyQrDetailsInfo(composeMyQrDetailsLines(_myQrLastDiag));
  }



  function pickBestQrDiag(text){
    const t = String(text || "").trim();
    let qrL = null, qrM = null;
    let errL = null, errM = null;
    try{ qrL = buildQrInstance(t, "L"); }catch(e){ errL = e; qrL = null; }
    try{ qrM = buildQrInstance(t, "M"); }catch(e){ errM = e; qrM = null; }

    if (qrL && qrM){
      const nL = qrL.getModuleCount();
      const nM = qrM.getModuleCount();
      if (nL < nM) return { qr: qrL, ec: "L", errL, errM };
      if (nM < nL) return { qr: qrM, ec: "M", errL, errM };
      return { qr: qrM, ec: "M", errL, errM };
    }
    if (qrM) return { qr: qrM, ec: "M", errL, errM };
    if (qrL) return { qr: qrL, ec: "L", errL, errM };

    const err = errM || errL || new Error("QR make failed");
    try{ err.__sigilo_qr = { errL, errM }; }catch(_e){}
    throw err;
  }

  // Pick between L and M. Choose the one that yields fewer modules (less dense).
  // If tie, prefer M for a bit more resilience.
  function pickBestQr(text){
    const t = String(text || "").trim();
    let qrL = null;
    let qrM = null;
    try{ qrL = buildQrInstance(t, "L"); }catch(e){ qrL = null; }
    try{ qrM = buildQrInstance(t, "M"); }catch(e){ qrM = null; }

    if (qrL && qrM){
      const nL = qrL.getModuleCount();
      const nM = qrM.getModuleCount();
      if (nL < nM) return { qr: qrL, ec: "L" };
      if (nM < nL) return { qr: qrM, ec: "M" };
      return { qr: qrM, ec: "M" };
    }
    if (qrM) return { qr: qrM, ec: "M" };
    if (qrL) return { qr: qrL, ec: "L" };

    // last resort
    const qr = buildQrInstance(t, SIGILO_QR_EC_LEVEL_FALLBACK);
    return { qr, ec: SIGILO_QR_EC_LEVEL_FALLBACK };
  }

  function renderQrToCanvas(text, canvas){
    if (!canvas) return { ok:false, ec:null, err:new Error("NO_CANVAS") };

    if (!isQrLibOk()){
      return { ok:false, ec:null, err:new Error("QR_LIB_MISSING") };
    }

    const t = String(text || "").trim();
    if (!t){
      const ctx0 = canvas.getContext("2d");
      canvas.width = 1; canvas.height = 1;
      ctx0 && ctx0.clearRect(0,0,1,1);
      return { ok:true, ec:null, err:null };
    }

    let qrPack;
    try{
      qrPack = pickBestQrDiag(t);
    }catch(e){
      return { ok:false, ec:null, err:e };
    }

    const qr = qrPack.qr;
    const count = qr.getModuleCount();
    const quiet = 4; // modules
    const totalModules = count + quiet * 2;

    // Compute an on-screen size that fits the qr-box without CSS stretching.
    const box = canvas.closest?.(".qr-box") || canvas.parentElement;
    let targetCss = 320;
    try{
      if (box){
        const rect = box.getBoundingClientRect();
        targetCss = Number(rect?.width || targetCss) || targetCss;
        const cs = window.getComputedStyle ? getComputedStyle(box) : null;
        const padL = cs ? parseFloat(cs.paddingLeft) || 0 : 0;
        const padR = cs ? parseFloat(cs.paddingRight) || 0 : 0;
        targetCss = targetCss - padL - padR;
      }
    }catch(e){ /* ignore */ }
    targetCss = Math.max(160, Math.min(420, targetCss || 320));

    const dpr = Math.max(1, Number(window.devicePixelRatio || 1));
    const modulePx = Math.max(1, Math.floor((targetCss * dpr) / totalModules));
    const sizePx = modulePx * totalModules;

    canvas.width = sizePx;
    canvas.height = sizePx;

    const cssSize = sizePx / dpr;
    const cssPx = (Math.round(cssSize * 100) / 100).toString();
    canvas.style.width = cssPx + "px";
    canvas.style.height = cssPx + "px";

    const ctx = canvas.getContext("2d");
    if (!ctx) return { ok:false, ec:qrPack.ec, err:new Error("NO_CTX") };
    ctx.imageSmoothingEnabled = false;

    // White background (real #fff) + black modules (#000)
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, sizePx, sizePx);

    ctx.fillStyle = "#000000";
    for (let r=0; r<count; r++){
      const y = (r + quiet) * modulePx;
      for (let c=0; c<count; c++){
        if (qr.isDark(r, c)){
          ctx.fillRect((c + quiet) * modulePx, y, modulePx, modulePx);
        }
      }
    }

    return { ok:true, ec:qrPack.ec, err:null };
  }

  function renderQrToSvgInline(text, mountEl, altText){
    if (!mountEl) return { ok:false, ec:null, err:new Error("NO_MOUNT") };
    if (!isQrLibOk()) return { ok:false, ec:null, err:new Error("QR_LIB_MISSING") };

    const t = String(text || "").trim();
    if (!t){
      mountEl.innerHTML = "";
      return { ok:true, ec:null, err:null };
    }

    try{
      const { qr, ec } = pickBestQrDiag(t);
      const cellSize = 4;
      const margin = cellSize * 4; // quiet zone = 4 modules
      mountEl.innerHTML = qr.createSvgTag({ cellSize, margin, scalable: true, alt: (altText || "Mi QR") });
      return { ok:true, ec, err:null };
    }catch(e){
      mountEl.innerHTML = "";
      return { ok:false, ec:null, err:e };
    }
  }


  // ---------- Backup/Restore (Etapa 8) ----------
  const SIGILO_BACKUP_PREFIX = "SIGILOA33:BACKUP";
  const SIGILO_BACKUP_VERSION = 1;
  const SIGILO_BACKUP_AAD = `${SIGILO_BACKUP_PREFIX}:${SIGILO_BACKUP_VERSION}`;
  const SIGILO_BACKUP_PBKDF2_ITERS = 220000;

  function isBackupText(raw){
    const t = String(raw || "").trim();
    return t.startsWith(SIGILO_BACKUP_PREFIX + ":");
  }

  function parseBackupEnvelope(text){
    const t = String(text || "").trim();
    const m = t.match(/^SIGILOA33:BACKUP:(\d+):([A-Za-z0-9_-]+)$/);
    if (!m) throw new Error("Backup corrupto");
    const ver = Number(m[1]);
    if (!Number.isFinite(ver) || ver !== SIGILO_BACKUP_VERSION) throw new Error("Backup corrupto");
    const b64 = m[2];
    const env = base64UrlDecodeJson(b64);
    if (!env || typeof env !== "object") throw new Error("Backup corrupto");
    return env;
  }

  async function deriveBackupKey(password, saltBytes, iterations){
    const pw = String(password || "");
    if (!pw) throw new Error("Contraseña requerida");
    if (!(window.crypto && crypto.subtle)) throw new Error("WebCrypto no disponible");

    const salt = saltBytes instanceof Uint8Array ? saltBytes : new Uint8Array();
    const iter = Number(iterations || 0) || SIGILO_BACKUP_PBKDF2_ITERS;

    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(pw),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptBackupPlain(plain, password){
    const salt = randBytes(16);
    const iv = randBytes(12);
    const iterations = SIGILO_BACKUP_PBKDF2_ITERS;

    const key = await deriveBackupKey(password, salt, iterations);

    const aad = new TextEncoder().encode(SIGILO_BACKUP_AAD);
    const pt = new TextEncoder().encode(JSON.stringify(plain));

    const ctBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      pt
    );

    const ct = new Uint8Array(ctBuf);

    return {
      v: SIGILO_BACKUP_VERSION,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iter: iterations,
        salt: base64UrlEncodeBytes(salt)
      },
      aead: {
        name: "AES-GCM",
        iv: base64UrlEncodeBytes(iv),
        tagLength: 128,
        aad: SIGILO_BACKUP_AAD
      },
      ct: base64UrlEncodeBytes(ct)
    };
  }

  async function decryptBackupEnvelope(env, password){
    try{
      if (!env || typeof env !== "object") throw new Error("Backup corrupto");
      if (env.v !== SIGILO_BACKUP_VERSION) throw new Error("Backup corrupto");

      const kdf = env.kdf || {};
      const aead = env.aead || {};

      if (kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256") throw new Error("Backup corrupto");
      if (aead.name !== "AES-GCM") throw new Error("Backup corrupto");

      const salt = base64UrlDecodeBytes(String(kdf.salt || ""));
      const iv = base64UrlDecodeBytes(String(aead.iv || ""));
      const iterations = Number(kdf.iter || 0);
      const aadStr = String(aead.aad || "");

      if (!(salt instanceof Uint8Array) || salt.length < 8) throw new Error("Backup corrupto");
      if (!(iv instanceof Uint8Array) || iv.length < 8) throw new Error("Backup corrupto");
      if (!Number.isFinite(iterations) || iterations < 5000) throw new Error("Backup corrupto");
      if (aadStr !== SIGILO_BACKUP_AAD) throw new Error("Backup corrupto");

      const ct = base64UrlDecodeBytes(String(env.ct || ""));
      if (!(ct instanceof Uint8Array) || ct.length < 16) throw new Error("Backup corrupto");

      const key = await deriveBackupKey(password, salt, iterations);
      const aad = new TextEncoder().encode(aadStr);

      const ptBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        key,
        ct
      );

      const pt = new TextDecoder().decode(ptBuf);
      const obj = parseJsonMaybe(pt);
      if (!obj) throw new Error("Backup corrupto");
      return obj;
    }catch(e){
      // Si el envelope es válido, el fallo suele ser contraseña o tamper.
      const msg = String(e?.message || "");
      if (msg.includes("Backup corrupto")) throw e;
      throw new Error("Contraseña incorrecta");
    }
  }

  async function buildBackupText(plain, password){
    const env = await encryptBackupPlain(plain, password);
    const b64 = base64UrlEncodeJson(env);
    return `${SIGILO_BACKUP_PREFIX}:${SIGILO_BACKUP_VERSION}:${b64}`;
  }

  async function parseAndDecryptBackup(text, password){
    const env = parseBackupEnvelope(text);
    return decryptBackupEnvelope(env, password);
  }

  async function normalizeIdentityFromBackup(raw){
    if (!raw || typeof raw !== "object") throw new Error("Backup corrupto");
    const keys = raw.keys || raw.llaves || raw.keypair;
    if (!keys || typeof keys !== "object") throw new Error("Backup corrupto");
    const publicJwk = keys.publicJwk;
    const privateJwk = keys.privateJwk;
    if (!publicJwk || !privateJwk) throw new Error("Backup corrupto");

    const fpHex = await sha256Hex(stableStringify(publicJwk));
    const fpShort = shortFingerprintFromHex(fpHex);

    const prof = raw.profile || {};
    const profile = {
      name: String(prof.name || "").trim(),
      last: String(prof.last || "").trim(),
      alias: String(prof.alias || "").trim()
    };

    const now = Date.now();
    return {
      id: IDENTITY_ID,
      createdAt: Number(raw.createdAt || now) || now,
      updatedAt: now,
      profile,
      keys: { publicJwk, privateJwk },
      fingerprint: { hex: fpHex, short: fpShort },
      meta: raw.meta && typeof raw.meta === "object" ? raw.meta : { v: 1 }
    };
  }

  async function normalizeContactsFromBackup(list){
    const arr = Array.isArray(list) ? list : [];
    const out = [];
    const seenHuella = new Set();
    for (const c of arr){
      if (!c || typeof c !== "object") continue;
      const nombre = String(c.nombre || "").trim();
      const apellidos = String(c.apellidos || "").trim();
      const candadoPublico = String(c.candadoPublico || "").trim();
      if (!nombre || !apellidos || !candadoPublico) continue;

      let huella = String(c.huella || "").trim().toLowerCase();
      if (!isHex64(huella)){
        // como fallback, hash del texto
        huella = await sha256Hex(candadoPublico);
      }
      if (seenHuella.has(huella)) continue;
      seenHuella.add(huella);

      const rec = {
        id: String(c.id || "") || randomId("ct"),
        nombre,
        apellidos,
        alias: normalizeAlias(c.alias || ""),
        candadoPublico,
        huella,
        huellaShort: String(c.huellaShort || "") || shortFingerprintFromHex(huella),
        verificado: !!c.verificado,
        createdAt: Number(c.createdAt || Date.now()) || Date.now()
      };
      out.push(rec);
    }
    return out;
  }

  function downloadText(filename, text){
    const blob = new Blob([String(text || "")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 800);
  }

  function fileStamp(){
    const d = new Date();
    const pad = (n) => String(n).padStart(2,"0");
    return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}`;
  }

  // ---------- Perfil UI ----------
  const elName = $("#profileName");
  const elLast = $("#profileLast");
  const elAlias = $("#profileAlias");
  const elFp = $("#profileFingerprint");
  const elLockPrev = $("#profileLockPreview");
  const elErrCard = $("#identityError");
  const elErrTxt = $("#identityErrorText");
  const btnCopyLock = $("#btnCopyLock");
  const btnCopyFp = $("#btnCopyFingerprint");
  const btnShowMyQR = $("#btnShowMyQR");

  // Build stamps (Etapa 8E)
  const buildStampProfile = $("#buildStampProfile");
  const myQrBuildStamp = $("#myQrBuildStamp");

  const myQrModal = $("#myQrModal");
  const btnCloseMyQrModal = $("#btnCloseMyQrModal");
  const myQrSvg = $("#myQrSvg");
  const myQrCanvas = $("#myQrCanvas");
  const myQrText = $("#myQrText");
  const myQrTextWrap = $("#myQrTextWrap");
  const myQrGenRow = $("#myQrGenRow");
  const btnGenerateMyQr = $("#btnGenerateMyQr");
  const myQrStaleRow = $("#myQrStaleRow");
  const myQrStaleBadge = $("#myQrStaleBadge");
  const btnUpdateMyQr = $("#btnUpdateMyQr");
  const myQrStatus = $("#myQrStatus");
  const myQrWarn = $("#myQrWarn");
  const myQrErr = $("#myQrErr");
  const myQrDetails = $("#myQrDetails");
  const myQrDetailsBody = $("#myQrDetailsBody");
  const btnCopyMyQrText = $("#btnCopyMyQrText");
  const btnCopyMyCandado = $("#btnCopyMyCandado");
  const btnRepairCache = $("#btnRepairCache");

  // Backup UI (Etapa 8)
  const bePass = $("#backupExportPass");
  const bePass2 = $("#backupExportPass2");
  const btnExportBackup = $("#btnExportBackup");
  const btnCopyBackup = $("#btnCopyBackup");
  const beOut = $("#backupExportOut");
  const beErr = $("#backupExportErr");

  const biFile = $("#backupFile");
  const btnPickBackupFile = $("#btnPickBackupFile");
  const btnPasteBackup = $("#btnPasteBackup");
  const biText = $("#backupImportText");
  const biPass = $("#backupImportPass");
  const btnImportBackup = $("#btnImportBackup");
  const biErr = $("#backupImportErr");

  const replaceIdentityModal = $("#replaceIdentityModal");
  const replaceIdentityInfo = $("#replaceIdentityInfo");
  const replaceIdentityWord = $("#replaceIdentityWord");
  const replaceIdentityErr = $("#replaceIdentityErr");
  const btnCloseReplaceIdentityModal = $("#btnCloseReplaceIdentityModal");
  const btnReplaceIdentityCancel = $("#btnReplaceIdentityCancel");
  const btnReplaceIdentityConfirm = $("#btnReplaceIdentityConfirm");

  let _backupLastExportText = "";
  let _pendingBackup = null;
  let _importBusy = false;

  function renderBuildStamps(){
    const txt = `Build: ${BUILD_ID}`;
    if (buildStampProfile) buildStampProfile.textContent = txt;
    if (myQrBuildStamp) myQrBuildStamp.textContent = txt;
  }

  // Siempre visible, incluso antes de cargar identidad.
  renderBuildStamps();


  let saveTimer = null;

  function showIdentityError(msg){
    if (!elErrCard) return;
    elErrCard.hidden = false;
    if (elErrTxt) elErrTxt.textContent = msg || "No se pudo inicializar identidad.";
  }

  function renderProfile(){
    if (!_identity) return;

    const p = _identity.profile || { name:"", last:"", alias:"" };
    if (elName) elName.value = p.name || "";
    if (elLast) elLast.value = p.last || "";
    if (elAlias) elAlias.value = p.alias || "";

    if (elFp) elFp.textContent = _identity?.fingerprint?.short || "—";

    const lockStr = candadoPayload();
    if (elLockPrev){
      elLockPrev.textContent = candadoPreview(lockStr);
      elLockPrev.classList.toggle("empty", !lockStr);
    }
  }

  async function saveProfileDebounced(){
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      if (!_identity || !_storage) return;
      const p = _identity.profile || (_identity.profile = { name:"", last:"", alias:"" });
      p.name = (elName?.value || "").trim();
      p.last = (elLast?.value || "").trim();
      p.alias = (elAlias?.value || "").trim();
      _identity.updatedAt = Date.now();

      try{
        await _storage.setIdentity(_identity);
      }catch(e){
        toast("No se pudo guardar Perfil");
        showIdentityError(`No se pudo guardar Perfil: ${e?.message || e}`);
      }
    }, 320);
  }

  function bindProfileEvents(){
    const on = () => saveProfileDebounced();
    elName?.addEventListener("input", on);
    elLast?.addEventListener("input", on);
    elAlias?.addEventListener("input", on);

    btnCopyLock?.addEventListener("click", async () => {
      try{
        await copyToClipboard(candadoPayload());
        toast("Candado copiado");
      }catch(e){
        toast("No se pudo copiar candado");
      }
    });

    btnCopyFp?.addEventListener("click", async () => {
      try{
        await copyToClipboard(_identity?.fingerprint?.short || "");
        toast("Huella copiada");
      }catch(e){
        toast("No se pudo copiar huella");
      }
    });

    // Mi QR (Etapa 5)
    btnShowMyQR?.addEventListener("click", () => openMyQr());

    btnCloseMyQrModal?.addEventListener("click", closeMyQr);
    myQrModal?.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t.dataset && t.dataset.close) closeMyQr();
    });

    btnCopyMyQrText?.addEventListener("click", async () => {
      const t = (myQrText?.value || "").trim();
      if (!t){ toast("QR vacío"); return; }
      await copyToClipboard(t);
      toast("Texto QR copiado");
    });

    btnCopyMyCandado?.addEventListener("click", async () => {
      const t = candadoPayload();
      if (!t){ toast("Candado vacío"); return; }
      await copyToClipboard(t);
      toast("Candado copiado");
    });

    btnGenerateMyQr?.addEventListener("click", () => {
      scheduleGenerateMyQr();
    });

    btnUpdateMyQr?.addEventListener("click", () => {
      scheduleGenerateMyQr();
    });

    // Salida de emergencia (Etapa 8F)
    btnRepairCache?.addEventListener("click", () => {
      try{ repairCacheRescue(); }catch(_e){ location.reload(); }
    });

    // Rotación / resize: mantener el QR visible
    window.addEventListener("resize", () => {
      if (myQrModal && !myQrModal.hidden){
        clearTimeout(_myQrResizeTimer);
        _myQrResizeTimer = setTimeout(scheduleMyQrRender, 120);
      }
    });
  }

  function openMyQr(){
    const t = buildMyQrText();
    if (myQrText) myQrText.value = t || "";

    // Reset QR modal UI
    setHintError(myQrErr, "");
    setMyQrStatusMsg(false);
    setMyQrWarnMsg("", false);
    setMyQrStaleUI(false);
    if (myQrDetails) myQrDetails.open = false;
    setMyQrDetailsInfo([]);

    // Diagnóstico visible (build + SW)
    renderBuildStamps();
    swSnapshot();
    refreshSwDiag();

    openModal(myQrModal);
    scheduleMyQrRender();
  }

  function closeMyQr(){
    if (_myQrRaf) cancelAnimationFrame(_myQrRaf);
    _myQrRaf = 0;
    closeModal(myQrModal);
  }

  let _myQrRaf = 0;
  let _myQrResizeTimer = null;

  function scheduleMyQrRender(){
    if (!myQrModal || myQrModal.hidden) return;

    // Reset UI (sin consola)
    setHintError(myQrErr, "");
    setMyQrWarnMsg("", false);
    setMyQrStaleUI(false);
    if (myQrDetails) myQrDetails.open = false;
    setMyQrDetailsInfo([]);

    swSnapshot();

    if (_myQrRaf) cancelAnimationFrame(_myQrRaf);
    _myQrRaf = requestAnimationFrame(() => {
      _myQrRaf = 0;

      (async () => {
        // Render SOLO desde guardado (Etapa 1B)
        const saved = renderMyQrFromSaved();

        const t = (myQrText?.value || "").trim();
        const libOk = isQrLibOk();

        // Hash del payload actual (Etapa 2A)
        let payloadHash = "";
        try{ payloadHash = t ? await sha256Hex(t) : ""; }catch(_e){ payloadHash = ""; }

        const sm = saved && saved.meta ? saved.meta : null;
        const savedPayloadLen = Number(sm?.payloadLen || 0) || 0;
        const savedPayloadHash = String(sm?.payloadHash || "").trim().toLowerCase().replace(/[^0-9a-f]/g, "");

        // Determinar si el QR guardado corresponde a la identidad actual:
        // - Preferir hash de payload (Etapa 2A)
        // - Fallback: si no hay hash guardado, usar updatedAt vs ts (más seguro que asumir).
        const metaTs = Number(sm?.ts || 0) || 0;
        const idUpdatedAt = Number(_identity?.updatedAt || 0) || 0;
        const hashMismatch = !!(savedPayloadHash && payloadHash && savedPayloadHash !== payloadHash);
        const tsMismatch = !!(!savedPayloadHash && metaTs && idUpdatedAt && idUpdatedAt > metaTs);
        const unknownNoMeta = !!(!savedPayloadHash && !metaTs);
        const stale = !!saved.ok && (hashMismatch || tsMismatch || unknownNoMeta);

        // UI
        setMyQrStaleUI(!!saved.ok && stale);
        setMyQrStatusMsg(!!saved.ok && !stale);

        _myQrLastDiag = {
          payloadLen: t.length,
          payloadHash,
          savedPayloadLen,
          savedPayloadHash,
          stale,
          libOk,
          genOk: (sm && typeof sm.lastGenOk === 'boolean') ? sm.lastGenOk : null,
          errCode: (sm && sm.lastErrCode) ? String(sm.lastErrCode) : '',
          attempted: (saved.ok ? [`saved:${saved.kind}`] : []),
          usedRenderer: (saved.ok ? `saved:${saved.kind}` : "-"),
          ecUsed: "-",
          errMsg: "",
          qrSaved: !!saved.ok,
          qrTs: Number(sm?.ts || 0) || 0
        };
        updateMyQrDiagUI(true);
      })();
    });
  }

  // ---------- Mi QR actions (Etapa 2B) ----------
  let _myQrGenBusy = false;

  function setMyQrGenBusy(on){
    _myQrGenBusy = !!on;
    const dis = _myQrGenBusy;
    try{
      if (btnGenerateMyQr){
        if (dis) btnGenerateMyQr.setAttribute("disabled","disabled");
        else btnGenerateMyQr.removeAttribute("disabled");
      }
      if (btnUpdateMyQr){
        if (dis) btnUpdateMyQr.setAttribute("disabled","disabled");
        else btnUpdateMyQr.removeAttribute("disabled");
      }
    }catch(_e){}
  }

  function myQrFailUi(code, errCode, hadSaved){
    const cause = qrCauseLabel(code) || "C) Error interno al renderizar";
    const msg = `${cause} (${errCode})`;
    if (!hadSaved){
      setMyQrPlaceholder(code);
    }
    setMyQrStatusMsg(false);
    setMyQrWarnMsg(msg, true);
    try{ if (myQrDetails) myQrDetails.open = true; }catch(_e){}
  }

  function scheduleGenerateMyQr(){
    if (_myQrGenBusy) return;
    if (!myQrModal || myQrModal.hidden) return;
    setMyQrGenBusy(true);

    // Timing robusto iPad: modal abierto → rAF → setTimeout(50) → generar
    requestAnimationFrame(() => {
      setTimeout(() => {
        generateMyQrNow().finally(() => setMyQrGenBusy(false));
      }, 50);
    });
  }

  async function generateMyQrNow(){
    const t = (myQrText?.value || buildMyQrText() || "").trim();
    if (myQrText) myQrText.value = t || "";

    setHintError(myQrErr, "");
    setMyQrWarnMsg("", false);

    const prevSaved = readSavedMyQr();
    const hadSaved = !!prevSaved.ok;

    const libOk = isQrLibOk();
    if (!libOk){
      await saveMyQrMetaForPayload(t, { ok:false, errCode:"QR_LIB_MISSING" });
      if (hadSaved){
        scheduleMyQrRender();
        setTimeout(() => {
          myQrFailUi("A", "QR_LIB_MISSING", true);
          if (_myQrLastDiag){ _myQrLastDiag.genOk = false; _myQrLastDiag.errCode = "QR_LIB_MISSING"; _myQrLastDiag.libOk = false; }
          updateMyQrDiagUI(true);
        }, 80);
      }else{
        myQrFailUi("A", "QR_LIB_MISSING", false);
        if (_myQrLastDiag){ _myQrLastDiag.genOk = false; _myQrLastDiag.errCode = "QR_LIB_MISSING"; _myQrLastDiag.libOk = false; }
        updateMyQrDiagUI(true);
      }
      return;
    }

    // Generar SVG
    let svgStr = "";
    try{
      const pack = pickBestQrDiag(t);
      const qr = pack.qr;
      const cellSize = 4;
      const margin = cellSize * 4;
      svgStr = qr.createSvgTag({ cellSize, margin, scalable:true, alt:"Mi QR" });
      if (!svgStr || !/<svg[\s>]/i.test(svgStr)) throw new Error("SVG_EMPTY");

      // Guardado seguro: no perder QR previo si falla
      const prevSvg = String(lsGetSafe(SIGILOA33_QR_IDENTITY_SVG_V1) || "");
      const prevPng = String(lsGetSafe(SIGILOA33_QR_IDENTITY_PNG_V1) || "");

      lsSetSafe(SIGILOA33_QR_IDENTITY_SVG_V1, svgStr);
      const back = String(lsGetSafe(SIGILOA33_QR_IDENTITY_SVG_V1) || "");
      if (back.trim() !== svgStr.trim()){
        // Revertir
        lsSetSafe(SIGILOA33_QR_IDENTITY_SVG_V1, prevSvg);
        lsSetSafe(SIGILOA33_QR_IDENTITY_PNG_V1, prevPng);
        throw new Error("SAVE_FAIL");
      }

      // Preferir SVG: limpiar PNG legacy
      lsSetSafe(SIGILOA33_QR_IDENTITY_PNG_V1, "");

    }catch(e){
      const tooLong = isQrCapacityError(e);
      const code = tooLong ? "B" : "C";
      const errCode = tooLong ? "QR_TEXT_TOO_LONG" : "QR_GEN_FAIL_1";

      await saveMyQrMetaForPayload(t, { ok:false, errCode });

      if (hadSaved){
        scheduleMyQrRender();
        setTimeout(() => {
          myQrFailUi(code, errCode, true);
          if (_myQrLastDiag){ _myQrLastDiag.genOk = false; _myQrLastDiag.errCode = errCode; _myQrLastDiag.errMsg = String(e?.message || e || ""); }
          updateMyQrDiagUI(true);
        }, 90);
      }else{
        myQrFailUi(code, errCode, false);
        if (_myQrLastDiag){ _myQrLastDiag.genOk = false; _myQrLastDiag.errCode = errCode; _myQrLastDiag.errMsg = String(e?.message || e || ""); }
        updateMyQrDiagUI(true);
      }
      return;
    }

    // Meta: solo después de guardado correcto
    await saveMyQrMetaForPayload(t, { ok:true, errCode:"" });
    toast("QR guardado");
    scheduleMyQrRender();
  }

  // ---------- Backup UI actions (Etapa 8) ----------
  function setHintError(el, msg){
    if (!el) return;
    const m = String(msg || "").trim();
    if (m){
      el.hidden = false;
      el.textContent = m;
    }else{
      el.hidden = true;
      el.textContent = "";
    }
  }

  function setBackupExportText(text){
    _backupLastExportText = String(text || "").trim();
    if (beOut) beOut.value = _backupLastExportText;
    if (btnCopyBackup) btnCopyBackup.disabled = !_backupLastExportText;
  }

  function summarizeBackupForReplace(identityRec, contactsArr){
    const cur = _identity?.fingerprint?.short || "—";
    const bk = identityRec?.fingerprint?.short || "—";
    const n = Array.isArray(contactsArr) ? contactsArr.length : 0;
    const alias = normalizeAlias(identityRec?.profile?.alias || "");
    const a = alias ? ` (@${alias})` : "";
    return `Actual: ${cur}
Backup: ${bk}${a}
Contactos: ${n}`;
  }

  function closeReplaceIdentityModal(){
    setHintError(replaceIdentityErr, "");
    if (replaceIdentityWord) replaceIdentityWord.value = "";
    _pendingBackup = null;
    closeModal(replaceIdentityModal);
  }

  function openReplaceIdentityModal(identityRec, contactsArr){
    _pendingBackup = { identity: identityRec, contacts: contactsArr };
    setHintError(replaceIdentityErr, "");
    if (replaceIdentityInfo) replaceIdentityInfo.textContent = summarizeBackupForReplace(identityRec, contactsArr);
    if (replaceIdentityWord) replaceIdentityWord.value = "";
    openModal(replaceIdentityModal);
    setTimeout(() => replaceIdentityWord?.focus(), 60);
  }

  async function applyBackupNow(identityRec, contactsArr, opts={}){
    const replaceIdentity = !!opts.replaceIdentity;
    if (!_storage) await initStorage();

    // Identidad
    if (replaceIdentity){
      await _storage.setIdentity(identityRec);
      _identity = identityRec;
      _myPrivKey = null;
      _pubKeyCache.clear();
    } else {
      // Si no se reemplaza, al menos se actualiza el perfil.
      if (_identity){
        _identity.profile = identityRec.profile;
        _identity.updatedAt = Date.now();
        await _storage.setIdentity(_identity);
      }
    }

    // Contactos
    const list = Array.isArray(contactsArr) ? contactsArr : [];
    await _storage.replaceContacts(list);
    _pubKeyCache.clear();

    await loadContacts();
    renderProfile();
    renderContacts();
    renderEncryptContactSelect();
    refreshEncryptState();

    toast("Backup restaurado");
  }

  async function handleExportBackup(){
    if (!_storage) await initStorage();
    if (!_identity){ toast("Identidad no lista"); return; }

    setHintError(beErr, "");

    const p1 = String(bePass?.value || "");
    const p2 = String(bePass2?.value || "");
    if (!p1){
      setHintError(beErr, "Falta contraseña");
      toast("Falta contraseña");
      return;
    }
    if (p1.length < 6){
      setHintError(beErr, "Contraseña muy corta (mínimo 6)");
      toast("Contraseña muy corta");
      return;
    }
    if (p1 !== p2){
      setHintError(beErr, "Las contraseñas no coinciden");
      toast("No coinciden");
      return;
    }

    btnExportBackup?.setAttribute("disabled", "disabled");
    try{
      // asegurar contactos frescos
      await loadContacts();

      const plain = {
        kind: "sigiloa33-backup",
        v: 1,
        exportedAt: Date.now(),
        identity: {
          id: IDENTITY_ID,
          createdAt: _identity.createdAt,
          updatedAt: _identity.updatedAt,
          profile: _identity.profile,
          keys: _identity.keys,
          fingerprint: _identity.fingerprint,
          meta: _identity.meta
        },
        contacts: _contacts.slice()
      };

      const text = await buildBackupText(plain, p1);
      setBackupExportText(text);
      // bajar archivo
      downloadText(`SigiloA33_backup_${fileStamp()}.txt`, text);
      toast("Backup exportado");
    }catch(e){
      setHintError(beErr, e?.message || "No se pudo exportar");
      toast("No se pudo exportar");
    }finally{
      btnExportBackup?.removeAttribute("disabled");
    }
  }

  async function handleImportBackup(){
    if (_importBusy) return;
    _importBusy = true;
    btnImportBackup?.setAttribute("disabled", "disabled");

    try{
      setHintError(biErr, "");

      const raw = String(biText?.value || "").trim();
      const pass = String(biPass?.value || "");

      if (!raw){
        setHintError(biErr, "Pega o sube un backup");
        toast("Falta backup");
        return;
      }
      if (!isBackupText(raw)){
        setHintError(biErr, "Formato inválido");
        toast("Formato inválido");
        return;
      }
      if (!pass){
        setHintError(biErr, "Falta contraseña");
        toast("Falta contraseña");
        return;
      }

      const plain = await parseAndDecryptBackup(raw, pass);

      const rawId = plain.identity || plain.identidad;
      const rawContacts = plain.contacts || plain.contactos || [];

      const idRec = await normalizeIdentityFromBackup(rawId);
      const ctArr = await normalizeContactsFromBackup(rawContacts);

      const currentHex = _identity?.fingerprint?.hex || "";
      const backupHex = idRec?.fingerprint?.hex || "";

      // Si hay identidad actual distinta, exigir confirmación fuerte.
      if (_identity && currentHex && backupHex && currentHex !== backupHex){
        openReplaceIdentityModal(idRec, ctArr);
        toast("Confirma reemplazo");
        return;
      }

      await applyBackupNow(idRec, ctArr, { replaceIdentity: true });
    }catch(e){
      const msg = String(e?.message || "") || "No se pudo importar";
      setHintError(biErr, msg);
      toast(msg);
    }finally{
      btnImportBackup?.removeAttribute("disabled");
      _importBusy = false;
    }
  }

  function bindBackupEvents(){
    btnExportBackup?.addEventListener("click", handleExportBackup);

    btnCopyBackup?.addEventListener("click", async () => {
      const t = String(_backupLastExportText || "").trim();
      if (!t){ toast("Nada para copiar"); return; }
      try{
        await copyToClipboard(t);
        toast("Backup copiado");
      }catch{
        toast("No se pudo copiar");
      }
    });

    btnPickBackupFile?.addEventListener("click", () => biFile?.click());

    biFile?.addEventListener("change", async () => {
      setHintError(biErr, "");
      const f = biFile.files && biFile.files[0];
      if (!f) return;
      try{
        const text = await f.text();
        if (biText) biText.value = String(text || "").trim();
        toast("Backup cargado");
      }catch{
        toast("No se pudo leer archivo");
      }
    });

    btnPasteBackup?.addEventListener("click", async () => {
      setHintError(biErr, "");
      try{
        const t = await navigator.clipboard.readText();
        if (biText) biText.value = String(t || "").trim();
        toast("Pegado");
      }catch{
        toast("No se pudo pegar");
      }
    });

    btnImportBackup?.addEventListener("click", handleImportBackup);

    // Modal reemplazar identidad
    btnCloseReplaceIdentityModal?.addEventListener("click", closeReplaceIdentityModal);
    btnReplaceIdentityCancel?.addEventListener("click", closeReplaceIdentityModal);

    replaceIdentityModal?.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t.dataset && t.dataset.close) closeReplaceIdentityModal();
    });

    btnReplaceIdentityConfirm?.addEventListener("click", async () => {
      setHintError(replaceIdentityErr, "");
      const w = String(replaceIdentityWord?.value || "").trim().toUpperCase();
      if (w !== "REEMPLAZAR"){
        setHintError(replaceIdentityErr, "Escribe REEMPLAZAR para confirmar");
        return;
      }
      const payload = _pendingBackup;
      if (!payload){
        closeReplaceIdentityModal();
        return;
      }
      closeReplaceIdentityModal();
      try{
        await applyBackupNow(payload.identity, payload.contacts, { replaceIdentity: true });
      }catch(e){
        toast(e?.message || "No se pudo restaurar");
      }
    });
  }

  // ---------- Contactos UI (Etapa 4) ----------
  const elContactSearch = $("#contactSearch");
  const elContactsEmpty = $("#contactsEmpty");
  const elContactsList = $("#contactsList");
  const contactItemTpl = $("#contactItemTpl");
  const btnAddContact = $("#btnAddContact");

  const contactModal = $("#contactModal");
  const cmTitle = $("#contactModalTitle");
  const cmName = $("#contactName");
  const cmLast = $("#contactLast");
  const cmAlias = $("#contactAlias");
  const cmLock = $("#contactLock");
  const cmQrText = $("#contactQrText");
  const cmQrError = $("#contactQrError");
  const btnScanContactQR = $("#btnScanContactQR");
  const cmDetectedAlias = $("#contactDetectedAlias");
  const cmDetectedHuella = $("#contactDetectedHuella");
  const cmVerified = $("#contactVerified");
  const btnSaveContact = $("#btnSaveContact");
  const btnCancelContact = $("#btnCancelContact");
  const btnCloseContactModal = $("#btnCloseContactModal");

  // Modal: Escanear QR (Etapa 6)
  const scanQrModal = $("#scanQrModal");
  const scanQrVideo = $("#scanQrVideo");
  const scanQrError = $("#scanQrError");
  const btnCloseScanQrModal = $("#btnCloseScanQrModal");
  const btnScanQrPaste = $("#btnScanQrPaste");
  const btnScanQrCancel = $("#btnScanQrCancel");

  const confirmModal = $("#confirmModal");
  const confirmText = $("#confirmText");
  const btnConfirmCancel = $("#btnConfirmCancel");
  const btnConfirmDelete = $("#btnConfirmDelete");
  const btnCloseConfirmModal = $("#btnCloseConfirmModal");

  let _scanStream = null;
  let _scanLoopOn = false;
  let _scanLastTs = 0;

  let _pendingDelete = null;
  let _savingContact = false;

  function setScanQrError(msg){
    if (!scanQrError) return;
    const m = String(msg || "").trim();
    if (m){
      scanQrError.hidden = false;
      scanQrError.textContent = m;
    }else{
      scanQrError.hidden = true;
      scanQrError.textContent = "";
    }
  }

  function setDetected(alias, huellaHex){
    const a = normalizeAlias(alias || "");
    if (cmDetectedAlias) cmDetectedAlias.textContent = a ? "@" + a : "—";
    if (cmDetectedHuella){
      const hx = String(huellaHex || "").trim().toLowerCase();
      cmDetectedHuella.textContent = /^[0-9a-f]{64}$/.test(hx) ? shortFingerprintFromHex(hx) : "—";
    }
  }

  function clearDetected(){
    setDetected("", "");
  }

  async function applyQrTextToContactForm(qrText){
    const t = String(qrText || "").trim();
    if (!t){
      setContactQrError("");
      clearDetected();
      return;
    }
    try{
      const parsed = await parseSigiloQrPayload(t);
      setContactQrError("");
      setDetected(parsed.alias, parsed.huella);
      if (parsed.candadoPublico && cmLock) cmLock.value = parsed.candadoPublico;
      if (parsed.alias && cmAlias) cmAlias.value = "@" + normalizeAlias(parsed.alias);
      if (parsed.nombre && cmName) cmName.value = parsed.nombre;
      if (parsed.apellidos && cmLast) cmLast.value = parsed.apellidos;
    }catch(e){
      setContactQrError(e?.message || "QR inválido");
      clearDetected();
    }
  }

  function scanFallbackToPaste(reason){
    // Fallback inmediato a pegar texto QR
    if (reason) toast(reason);
    closeModal(scanQrModal);
    stopQrScan();
    setTimeout(() => cmQrText?.focus(), 50);
  }

  function stopQrScan(){
    _scanLoopOn = false;
    if (_scanStream){
      try{ _scanStream.getTracks().forEach(t => t.stop()); }catch{}
      _scanStream = null;
    }
    if (scanQrVideo){
      try{ scanQrVideo.srcObject = null; }catch{}
    }
  }

  async function startQrScan(){
    // Requisitos mínimos
    if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)){
      scanFallbackToPaste("No hay cámara en este navegador");
      return;
    }
    if (!window.isSecureContext){
      scanFallbackToPaste("La cámara requiere HTTPS. Usa https o pega el texto QR.");
      return;
    }
    if (!("BarcodeDetector" in window)){
      scanFallbackToPaste("Este navegador no soporta escaneo QR. Pega el texto QR.");
      return;
    }

    let detector;
    try{
      detector = new BarcodeDetector({ formats: ["qr_code"] });
    }catch{
      scanFallbackToPaste("Escaneo QR no disponible. Pega el texto QR.");
      return;
    }

    setScanQrError("");
    try{
      _scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
    }catch(e){
      const name = e?.name || "";
      if (name === "NotAllowedError" || name === "PermissionDeniedError"){
        scanFallbackToPaste("Permiso de cámara denegado. Pega el texto QR.");
        return;
      }
      if (name === "NotFoundError" || name === "OverconstrainedError"){
        scanFallbackToPaste("No se encontró cámara. Pega el texto QR.");
        return;
      }
      scanFallbackToPaste("No se pudo abrir la cámara. Pega el texto QR.");
      return;
    }

    if (scanQrVideo){
      scanQrVideo.srcObject = _scanStream;
      try{ await scanQrVideo.play(); }catch{}
    }

    _scanLoopOn = true;
    _scanLastTs = 0;

    const loop = async (ts) => {
      if (!_scanLoopOn) return;
      // throttle ~4fps
      if (ts && _scanLastTs && (ts - _scanLastTs) < 240){
        requestAnimationFrame(loop);
        return;
      }
      _scanLastTs = ts || (Date.now());

      try{
        const img = scanQrVideo;
        if (img && img.readyState >= 2){
          const codes = await detector.detect(img);
          if (codes && codes.length){
            const raw = String(codes[0].rawValue || "").trim();
            if (raw){
              stopQrScan();
              closeModal(scanQrModal);
              if (cmQrText) cmQrText.value = raw;
              await applyQrTextToContactForm(raw);
              toast("QR leído");
              return;
            }
          }
        }
      }catch{
        // si falla, solo sigue; el usuario puede fallback
      }
      requestAnimationFrame(loop);
    };

    requestAnimationFrame(loop);
  }

  function randomId(prefix="c"){
    const buf = new Uint8Array(8);
    (crypto.getRandomValues ? crypto.getRandomValues(buf) : buf.fill(Math.floor(Math.random()*256)));
    let s = "";
    for (const b of buf) s += b.toString(16).padStart(2,"0");
    return `${prefix}_${Date.now().toString(36)}_${s}`;
  }

  function normalizeAlias(a){
    let t = String(a || "").trim();
    if (!t) return "";
    if (t.startsWith("@")) t = t.slice(1);
    t = t.replace(/\s+/g, "");
    return t;
  }

  function formatDisplayName(c){
    const n = `${(c.nombre||"").trim()} ${(c.apellidos||"").trim()}`.trim() || "(Sin nombre)";
    const a = normalizeAlias(c.alias);
    return a ? `${n} (@${a})` : n;
  }

  function lockToFingerprintShort12(hex){
    const h = (hex || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
    return h.slice(0, 12);
  }

  function parseJsonMaybe(text){
    try{
      const obj = JSON.parse(text);
      return (obj && typeof obj === "object") ? obj : null;
    }catch{
      return null;
    }
  }

  function setContactQrError(msg){
    if (!cmQrError) return;
    const m = String(msg || "").trim();
    if (m){
      cmQrError.hidden = false;
      cmQrError.textContent = m;
    }else{
      cmQrError.hidden = true;
      cmQrError.textContent = "";
    }
  }

  async function computeContactMeta(candadoPublico){
    const raw = String(candadoPublico || "").trim();
    const obj = parseJsonMaybe(raw);
    if (obj && obj.pub){
      const fpHex = await sha256Hex(stableStringify(obj.pub));
      const fpShort = shortFingerprintFromHex(fpHex);
      const expectedShort12 = lockToFingerprintShort12(fpHex);
      const providedShort12 = lockToFingerprintShort12(obj.fp || "");
      let verificado = false;
      const schemaOk = (obj.t === "sigilo-a33-candado-v1" && obj.alg === "RSA-OAEP-256");
      if (schemaOk){
        verificado = providedShort12 ? (providedShort12 === expectedShort12) : true;
      }
      return { fpHex, fpShort, verificado };
    }

    // fallback: huella por texto
    const fpHex = await sha256Hex(raw);
    return { fpHex, fpShort: shortFingerprintFromHex(fpHex), verificado: false };
  }

  async function loadContacts(){
    if (!_storage) await initStorage();
    const arr = await _storage.getContacts();
    _contacts = Array.isArray(arr) ? arr.slice() : [];
    // Orden compacto: por nombre/apellidos, luego createdAt
    _contacts.sort((a,b) => {
      const an = `${(a?.nombre||"").toLowerCase()} ${(a?.apellidos||"").toLowerCase()}`.trim();
      const bn = `${(b?.nombre||"").toLowerCase()} ${(b?.apellidos||"").toLowerCase()}`.trim();
      if (an < bn) return -1;
      if (an > bn) return 1;
      return (a?.createdAt||0) - (b?.createdAt||0);
    });
  }

  function setContactsEmptyState(mode){
    if (!elContactsEmpty) return;
    const title = elContactsEmpty.querySelector(".empty-title");
    const subtitle = elContactsEmpty.querySelector(".empty-subtitle");
    if (mode === "noresults"){
      if (title) title.textContent = "Sin resultados";
      if (subtitle) subtitle.textContent = "Prueba con otro nombre, apellido o alias.";
    } else {
      if (title) title.textContent = "Sin contactos todavía";
      if (subtitle) subtitle.textContent = "Agrega uno para cifrar con su clave.";
    }
  }

  function filterContacts(q){
    const t = String(q || "").trim().toLowerCase();
    if (!t) return _contacts.slice();
    return _contacts.filter(c => {
      const hay = `${c?.nombre||""} ${c?.apellidos||""} ${normalizeAlias(c?.alias||"")}`.toLowerCase();
      return hay.includes(t);
    });
  }

  function renderContacts(){
    if (!elContactsList || !contactItemTpl) return;

    const q = elContactSearch?.value || "";
    const list = filterContacts(q);

    elContactsList.innerHTML = "";

    if (list.length === 0){
      elContactsList.hidden = true;
      if (elContactsEmpty){
        elContactsEmpty.hidden = false;
        setContactsEmptyState(_contacts.length ? "noresults" : "empty");
      }
      return;
    }

    if (elContactsEmpty) elContactsEmpty.hidden = true;
    elContactsList.hidden = false;

    for (const c of list){
      const node = contactItemTpl.content.firstElementChild.cloneNode(true);
      node.dataset.id = c.id;

      const titleEl = node.querySelector(".item-title");
      if (titleEl) titleEl.textContent = formatDisplayName(c);

      const subEl = node.querySelector(".item-subtitle");
      if (subEl){
        subEl.textContent = "";
        subEl.classList.add("item-subrow");

        const badge = document.createElement("span");
        badge.className = `badge ${c.verificado ? "ok" : "no"}`;
        badge.textContent = c.verificado ? "Verificado" : "No verificado";

        const fp = document.createElement("span");
        fp.className = "mono tiny";
        fp.textContent = c.huellaShort || shortFingerprintFromHex(c.huella);

        subEl.appendChild(badge);
        subEl.appendChild(fp);
      }

      const btnDel = node.querySelector("button");
      if (btnDel){
        btnDel.dataset.action = "delete";
        btnDel.type = "button";
      }

      elContactsList.appendChild(node);
    }
  }

  function openModal(el){
    if (!el) return;
    el.hidden = false;
    el.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
  }

  function closeModal(el){
    if (!el) return;
    el.hidden = true;
    el.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
  }

  function openAddContact(){
    if (!_identity){
      toast("Identidad no lista");
      return;
    }
    if (cmTitle) cmTitle.textContent = "Agregar contacto";
    if (cmName) cmName.value = "";
    if (cmLast) cmLast.value = "";
    if (cmAlias) cmAlias.value = "";
    if (cmLock) cmLock.value = "";
    if (cmQrText) cmQrText.value = "";
    if (cmVerified) cmVerified.checked = false;
    clearDetected();
    setContactQrError("");
    openModal(contactModal);
    setTimeout(() => cmName?.focus(), 50);
  }

  function openConfirmDelete(contact){
    _pendingDelete = contact;
    if (confirmText) confirmText.textContent = `¿Eliminar ${formatDisplayName(contact)}?`;
    openModal(confirmModal);
  }

  async function handleSaveContact(){
    if (_savingContact) return;
    if (!_storage) await initStorage();

    let nombre = (cmName?.value || "").trim();
    let apellidos = (cmLast?.value || "").trim();
    let alias = normalizeAlias(cmAlias?.value || "");
    let candadoPublico = (cmLock?.value || "").trim();
    const qrText = (cmQrText?.value || "").trim();
    const verificado = !!(cmVerified && cmVerified.checked);

    if (qrText){
      try{
        const parsed = await parseSigiloQrPayload(qrText);
        candadoPublico = parsed.candadoPublico;

        if (!alias && parsed.alias) alias = normalizeAlias(parsed.alias);
        if (!nombre && parsed.nombre) nombre = parsed.nombre;
        if (!apellidos && parsed.apellidos) apellidos = parsed.apellidos;

        // Transparencia: reflejar lo importado
        if (cmLock) cmLock.value = candadoPublico;
        if (parsed.alias && cmAlias && !cmAlias.value.trim()) cmAlias.value = "@" + normalizeAlias(parsed.alias);
        if (parsed.nombre && cmName && !cmName.value.trim()) cmName.value = parsed.nombre;
        if (parsed.apellidos && cmLast && !cmLast.value.trim()) cmLast.value = parsed.apellidos;

        setContactQrError("");
      }catch(e){
        const msg = e?.message || "QR inválido";
        setContactQrError(msg);
        toast(msg);
        return;
      }
    }else{
      setContactQrError("");
    }

    if (!nombre || !apellidos){
      toast("Falta nombre/apellidos");
      return;
    }
    if (!candadoPublico){
      toast("Pega el candado público");
      return;
    }

    try{
      _savingContact = true;
      btnSaveContact?.setAttribute("disabled","disabled");

      const meta = await computeContactMeta(candadoPublico);

      // Anti-duplicados por huella
      const existing = await _storage.findContactByHuella(meta.fpHex);
      if (existing){
        toast("Ese candado ya existe");
        return;
      }

      const rec = {
        id: randomId("ct"),
        nombre,
        apellidos,
        alias,
        candadoPublico,
        huella: meta.fpHex,
        huellaShort: meta.fpShort,
        verificado, // Etapa 6: se marca manualmente
        createdAt: Date.now()
      };

      await _storage.addContact(rec);
      await loadContacts();
      renderContacts();
      renderEncryptContactSelect();
      closeModal(contactModal);
      toast("Contacto guardado");
    }catch(e){
      const name = e?.name || "";
      if (name === "ConstraintError") toast("Ese candado ya existe");
      else toast("No se pudo guardar");
    }finally{
      _savingContact = false;
      btnSaveContact?.removeAttribute("disabled");
    }
  }

  async function handleDeleteContact(){
    if (!_pendingDelete) return;
    if (!_storage) await initStorage();
    const id = _pendingDelete.id;
    try{
      await _storage.deleteContact(id);
      _pendingDelete = null;
      closeModal(confirmModal);
      await loadContacts();
      renderContacts();
      renderEncryptContactSelect();
      toast("Contacto eliminado");
    }catch(e){
      toast("No se pudo eliminar");
    }
  }

  function bindContactEvents(){
    btnAddContact?.addEventListener("click", openAddContact);

    // Escanear QR (cámara)
    btnScanContactQR?.addEventListener("click", async () => {
      openModal(scanQrModal);
      await startQrScan();
    });

    const closeScan = () => {
      closeModal(scanQrModal);
      stopQrScan();
      setScanQrError("");
    };

    btnCloseScanQrModal?.addEventListener("click", closeScan);
    btnScanQrCancel?.addEventListener("click", closeScan);
    btnScanQrPaste?.addEventListener("click", () => scanFallbackToPaste(""));

    scanQrModal?.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t.dataset && t.dataset.close) closeScan();
    });

    // QR (autorrelleno por texto)
    let qrTimer = null;
    cmQrText?.addEventListener("input", () => {
      clearTimeout(qrTimer);
      qrTimer = setTimeout(async () => {
        const t = (cmQrText.value || "").trim();
        await applyQrTextToContactForm(t);
      }, 220);
    });


    // Search
    elContactSearch?.addEventListener("input", () => renderContacts());

    // Lista (delegación)
    elContactsList?.addEventListener("click", (ev) => {
      const btn = ev.target?.closest?.("button");
      if (!btn) return;
      if (btn.dataset.action !== "delete") return;
      const item = ev.target?.closest?.(".item");
      const id = item?.dataset?.id;
      if (!id) return;
      const c = _contacts.find(x => x.id === id);
      if (!c) return;
      openConfirmDelete(c);
    });

    // Modales: cerrar
    const closeCM = () => {
      closeModal(contactModal);
      closeScan();
    };
    const closeConf = () => { _pendingDelete = null; closeModal(confirmModal); };

    btnCancelContact?.addEventListener("click", closeCM);
    btnCloseContactModal?.addEventListener("click", closeCM);
    btnSaveContact?.addEventListener("click", handleSaveContact);

    btnConfirmCancel?.addEventListener("click", closeConf);
    btnCloseConfirmModal?.addEventListener("click", closeConf);
    btnConfirmDelete?.addEventListener("click", handleDeleteContact);

    // Backdrops click
    contactModal?.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t.dataset && t.dataset.close) closeCM();
    });
    confirmModal?.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t.dataset && t.dataset.close) closeConf();
    });

    // Escape
    window.addEventListener("keydown", (ev) => {
      if (ev.key !== "Escape") return;
      if (scanQrModal && !scanQrModal.hidden) closeScan();
      if (contactModal && !contactModal.hidden) closeCM();
      if (confirmModal && !confirmModal.hidden) closeConf();
      if (myQrModal && !myQrModal.hidden) closeMyQr();
    });
  }

  // ENCRIPTAR: poblar selector de contactos (útil ya en Etapa 4)
  const elEncryptSelect = $("#encryptContact");
  function renderEncryptContactSelect(){
    if (!elEncryptSelect) return;
    elEncryptSelect.innerHTML = "";
    if (!_contacts.length){
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "Sin contactos aún";
      elEncryptSelect.appendChild(opt);
      return;
    refreshEncryptState();
  }
    const opt0 = document.createElement("option");
    opt0.value = "";
    opt0.textContent = "Selecciona un contacto…";
    elEncryptSelect.appendChild(opt0);
    for (const c of _contacts){
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = formatDisplayName(c);
      elEncryptSelect.appendChild(opt);
    }
  }

  // Tabs navigation
  tabs.forEach(btn => {
    btn.addEventListener("click", () => setActive(btn.dataset.tab));
  });


  // ---------- Encriptar / Desencriptar UI (Etapa 7) ----------
  const elEncryptInput = $("#encryptInput");
  const elEncryptResult = $("#encryptResult");
  const btnEncrypt = $("#btnEncrypt");
  const btnCopyEncrypted = $("#btnCopyEncrypted");
  const btnShareEncrypted = $("#btnShareEncrypted");

  const elDecryptInput = $("#decryptInput");
  const elDecryptResult = $("#decryptResult");
  const btnDecrypt = $("#btnDecrypt");

  function setEncryptResultText(text){
    if (!elEncryptResult) return;
    elEncryptResult.value = String(text || "");
  }

  function setDecryptResultText(text, isError=false){
    if (!elDecryptResult) return;
    elDecryptResult.classList.remove("empty");
    elDecryptResult.textContent = String(text || "");
    if (isError) elDecryptResult.classList.add("empty");
  }

  function refreshEncryptState(){
    const msgOk = !!(elEncryptInput && elEncryptInput.value.trim());
    const contactOk = !!(elEncryptSelect && elEncryptSelect.value);
    const hasContacts = !!(_contacts && _contacts.length);
    const can = hasContacts && msgOk && contactOk && !!_identity;
    if (btnEncrypt){
      if (can) btnEncrypt.removeAttribute("disabled");
      else btnEncrypt.setAttribute("disabled","disabled");
    }

    // Copiar/Compartir habilitados solo si hay paquete
    const hasPkg = !!(elEncryptResult && elEncryptResult.value.trim());
    if (btnCopyEncrypted){
      if (hasPkg) btnCopyEncrypted.removeAttribute("disabled");
      else btnCopyEncrypted.setAttribute("disabled","disabled");
    }
    if (btnShareEncrypted){
      if (!navigator.share) {
        btnShareEncrypted.hidden = true;
      } else {
        btnShareEncrypted.hidden = false;
        if (hasPkg) btnShareEncrypted.removeAttribute("disabled");
        else btnShareEncrypted.setAttribute("disabled","disabled");
      }
    }
  }

  elEncryptInput?.addEventListener("input", refreshEncryptState);
  elEncryptSelect?.addEventListener("change", refreshEncryptState);

  btnEncrypt?.addEventListener("click", async () => {
    try{
      if (!_identity){ toast("Cargando identidad…"); return; }
      const contactId = elEncryptSelect?.value || "";
      const msg = (elEncryptInput?.value || "").trim();

      if (!_contacts.length){ toast("No hay contactos"); return; }
      if (!contactId){ toast("Selecciona un contacto"); return; }
      if (!msg){ toast("Mensaje vacío"); return; }

      btnEncrypt?.setAttribute("disabled","disabled");
      setEncryptResultText("");

      const pkg = await encrypt1to1(contactId, msg);
      setEncryptResultText(pkg);
      toast("Listo: paquete generado");

      refreshEncryptState();
    }catch(e){
      const m = e?.message || "No se pudo encriptar";
      toast(m);
      setEncryptResultText("");
      refreshEncryptState();
    }
  });

  btnCopyEncrypted?.addEventListener("click", async () => {
    try{
      const t = (elEncryptResult?.value || "").trim();
      if (!t){ toast("Nada para copiar"); return; }
      await copyToClipboard(t);
      toast("Copiado");
    }catch{
      toast("No se pudo copiar");
    }
  });

  btnShareEncrypted?.addEventListener("click", async () => {
    try{
      const t = (elEncryptResult?.value || "").trim();
      if (!t){ toast("Nada para compartir"); return; }
      if (!navigator.share){ toast("Compartir no disponible"); return; }
      await navigator.share({ text: t, title: "Sigilo A33" });
    }catch{
      // usuario canceló o falla: silencio
    }
  });

  btnDecrypt?.addEventListener("click", async () => {
    try{
      if (!_identity){ toast("Cargando identidad…"); return; }
      const raw = (elDecryptInput?.value || "").trim();
      if (!raw){ toast("Pega el paquete"); return; }

      btnDecrypt?.setAttribute("disabled","disabled");
      setDecryptResultText("⏳ Desencriptando…", true);

      const res = await decrypt1to1(raw);

      // Si podemos, etiquetar el remitente por contactos
      let header = "";
      if (res.fromFingerprint && isHex64(res.fromFingerprint)){
        const c = _contacts.find(x => x && String(x.huella||"").toLowerCase() === res.fromFingerprint);
        if (c) header = `De: ${formatDisplayName(c)}

`;
      }

      setDecryptResultText(header + (res.text || ""), false);
      toast("Listo");
    }catch(e){
      const m = e?.message || "Clave incorrecta o mensaje alterado";
      setDecryptResultText(m, true);
      toast(m);
    }finally{
      btnDecrypt?.removeAttribute("disabled");
    }
  });


  window.addEventListener("hashchange", () => setActive(parseRoute()));

  // Initial route
  setActive(parseRoute());

  // Etapa 2: identidad local
  (async () => {
    try{
      await ensureIdentity();
      renderProfile();
      bindProfileEvents();
      bindBackupEvents();

      // Etapa 4: contactos persistentes
      await loadContacts();
      renderContacts();
      renderEncryptContactSelect();
      refreshEncryptState();
      bindContactEvents();
    }catch(e){
      const cause = e?.message || String(e);
      showIdentityError(`No se pudo inicializar identidad: ${cause}`);
    }
  })();

  // PWA: register SW (safe no-op if not supported)
  function registerSwBestEffort(){
    if (!('serviceWorker' in navigator)) return;
    try{
      navigator.serviceWorker.register(SW_VERSIONED_FILE)
        .then(() => { try{ refreshSwDiag(); }catch(_e){} })
        .catch(() => { try{ navigator.serviceWorker.register(SW_BRIDGE_FILE).catch(() => {}); }catch(_e){} });
    }catch(_e){}
  }

  // Registrar lo antes posible (mejor para iPad/PWA post “Reparar caché”)
  registerSwBestEffort();
  window.addEventListener('load', () => { try{ registerSwBestEffort(); }catch(_e){} });

    // Puente: si un SW viejo te avisa que está en modo rescate, re-registra el SW versionado.
    try{
      navigator.serviceWorker.addEventListener("message", (ev) => {
        const d = ev && ev.data ? ev.data : null;
        if (!d || typeof d !== "object") return;
        if (d.type !== "SW_BRIDGE_TO_VERSIONED") return;
        // Best-effort: intenta migrar al SW versionado y recarga.
        navigator.serviceWorker.register(SW_VERSIONED_FILE).then(() => {
          try{ refreshSwDiag(); }catch(_e){}
          try{ location.reload(); }catch(_e){}
        }).catch(() => {});
      });
    }catch(_e){}

})();
