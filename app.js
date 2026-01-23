(() => {
  const SCREENS = ["encrypt","decrypt","contacts","profile"];

  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  const screens = $$(".screen");
  const tabs = $$(".tab");

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

  // Tabs navigation
  tabs.forEach(btn => {
    btn.addEventListener("click", () => setActive(btn.dataset.tab));
  });

  // Placeholder buttons (no crypto yet)
  $("#btnEncrypt")?.addEventListener("click", () => {
    const out = $("#encryptResult");
    out.classList.remove("empty");
    out.textContent = "⏳ Aún no ciframos en Etapa 1. Aquí se mostrará el resultado.";
    out.classList.add("empty");
  });

  $("#btnDecrypt")?.addEventListener("click", () => {
    const out = $("#decryptResult");
    out.classList.remove("empty");
    out.textContent = "⏳ Aún no desciframos en Etapa 1. Aquí se mostrará el resultado.";
    out.classList.add("empty");
  });

  $("#btnAddContact")?.addEventListener("click", () => {
    // Etapa 1: solo UI.
    alert("Próximamente: agregar contacto.");
  });

  window.addEventListener("hashchange", () => setActive(parseRoute()));

  // Initial route
  setActive(parseRoute());

  // PWA: register SW (safe no-op if not supported)
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js").catch(() => {});
    });
  }
})();
