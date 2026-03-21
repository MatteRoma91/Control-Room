/**
 * Theme: localStorage cr-theme = light | dark | system
 * Dispatches window event cr-theme-change after apply.
 */
(function () {
  const KEY = "cr-theme";

  function getMode() {
    try {
      const s = localStorage.getItem(KEY);
      if (s === "light" || s === "dark" || s === "system") return s;
    } catch (_) {}
    return "system";
  }

  function isDark(mode) {
    if (mode === "dark") return true;
    if (mode === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function syncMetaThemeColor() {
    const el = document.querySelector('meta[name="theme-color"]');
    if (!el) return;
    const v = getComputedStyle(document.documentElement)
      .getPropertyValue("--cr-theme-color")
      .trim();
    if (v) el.setAttribute("content", v);
  }

  function applyFromStorage() {
    const mode = getMode();
    const dark = isDark(mode);
    document.documentElement.classList.toggle("dark", dark);
    syncMetaThemeColor();
    window.dispatchEvent(
      new CustomEvent("cr-theme-change", { detail: { mode, dark } })
    );
    updateToggleUI();
  }

  function cycle() {
    const order = ["system", "light", "dark"];
    const cur = getMode();
    const i = order.indexOf(cur);
    const next = order[(i + 1) % order.length];
    try {
      localStorage.setItem(KEY, next);
    } catch (_) {}
    applyFromStorage();
  }

  function updateToggleUI() {
    const mode = getMode();
    const labels = { system: "Sistema", light: "Chiaro", dark: "Scuro" };
    document.querySelectorAll("[data-cr-theme-label]").forEach((el) => {
      el.textContent = labels[mode] || mode;
    });
    document.querySelectorAll("[data-cr-theme-cycle]").forEach((btn) => {
      btn.setAttribute(
        "title",
        "Tema: " +
          (labels[mode] || mode) +
          " (clic per cambiare: sistema → chiaro → scuro)"
      );
      btn.setAttribute(
        "aria-label",
        "Cambia tema. Attuale: " + (labels[mode] || mode)
      );
    });
  }

  window.CRTheme = { getMode, cycle, apply: applyFromStorage };

  document.addEventListener("DOMContentLoaded", function () {
    applyFromStorage();
    window
      .matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", function () {
        if (getMode() === "system") applyFromStorage();
      });
    document.querySelectorAll("[data-cr-theme-cycle]").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        cycle();
      });
    });
  });
})();
