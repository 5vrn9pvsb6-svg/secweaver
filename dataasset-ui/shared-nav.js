(() => {
  const t = window.SW_I18N?.t || ((key) => key);
  const resourceModules = [
    { key: "asset", href: "./assets.html", labelKey: "module.asset", countId: "assetCount" },
    { key: "connector", href: "./connectors.html", labelKey: "module.connector", countId: "connectorCount" },
    { key: "credential", href: "./credentials.html", labelKey: "module.credential", countId: "credentialCount" },
    { key: "host", href: "./hosts.html", labelKey: "module.host", countId: "hostCount" },
    { key: "network", href: "./networks.html", labelKey: "module.network", countId: "networkCount" },
    { key: "bundle", href: "./bundles.html", labelKey: "module.bundle", countId: "bundleCount" },
    { key: "correlation", href: "./correlation.html", labelKey: "module.correlation", countId: "correlationCount" },
    { key: "scenario", href: "./scenarios.html", labelKey: "module.scenario", countId: "scenarioCount" },
  ];

  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

  function activeTopClass(key) {
    const page = document.body.dataset.page;
    const module = document.body.dataset.module;
    if (key === "home" && page === "home") return " active";
    if (key === "studio" && module) return " active";
    if (key === "onboarding" && page === "onboarding") return " active";
    if (key === "validation" && page === "validation") return " active";
    return "";
  }

  function renderTopbar() {
    const topbar = document.getElementById("appTopbar");
    if (!topbar) return;
    topbar.classList.add("topbar");
    topbar.innerHTML = `
      <div class="topbar-brand"><span class="brand-mark">SW</span><strong>${escapeHtml(t("app.title"))}</strong></div>
      <nav class="topbar-nav" aria-label="${escapeHtml(t("nav.navigation"))}">
        <a class="topbar-link${activeTopClass("home")}" href="./index.html">${escapeHtml(t("nav.home"))}</a>
        <a class="topbar-link${activeTopClass("onboarding")}" href="./onboarding.html">${escapeHtml(t("nav.onboarding"))}</a>
        <a class="topbar-link${activeTopClass("studio")}" href="./assets.html">${escapeHtml(t("nav.studio"))}</a>
        <a class="topbar-link${activeTopClass("validation")}" href="./validation.html">${escapeHtml(t("nav.validation"))}</a>
      </nav>
      <button id="languageToggle" class="button tiny ghost" type="button">${escapeHtml(t("lang.switch"))}</button>
    `;
    document.getElementById("languageToggle")?.addEventListener("click", () => window.SW_I18N?.toggleLanguage());
  }

  function renderSidebar() {
    const sidebar = document.getElementById("appSidebar");
    if (!sidebar) return;
    const currentModule = document.body.dataset.module;
    const currentPage = document.body.dataset.page;
    sidebar.classList.add("sidebar");
    sidebar.innerHTML = `
      <div class="panel compact resource-panel">
        <div class="section-heading sidebar-heading"><span class="section-kicker">${escapeHtml(t("nav.navigation"))}</span><h2>${escapeHtml(t("nav.resources"))}</h2></div>
        <nav class="resource-nav" aria-label="${escapeHtml(t("nav.resources"))}">
          ${resourceModules.map((item) => `
            <a class="nav-item${item.key === currentModule || item.key === currentPage ? " active" : ""}" href="${escapeHtml(item.href)}" data-nav-module="${escapeHtml(item.key)}">
              <span>${escapeHtml(t(item.labelKey))}</span><strong${item.countId ? ` id="${escapeHtml(item.countId)}"` : ""}>${escapeHtml(item.badge || "0/0")}</strong>
            </a>
          `).join("")}
        </nav>
      </div>
    `;
  }

  function initSidebarResize() {
    const sidebar = document.getElementById("appSidebar");
    const workbench = sidebar?.closest(".workbench");
    if (!sidebar || !workbench || workbench.querySelector(".sidebar-resizer")) return;
    const storageKey = "secweaver_sidebar_width";
    const minWidth = 200;
    const maxWidth = 420;
    const savedWidth = Number(localStorage.getItem(storageKey));
    if (savedWidth) {
      document.documentElement.style.setProperty("--sidebar-width", `${Math.min(maxWidth, Math.max(minWidth, savedWidth))}px`);
    }
    const resizer = document.createElement("div");
    resizer.className = "sidebar-resizer";
    resizer.title = "Drag to resize sidebar";
    resizer.setAttribute("role", "separator");
    resizer.setAttribute("aria-orientation", "vertical");
    sidebar.insertAdjacentElement("afterend", resizer);

    let startX = 0;
    let startWidth = 0;
    const stopResize = () => {
      document.body.classList.remove("sidebar-resizing");
      window.removeEventListener("mousemove", resize);
      window.removeEventListener("mouseup", stopResize);
    };
    const resize = (event) => {
      const width = Math.min(maxWidth, Math.max(minWidth, startWidth + event.clientX - startX));
      document.documentElement.style.setProperty("--sidebar-width", `${width}px`);
      localStorage.setItem(storageKey, String(width));
    };
    resizer.addEventListener("mousedown", (event) => {
      event.preventDefault();
      startX = event.clientX;
      startWidth = sidebar.getBoundingClientRect().width;
      document.body.classList.add("sidebar-resizing");
      window.addEventListener("mousemove", resize);
      window.addEventListener("mouseup", stopResize);
    });
  }

  renderTopbar();
  renderSidebar();
  initSidebarResize();
})();
