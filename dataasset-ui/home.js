const $ = (id) => document.getElementById(id);
const t = window.SW_I18N?.t || ((key, params = {}) => Object.entries(params).reduce((text, [name, value]) => text.replaceAll(`{${name}}`, value), key));

const moduleLinks = {
  asset: "./assets.html",
  connector: "./connectors.html",
  credential: "./credentials.html",
  host: "./hosts.html",
  network: "./networks.html",
  bundle: "./bundles.html",
  correlation: "./correlation.html",
  scenario: "./scenarios.html",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || (payload.ok === false && payload.error)) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

function summarizeBy(items, key = "status") {
  return items.reduce((acc, item) => {
    const value = item[key] || "unknown";
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {});
}

function statusRows(title, items) {
  const summary = summarizeBy(items);
  const rows = Object.entries(summary)
    .map(([name, count]) => `<span class="status-chip"><strong>${escapeHtml(name)}</strong>${count}</span>`)
    .join("");
  return `<div class="status-row-card"><b>${escapeHtml(title)}</b><div>${rows || `<span class="hint">${escapeHtml(t("home.noData"))}</span>`}</div></div>`;
}

function activeTotalText(items = []) {
  const total = items.length;
  const active = items.filter((item) => item.status === "active").length;
  return `${active}/${total}`;
}

function topoDomId(prefix, id) {
  return `${prefix}-${String(id || "").replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

function shortAssetBadge(asset) {
  const type = String(asset.asset_type || "").toLowerCase();
  const name = String(asset.name || asset.asset_id || "");
  if (type.includes("waf")) return "WAF";
  if (type.includes("web_access") || name.includes("GW") || name.includes("网关")) return "GW";
  if (type.includes("host_exec")) return "EXEC";
  if (type.includes("host_connect")) return "CONN";
  if (type.includes("ssh")) return "SSH";
  if (type.includes("sls") || name.includes("SLS")) return "SLS";
  if (type.includes("firewall")) return "FW";
  const token = type.split("_").filter(Boolean)[0] || "asset";
  return token.slice(0, 4).toUpperCase();
}

function collectTopologyGraph(topology) {
  const linkedAssets = new Map();
  const edges = [];
  const networks = topology.networks || [];

  networks.forEach((network) => {
    (network.hosts || []).forEach((host) => {
      (host.assets || []).forEach((asset) => {
        const assetId = asset.asset_id;
        if (!assetId) return;
        if (!linkedAssets.has(assetId)) linkedAssets.set(assetId, asset);
        edges.push({ asset_id: assetId, host_id: host.host_id });
      });
    });
  });

  (topology.orphan_hosts || []).forEach((host) => {
    (host.assets || []).forEach((asset) => {
      const assetId = asset.asset_id;
      if (!assetId) return;
      if (!linkedAssets.has(assetId)) linkedAssets.set(assetId, asset);
      edges.push({ asset_id: assetId, host_id: host.host_id });
    });
  });

  return { linkedAssets, edges, networks };
}

const topoHiddenAssets = new Set();

function renderAssetOrbit(asset) {
  const assetId = asset.asset_id || "";
  const hidden = topoHiddenAssets.has(assetId);
  return `
    <div class="topo-asset-orbit${hidden ? " is-collapsed" : ""}" id="${topoDomId("topo-asset", assetId)}" data-asset-id="${escapeHtml(assetId)}">
      <button type="button" class="topo-circle asset-circle" title="${escapeHtml(assetId)}" aria-pressed="${hidden ? "true" : "false"}">
        <span class="topo-circle-badge">${escapeHtml(shortAssetBadge(asset))}</span>
        <strong>${escapeHtml(asset.name || assetId)}</strong>
        <small>${escapeHtml(asset.asset_type || "-")}</small>
      </button>
    </div>
  `;
}

function resolveHostExternalIp(host) {
  const external = String(host.external_ip || "").trim();
  const internal = String(host.host_ip || host.hostname || host.host_id || "").trim();
  if (!external || external === internal) return "";
  return external;
}

function buildHostTooltip(host) {
  const ip = host.host_ip || host.hostname || host.host_id || "";
  const externalIp = resolveHostExternalIp(host);
  const lines = [
    host.name && host.name !== ip ? host.name : "",
    externalIp ? `${t("home.topoExternalIp")}: ${externalIp}` : "",
    host.description || "",
  ].filter(Boolean);
  if (!lines.length) lines.push(host.hostname || host.host_id || ip);
  return lines.join("\n");
}

function renderHostBox(host) {
  const hostId = host.host_id || "";
  const ip = host.host_ip || host.hostname || hostId;
  const externalIp = resolveHostExternalIp(host);
  const isGateway = String(host.host_type || "").toLowerCase() === "gateway";
  const typeClass = isGateway ? " is-gateway" : "";
  const tip = buildHostTooltip(host);
  const label = externalIp ? `${ip} / ${externalIp}` : ip;
  const externalHtml = externalIp
    ? `<span class="topo-host-ip-ext" title="${escapeHtml(t("home.topoExternalIp"))}">${escapeHtml(externalIp)}</span>`
    : "";
  return `
    <div class="topo-host-slot" id="${topoDomId("topo-host", hostId)}" data-host-id="${escapeHtml(hostId)}">
      <button type="button" class="topo-host-box${typeClass}${externalIp ? " has-external-ip" : ""}" aria-label="${escapeHtml(label)}">
        <span class="topo-host-ip">
          <span class="topo-host-ip-inner">${escapeHtml(ip)}</span>
          ${externalHtml}
        </span>
        <div class="topo-host-tip" role="tooltip">${escapeHtml(tip).replaceAll("\n", "<br>")}</div>
      </button>
    </div>
  `;
}

function renderNetworkZone(network) {
  const networkId = network.network_id || "";
  const hosts = network.hosts || [];
  const hostHtml = hosts.length
    ? hosts.map(renderHostBox).join("")
    : `<div class="topo-empty-inline">${escapeHtml(t("home.topoNoHosts"))}</div>`;

  return `
    <div class="topo-zone" id="${topoDomId("topo-net", networkId)}" data-network-id="${escapeHtml(networkId)}">
      <header class="topo-zone-head">
        <a href="./networks.html">${escapeHtml(network.name || networkId)}</a>
        <span>${escapeHtml(network.cidr || "-")}</span>
      </header>
      <div class="topo-zone-hosts">${hostHtml}</div>
    </div>
  `;
}

function drawTopologyLines() {
  const canvas = document.getElementById("topoCanvas");
  const svg = document.getElementById("topoSvg");
  if (!canvas || !svg) return;

  let edges = [];
  try {
    edges = JSON.parse(canvas.dataset.edges || "[]");
  } catch {
    edges = [];
  }

  const canvasRect = canvas.getBoundingClientRect();
  svg.setAttribute("width", String(Math.max(canvasRect.width, 1)));
  svg.setAttribute("height", String(Math.max(canvasRect.height, 1)));
  svg.innerHTML = "";

  edges.forEach((edge) => {
    const assetEl = document.getElementById(topoDomId("topo-asset", edge.asset_id));
    const hostEl = document.getElementById(topoDomId("topo-host", edge.host_id));
    if (!assetEl || !hostEl) return;
    if (assetEl.classList.contains("is-collapsed")) return;

    const assetRect = assetEl.getBoundingClientRect();
    const hostRect = hostEl.getBoundingClientRect();
    const x1 = assetRect.left + assetRect.width / 2 - canvasRect.left;
    const y1 = assetRect.bottom - canvasRect.top;
    const x2 = hostRect.left + hostRect.width / 2 - canvasRect.left;
    const y2 = hostRect.top - canvasRect.top;
    const midY = y1 + Math.max(28, (y2 - y1) * 0.42);

    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`);
    path.setAttribute("class", "topo-edge");
    svg.appendChild(path);
  });
}

function scheduleTopologyLines() {
  requestAnimationFrame(() => {
    drawTopologyLines();
    requestAnimationFrame(drawTopologyLines);
  });
}

let topoResizeObserver = null;

function bindTopologyResize() {
  const canvas = document.getElementById("topoCanvas");
  if (!canvas) return;
  if (topoResizeObserver) topoResizeObserver.disconnect();
  if (typeof ResizeObserver !== "undefined") {
    topoResizeObserver = new ResizeObserver(scheduleTopologyLines);
    topoResizeObserver.observe(canvas);
  }
  window.addEventListener("resize", scheduleTopologyLines, { passive: true });
}

function renderAssetNode(asset, extraClass = "") {
  const assetId = asset.asset_id || "";
  const linkKind = asset.link_kind || "";
  const coverageHosts = (asset.coverage_hosts || []).length ? ` · coverage.hosts` : "";
  const modeLabel = (linkKind === "coverage" || (linkKind === "single" && (asset.coverage_hosts || []).length))
    ? (coverageHosts || ` · ${escapeHtml(t("home.topoLegendLink"))}`)
    : "";
  return `
    <a class="topo-node asset ${escapeHtml(extraClass)}" href="./assets.html" title="${escapeHtml(assetId)}">
      <b>${escapeHtml(asset.name || assetId)}</b>
      <span>${escapeHtml(asset.asset_type || "-")}${modeLabel}</span>
    </a>
  `;
}

function renderHostNode(host) {
  return renderHostBox(host);
}

function renderTopologySection(title, innerHtml) {
  if (!innerHtml) return "";
  return `
    <section class="topo-section">
      <div class="topo-section-title">${escapeHtml(title)}</div>
      ${innerHtml}
    </section>
  `;
}

function renderTopology(topology) {
  const stats = topology.stats || {};
  $("topoStats").innerHTML = `
    <span class="topo-stat-chip">${escapeHtml(t("home.topoStats", {
      networks: stats.networks || 0,
      hosts: stats.hosts || 0,
      assets: stats.assets || 0,
      linked: stats.linked_assets || 0,
    }))}</span>
  `;

  $("topoLegend").innerHTML = [
    `<span class="topo-legend-item"><i class="topo-legend-dot asset"></i>${escapeHtml(t("home.topoLegendAsset"))}</span>`,
    `<span class="topo-legend-item"><i class="topo-legend-dot network"></i>${escapeHtml(t("home.topoLegendNetwork"))}</span>`,
    `<span class="topo-legend-item"><i class="topo-legend-dot host"></i>${escapeHtml(t("home.topoLegendHost"))}</span>`,
    `<span class="topo-legend-item"><i class="topo-legend-dot gateway"></i>${escapeHtml(t("home.topoLegendGateway"))}</span>`,
    `<span class="topo-legend-item"><i class="topo-legend-dot platform"></i>${escapeHtml(t("home.topoPlatform"))}</span>`,
  ].join("");

  const { linkedAssets, edges, networks } = collectTopologyGraph(topology);
  const linkedList = [...linkedAssets.values()];
  const sections = [];

  if (networks.length || linkedList.length) {
    const assetsOrbit = linkedList.length
      ? linkedList.map(renderAssetOrbit).join("")
      : `<div class="topo-empty-inline">${escapeHtml(t("home.topoNoLinkedAssets"))}</div>`;

    const zonesHtml = networks.length
      ? networks.map(renderNetworkZone).join("")
      : `<div class="topo-empty">${escapeHtml(t("home.topoEmpty"))}</div>`;

    sections.push(`
      <div class="topo-canvas" id="topoCanvas">
        <div class="topo-layer topo-layer-assets">
          <div class="topo-layer-label">${escapeHtml(t("home.topoLegendAsset"))}</div>
          <div class="topo-assets-orbit">${assetsOrbit}</div>
        </div>
        <div class="topo-layer topo-layer-networks">
          <div class="topo-layer-label">${escapeHtml(t("home.topoLegendNetwork"))} · ${escapeHtml(t("home.topoLegendHost"))}</div>
          <div class="topo-zones-row">${zonesHtml}</div>
        </div>
        <svg class="topo-svg" id="topoSvg" aria-hidden="true"></svg>
      </div>
    `);
  } else {
    sections.push(`<div class="topo-empty">${escapeHtml(t("home.topoEmpty"))}</div>`);
  }

  const platformAssets = topology.platform_assets || [];
  if (platformAssets.length) {
    sections.push(renderTopologySection(
      t("home.topoPlatform"),
      `<div class="topo-platform-grid">${platformAssets.map((asset) => renderAssetNode(asset, "platform")).join("")}</div>`,
    ));
  }

  const unbound = topology.unbound_assets || [];
  if (unbound.length) {
    sections.push(renderTopologySection(
      t("home.topoUnbound"),
      `<div class="topo-floating-grid">${unbound.map((asset) => renderAssetNode(asset, "platform")).join("")}</div>`,
    ));
  }

  const orphanHosts = topology.orphan_hosts || [];
  if (orphanHosts.length) {
    sections.push(renderTopologySection(
      t("home.topoOrphanHosts"),
      `<div class="topo-zones-row">${orphanHosts.map((host) => `
        <div class="topo-zone topo-zone-orphan">
          <header class="topo-zone-head"><span>${escapeHtml(t("home.topoOrphanHosts"))}</span></header>
          <div class="topo-zone-hosts">${renderHostBox(host)}</div>
        </div>
      `).join("")}</div>`,
    ));
  }

  $("topologyMap").innerHTML = sections.join("");
  const canvas = document.getElementById("topoCanvas");
  if (canvas) canvas.dataset.edges = JSON.stringify(edges);
  bindHostTooltips();
  bindAssetToggle();
  scheduleTopologyLines();
  bindTopologyResize();
}

function bindAssetToggle() {
  document.querySelectorAll(".topo-asset-orbit .topo-circle").forEach((node) => {
    if (node.dataset.toggleBound === "1") return;
    node.dataset.toggleBound = "1";
    node.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const orbit = node.closest(".topo-asset-orbit");
      if (!orbit) return;
      const assetId = orbit.dataset.assetId || "";
      const collapsed = orbit.classList.toggle("is-collapsed");
      if (collapsed) topoHiddenAssets.add(assetId);
      else topoHiddenAssets.delete(assetId);
      node.setAttribute("aria-pressed", collapsed ? "true" : "false");
      scheduleTopologyLines();
    });
  });
}

let topoHostTipBound = false;

function bindHostTooltips() {
  document.querySelectorAll(".topo-host-box").forEach((node) => {
    if (node.dataset.tipBound === "1") return;
    node.dataset.tipBound = "1";
    node.addEventListener("click", (event) => {
      event.stopPropagation();
      const open = node.classList.contains("is-tip-open");
      document.querySelectorAll(".topo-host-box.is-tip-open").forEach((item) => {
        item.classList.remove("is-tip-open");
      });
      if (!open) node.classList.add("is-tip-open");
    });
  });
  if (topoHostTipBound) return;
  topoHostTipBound = true;
  document.addEventListener("click", () => {
    document.querySelectorAll(".topo-host-box.is-tip-open").forEach((item) => {
      item.classList.remove("is-tip-open");
    });
  });
}

async function loadTopology() {
  const payload = await api("/api/topology");
  renderTopology(payload.data || {});
}

function renderCounts(registry) {
  const countMap = {
    assetCount: activeTotalText(registry.assets || []),
    connectorCount: activeTotalText(registry.connectors || []),
    credentialCount: activeTotalText(registry.credentials || []),
    hostCount: activeTotalText(registry.hosts || []),
    networkCount: activeTotalText(registry.networks || []),
    bundleCount: activeTotalText(registry.bundles || []),
    correlationCount: activeTotalText(registry.correlations || []),
    scenarioCount: activeTotalText(registry.scenarios || []),
  };
  Object.entries(countMap).forEach(([id, value]) => {
    const node = $(id);
    if (node) node.textContent = value;
  });
}

function renderDashboard(registry) {
  const cards = [
    { mode: "asset", label: t("module.asset"), value: registry.assets.length, note: t("home.assetNote"), tone: "blue" },
    { mode: "connector", label: t("module.connector"), value: registry.connectors.length, note: t("home.connectorNote"), tone: "green" },
    { mode: "credential", label: t("module.credential"), value: registry.credentials.length, note: t("home.credentialNote"), tone: "purple" },
    { mode: "host", label: t("module.host"), value: registry.hosts.length, note: t("home.hostNote"), tone: "orange" },
    { mode: "network", label: t("module.network"), value: registry.networks.length, note: t("home.networkNote"), tone: "purple" },
    { mode: "bundle", label: t("module.bundle"), value: registry.bundles.length, note: t("home.bundleNote"), tone: "gold" },
  ];

  const overviewCards = $("overviewCards");
  if (overviewCards) {
    overviewCards.innerHTML = cards.map((card) => `
      <a class="overview-card ${escapeHtml(card.tone)}" href="${escapeHtml(moduleLinks[card.mode])}">
        <span>${escapeHtml(card.label)}</span>
        <strong>${card.value}</strong>
        <small>${escapeHtml(card.note)}</small>
      </a>
    `).join("");
  }

  const statusOverview = $("statusOverview");
  if (statusOverview) {
    statusOverview.innerHTML = [
      statusRows(t("module.asset"), registry.assets),
      statusRows(t("module.connector"), registry.connectors),
      statusRows(t("module.credential"), registry.credentials),
      statusRows(t("module.host"), registry.hosts),
      statusRows(t("module.bundle"), registry.bundles),
    ].join("");
  }

  const globalObjectOverview = $("globalObjectOverview");
  if (globalObjectOverview) {
    globalObjectOverview.innerHTML = `
      <a class="global-object-card" href="./correlation.html"><strong>${escapeHtml(t("module.correlation"))}</strong><span>${escapeHtml(t("home.globalCorrelation", { count: registry.correlations.length }))}</span></a>
      <a class="global-object-card" href="./scenarios.html"><strong>${escapeHtml(t("module.scenario"))}</strong><span>${escapeHtml(t("home.globalScenario", { count: registry.scenarios.length }))}</span></a>
      <a class="global-object-card" href="./networks.html"><strong>${escapeHtml(t("home.networkCoverage"))}</strong><span>${escapeHtml(t("home.networkObjects", { count: registry.networks.length }))}</span></a>
    `;
  }
}

async function loadHome() {
  const [registryPayload] = await Promise.all([
    api("/api/registry"),
    loadTopology().catch((error) => {
      $("topologyMap").innerHTML = `<div class="topo-empty">拓扑加载失败：${escapeHtml(error.message)}</div>`;
    }),
  ]);
  const registry = {
    assets: registryPayload.data?.assets || [],
    connectors: registryPayload.data?.connectors || [],
    credentials: registryPayload.data?.credentials || [],
    hosts: registryPayload.data?.hosts || [],
    networks: registryPayload.data?.networks || [],
    bundles: registryPayload.data?.bundles || [],
    correlations: registryPayload.data?.correlations || [],
    scenarios: registryPayload.data?.scenarios || [],
  };
  renderCounts(registry);
  renderDashboard(registry);
}

function initHomeText() {
  document.title = t("app.title");
  const pageTitle = document.querySelector(".page-title h1");
  const pageSubtitle = document.querySelector(".page-title .subtitle");
  const tenantCard = document.querySelector(".tenant-card");
  if (pageTitle) pageTitle.textContent = t("home.title");
  if (pageSubtitle) pageSubtitle.textContent = t("home.subtitle");
  if (tenantCard) tenantCard.textContent = t("home.tenant");
  const dashboardTitle = document.querySelector(".dashboard-hero h2");
  const dashboardHint = document.querySelector(".dashboard-hero .hint");
  const dashboardRefreshBtn = $("dashboardRefreshBtn");
  if (dashboardTitle) dashboardTitle.textContent = t("home.dashboardTitle");
  if (dashboardHint) dashboardHint.textContent = t("home.dashboardHint");
  if (dashboardRefreshBtn) dashboardRefreshBtn.textContent = t("home.refresh");
  const panelTitles = document.querySelectorAll(".dashboard-grid .panel-title-row h3");
  const panelHints = document.querySelectorAll(".dashboard-grid .panel-title-row .hint");
  if (panelTitles[0]) panelTitles[0].textContent = t("home.statusDistribution");
  if (panelHints[0]) panelHints[0].textContent = t("home.statusHint");
  if (panelTitles[1]) panelTitles[1].textContent = t("home.keyObjects");
  if (panelHints[1]) panelHints[1].textContent = t("home.keyObjectsHint");
  $("topoTitle").textContent = t("home.topoTitle");
  $("topoHint").textContent = t("home.topoHint");
}

initHomeText();
$("refreshBtn")?.addEventListener("click", loadHome);
$("dashboardRefreshBtn")?.addEventListener("click", loadHome);

loadHome().catch((error) => {
  const overviewCards = $("overviewCards");
  const errorHtml = `<div class="hint">${escapeHtml(t("home.loadFailed", { message: error.message }))}</div>`;
  if (overviewCards) overviewCards.innerHTML = errorHtml;
  else $("topologyMap").innerHTML = errorHtml;
});
