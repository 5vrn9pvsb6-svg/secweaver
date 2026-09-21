const state = {
  registry: {
    assets: [],
    connectors: [],
    hosts: [],
    networks: [],
    bundles: [],
    correlations: [],
    scenarios: [],
    templates: [],
  },
  mode: "home",
  asset: null,
  host: null,
  detail: null,
  selectedAssetId: null,
  selectedHostId: null,
  selectedDetail: { kind: null, id: null },
  assetDirty: false,
  hostDirty: false,
};

const readonlyModes = ["connector", "network", "bundle", "correlation", "scenario"];

const $ = (id) => document.getElementById(id);

const assetControls = [
  "asset_id", "name", "asset_type", "domain", "status", "environment", "owner_team",
  "sensitivity", "description", "host_mode", "host_id", "host_field", "connector_id",
  "schema_fields", "time_field", "retention_days", "text_parser", "tags", "rawJson",
];

const hostControls = [
  "host_form_id", "host_form_name", "host_form_hostname", "host_form_type", "host_form_os",
  "host_form_environment", "host_form_status", "host_form_zone", "host_form_description",
  "host_form_ip", "host_form_gateway", "host_form_roles", "host_form_tags", "hostRawJson",
];

function api(path, options = {}) {
  return fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  }).then(async (response) => {
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || (payload.ok === false && payload.error)) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    return payload;
  });
}

function linesToArray(text) {
  return text.split("\n").map((item) => item.trim()).filter(Boolean);
}

function csvToArray(text) {
  return text.split(",").map((item) => item.trim()).filter(Boolean);
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

const moduleMeta = {
  home: { label: "首页总览", kicker: "Overview", description: "查看数据资产、主机、网络、Bundle 等配置对象的整体状态。" },
  asset: { label: "数据资产", kicker: "Data Asset", description: "管理安全数据源资产、字段、连接器和查询模板。" },
  connector: { label: "Connector", kicker: "Connector", description: "查看数据源连接器配置与接入方式。" },
  host: { label: "主机", kicker: "Host", description: "管理主机身份、网络位置、角色和标签。" },
  network: { label: "网络", kicker: "Network", description: "查看网段、逻辑区域、网络用途和信任等级。" },
  bundle: { label: "Bundle", kicker: "Bundle", description: "查看调查场景所需的数据资产包。" },
  correlation: { label: "Correlation Matrix", kicker: "Correlation", description: "查看跨源 Join 合同、时间窗与关联规则。" },
  scenario: { label: "Scenario Pattern", kicker: "Scenario", description: "查看调查场景编排、推荐 Join 链和默认资产包。" },
};

function updateListHeader(mode) {
  const meta = moduleMeta[mode] || moduleMeta.asset;
  if ($("listKicker")) $("listKicker").textContent = meta.kicker;
  if ($("listTitle")) $("listTitle").textContent = meta.label;
  if ($("listDescription")) $("listDescription").textContent = meta.description;
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
  const rows = Object.entries(summary).map(([name, count]) => `<span class="status-chip"><strong>${escapeHtml(name)}</strong>${count}</span>`).join("");
  return `<div class="status-row-card"><b>${escapeHtml(title)}</b><div>${rows || "<span class=\"hint\">暂无数据</span>"}</div></div>`;
}

function renderDashboard() {
  const cards = [
    { mode: "asset", label: "数据资产", value: state.registry.assets.length, note: "已注册资产", tone: "blue" },
    { mode: "connector", label: "Connector", value: state.registry.connectors.length, note: "连接器配置", tone: "green" },
    { mode: "host", label: "主机", value: state.registry.hosts.length, note: "主机身份", tone: "orange" },
    { mode: "network", label: "网络", value: state.registry.networks.length, note: "网段与区域", tone: "purple" },
    { mode: "bundle", label: "Bundle", value: state.registry.bundles.length, note: "资产包", tone: "gold" },
  ];
  $("overviewCards").innerHTML = cards.map((card) => `
    <button class="overview-card ${escapeHtml(card.tone)}" type="button" data-dashboard-mode="${escapeHtml(card.mode)}">
      <span>${escapeHtml(card.label)}</span>
      <strong>${card.value}</strong>
      <small>${escapeHtml(card.note)}</small>
    </button>
  `).join("");
  document.querySelectorAll("[data-dashboard-mode]").forEach((button) => {
    button.addEventListener("click", () => openModule(button.dataset.dashboardMode));
  });
  $("statusOverview").innerHTML = [
    statusRows("数据资产", state.registry.assets),
    statusRows("Connector", state.registry.connectors),
    statusRows("主机", state.registry.hosts),
    statusRows("Bundle", state.registry.bundles),
  ].join("");
  $("globalObjectOverview").innerHTML = `
    <button class="global-object-card" type="button" data-dashboard-mode="correlation"><strong>Correlation Matrix</strong><span>${state.registry.correlations.length} 个全局关联配置</span></button>
    <button class="global-object-card" type="button" data-dashboard-mode="scenario"><strong>Scenario Pattern</strong><span>${state.registry.scenarios.length} 个场景编排配置</span></button>
    <button class="global-object-card" type="button" data-dashboard-mode="network"><strong>网络覆盖</strong><span>${state.registry.networks.length} 个网段对象</span></button>
  `;
  document.querySelectorAll("#globalObjectOverview [data-dashboard-mode]").forEach((button) => {
    button.addEventListener("click", () => openModule(button.dataset.dashboardMode));
  });
}

function openModule(mode) {
  if (hasDirtyChanges() && state.mode !== mode && !confirm("当前有未保存修改，确定切换吗？")) return;
  state.asset = null;
  state.host = null;
  state.detail = null;
  setAssetDirty(false);
  setHostDirty(false);
  setMode(mode, { detail: false });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setMode(mode, options = {}) {
  if (hasDirtyChanges() && state.mode !== mode && !confirm("当前有未保存修改，确定切换吗？")) return;
  const isDetail = Boolean(options.detail);
  state.mode = mode;
  const modes = ["asset", "connector", "host", "network", "bundle", "correlation", "scenario"];
  modes.forEach((item) => {
    const tab = $(`${item}Tab`);
    if (tab) tab.classList.toggle("active", mode === item && !isDetail);
  });

  if ($("moduleSearch")) {
    $("moduleSearch").value = options.preserveSearch ? $("moduleSearch").value : "";
    $("moduleSearch").classList.toggle("hidden", mode === "home" || isDetail);
    $("moduleSearch").placeholder = moduleMeta[mode] ? `搜索${moduleMeta[mode].label}` : "搜索当前模块";
  }

  $("homeDashboard").classList.toggle("hidden", mode !== "home" || isDetail);
  $("listPage").classList.toggle("hidden", mode === "home" || isDetail);
  $("assetForm").classList.toggle("hidden", !(isDetail && mode === "asset" && state.asset));
  $("hostForm").classList.toggle("hidden", !(isDetail && mode === "host" && state.host));
  $("detailView").classList.toggle("hidden", !(isDetail && readonlyModes.includes(mode) && state.detail));
  $("emptyState").classList.toggle("hidden", mode === "home" || !isDetail);

  updateListHeader(mode);
  if (mode !== "home" && !isDetail) renderModuleList();
  $("newAssetBtn").classList.toggle("hidden", mode !== "asset" || isDetail);
  $("newHostBtn").classList.toggle("hidden", mode !== "host" || isDetail);
  $("deleteHostBtn").classList.toggle("hidden", !(isDetail && mode === "host" && state.host));
  $("saveBtn").classList.toggle("hidden", !isDetail || readonlyModes.includes(mode));
  $("saveBtn").textContent = mode === "host" ? "保存主机" : "保存资产";
}

function hasDirtyChanges() {
  return state.assetDirty || state.hostDirty;
}

function setAssetDirty(dirty) {
  state.assetDirty = dirty;
  const badge = $("dirtyBadge");
  badge.textContent = dirty ? "有未保存修改" : "未修改";
  badge.className = dirty ? "pill warn" : "pill muted";
}

function setHostDirty(dirty) {
  state.hostDirty = dirty;
  const badge = $("hostDirtyBadge");
  badge.textContent = dirty ? "有未保存修改" : "未修改";
  badge.className = dirty ? "pill warn" : "pill muted";
}

function showSaveStatus(text, type = "") {
  const node = state.mode === "host" ? $("hostSaveStatus") : $("saveStatus");
  node.textContent = text;
  node.style.color = type === "error" ? "#a64035" : "";
}

function currentFields() {
  return linesToArray($("schema_fields").value);
}

function selectedTemplates() {
  return [...document.querySelectorAll("[data-template-id]")]
    .filter((input) => input.checked)
    .map((input) => input.dataset.templateId);
}

function aliasObjectFromRows() {
  const aliases = {};
  document.querySelectorAll(".alias-row").forEach((row) => {
    const source = row.querySelector("[data-alias-source]").value.trim();
    const target = row.querySelector("[data-alias-target]").value.trim();
    if (source && target) aliases[source] = target;
  });
  return aliases;
}

function updateFieldSelects() {
  const fields = currentFields();
  const aliasTargets = Object.values(aliasObjectFromRows());
  const options = unique([...fields, ...aliasTargets, "host", "timestamp"]);
  const previousTime = $("time_field").value;
  const previousHostField = $("host_field").value;

  $("time_field").innerHTML = options.map((field) => `<option value="${escapeHtml(field)}">${escapeHtml(field)}</option>`).join("");
  $("host_field").innerHTML = options.map((field) => `<option value="${escapeHtml(field)}">${escapeHtml(field)}</option>`).join("");

  if (options.includes(previousTime)) $("time_field").value = previousTime;
  if (options.includes(previousHostField)) $("host_field").value = previousHostField;
}

const moduleListConfig = {
  asset: { items: () => state.registry.assets, idAttr: "asset", selected: () => state.selectedAssetId, empty: "没有匹配的数据资产。", open: (id) => loadAsset(id) },
  host: { items: () => state.registry.hosts, idAttr: "host", selected: () => state.selectedHostId, empty: "没有匹配的主机。", open: (id) => loadHost(id) },
  connector: { items: () => state.registry.connectors, kind: "connector", selected: () => state.selectedDetail.id, empty: "没有匹配的 Connector。" },
  network: { items: () => state.registry.networks, kind: "network", selected: () => state.selectedDetail.id, empty: "没有匹配的网络对象。" },
  bundle: { items: () => state.registry.bundles, kind: "bundle", selected: () => state.selectedDetail.id, empty: "没有匹配的 Bundle。" },
  correlation: { items: () => state.registry.correlations, kind: "correlation", selected: () => state.selectedDetail.id, empty: "暂无 Correlation Matrix。" },
  scenario: { items: () => state.registry.scenarios, kind: "scenario", selected: () => state.selectedDetail.id, empty: "暂无 Scenario Pattern。" },
};

function itemSearchText(item) {
  return `${item.id || ""} ${item.name || ""} ${item.type || ""} ${item.status || ""} ${item.environment || ""}`.toLowerCase();
}

function activeTotalText(items = []) {
  const total = items.length;
  const active = items.filter((item) => item.status === "active").length;
  return `${active}/${total}`;
}

function renderCounts() {
  const countMap = {
    assetCount: activeTotalText(state.registry.assets || []),
    connectorCount: activeTotalText(state.registry.connectors || []),
    hostCount: activeTotalText(state.registry.hosts || []),
    networkCount: activeTotalText(state.registry.networks || []),
    bundleCount: activeTotalText(state.registry.bundles || []),
    correlationCount: activeTotalText(state.registry.correlations || []),
    scenarioCount: activeTotalText(state.registry.scenarios || []),
  };
  Object.entries(countMap).forEach(([id, value]) => {
    const node = $(id);
    if (node) node.textContent = value;
  });
}

function renderModuleList() {
  const config = moduleListConfig[state.mode];
  if (!config || !$("moduleList")) return;
  const query = ($("moduleSearch")?.value || "").trim().toLowerCase();
  const items = config.items();
  const filtered = items.filter((item) => itemSearchText(item).includes(query));
  $("moduleList").innerHTML = filtered.map((item) => {
    const active = item.id === config.selected() ? " active" : "";
    const dataAttr = config.idAttr
      ? `data-${config.idAttr}=\"${escapeHtml(item.id)}\"`
      : `data-kind=\"${escapeHtml(config.kind)}\" data-id=\"${escapeHtml(item.id)}\"`;
    return `
      <button class="asset-item${active}" ${dataAttr}>
        <strong>${escapeHtml(item.id || item.file)}</strong>
        <div>${escapeHtml(item.name || moduleMeta[state.mode]?.label || "未命名")}</div>
        <div class="asset-meta">
          <span class="pill muted">${escapeHtml(item.type || state.mode)}</span>
          <span class="pill ${item.status === "active" ? "" : "warn"}">${escapeHtml(item.status || "unknown")}</span>
        </div>
      </button>
    `;
  }).join("") || `<div class="hint empty-list">${escapeHtml(config.empty)}</div>`;

  document.querySelectorAll("#moduleList [data-asset]").forEach((button) => {
    button.addEventListener("click", () => loadAsset(button.dataset.asset));
  });
  document.querySelectorAll("#moduleList [data-host]").forEach((button) => {
    button.addEventListener("click", () => loadHost(button.dataset.host));
  });
  document.querySelectorAll("#moduleList [data-kind]").forEach((button) => {
    button.addEventListener("click", () => loadReadonlyDetail(button.dataset.kind, button.dataset.id));
  });
}

function summarizeDetail(kind, data) {
  const rows = [];
  const push = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(Array.isArray(value) ? value.join(", ") : value)}</span></div>`);
  };
  push("ID", data.asset_id || data.connector_id || data.host_id || data.network_id || data.bundle_id || (kind === "correlation" ? "correlation-matrix" : "anchor-patterns"));
  push("名称", data.name || data.description);
  push("类型", data.asset_type || data.connector_type || data.host_type || data.network_type || kind);
  push("状态", data.status || data.version);
  push("环境", data.environment || data.zone);
  push("说明", data.description || data.notes);
  if (kind === "bundle") push("资产数量", data.asset_ids?.length);
  if (kind === "correlation") {
    push("内部 Join", data.internal_joins?.length);
    push("跨源 Join", data.cross_source_joins?.length);
    push("时间窗", data.time_windows ? Object.keys(data.time_windows).length : undefined);
  }
  if (kind === "scenario") push("场景数量", data.patterns ? Object.keys(data.patterns).length : undefined);
  return rows.join("") || `<p class="hint">暂无可摘要字段，请查看原始 JSON。</p>`;
}

function fillDetailView(kind, objectId, data, file) {
  state.detail = data;
  state.selectedDetail = { kind, id: objectId };
  state.asset = null;
  state.host = null;
  $("detailKind").textContent = kind;
  $("detailTitle").textContent = data.name || data.asset_id || data.connector_id || data.host_id || data.network_id || data.bundle_id || objectId;
  $("detailFile").textContent = file || "只读";
  $("detailSummary").innerHTML = summarizeDetail(kind, data);
  $("detailRawJson").value = JSON.stringify(data, null, 2);
  setAssetDirty(false);
  setHostDirty(false);
  setMode(kind, { detail: true });
  renderModuleList();
}

async function loadReadonlyDetail(kind, objectId) {
  if (hasDirtyChanges() && !confirm("当前有未保存修改，确定切换吗？")) return;
  const payload = await api(`/api/detail?kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(objectId)}`);
  fillDetailView(kind, objectId, payload.data, payload.file);
}

function renderConnectorOptions() {
  $("connector_id").innerHTML = ["<option value=\"\">不选择</option>", ...state.registry.connectors.map((connector) => {
    const label = `${connector.id} · ${connector.type || ""} · ${connector.status || ""}`;
    return `<option value="${escapeHtml(connector.id)}">${escapeHtml(label)}</option>`;
  })].join("");
}

function renderHostOptions() {
  $("host_id").innerHTML = ["<option value=\"\">请选择 host</option>", ...state.registry.hosts.map((host) => {
    const label = `${host.id} · ${host.name || ""} · ${host.environment || ""}`;
    return `<option value="${escapeHtml(host.id)}">${escapeHtml(label)}</option>`;
  })].join("");
}

function renderTemplateList(selected = []) {
  const assetType = $("asset_type").value;
  const connectorId = $("connector_id").value;
  const connector = state.registry.connectors.find((item) => item.id === connectorId);
  const connectorType = connector?.type;

  $("templateList").innerHTML = state.registry.templates.map((template) => {
    const checked = selected.includes(template.id) ? "checked" : "";
    const assetMatch = !assetType || template.asset_types.includes(assetType);
    const connectorMatch = !connectorType || template.connector_types.includes(connectorType);
    const opacity = assetMatch && connectorMatch ? "" : " style=\"opacity:.48\"";
    return `
      <label class="check-row"${opacity}>
        <input type="checkbox" data-template-id="${escapeHtml(template.id)}" ${checked} />
        <span>
          <strong>${escapeHtml(template.id)}</strong>
          <small>${escapeHtml(template.description || "")}</small>
          <small>asset_types: ${escapeHtml(template.asset_types.join(", ")) || "-"}</small>
          <small>connector_types: ${escapeHtml(template.connector_types.join(", ")) || "-"}</small>
        </span>
      </label>
    `;
  }).join("");

  document.querySelectorAll("[data-template-id]").forEach((input) => {
    input.addEventListener("change", () => {
      syncAssetPreview();
      setAssetDirty(true);
    });
  });
}

function renderAliasRows(aliases = {}) {
  const entries = Object.entries(aliases);
  $("aliasRows").innerHTML = entries.map(([source, target]) => aliasRowHtml(source, target)).join("");
  bindAliasRows();
}

function aliasRowHtml(source = "", target = "") {
  return `
    <div class="alias-row">
      <input data-alias-source value="${escapeHtml(source)}" placeholder="源字段，如 host_name" />
      <input data-alias-target value="${escapeHtml(target)}" placeholder="canonical，如 host" />
      <button type="button" title="删除">×</button>
    </div>
  `;
}

function bindAliasRows() {
  document.querySelectorAll(".alias-row input").forEach((input) => {
    input.addEventListener("input", () => {
      updateFieldSelects();
      syncAssetPreview();
      setAssetDirty(true);
    });
  });
  document.querySelectorAll(".alias-row button").forEach((button) => {
    button.addEventListener("click", () => {
      button.closest(".alias-row").remove();
      updateFieldSelects();
      syncAssetPreview();
      setAssetDirty(true);
    });
  });
}

function updateModeVisibility() {
  const mode = $("host_mode").value;
  $("hostIdWrap").style.display = mode === "single" ? "block" : "none";
  $("hostFieldWrap").style.display = mode === "aggregated" ? "block" : "none";
}

function updatePreviews() {
  const host = state.registry.hosts.find((item) => item.id === $("host_id").value);
  $("hostPreview").innerHTML = host
    ? `<strong>${escapeHtml(host.id)}</strong><br/>${escapeHtml(host.name || "")} · ${escapeHtml(host.type || "")} · ${escapeHtml(host.environment || "")}`
    : "选择 single 模式时，这里会显示主机摘要。";

  const connector = state.registry.connectors.find((item) => item.id === $("connector_id").value);
  $("connectorPreview").innerHTML = connector
    ? `<strong>${escapeHtml(connector.id)}</strong><br/>类型：${escapeHtml(connector.type || "-")} · 状态：${escapeHtml(connector.status || "-")}`
    : "选择连接器后，这里会显示连接器摘要。";
}

function fillAssetForm(asset) {
  state.asset = structuredClone(asset);
  state.selectedAssetId = asset.asset_id;

  $("asset_id").value = asset.asset_id || "";
  $("name").value = asset.name || "";
  $("asset_type").value = asset.asset_type || "";
  $("domain").value = asset.domain || "";
  $("status").value = asset.status || "draft";
  $("environment").value = asset.environment || "development";
  $("owner_team").value = asset.owner_team || "";
  $("sensitivity").value = asset.sensitivity || "";
  $("description").value = asset.description || "";
  $("connector_id").value = asset.connector_id || "";
  $("schema_fields").value = (asset.schema?.fields || []).join("\n");
  $("retention_days").value = asset.schema?.retention_days ?? "";
  $("text_parser").value = asset.text_parser || "";
  $("tags").value = (asset.tags || []).join(", ");

  $("host_mode").value = "none";
  $("host_id").value = "";
  renderAliasRows(asset.field_aliases || {});
  updateFieldSelects();
  $("time_field").value = asset.schema?.time_field || "";
  $("host_field").value = "";
  renderTemplateList(asset.query_template_ids || []);
  updateModeVisibility();
  updatePreviews();
  syncAssetPreview(false);

  $("currentAssetTitle").textContent = asset.asset_id || "未命名资产";
  setAssetDirty(false);
  $("saveStatus").textContent = "";
  setMode("asset", { detail: true });
  renderModuleList();
}

function assetFromForm() {
  let base = {};
  try {
    base = JSON.parse($("rawJson").value || "{}");
  } catch {
    base = structuredClone(state.asset || {});
  }

  base.asset_id = $("asset_id").value.trim();
  base.name = $("name").value.trim();
  base.asset_type = $("asset_type").value.trim();
  base.domain = $("domain").value.trim();
  base.status = $("status").value;
  base.environment = $("environment").value;
  base.owner_team = $("owner_team").value.trim();
  base.sensitivity = $("sensitivity").value.trim();
  base.description = $("description").value.trim();
  base.connector_id = $("connector_id").value.trim();
  base.text_parser = $("text_parser").value.trim() || undefined;
  base.query_template_ids = selectedTemplates();
  base.tags = csvToArray($("tags").value);

  base.schema = base.schema || {};
  base.schema.fields = currentFields();
  base.schema.time_field = $("time_field").value || undefined;
  const retention = $("retention_days").value;
  if (retention === "") delete base.schema.retention_days;
  else base.schema.retention_days = Number(retention);

  const aliases = aliasObjectFromRows();
  if (Object.keys(aliases).length) base.field_aliases = aliases;
  else delete base.field_aliases;

  delete base["host_" + "binding"];

  Object.keys(base).forEach((key) => {
    if (base[key] === undefined || base[key] === "") delete base[key];
  });

  return base;
}

function syncAssetPreview(markDirty = true) {
  const asset = assetFromForm();
  $("rawJson").value = JSON.stringify(asset, null, 2);
  $("currentAssetTitle").textContent = asset.asset_id || "未命名资产";
  if (markDirty) setAssetDirty(true);
}

function fillHostForm(host) {
  state.host = structuredClone(host);
  state.selectedHostId = host.host_id;

  $("host_form_id").value = host.host_id || "";
  $("host_form_name").value = host.name || "";
  $("host_form_hostname").value = host.hostname || "";
  $("host_form_type").value = host.host_type || "server";
  $("host_form_os").value = host.host_os || "linux";
  $("host_form_environment").value = host.environment || "production";
  $("host_form_status").value = host.status || "active";
  $("host_form_zone").value = host.zone || "";
  $("host_form_description").value = host.description || "";
  $("host_form_ip").value = host.host_ip || "";
  $("host_form_gateway").value = host.gateway_ip || "";
  $("host_form_roles").value = (host.roles || []).join(", ");
  $("host_form_tags").value = (host.tags || []).join(", ");

  syncHostPreview(false);
  $("currentHostTitle").textContent = host.host_id || "未命名主机";
  setHostDirty(false);
  $("hostSaveStatus").textContent = "";
  setMode("host", { detail: true });
  renderModuleList();
}

function hostFromForm() {
  let base = {};
  try {
    base = JSON.parse($("hostRawJson").value || "{}");
  } catch {
    base = structuredClone(state.host || {});
  }

  base.host_id = $("host_form_id").value.trim();
  base.name = $("host_form_name").value.trim();
  base.hostname = $("host_form_hostname").value.trim();
  base.host_type = $("host_form_type").value;
  base.host_os = $("host_form_os").value;
  base.host_ip = $("host_form_ip").value.trim();
  base.gateway_ip = $("host_form_gateway").value.trim();
  base.zone = $("host_form_zone").value.trim();
  base.roles = csvToArray($("host_form_roles").value);
  base.environment = $("host_form_environment").value;
  base.status = $("host_form_status").value;
  base.description = $("host_form_description").value.trim();
  base.tags = csvToArray($("host_form_tags").value);

  Object.keys(base).forEach((key) => {
    if (base[key] === undefined || base[key] === "") delete base[key];
  });

  return base;
}

function syncHostPreview(markDirty = true) {
  const host = hostFromForm();
  $("hostRawJson").value = JSON.stringify(host, null, 2);
  $("currentHostTitle").textContent = host.host_id || "未命名主机";
  if (markDirty) setHostDirty(true);
}

async function loadRegistry() {
  const payload = await api("/api/registry");
  state.registry = {
    assets: payload.data?.assets || [],
    connectors: payload.data?.connectors || [],
    hosts: payload.data?.hosts || [],
    networks: payload.data?.networks || [],
    bundles: payload.data?.bundles || [],
    correlations: payload.data?.correlations || [],
    scenarios: payload.data?.scenarios || [],
    templates: payload.data?.templates || [],
    default_templates: payload.data?.default_templates || {},
  };
  renderCounts();
  renderModuleList();
  renderDashboard();
  renderConnectorOptions();
  renderHostOptions();
  renderTemplateList(state.asset?.query_template_ids || []);
  updatePreviews();
}

async function loadAsset(assetId) {
  if (hasDirtyChanges() && !confirm("当前有未保存修改，确定切换吗？")) return;
  const payload = await api(`/api/asset?id=${encodeURIComponent(assetId)}`);
  state.hostDirty = false;
  state.detail = null;
  fillAssetForm(payload.data);
}

async function loadHost(hostId) {
  if (hasDirtyChanges() && !confirm("当前有未保存修改，确定切换吗？")) return;
  const payload = await api(`/api/host?id=${encodeURIComponent(hostId)}`);
  state.assetDirty = false;
  state.detail = null;
  fillHostForm(payload.data);
}

function newAsset() {
  if (hasDirtyChanges() && !confirm("当前有未保存修改，确定新建吗？")) return;
  state.hostDirty = false;
  fillAssetForm({
    asset_id: "asset-new-draft",
    name: "新数据源资产",
    asset_type: "host_exec",
    domain: "D2",
    owner_team: "security-ops",
    environment: "development",
    status: "draft",
    connector_id: "",
    description: "",
    schema: { fields: ["timestamp", "host"], time_field: "timestamp", retention_days: 30 },
    query_template_ids: [],
    tags: [],
  });
  setAssetDirty(true);
}

function newHost() {
  if (hasDirtyChanges() && !confirm("当前有未保存修改，确定新建吗？")) return;
  state.assetDirty = false;
  fillHostForm({
    host_id: "host-new-draft",
    name: "新主机",
    hostname: "new-host",
    host_type: "server",
    host_os: "linux",
    host_ip: "",
    gateway_ip: "",
    zone: "internal",
    roles: [],
    environment: "production",
    status: "draft",
    description: "",
    tags: [],
  });
  setHostDirty(true);
}

async function saveAsset() {
  let asset;
  try {
    asset = JSON.parse($("rawJson").value);
  } catch (error) {
    showSaveStatus(`JSON 格式错误：${error.message}`, "error");
    return;
  }
  if (!asset.asset_id) {
    showSaveStatus("asset_id 不能为空", "error");
    return;
  }
  const payload = await api("/api/asset", {
    method: "POST",
    body: JSON.stringify({ asset }),
  });
  showSaveStatus(`已保存：${payload.file}`);
  setAssetDirty(false);
  await loadRegistry();
  state.selectedAssetId = asset.asset_id;
  renderModuleList();
}

async function saveHost() {
  let host;
  try {
    host = JSON.parse($("hostRawJson").value);
  } catch (error) {
    showSaveStatus(`JSON 格式错误：${error.message}`, "error");
    return;
  }
  if (!host.host_id) {
    showSaveStatus("host_id 不能为空", "error");
    return;
  }
  const payload = await api("/api/host", {
    method: "POST",
    body: JSON.stringify({ host }),
  });
  showSaveStatus(`已保存：${payload.file}`);
  setHostDirty(false);
  await loadRegistry();
  state.selectedHostId = host.host_id;
  renderModuleList();
  renderHostOptions();
}

async function deleteHost() {
  if (!state.host?.host_id) return;
  const hostId = state.host.host_id;
  if (!confirm(`确定删除主机 ${hostId} 吗？`)) return;
  await api(`/api/host?id=${encodeURIComponent(hostId)}`, { method: "DELETE" });
  state.host = null;
  state.selectedHostId = null;
  setHostDirty(false);
  await loadRegistry();
  openModule("host");
  $("hostSaveStatus").textContent = `已删除：${hostId}`;
}

async function saveCurrent() {
  if (readonlyModes.includes(state.mode)) return;
  if (state.mode === "host") await saveHost();
  else await saveAsset();
}

function reportVerdict(name, data) {
  if (!data) return "missing";
  if (name === "alert") return data.alert_verdict || data.attack_outcome || "unknown";
  return data.overall_verdict || data.verdict || data.alert_type || "unknown";
}

function reportConfidence(data) {
  if (!data) return "-";
  const value = data.confidence ?? data.confidence_ceiling ?? "-";
  return typeof value === "number" ? value.toFixed(2) : String(value);
}

function reportSummaryText(name, data) {
  if (!data) return "报告文件尚未生成。";
  if (typeof data.summary === "string") return data.summary;
  if (name === "risk" && data.summary) {
    return `扫描 ${data.summary.total_events_scanned ?? 0} 条事件，发现 ${data.summary.risk_items ?? 0} 个风险项，其中 P0 ${data.summary.p0 ?? 0} 个。`;
  }
  return "已生成结构化样例输出。";
}

function reportGaps(data) {
  if (!data) return [];
  const gaps = data.data_gaps || data.data_gaps_impact || [];
  if (!Array.isArray(gaps)) return [];
  return gaps.map((gap) => {
    if (typeof gap === "string") return gap;
    return [gap.missing_domain, gap.impact, gap.message].filter(Boolean).join("：") || JSON.stringify(gap);
  });
}

function renderReports(reports = {}) {
  const order = [
    ["completeness", "数据源完整性"],
    ["alert", "告警确认"],
    ["traceability", "溯源分析"],
    ["risk", "风险识别"],
  ];
  const readyCount = order.filter(([key]) => reports[key] && !reports[key].missing).length;
  $("reportSummary").innerHTML = `<strong>报告状态</strong><br/>已生成 ${readyCount} / ${order.length} 个 demo 输出。`;
  $("reportCards").innerHTML = order.map(([key, label]) => {
    const item = reports[key] || {};
    const data = item.data;
    const gaps = reportGaps(data);
    const cardClass = item.missing ? " missing" : "";
    return `
      <article class="report-card${cardClass}">
        <div class="report-card-head">
          <h4>${escapeHtml(label)}</h4>
          <span class="pill ${item.missing ? "warn" : ""}">${escapeHtml(reportVerdict(key, data))}</span>
        </div>
        <div class="report-meta">confidence: ${escapeHtml(reportConfidence(data))}</div>
        <p>${escapeHtml(reportSummaryText(key, data))}</p>
        <div class="report-file">${escapeHtml(item.file || "examples/reports/*.json")}</div>
        ${gaps.length ? `<ul>${gaps.slice(0, 3).map((gap) => `<li>${escapeHtml(gap)}</li>`).join("")}</ul>` : ""}
      </article>
    `;
  }).join("");
}

async function refreshReports() {
  $("reportSummary").textContent = "正在读取 examples/reports ...";
  const payload = await api("/api/reports");
  renderReports(payload.data || {});
}

async function runDemoAll() {
  $("reportSummary").textContent = "正在运行 python3 src/secweaver.py demo all ...";
  $("demoOutput").textContent = "";
  const payload = await api("/api/demo/all", { method: "POST", body: JSON.stringify({}) });
  $("demoOutput").textContent = payload.output || "无输出";
  renderReports(payload.reports || {});
}

function renderValidation(payload) {
  const output = payload.output || "";
  const summary = payload.structured?.summary || {};
  const diagnostics = payload.structured?.diagnostics || payload.diagnostics || {};
  const issues = payload.advice || [];
  const errors = summary.error_count ?? (output.match(/^ERROR:/gm) || []).length;
  const warnings = summary.warning_count ?? (output.match(/^WARN:/gm) || []).length;
  const blocking = summary.blocking_count ?? errors;
  const categoryText = Array.isArray(diagnostics.categories) && diagnostics.categories.length
    ? diagnostics.categories.map((item) => `${item.category}:${item.blocking_count || 0}/${(item.error_count || 0) + (item.warning_count || 0)}`).join(" · ")
    : "无分类问题";
  $("validationSummary").innerHTML = `
    <strong>${payload.ok ? "校验通过" : "校验未通过"}</strong><br/>
    Errors: ${errors} · Warnings: ${warnings} · Blocking: ${blocking} · returncode: ${payload.returncode}<br/>
    诊断分类：${escapeHtml(categoryText)}<br/>
    Python: ${escapeHtml(payload.python || "unknown")}
  `;
  $("validateOutput").textContent = output || "无输出";
  $("adviceCards").innerHTML = issues.map((card) => {
    const diagnosis = card.diagnosis || {};
    const priority = card.priority || (card.severity === "error" ? "P0" : "P1");
    const message = card.message || card.meaning || "校验问题";
    const raw = card.raw || `${card.severity || "issue"}: ${message}`;
    const fix = card.suggested_fix || card.advice || "按对象查看对应 JSON 并修复。";
    const object = [card.object_type, card.object_id].filter(Boolean).join(" · ");
    const category = card.category || diagnosis.category || "generic-config";
    const rootCause = card.root_cause || diagnosis.root_cause || "";
    const fixSteps = card.fix_steps || diagnosis.fix_steps || [];
    const docs = card.docs || diagnosis.docs || [];
    const example = card.example || diagnosis.example || "";
    return `
      <article class="advice-card ${priority === "P0" ? "p0" : ""}">
        <h4>${escapeHtml(priority)} · ${escapeHtml(message)}</h4>
        <div><strong>分类：</strong>${escapeHtml(category)}</div>
        ${object ? `<div><strong>对象：</strong>${escapeHtml(object)}</div>` : ""}
        ${card.field ? `<div><strong>字段：</strong>${escapeHtml(card.field)}</div>` : ""}
        <div><strong>原始输出：</strong>${escapeHtml(raw)}</div>
        ${rootCause ? `<div><strong>原因：</strong>${escapeHtml(rootCause)}</div>` : ""}
        <div><strong>影响：</strong>${escapeHtml(card.impact || "可能影响上线或研判可信度。")}</div>
        <div><strong>建议：</strong>${escapeHtml(fix)}</div>
        ${fixSteps.length ? `<ol class="advice-steps">${fixSteps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
        ${example ? `<div><strong>示例：</strong><code>${escapeHtml(example)}</code></div>` : ""}
        ${docs.length ? `<div><strong>文档：</strong>${docs.map((doc) => `<code>${escapeHtml(doc)}</code>`).join(" ")}</div>` : ""}
        <div><strong>处理人：</strong>${escapeHtml(card.owner || "高阶运营")}</div>
      </article>
    `;
  }).join("") || "<p class=\"hint\">没有 ERROR/WARN 建议卡片。</p>";
}

async function runValidate(options = {}) {
  $("validationSummary").textContent = "正在运行 validate.py ...";
  $("adviceCards").innerHTML = "";
  $("validateOutput").textContent = "";
  const payload = await api("/api/validate", {
    method: "POST",
    body: JSON.stringify({
      sync_catalog: Boolean(options.syncCatalog),
      strict: Boolean(options.strict),
      only_active: Boolean(options.onlyActive),
    }),
  });
  renderValidation(payload);
}

function bindEvents() {
  ["asset", "connector", "host", "network", "bundle", "correlation", "scenario"].forEach((mode) => {
    const tab = $(`${mode}Tab`);
    if (tab) tab.addEventListener("click", () => openModule(mode));
  });
  $("moduleSearch").addEventListener("input", () => setMode(state.mode, { preserveSearch: true }));
  $("refreshBtn").addEventListener("click", loadRegistry);
  $("dashboardRefreshBtn").addEventListener("click", loadRegistry);
  $("newAssetBtn").addEventListener("click", newAsset);
  $("newHostBtn").addEventListener("click", newHost);
  $("deleteHostBtn").addEventListener("click", deleteHost);
  $("saveBtn").addEventListener("click", saveCurrent);
  $("validateBtn").addEventListener("click", () => runValidate());
  $("strictValidateBtn").addEventListener("click", () => runValidate({ strict: true, onlyActive: true }));
  $("syncValidateBtn").addEventListener("click", () => runValidate({ syncCatalog: true }));
  $("runDemoAllBtn").addEventListener("click", runDemoAll);
  $("refreshReportsBtn").addEventListener("click", refreshReports);
  $("addAliasBtn").addEventListener("click", () => {
    $("aliasRows").insertAdjacentHTML("beforeend", aliasRowHtml());
    bindAliasRows();
    setAssetDirty(true);
  });
  $("formatBtn").addEventListener("click", () => syncAssetPreview(true));
  $("hostFormatBtn").addEventListener("click", () => syncHostPreview(true));

  assetControls.forEach((id) => {
    const node = $(id);
    if (!node) return;
    node.addEventListener("input", () => {
      if (id === "schema_fields") updateFieldSelects();
      if (["asset_type", "connector_id"].includes(id)) renderTemplateList(selectedTemplates());
      if (id === "host_mode") updateModeVisibility();
      if (["host_id", "connector_id"].includes(id)) updatePreviews();
      if (id !== "rawJson") syncAssetPreview(true);
      else setAssetDirty(true);
    });
    node.addEventListener("change", () => {
      if (id === "host_mode") updateModeVisibility();
      if (["host_id", "connector_id"].includes(id)) updatePreviews();
      if (id !== "rawJson") syncAssetPreview(true);
    });
  });

  hostControls.forEach((id) => {
    const node = $(id);
    if (!node) return;
    node.addEventListener("input", () => {
      if (id !== "hostRawJson") syncHostPreview(true);
      else setHostDirty(true);
    });
    node.addEventListener("change", () => {
      if (id !== "hostRawJson") syncHostPreview(true);
    });
  });

  window.addEventListener("beforeunload", (event) => {
    if (!hasDirtyChanges()) return;
    event.preventDefault();
    event.returnValue = "";
  });
}

bindEvents();
Promise.all([loadRegistry(), refreshReports()])
  .then(() => setMode("home"))
  .catch((error) => {
    $("moduleList").innerHTML = `<div class="hint">加载失败：${escapeHtml(error.message)}</div>`;
  });
