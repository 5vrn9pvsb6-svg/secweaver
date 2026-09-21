const $ = (id) => document.getElementById(id);
const t = window.SW_I18N?.t || ((key, params = {}) => Object.entries(params).reduce((text, [name, value]) => text.replaceAll(`{${name}}`, value), key));

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


function summarizeDetail(data) {
  const rows = [];
  const push = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(Array.isArray(value) ? value.join(", ") : value)}</span></div>`);
  };
  push("ID", data.asset_id || data.connector_id || data.credential_id || data.host_id || data.network_id || data.bundle_id || selectedId);
  push(t("summary.name"), data.name || data.description);
  push(t("summary.type"), data.asset_type || data.connector_type || data.credential_type || data.host_type || data.network_type || pageModule);
  push(t("summary.status"), data.status || data.version);
  push(t("summary.environment"), data.environment || data.zone);
  push(t("summary.description"), data.description || data.notes);
  if (pageModule === "bundle") push(t("summary.assetCount"), data.asset_ids?.length);
  if (pageModule === "correlation") {
    push(t("summary.internalJoins"), data.internal_joins?.length);
    push(t("summary.crossSourceJoins"), data.cross_source_joins?.length);
  }
  if (pageModule === "scenario") push(t("summary.scenarioCount"), data.patterns ? Object.keys(data.patterns).length : undefined);
  return rows.join("") || `<p class="hint">${escapeHtml(t("summary.empty"))}</p>`;
}

function ensureModuleActions() {
  const listActions = document.querySelector(".list-actions");
  if (!listActions) return;
  if (!$("refreshBtn")) {
    const refreshButton = document.createElement("button");
    refreshButton.id = "refreshBtn";
    refreshButton.className = "button ghost page-action";
    refreshButton.type = "button";
    refreshButton.textContent = t("button.refresh");
    listActions.appendChild(refreshButton);
  }
  if (!$("newBtn")) {
    const newButton = document.createElement("button");
    newButton.id = "newBtn";
    newButton.className = "button primary page-action";
    newButton.type = "button";
    newButton.textContent = pageConfig.newButtonText || t("button.create");
    listActions.appendChild(newButton);
  }
}

function closeDetailModal() {
  $("detailView").classList.add("hidden");
  document.body.classList.remove("detail-modal-open");
  selectedId = null;
  currentData = null;
  currentFile = null;
  isCreating = false;
  renderStructuredEditor();
  renderList();
}

function ensureModalControls() {
  const detailView = $("detailView");
  detailView.setAttribute("role", "dialog");
  detailView.setAttribute("aria-modal", "true");
  detailView.setAttribute("aria-labelledby", "detailTitle");
  detailView.tabIndex = -1;
  let closeButton = $("closeDetailBtn");
  if (!closeButton) {
    closeButton = document.createElement("button");
    closeButton.id = "closeDetailBtn";
    closeButton.className = "button ghost";
    closeButton.type = "button";
    closeButton.textContent = t("button.close");
    $("saveDetailBtn").insertAdjacentElement("afterend", closeButton);
    closeButton.addEventListener("click", closeDetailModal);
  }
  if (detailView.dataset.escapeBound !== "1") {
    detailView.dataset.escapeBound = "1";
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !detailView.classList.contains("hidden")) closeDetailModal();
    });
  }
}

function selectOptions(values, selected, includeEmpty = true) {
  const uniqueValues = [...new Set(values.filter(Boolean))];
  const allValues = selected && !uniqueValues.includes(selected) ? [selected, ...uniqueValues] : uniqueValues;
  return `${includeEmpty ? '<option value="">-</option>' : ""}${allValues.map((value) => `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}`;
}

function csvText(value = []) {
  return Array.isArray(value) ? value.join(", ") : String(value || "");
}

function csvValue(value = "") {
  return String(value || "")
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function numericOrEmpty(value) {
  if (value === undefined || value === null || value === "") return "";
  return Number.isFinite(Number(value)) ? Number(value) : value;
}

function jsonPretty(value, fallback) {
  return JSON.stringify(value ?? fallback, null, 2);
}

function syncCurrentDataToRaw(message = t("detail.synced")) {
  const raw = $("detailRawJson");
  if (!raw || !currentData) return;
  raw.value = JSON.stringify(currentData, null, 2);
  const summary = $("detailSummary");
  if (summary) summary.innerHTML = summarizeDetail(currentData);
  const status = $("detailStatus");
  if (status) status.textContent = message;
}

function parseRawIntoCurrentData() {
  try {
    currentData = JSON.parse($("detailRawJson").value || "{}");
    renderStructuredEditor();
    $("detailStatus").textContent = t("detail.refreshed");
  } catch (error) {
    $("detailStatus").textContent = t("detail.jsonError", { message: error.message });
  }
}

async function ensureCorrelationContext() {
  if (correlationContext) return correlationContext;
  if (!correlationContextPromise) {
    correlationContextPromise = api("/api/detail?kind=correlation&id=correlation-matrix")
      .then((payload) => {
        correlationContext = payload.data || null;
        return correlationContext;
      })
      .catch(() => null);
  }
  return correlationContextPromise;
}
