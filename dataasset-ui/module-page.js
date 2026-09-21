Object.entries(MODULE_PAGES).forEach(([key, config]) => {
  config.label = t(`module.${key}`);
  config.description = t(`module.${key}.desc`);
  config.newButtonText = t(`button.create.${key}`) === `button.create.${key}` ? t("button.create") : t(`button.create.${key}`);
});
const pageModule = document.body.dataset.module;
const pageConfig = MODULE_PAGES[pageModule];
let registry = {};
let selectedId = null;
let currentData = null;
let currentFile = null;
let isCreating = false;
let detailMode = "view";
let currentPage = 1;
let correlationContext = null;
let correlationContextPromise = null;
const PAGE_SIZE = 10;
const CONNECTIVITY_STORAGE_KEY = "secweaver_connectivity_asset_status";
const LEGACY_CONNECTIVITY_OK_KEY = "secweaver_connectivity_ok_assets";
const legacyOkAssets = JSON.parse(localStorage.getItem(LEGACY_CONNECTIVITY_OK_KEY) || "[]");
let connectivityAssetStatus = JSON.parse(localStorage.getItem(CONNECTIVITY_STORAGE_KEY) || "{}");
if (!Object.keys(connectivityAssetStatus).length && Array.isArray(legacyOkAssets) && legacyOkAssets.length) {
  connectivityAssetStatus = Object.fromEntries(legacyOkAssets.map((assetId) => [assetId, "ok"]));
  localStorage.setItem(CONNECTIVITY_STORAGE_KEY, JSON.stringify(connectivityAssetStatus));
}

function showDetail(data, file, options = {}) {
  currentData = data;
  currentFile = file;
  isCreating = Boolean(options.creating);
  detailMode = options.mode || (isCreating ? "edit" : detailMode);
  const canEdit = pageConfig.editable && detailMode === "edit";
  $("emptyState").classList.add("hidden");
  $("detailView").classList.remove("hidden");
  document.body.classList.toggle("detail-modal-open", !pageConfig.singleton);
  $("detailKind").textContent = pageConfig.kicker;
  $("detailTitle").textContent = data.name || data[pageConfig.idField] || selectedId || pageConfig.label;
  $("detailFile").textContent = file || t("detail.readonlyLabel");
  const detailSummary = $("detailSummary");
  const detailSummaryPanel = detailSummary?.closest(".panel");
  if (detailSummary) detailSummary.innerHTML = summarizeDetail(data);
  if (detailSummaryPanel) detailSummaryPanel.classList.toggle("hidden", isCreating || pageModule === "credential");
  if (pageModule === "asset") {
    const assetPanel = $("assetFieldsPanel");
    const assetFields = $("assetFields");
    if (assetPanel && assetFields) {
      assetPanel.classList.remove("hidden");
      assetFields.innerHTML = renderAssetFields(data);
      bindAssetFieldSync();
      assetFields.querySelectorAll("input, select, textarea").forEach((control) => { control.disabled = !canEdit; });
      if (!isCreating && $("assetIdInput")) $("assetIdInput").disabled = true;
    }
    const credentialPanel = $("credentialFieldsPanel");
    if (credentialPanel) credentialPanel.classList.add("hidden");
    const hostPanel = $("hostFieldsPanel");
    if (hostPanel) hostPanel.classList.add("hidden");
    $("detailRawJson").value = JSON.stringify(data, null, 2);
    $("detailRawJson").readOnly = !canEdit;
    $("saveDetailBtn").classList.toggle("hidden", !canEdit);
    ensureModalControls();
    $("detailHint").textContent = canEdit ? t("detail.jsonHint") : t("detail.readonly");
    $("detailStatus").textContent = isCreating ? t("detail.creatingJson") : "";
    renderList();
    $("detailView").scrollTop = 0;
    $("detailView").focus();
    return;
  }
  if (pageModule === "host") {
    const fieldsPanel = $("hostFieldsPanel");
    const fields = $("hostFields");
    if (fieldsPanel && fields) {
      fieldsPanel.classList.remove("hidden");
      fields.innerHTML = renderHostFields(data);
      bindHostFieldSync();
      fields.querySelectorAll("input, select, textarea").forEach((control) => { control.disabled = !canEdit; });
      if (!isCreating && $("hostIdInput")) $("hostIdInput").disabled = true;
    }
    const assetPanel = $("assetFieldsPanel");
    if (assetPanel) assetPanel.classList.add("hidden");
    const credentialPanel = $("credentialFieldsPanel");
    if (credentialPanel) credentialPanel.classList.add("hidden");
    $("detailRawJson").value = JSON.stringify(data, null, 2);
    $("detailRawJson").readOnly = !canEdit;
    $("saveDetailBtn").classList.toggle("hidden", !canEdit);
    ensureModalControls();
    $("detailHint").textContent = canEdit ? t("detail.jsonHint") : t("detail.readonly");
    $("detailStatus").textContent = isCreating ? t("detail.creatingJson") : "";
    renderList();
    return;
  }
  if (pageModule === "credential") {
    const fieldsPanel = $("credentialFieldsPanel");
    const fields = $("credentialFields");
    if (fieldsPanel && fields) {
      fieldsPanel.classList.remove("hidden");
      fields.innerHTML = renderCredentialFields(data);
      bindCredentialFieldSync();
      fields.querySelectorAll("input, select, textarea").forEach((control) => { control.disabled = !canEdit; });
      if (!isCreating && $("credentialIdInput")) $("credentialIdInput").disabled = true;
    }
    const assetPanel = $("assetFieldsPanel");
    if (assetPanel) assetPanel.classList.add("hidden");
    const hostPanel = $("hostFieldsPanel");
    if (hostPanel) hostPanel.classList.add("hidden");
    $("detailRawJson").value = data.content || "";
    $("detailRawJson").readOnly = !canEdit;
    $("saveDetailBtn").classList.toggle("hidden", !canEdit);
    ensureModalControls();
    $("detailHint").textContent = canEdit ? t("detail.yamlHint") : t("detail.readonly");
    $("detailStatus").textContent = isCreating ? t("detail.creatingYaml") : "";
    renderList();
    return;
  }
  const fieldsPanel = $("credentialFieldsPanel");
  if (fieldsPanel) fieldsPanel.classList.add("hidden");
  const assetPanel = $("assetFieldsPanel");
  if (assetPanel) assetPanel.classList.add("hidden");
  const hostPanel = $("hostFieldsPanel");
  if (hostPanel) hostPanel.classList.add("hidden");
  const resourcePanel = ensureResourceFieldsPanel();
  const resourceFields = $("resourceFields");
  if (["connector", "network", "bundle"].includes(pageModule)) {
    resourcePanel.classList.remove("hidden");
    $("resourceFieldsTitle").textContent = t("detail.basicFields", { label: pageConfig.label });
    resourceFields.innerHTML = resourceFieldsForPage(data);
    bindResourceFieldSync();
    resourceFields.querySelectorAll("input, select, textarea").forEach((control) => { control.disabled = !canEdit; });
    const resourceIdInput = $({ connector: "connectorIdInput", network: "networkIdInput", bundle: "bundleIdInput" }[pageModule]);
    if (!isCreating && resourceIdInput) resourceIdInput.disabled = true;
  } else {
    resourcePanel.classList.add("hidden");
    resourceFields.innerHTML = "";
  }
  $("detailRawJson").value = JSON.stringify(data, null, 2);
  $("detailRawJson").readOnly = !canEdit;
  $("saveDetailBtn").classList.toggle("hidden", !canEdit);
  ensureModalControls();
  $("detailHint").textContent = canEdit ? t("detail.jsonHint") : t("detail.readonly");
  $("detailStatus").textContent = isCreating ? t("detail.creatingJson") : "";
  renderStructuredEditor();
  $("structuredEditor")?.querySelectorAll("input, select, textarea, button").forEach((control) => { control.disabled = !canEdit; });
  renderList();
}

async function loadDetail(id, mode = "view") {
  selectedId = id;
  isCreating = false;
  detailMode = mode;
  const payload = await api(`/api/detail?kind=${encodeURIComponent(pageConfig.detailKind)}&id=${encodeURIComponent(id)}`);
  showDetail(payload.data, payload.file, { mode });
}

function createNew() {
  if (!pageConfig.canCreate) return;
  const data = pageConfig.newTemplate();
  selectedId = data[pageConfig.idField];
  showDetail(data, t("detail.newObject"), { creating: true, mode: "edit" });
}

function idFromData(data) {
  if (pageConfig.idField) return data[pageConfig.idField];
  return selectedId;
}

async function saveDetail() {
  if (!pageConfig.editable) return;
  let data;
  if (pageModule === "credential") {
    const fields = readCredentialFields();
    if (!fields.credential_type) {
      $("detailStatus").textContent = t("credential.typeRequired");
      return;
    }
    if (fields.namespace !== fields.credential_type) {
      $("detailStatus").textContent = t("credential.namespaceMismatch", { type: fields.credential_type });
      return;
    }
    const content = setYamlType($("detailRawJson").value, fields.credential_type);
    $("detailRawJson").value = content;
    data = {
      ...(currentData || {}),
      ...fields,
      path: fields.credential_id,
      content,
    };
  } else if (pageModule === "asset") {
    try {
      data = JSON.parse($("detailRawJson").value || "{}");
    } catch (error) {
      $("detailStatus").textContent = t("detail.jsonError", { message: error.message });
      return;
    }
    data = mergeAssetFields(data, readAssetFields());
    $("detailRawJson").value = JSON.stringify(data, null, 2);
  } else if (pageModule === "host") {
    try {
      data = JSON.parse($("detailRawJson").value || "{}");
    } catch (error) {
      $("detailStatus").textContent = t("detail.jsonError", { message: error.message });
      return;
    }
    data = mergeHostFields(data, readHostFields());
    Object.keys(data).forEach((key) => {
      if (data[key] === "" || (Array.isArray(data[key]) && !data[key].length)) delete data[key];
    });
    $("detailRawJson").value = JSON.stringify(data, null, 2);
  } else {
    try {
      data = JSON.parse($("detailRawJson").value || "{}");
    } catch (error) {
      $("detailStatus").textContent = t("detail.jsonError", { message: error.message });
      return;
    }
    if (["connector", "network", "bundle"].includes(pageModule)) {
      data = { ...data, ...readResourceFields() };
    }
  }
  const idValue = idFromData(data);
  if (pageConfig.idField && !idValue) {
    $("detailStatus").textContent = t("detail.required", { field: pageConfig.idField });
    return;
  }
  try {
    const payload = await api("/api/object", {
      method: "POST",
      body: JSON.stringify({ kind: pageConfig.detailKind, data, original_id: isCreating ? "" : selectedId }),
    });
    selectedId = payload.id || idValue;
    currentData = data;
    isCreating = false;
    $("detailStatus").textContent = t("detail.saved", { file: payload.file });
    await loadRegistry();
    if (pageModule === "credential") {
      await loadDetail(selectedId);
      $("detailStatus").textContent = t("detail.saved", { file: payload.file });
      return;
    }
    showDetail(data, payload.file, { mode: "edit" });
    $("detailStatus").textContent = t("detail.saved", { file: payload.file });
  } catch (error) {
    $("detailStatus").textContent = t("detail.saveFailed", { message: error.message });
  }
}

async function runAssetAction(assetId, action) {
  if (pageModule !== "asset" || !assetId) return;
  const title = action === "test_connection" ? t("button.test") : t("button.discover");
  const data = {
    asset_id: assetId,
    name: `${title} · ${assetId}`,
    action,
    status: "running",
    output: t("action.running"),
  };
  selectedId = assetId;
  showDetail(data, title);
  $("detailRawJson").readOnly = true;
  $("saveDetailBtn").classList.add("hidden");
  $("detailHint").textContent = t("action.resultHint");
  try {
    const payload = await api("/api/asset/action", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, action }),
    });
    if (action === "test_connection") {
      markConnectivityResult(assetId, Boolean(payload.ok));
    }
    const result = {
      asset_id: assetId,
      name: `${payload.title || title} · ${assetId}`,
      action,
      ok: payload.ok,
      returncode: payload.returncode,
      summary: payload.summary,
      output: payload.output || t("action.noOutput"),
    };
    showDetail(result, payload.title || title);
    $("detailRawJson").readOnly = true;
    $("saveDetailBtn").classList.add("hidden");
    $("detailHint").textContent = t("action.resultHint");
  } catch (error) {
    if (action === "test_connection") {
      markConnectivityResult(assetId, false);
    }
    const result = {
      asset_id: assetId,
      name: t("action.failedTitle", { title, id: assetId }),
      action,
      ok: false,
      error: error.message,
    };
    showDetail(result, title);
    $("detailRawJson").readOnly = true;
    $("saveDetailBtn").classList.add("hidden");
    $("detailHint").textContent = t("action.failedHint");
  }
}

async function deleteDetail(targetId = selectedId) {
  if (!pageConfig.deletable || !targetId) return;
  const target = targetId;
  const deleteHint = pageModule === "credential" ? t("delete.credentialHint") : t("delete.jsonHint");
  if (!confirm(t("delete.confirm", { label: pageConfig.label, id: target, hint: deleteHint }))) return;
  try {
    const payload = await api(`/api/object?kind=${encodeURIComponent(pageConfig.detailKind)}&id=${encodeURIComponent(target)}`, {
      method: "DELETE",
    });
    selectedId = null;
    currentData = null;
    currentFile = null;
    isCreating = false;
    $("detailView").classList.add("hidden");
    $("emptyState").classList.add("hidden");
    $("detailStatus").textContent = t("detail.deleted", { file: payload.deleted });
    await loadRegistry();
  } catch (error) {
    $("detailStatus").textContent = t("detail.deleteFailed", { message: error.message });
  }
}

async function setCredentialOperationalStatus(credentialId, status) {
  if (pageModule !== "credential" || !credentialId) return;
  const action = status === "active" ? t("button.activate") : t("button.deactivate");
  if (!confirm(t("credential.statusConfirm", { action, id: credentialId }))) return;
  try {
    await api("/api/credential/status", {
      method: "POST",
      body: JSON.stringify({ credential_id: credentialId, status }),
    });
    $("detailStatus").textContent = t("credential.statusUpdated", { id: credentialId, status });
    await loadRegistry();
  } catch (error) {
    $("detailStatus").textContent = t("credential.statusFailed", { message: error.message });
  }
}

async function loadRegistry() {
  const payload = await api("/api/registry");
  registry = {
    assets: payload.data?.assets || [],
    connectors: payload.data?.connectors || [],
    credentials: payload.data?.credentials || [],
    hosts: payload.data?.hosts || [],
    networks: payload.data?.networks || [],
    bundles: payload.data?.bundles || [],
    correlations: payload.data?.correlations || [],
    scenarios: payload.data?.scenarios || [],
    templates: payload.data?.templates || [],
  };
  renderCounts();
  if (pageConfig.singleton) {
    const singletonItem = registry[pageConfig.registryKey]?.[0];
    const singletonId = pageConfig.singletonId || singletonItem?.id || singletonItem?.file;
    if (!singletonId) throw new Error(t("list.empty", { label: pageConfig.label }));
    await loadDetail(singletonId, "edit");
    return;
  }
  renderList();
}

function initPage() {
  if (!pageConfig) {
    throw new Error(t("module.unknown", { module: pageModule }));
  }
  document.body.classList.toggle("singleton-module", Boolean(pageConfig.singleton));
  if (pageConfig.singleton) document.querySelector(".list-page")?.classList.add("hidden");
  const pageKicker = $("pageKicker");
  const pageTitle = $("pageTitle");
  const pageDescription = $("pageDescription");
  if (pageKicker) pageKicker.textContent = pageConfig.kicker;
  if (pageTitle) pageTitle.textContent = pageConfig.label;
  if (pageDescription) pageDescription.textContent = pageConfig.description;
  document.title = `${pageConfig.label} · SecWeaver`;
  $("listKicker").textContent = pageConfig.kicker;
  $("listTitle").textContent = pageConfig.label;
  $("listDescription").textContent = t("list.description", {
    description: pageConfig.description,
    editable: pageConfig.editable ? t("list.editable") : "",
    deletable: pageConfig.deletable ? t("list.deletable") : "",
  });
  $("moduleSearch").placeholder = t("search.placeholder", { label: pageConfig.label });
  $("emptyState").classList.add("hidden");
  const emptyTitle = document.querySelector("#emptyState h2");
  const emptyText = document.querySelector("#emptyState p");
  if (emptyTitle) emptyTitle.textContent = t("detail.selectObject");
  if (emptyText) emptyText.textContent = t("detail.objectHere");
  const summaryTitle = $("detailSummary")?.closest(".panel")?.querySelector("h3");
  if (summaryTitle) summaryTitle.textContent = t("detail.summary");
  if ($("assetFieldsPanel")) $("assetFieldsPanel").querySelector("h3").textContent = t("detail.assetFields");
  if ($("hostFieldsPanel")) $("hostFieldsPanel").querySelector("h3").textContent = t("detail.hostFields");
  if ($("credentialFieldsPanel")) $("credentialFieldsPanel").querySelector("h3").textContent = t("credential.fields");
  const rawTitle = document.querySelector("#detailView .raw-panel h3");
  if (rawTitle) rawTitle.textContent = pageModule === "credential" ? t("detail.yaml") : t("detail.rawJson");
  ensureModuleActions();
  $("saveDetailBtn").textContent = t("button.save");
  if ($("refreshStructuredEditorBtn")) $("refreshStructuredEditorBtn").textContent = t("button.refreshForm");
  $("newBtn").classList.toggle("hidden", !pageConfig.canCreate);
  $("newBtn").textContent = pageConfig.newButtonText || t("button.create");
  $("refreshBtn").addEventListener("click", loadRegistry);
  $("moduleSearch").addEventListener("input", () => {
    currentPage = 1;
    renderList();
  });
  $("newBtn").addEventListener("click", createNew);
  $("saveDetailBtn").addEventListener("click", saveDetail);
  $("refreshStructuredEditorBtn")?.addEventListener("click", parseRawIntoCurrentData);
  ensureModalControls();
}

initPage();
loadRegistry().catch((error) => {
  $("moduleList").innerHTML = `<div class="hint">${escapeHtml(t("detail.loadFailed", { message: error.message }))}</div>`;
});
