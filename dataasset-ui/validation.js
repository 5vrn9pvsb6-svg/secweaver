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

function activeTotalText(items = []) {
  const total = items.length;
  const active = items.filter((item) => item.status === "active").length;
  return `${active}/${total}`;
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
    : t("validation.noCategories");
  $("validationSummary").innerHTML = `
    <strong>${payload.ok ? t("validation.pass") : t("validation.fail")}</strong><br />
    Errors: ${errors} · Warnings: ${warnings} · Blocking: ${blocking} · returncode: ${payload.returncode}<br />
    ${escapeHtml(t("validation.diagnosticCategories"))}${escapeHtml(categoryText)}<br />
    Python: ${escapeHtml(payload.python || "unknown")}
  `;
  const readiness = payload.structured?.runtime_readiness;
  const readinessNode = $("runtimeReadiness");
  if (readiness) {
    const rows = readiness.bundles || [];
    readinessNode.hidden = false;
    readinessNode.innerHTML = `
      <strong>${escapeHtml(t("validation.runtimeTitle"))}</strong><br />
      ${escapeHtml(t("validation.registryState"))}${escapeHtml(readiness.registry_valid ? t("validation.ready") : t("validation.notReady"))}<br />
      ${rows.map((row) => `${escapeHtml(row.bundle_id)}: ${escapeHtml(row.status === "ready" ? t("validation.ready") : t("validation.notReady"))} (${row.blockers.length})`).join("<br />") || escapeHtml(t("validation.runtimeNone"))}<br />
      ${escapeHtml(t("validation.liveUnchecked"))}
    `;
  } else {
    readinessNode.hidden = true;
    readinessNode.textContent = "";
  }
  $("validateOutput").textContent = output || t("validation.noOutput");
  $("adviceCards").innerHTML = issues.map((card) => {
    const diagnosis = card.diagnosis || {};
    const priority = card.priority || (card.severity === "error" ? "P0" : "P1");
    const message = card.message || card.meaning || t("validation.issue");
    const raw = card.raw || `${card.severity || "issue"}: ${message}`;
    const fix = card.suggested_fix || card.advice || t("validation.defaultFix");
    const object = [card.object_type, card.object_id].filter(Boolean).join(" · ");
    const category = card.category || diagnosis.category || "generic-config";
    const rootCause = card.root_cause || diagnosis.root_cause || "";
    const fixSteps = card.fix_steps || diagnosis.fix_steps || [];
    const docs = card.docs || diagnosis.docs || [];
    const example = card.example || diagnosis.example || "";
    return `
      <article class="advice-card ${priority === "P0" ? "p0" : ""}">
        <h4>${escapeHtml(priority)} · ${escapeHtml(message)}</h4>
        <div><strong>${escapeHtml(t("validation.category"))}</strong>${escapeHtml(category)}</div>
        ${object ? `<div><strong>${escapeHtml(t("validation.object"))}</strong>${escapeHtml(object)}</div>` : ""}
        ${card.field ? `<div><strong>${escapeHtml(t("validation.field"))}</strong>${escapeHtml(card.field)}</div>` : ""}
        <div><strong>${escapeHtml(t("validation.rawOutput"))}</strong>${escapeHtml(raw)}</div>
        ${rootCause ? `<div><strong>${escapeHtml(t("validation.rootCause"))}</strong>${escapeHtml(rootCause)}</div>` : ""}
        <div><strong>${escapeHtml(t("validation.impact"))}</strong>${escapeHtml(card.impact || t("validation.defaultImpact"))}</div>
        <div><strong>${escapeHtml(t("validation.advice"))}</strong>${escapeHtml(fix)}</div>
        ${fixSteps.length ? `<ol class="advice-steps">${fixSteps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
        ${example ? `<div><strong>${escapeHtml(t("validation.example"))}</strong><code>${escapeHtml(example)}</code></div>` : ""}
        ${docs.length ? `<div><strong>${escapeHtml(t("validation.docs"))}</strong>${docs.map((doc) => `<code>${escapeHtml(doc)}</code>`).join(" ")}</div>` : ""}
        <div><strong>${escapeHtml(t("validation.owner"))}</strong>${escapeHtml(card.owner || t("validation.defaultOwner"))}</div>
      </article>
    `;
  }).join("") || `<p class="hint">${escapeHtml(t("validation.noAdvice"))}</p>`;
}

async function runValidate(options = {}) {
  $("validateStatus").textContent = t("validation.running");
  $("validationSummary").textContent = t("validation.running");
  $("adviceCards").innerHTML = "";
  $("validateOutput").textContent = "";
  try {
    const payload = await api("/api/validate", {
      method: "POST",
      body: JSON.stringify({
        sync_catalog: Boolean(options.syncCatalog),
        strict: Boolean(options.strict),
        only_active: Boolean(options.onlyActive),
        runtime_ready: Boolean(options.runtimeReady),
        bundle_ids: options.bundleIds || [],
      }),
    });
    renderValidation(payload);
    $("validateStatus").textContent = payload.ok ? t("validation.done") : t("validation.fail");
  } catch (error) {
    $("validationSummary").textContent = t("validation.runFail", { message: error.message });
    $("validateOutput").textContent = String(error.stack || error.message);
    $("validateStatus").textContent = t("validation.runFail", { message: "" }).trim();
  }
}

async function loadCounts() {
  const payload = await api("/api/registry");
  renderCounts(payload.data || {});
}

function initValidationText() {
  document.title = `${t("validation.title")} · SecWeaver`;
  document.querySelector(".page-title h1").textContent = t("validation.title");
  document.querySelector(".page-title .subtitle").textContent = t("validation.subtitle");
  document.querySelector(".page-title .tenant-card").textContent = t("validation.tenant");
  document.querySelector(".workspace .section-heading h2").textContent = t("validation.result");
  document.querySelector(".workspace > .panel > .hint").textContent = t("validation.hint");
  $("validateBtn").textContent = t("validation.run");
  $("strictValidateBtn").textContent = t("validation.strict");
  $("runtimeReadyBtn").textContent = t("validation.runtime");
  $("syncValidateBtn").textContent = t("validation.sync");
  $("validationSummary").textContent = t("validation.notRun");
  document.querySelector(".raw-panel h3").textContent = t("validation.raw");
  $("validateOutput").textContent = t("validation.waiting");
}

initValidationText();
$("validateBtn").addEventListener("click", () => runValidate());
$("strictValidateBtn").addEventListener("click", () => runValidate({ strict: true, onlyActive: true }));
$("runtimeReadyBtn").addEventListener("click", () => runValidate({ runtimeReady: true }));
$("syncValidateBtn").addEventListener("click", () => runValidate({ syncCatalog: true }));

loadCounts().catch((error) => {
  $("validationSummary").textContent = t("validation.loadFail", { message: error.message });
});
