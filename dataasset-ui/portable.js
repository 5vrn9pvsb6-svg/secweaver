const portable$ = (id) => document.getElementById(id);
const portableT = (key, params = {}) => window.SW_I18N?.t(key, params) || key;

function portableEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setPortableText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function setPortableLabel(controlId, value) {
  const control = portable$(controlId);
  const label = control?.closest("label");
  if (!label) return;
  const textNode = Array.from(label.childNodes).find((node) => node.nodeType === Node.TEXT_NODE);
  if (textNode) textNode.nodeValue = value;
  else label.insertBefore(document.createTextNode(value), label.firstChild);
}

function setPortableCheckboxLabel(controlId, value) {
  const input = portable$(controlId);
  const label = input?.closest("label");
  if (!label || !input) return;
  label.textContent = "";
  label.append(input, ` ${value}`);
}

async function portableApi(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function initPortableText() {
  setPortableText("#portableTitle", portableT("portable.title"));
  setPortableText("#portableRefreshBtn", portableT("portable.refresh"));
  const stages = document.querySelectorAll(".portable-stage");
  if (stages[0]) {
    stages[0].querySelector("strong").textContent = portableT("portable.stageLaptop");
    stages[0].querySelector("small").textContent = portableT("portable.stageLaptopMeta");
  }
  if (stages[1]) {
    stages[1].querySelector("strong").textContent = portableT("portable.stageHost");
    stages[1].querySelector("small").textContent = portableT("portable.stageHostMeta");
  }
  const labels = {
    portableAdvertiseHost: "portable.advertiseHost",
    portableRetentionDays: "portable.retentionDays",
    portableIngestPort: "portable.ingestPort",
    portableQueryPort: "portable.queryPort",
    portableDataassetRoot: "portable.dataassetRoot",
    portableHostName: "portable.hostName",
    portableEnterpriseId: "portable.enterpriseId",
    portablePlatform: "portable.platform",
    portableAgentPackage: "portable.agentPackage",
    portableFluentPackage: "portable.fluentPackage",
    portableBufferLimit: "portable.bufferLimit",
  };
  Object.entries(labels).forEach(([id, key]) => setPortableLabel(id, portableT(key)));
  setPortableCheckboxLabel("portableReuseAgent", portableT("portable.reuseAgent"));
  setPortableCheckboxLabel("portableReuseFluent", portableT("portable.reuseFluent"));
  setPortableCheckboxLabel("portableRotate", portableT("portable.rotate"));
  const buttons = {
    portableInitBtn: "portable.init",
    portableUpBtn: "portable.start",
    portableDownBtn: "portable.stop",
    portableAssetsBtn: "portable.installAssets",
    portableEnrollBtn: "portable.enroll",
    portableCloseEnrollBtn: "portable.closeEnrollment",
    portableRevokeBtn: "portable.revoke",
    portableCopyBtn: "portable.copy",
  };
  Object.entries(buttons).forEach(([id, key]) => {
    portable$(id).textContent = portableT(key);
  });
  portable$("portableCommand").textContent = portableT("portable.noCommand");
}

function renderPortableStatus(payload) {
  const data = payload?.data || {};
  const initialized = Object.prototype.hasOwnProperty.call(data, "initialized") && data.initialized;
  const running = Boolean(data.running);
  const hostCount = Number(data.enrolled_hosts || 0);
  const retention = data.retention_days ? portableT("portable.days", { value: data.retention_days }) : "-";
  const runtimeDetail = data.ingest_url || data.checks?.find((item) => item.name === "runtime")?.detail || "-";
  portable$("portableSummary").innerHTML = `
    <div><strong>${portableEscape(initialized ? portableT("portable.initialized") : portableT("portable.notInitialized"))}</strong><span>${portableEscape(runtimeDetail)}</span></div>
    <div><strong>${portableEscape(running ? portableT("portable.running") : portableT("portable.stopped"))}</strong><span>${portableEscape(data.query_url || data.health_error || "OpenSearch")}</span></div>
    <div><strong>${portableEscape(portableT("portable.hosts"))}</strong><span>${portableEscape(String(hostCount))}</span></div>
    <div><strong>${portableEscape(portableT("portable.retention"))}</strong><span>${portableEscape(retention)}</span></div>
  `;
}

async function loadPortableStatus() {
  const payload = await portableApi("/api/portable/status");
  renderPortableStatus(payload);
  return payload;
}

async function runPortableAction(action, payload = {}) {
  portable$("portableStatus").textContent = portableT("portable.processing", { action });
  const result = await portableApi("/api/portable/action", {
    method: "POST",
    body: JSON.stringify({ action, payload }),
  });
  if (!result.ok) {
    portable$("portableStatus").textContent = portableT("portable.failed", {
      action,
      message: result.error || result.returncode,
    });
    return result;
  }
  portable$("portableStatus").textContent = portableT("portable.done", { action });
  await loadPortableStatus();
  return result;
}

function portableInitPayload() {
  return {
    advertise_host: portable$("portableAdvertiseHost").value.trim(),
    retention_days: Number(portable$("portableRetentionDays").value || 30),
    ingest_port: Number(portable$("portableIngestPort").value || 9443),
    query_port: Number(portable$("portableQueryPort").value || 9200),
  };
}

function portableEnrollPayload() {
  return {
    name: portable$("portableHostName").value.trim(),
    enterprise_id: portable$("portableEnterpriseId").value.trim(),
    platform: portable$("portablePlatform").value,
    agent_package: portable$("portableAgentPackage").value.trim(),
    fluent_bit_package: portable$("portableFluentPackage").value.trim(),
    buffer_limit: portable$("portableBufferLimit").value.trim() || "2G",
    reuse_agent: portable$("portableReuseAgent").checked,
    reuse_fluent_bit: portable$("portableReuseFluent").checked,
    rotate: portable$("portableRotate").checked,
  };
}

function reportPortableError(action, error) {
  portable$("portableStatus").textContent = portableT("portable.failed", { action, message: error.message });
}

function bindPortableActions() {
  portable$("portableRefreshBtn").addEventListener("click", () => {
    loadPortableStatus().catch((error) => reportPortableError(portableT("portable.refresh"), error));
  });
  portable$("portableInitBtn").addEventListener("click", () => {
    runPortableAction("init", portableInitPayload()).catch((error) => reportPortableError("init", error));
  });
  portable$("portableUpBtn").addEventListener("click", () => {
    runPortableAction("up").catch((error) => reportPortableError("up", error));
  });
  portable$("portableDownBtn").addEventListener("click", () => {
    runPortableAction("down").catch((error) => reportPortableError("down", error));
  });
  portable$("portableAssetsBtn").addEventListener("click", () => {
    runPortableAction("install_assets", { dataasset_root: portable$("portableDataassetRoot").value.trim() })
      .catch((error) => reportPortableError("install_assets", error));
  });
  portable$("portableEnrollBtn").addEventListener("click", async () => {
    try {
      const result = await runPortableAction("enroll", portableEnrollPayload());
      const command = result?.data?.install_command;
      if (command) {
        portable$("portableCommand").textContent = command;
        portable$("portableCopyBtn").disabled = false;
        portable$("portableStatus").textContent = portableT("portable.commandReady");
      }
    } catch (error) {
      reportPortableError("enroll", error);
    }
  });
  portable$("portableCloseEnrollBtn").addEventListener("click", () => {
    if (!window.confirm(portableT("portable.closeConfirm"))) return;
    runPortableAction("close_enrollment", { name: portable$("portableHostName").value.trim() })
      .catch((error) => reportPortableError("close_enrollment", error));
  });
  portable$("portableRevokeBtn").addEventListener("click", () => {
    if (!window.confirm(portableT("portable.revokeConfirm"))) return;
    runPortableAction("revoke", { name: portable$("portableHostName").value.trim() })
      .catch((error) => reportPortableError("revoke", error));
  });
  portable$("portableCopyBtn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(portable$("portableCommand").textContent || "");
      portable$("portableStatus").textContent = portableT("portable.commandCopied");
    } catch (error) {
      reportPortableError(portableT("portable.copy"), error);
    }
  });
}

initPortableText();
bindPortableActions();
loadPortableStatus().catch((error) => reportPortableError(portableT("portable.refresh"), error));
