(() => {
  const $ = (id) => document.getElementById(id);
  let lastProbe = null;
  const lang = window.SW_I18N?.language || "zh";
  const copy = {
    zh: {
      title: "接入客户自有 Elasticsearch", hint: "探测集群 -> 选择索引 -> 自动生成并激活 DataAsset",
      endpoint: "集群地址", credential: "已有凭证", authMode: "新凭证类型", username: "用户名", password: "密码", apiKey: "API Key (id:secret)",
      caFile: "私有 CA 文件", index: "索引 / Data Stream", timeField: "时间字段", name: "资产名称", assetType: "资产类型", retention: "保留天数",
      probeButton: "检测集群", inspectButton: "识别字段", applyButton: "接入并激活", fields: "已识别字段",
      probing: "正在检测集群...", inspect: "正在读取字段和样例...", applying: "正在加密凭证并生成 DataAsset...",
      probeFirst: "先检测集群，再输入索引并识别字段。", selectIndex: "输入或选择索引后点击“识别字段”。",
      ready: "查询验证成功，可以接入并激活。", applied: "客户 ES 已接入，connector、asset 和查询模板均已激活。",
      failed: "操作失败", noNew: "使用下方新凭证", cluster: "集群", version: "版本", status: "状态", indices: "可见索引",
    },
    en: {
      title: "Connect customer-managed Elasticsearch", hint: "Probe cluster -> select index -> generate and activate DataAsset",
      endpoint: "Cluster endpoint", credential: "Existing credential", authMode: "New credential type", username: "Username", password: "Password", apiKey: "API Key (id:secret)",
      caFile: "Private CA file", index: "Index / Data Stream", timeField: "Time field", name: "Asset name", assetType: "Asset type", retention: "Retention days",
      probeButton: "Probe cluster", inspectButton: "Inspect fields", applyButton: "Connect and activate", fields: "Discovered fields",
      probing: "Probing cluster...", inspect: "Inspecting fields and samples...", applying: "Encrypting credentials and generating DataAsset...",
      probeFirst: "Probe the cluster, then select an index and inspect its fields.", selectIndex: "Enter or select an index, then click Inspect fields.",
      ready: "Query validation passed. This source is ready to activate.", applied: "Customer ES connected. Connector, asset, and query template are active.",
      failed: "Operation failed", noNew: "Use new credentials below", cluster: "Cluster", version: "Version", status: "Status", indices: "Visible indices",
    },
  }[lang];
  document.querySelectorAll("[data-byo-text]").forEach((node) => {
    node.textContent = copy[node.dataset.byoText] || node.textContent;
  });

  async function api(path, body) {
    const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.error || payload.result?.error || `HTTP ${response.status}`);
    return payload;
  }

  function payload() {
    // The public wizard authenticates the ES peer during both probe and apply.
    // Private CAs are supplied separately; they never imply an insecure fallback.
    const mode = $("byoEsAuthMode").value;
    return {
      endpoint: $("byoEsEndpoint").value.trim(), credential_ref: $("byoEsCredential").value,
      tls_verify: true,
      credentials: mode === "api_key" ? { api_key: $("byoEsApiKey").value } : { username: $("byoEsUsername").value, password: $("byoEsPassword").value },
      ca_file: $("byoEsCaFile").value.trim(), index: $("byoEsIndex").value.trim(), time_field: $("byoEsTimeField").value,
      name: $("byoEsName").value.trim(), asset_type: $("byoEsAssetType").value, retention_days: Number($("byoEsRetention").value || 30),
    };
  }

  function render(data) {
    lastProbe = data;
    const cluster = data.cluster || {};
    $("byoEsSummary").innerHTML = `<span><strong>${copy.cluster}</strong>${cluster.name || "-"}</span><span><strong>${copy.version}</strong>${cluster.distribution || "ES"} ${cluster.version || "-"}</span><span><strong>${copy.status}</strong>${cluster.status || "unknown"}</span><span><strong>${copy.indices}</strong>${(data.indices || []).length}</span>`;
    $("byoEsIndexOptions").innerHTML = (data.indices || []).map((item) => `<option value="${String(item.name || "").replaceAll('"', '&quot;')}"></option>`).join("");
    $("byoEsInspectBtn").disabled = false;
    const times = data.time_field_candidates || [];
    if (times.length) {
      $("byoEsTimeField").innerHTML = times.map((item) => `<option value="${item}">${item}</option>`).join("");
      $("byoEsTimeField").value = data.suggested_time_field || times[0];
    }
    const fields = data.sample_fields || [];
    $("byoEsFieldsWrap").hidden = !fields.length;
    $("byoEsFields").textContent = fields.join("\n");
    $("byoEsApplyBtn").disabled = !data.selected_index || !fields.length;
    $("byoEsStatus").textContent = data.selected_index ? copy.ready : copy.selectIndex;
  }

  async function probe(withIndex) {
    $("byoEsStatus").textContent = withIndex ? copy.inspect : copy.probing;
    const body = payload();
    if (!withIndex) body.index = "";
    render(await api("/api/es/onboarding/probe", body));
  }

  async function init() {
    const meta = await fetch("/api/onboarding/meta").then((response) => response.json());
    const data = meta.data || {};
    $("byoEsCredential").innerHTML = `<option value="">${copy.noNew}</option>` + (data.credentials || []).filter((item) => ["es", "elasticsearch"].includes(item.type)).map((item) => `<option value="${item.id}">${item.id}</option>`).join("");
    $("byoEsAssetType").innerHTML = (data.asset_types || ["security_event"]).map((item) => `<option value="${item}">${item}</option>`).join("");
    $("byoEsAssetType").value = (data.asset_types || []).includes("web_access_log") ? "web_access_log" : (data.asset_types || [])[0];
    $("byoEsStatus").textContent = copy.probeFirst;
  }

  $("byoEsAuthMode").addEventListener("change", () => document.querySelectorAll("[data-byo-auth]").forEach((node) => { node.hidden = node.dataset.byoAuth !== $("byoEsAuthMode").value; }));
  $("byoEsCredential").addEventListener("change", () => document.querySelectorAll("[data-byo-auth]").forEach((node) => { node.hidden = Boolean($("byoEsCredential").value) || node.dataset.byoAuth !== $("byoEsAuthMode").value; }));
  $("byoEsProbeBtn").addEventListener("click", () => probe(false).catch((error) => { $("byoEsStatus").textContent = `${copy.failed}: ${error.message}`; }));
  $("byoEsInspectBtn").addEventListener("click", () => probe(true).catch((error) => { $("byoEsStatus").textContent = `${copy.failed}: ${error.message}`; }));
  $("byoEsApplyBtn").addEventListener("click", async () => {
    try {
      $("byoEsApplyBtn").disabled = true; $("byoEsStatus").textContent = copy.applying;
      const result = await api("/api/es/onboarding/apply", payload());
      $("byoEsStatus").textContent = result.ok ? copy.applied : `${copy.failed}: ${result.result?.error || "unknown"}`;
    } catch (error) { $("byoEsStatus").textContent = `${copy.failed}: ${error.message}`; }
    finally { $("byoEsApplyBtn").disabled = !lastProbe?.selected_index; }
  });
  init().catch((error) => { $("byoEsStatus").textContent = `${copy.failed}: ${error.message}`; });
})();
