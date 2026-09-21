const $ = (id) => document.getElementById(id);
const t = window.SW_I18N?.t || ((key, params = {}) => Object.entries(params).reduce((text, [name, value]) => text.replaceAll(`{${name}}`, value), key));
const DEFAULT_TEXT_PARSERS = ["json_lines", "json_lines2", "syslog_auth", "nginx_combined", "raw_only"];
let onboardingMeta = {};
let connectorCatalogRecords = [];
let connectorCatalogFilter = { source: "all", query: "" };

const QUICKSTART_GUIDES = {
  "data-sources.sample.json": {
    zh: {
      title: "最小接入链路",
      summary: "SLS、ES、SSH 文件三类基础源，适合第一次验证三件套生成流程。",
      audience: "新部署 / 本地 PoC",
      steps: ["载入示例", "预览三件套", "确认字段别名后再写入"],
    },
    en: {
      title: "Minimal Onboarding Path",
      summary: "SLS, ES, and SSH file basics for first-time bundle generation.",
      audience: "New deployment / local PoC",
      steps: ["Load the example", "Preview the generated bundle", "Review aliases before writing"],
    },
  },
  "vendor-quickstart-cloudwatch.json": {
    zh: {
      title: "AWS CloudWatch / CloudTrail",
      summary: "CloudWatch Logs Insights 样例，可接可选 boto3 外部执行器，也可先用本地样本。",
      audience: "AWS 云审计",
      steps: ["确认 log_group 和 region", "先用 sample_file 预览字段", "需要真实取数时启动 aws_cloudwatch_executor.py"],
    },
    en: {
      title: "AWS CloudWatch / CloudTrail",
      summary: "CloudWatch Logs Insights quickstart with optional boto3 executor and local sample fallback.",
      audience: "AWS cloud audit",
      steps: ["Confirm log_group and region", "Preview fields with sample_file", "Start aws_cloudwatch_executor.py for live fetch"],
    },
  },
  "vendor-quickstart-cloud-audit-siem.json": {
    zh: {
      title: "云审计 + SIEM",
      summary: "覆盖 AWS CloudTrail、Azure Activity / Entra、GCP Audit、Splunk ES notable 事件。",
      audience: "多云审计 / SIEM",
      steps: ["替换云账号、workspace、project 占位符", "检查 identity/cloud coverage", "预览后按真实保留天数调整 retention_days"],
    },
    en: {
      title: "Cloud Audit + SIEM",
      summary: "Covers AWS CloudTrail, Azure Activity / Entra, GCP Audit, and Splunk ES notable events.",
      audience: "Multi-cloud audit / SIEM",
      steps: ["Replace account, workspace, and project placeholders", "Review identity/cloud coverage", "Tune retention_days after preview"],
    },
  },
  "vendor-quickstart-cloud-vendors.json": {
    zh: {
      title: "多云日志接入",
      summary: "Azure Monitor、GCP Logging、Tencent CLS、Huawei LTS 的云厂商日志样例。",
      audience: "多云日志",
      steps: ["选择对应云厂商源", "替换 workspace/project/topic/logstream 占位符", "先用本地样本或 REST dry-run"],
    },
    en: {
      title: "Multi-cloud Logs",
      summary: "Cloud vendor examples for Azure Monitor, GCP Logging, Tencent CLS, and Huawei LTS.",
      audience: "Multi-cloud logs",
      steps: ["Choose the matching cloud source", "Replace workspace/project/topic/logstream placeholders", "Dry-run with local samples or REST first"],
    },
  },
  "vendor-quickstart-edr-identity-vendors.json": {
    zh: {
      title: "EDR + 身份源",
      summary: "覆盖 Defender XDR、SentinelOne、CrowdStrike、Okta、Google Workspace、Entra ID。",
      audience: "终端溯源 / 账号失陷",
      steps: ["先确认 host/user/src_ip 字段别名", "外部执行器负责厂商 SDK 或 API 鉴权", "保持 discovery，跑格式发现后再 active"],
    },
    en: {
      title: "EDR + Identity Sources",
      summary: "Covers Defender XDR, SentinelOne, CrowdStrike, Okta, Google Workspace, and Entra ID.",
      audience: "Endpoint tracing / account compromise",
      steps: ["Review host/user/src_ip aliases first", "Keep vendor SDK/API auth in an executor", "Keep discovery until format discovery is reviewed"],
    },
  },
  "vendor-quickstart-identity-edge-edr.json": {
    zh: {
      title: "身份 + 边缘 + CrowdStrike",
      summary: "Okta、Cloudflare、CrowdStrike 的外部执行器/本地样本样例。",
      audience: "登录溯源 / 边缘访问",
      steps: ["确认 org_url、zone、FDR bucket", "先用本地样本校验字段", "再替换 endpoint 接真实执行器"],
    },
    en: {
      title: "Identity + Edge + CrowdStrike",
      summary: "Okta, Cloudflare, and CrowdStrike examples for external executors or local samples.",
      audience: "Login tracing / edge access",
      steps: ["Confirm org_url, zone, and FDR bucket", "Validate fields with local samples", "Switch endpoint to a real executor"],
    },
  },
  "vendor-quickstart-siem-warehouse.json": {
    zh: {
      title: "Splunk + ClickHouse",
      summary: "SIEM 与日志数仓组合，适合把检索型日志和分析型日志一起注册。",
      audience: "SIEM / 数仓",
      steps: ["确认 Splunk index 和 ClickHouse database", "检查 SPL/SQL 的时间窗参数", "预览后再做连通测试"],
    },
    en: {
      title: "Splunk + ClickHouse",
      summary: "SIEM plus warehouse registration for search and analytical logs.",
      audience: "SIEM / warehouse",
      steps: ["Confirm Splunk index and ClickHouse database", "Review time-window params in SPL/SQL", "Preview before connectivity testing"],
    },
  },
  "vendor-quickstart-databases.json": {
    zh: {
      title: "数据库审计",
      summary: "MySQL、SQL Server、SQLite 只读审计样例。",
      audience: "DB 审计",
      steps: ["选择 engine", "确认只读账号和 SQL 模板", "active 前跑连通测试"],
    },
    en: {
      title: "Database Audit",
      summary: "Read-only audit examples for MySQL, SQL Server, and SQLite.",
      audience: "DB audit",
      steps: ["Choose the engine", "Confirm read-only credentials and SQL", "Run connectivity before active"],
    },
  },
  "vendor-quickstart-document-cache.json": {
    zh: {
      title: "文档日志 + 缓存资产",
      summary: "MongoDB 文档型日志和 Redis 资产缓存样例。",
      audience: "文档 / 缓存",
      steps: ["确认 collection 或 key_pattern", "检查只读权限", "用样本验证字段映射"],
    },
    en: {
      title: "Document Logs + Cache Assets",
      summary: "MongoDB document log and Redis asset cache examples.",
      audience: "Document / cache",
      steps: ["Confirm collection or key_pattern", "Review read-only permissions", "Validate field mappings with samples"],
    },
  },
  "vendor-quickstart-external-connector.json": {
    zh: {
      title: "配置型外置 Connector",
      summary: "Datadog 或内部厂商 API 样例，不改 Python，只用 external-connectors.json 注册。",
      audience: "外置执行器",
      steps: ["注册 connector_type 和 query_key", "填写 endpoint 或 sample_file", "预览通用 external 模板生成物"],
    },
    en: {
      title: "Config-only External Connector",
      summary: "Datadog or internal vendor API example registered through external-connectors.json without Python changes.",
      audience: "External executor",
      steps: ["Register connector_type and query_key", "Set endpoint or sample_file", "Preview the generic external template output"],
    },
  },
  "vendor-quickstart-plugin-connector.json": {
    zh: {
      title: "Connector 插件",
      summary: "本地插件 connector 示例，适合把 SDK 和厂商逻辑放在插件目录里。",
      audience: "开发贡献 / 插件扩展",
      steps: ["先看 plugin.json", "运行 plugin validate", "再用 onboarding 预览生成物"],
    },
    en: {
      title: "Connector Plugin",
      summary: "Local plugin connector example for SDK-owned vendor logic.",
      audience: "Developer contribution / plugin extension",
      steps: ["Inspect plugin.json", "Run plugin validate", "Preview generated onboarding files"],
    },
  },
};

const CONNECTION_FIELD_IDS = {
  project: "project",
  project_id: "projectId",
  logstore: "logstore",
  endpoint: "endpoint",
  fallback_endpoint: "fallbackEndpoint",
  executor_endpoint: "executorEndpoint",
  external_endpoint: "executorEndpoint",
  base_url: "baseUrl",
  region: "region",
  url: "url",
  index: "index",
  host: "host",
  host_id: "hostId",
  engine: "engine",
  database: "database",
  port: "port",
  path: "path",
  base_path: "basePath",
  collection: "collection",
  db: "db",
  driver: "driver",
  connection_string: "connectionString",
  auth_source: "authSource",
  ssl: "ssl",
  secure: "ssl",
  log_group: "logGroup",
  log_group_id: "logGroupId",
  log_stream_id: "logStreamId",
  log_stream_prefix: "logStreamPrefix",
  bucket: "bucket",
  prefix: "prefix",
  workspace_id: "workspaceId",
  tenant_id: "tenantId",
  topic_id: "topicId",
  sample_file: "sampleFile",
  sample_dir: "sampleDir",
};

const TEMPLATE_GENERIC_DEFAULTS = {
  params: "src_ip, target_ip, time_start, time_end, limit",
  defaults: JSON.stringify({ limit: 1000 }),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function currentLanguage() {
  return window.SW_I18N?.language || "zh";
}

function basename(path) {
  return String(path || "").split("/").filter(Boolean).pop() || "";
}

function dataassetFilePath(example) {
  const file = String(example?.file || "");
  if (!file) return "";
  return file.startsWith("dataasset/") ? file : `dataasset/${file}`;
}

function quickstartGuide(example) {
  const filename = basename(example?.file);
  const guide = QUICKSTART_GUIDES[filename];
  if (guide) return guide[currentLanguage()] || guide.en || guide.zh;
  const title = example?.name || filename || "Quickstart";
  return currentLanguage() === "zh"
    ? {
        title,
        summary: "可复制的数据源接入样例，适合先 dry-run，再按真实环境替换占位符。",
        audience: "通用接入",
        steps: ["载入示例", "检查凭证引用和连接参数", "预览三件套"],
      }
    : {
        title,
        summary: "Copyable onboarding example. Dry-run first, then replace placeholders for your environment.",
        audience: "General onboarding",
        steps: ["Load the example", "Review credential refs and connection params", "Preview the generated bundle"],
      };
}

function quickstartSample(example) {
  const data = example?.data || {};
  const sources = Array.isArray(data.data_sources) ? data.data_sources : [];
  const defaults = data.defaults && typeof data.defaults === "object" ? data.defaults : {};
  return defaults.sample_file
    || sources.find((source) => source?.sample_file)?.sample_file
    || sources.find((source) => source?.connector?.config?.sample_file)?.connector.config.sample_file
    || "";
}

function uniqueConnectorTypes(example) {
  return Array.from(new Set((example?.connector_types || []).filter(Boolean)));
}

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function setLabelText(controlId, value) {
  const control = $(controlId);
  const label = control?.closest("label");
  if (!label) return;
  const textNode = Array.from(label.childNodes).find((node) => node.nodeType === Node.TEXT_NODE);
  if (textNode) {
    textNode.nodeValue = value;
  } else {
    label.insertBefore(document.createTextNode(value), label.firstChild);
  }
}

function setCheckboxLabelText(selector, value) {
  const label = document.querySelector(selector);
  const input = label?.querySelector("input");
  if (!label || !input) return;
  label.textContent = "";
  label.append(input, ` ${value}`);
}

function initOnboardingText() {
  document.title = `${t("onboarding.title")} · SecWeaver`;
  setText(".onboarding-hero .eyebrow", t("onboarding.kicker"));
  setText(".onboarding-hero h1", t("onboarding.title"));
  setText(".onboarding-hero .subtitle", t("onboarding.subtitle"));
  $("buildConfigTopBtn").textContent = t("onboarding.buildConfig");
  $("previewTopBtn").textContent = t("onboarding.previewBundle");
  document.querySelectorAll(".onboarding-flow span").forEach((node, index) => {
    const keys = ["onboarding.flow.source", "onboarding.flow.config", "onboarding.flow.preview", "onboarding.flow.apply"];
    node.textContent = t(keys[index]);
  });
  setLabelText("quickstartSelect", t("onboarding.quickstart"));
  $("loadQuickstartBtn").textContent = t("onboarding.loadExample");
  $("previewQuickstartBtn").textContent = t("onboarding.previewExample");
  setText(".onboarding-vendor-panel h3", t("onboarding.vendorGuideTitle"));
  setText(".onboarding-vendor-panel .hint", t("onboarding.vendorGuideHint"));
  setText(".connector-catalog-panel h3", t("onboarding.catalogTitle"));
  setText(".connector-catalog-panel .hint", t("onboarding.catalogHint"));
  setLabelText("connectorCatalogSearch", t("onboarding.catalogSearch"));
  $("connectorCatalogSearch").placeholder = t("onboarding.catalogSearchPlaceholder");
  document.querySelectorAll("[data-source-filter]").forEach((node) => {
    const key = {
      all: "onboarding.filterAll",
      built_in: "onboarding.sourceBuiltIn",
      external_config: "onboarding.sourceExternal",
      plugin: "onboarding.sourcePlugin",
    }[node.dataset.sourceFilter];
    if (key) node.textContent = t(key);
  });
  setText(".onboarding-form-panel .section-kicker", "Source");
  setText(".onboarding-form-panel .section-heading h2", t("onboarding.sourceSection"));
  const stepHeadings = document.querySelectorAll(".onboarding-form-panel .onboarding-step h3");
  [t("onboarding.basicInfo"), t("onboarding.connectionParams"), t("onboarding.fieldsParsingCoverage"), t("onboarding.templateParams")].forEach((text, index) => {
    if (stepHeadings[index]) stepHeadings[index].textContent = text;
  });
  setLabelText("sourceName", t("onboarding.name"));
  setLabelText("connectorType", t("onboarding.connectorType"));
  setLabelText("assetType", t("onboarding.assetType"));
  setLabelText("credentialsRef", t("onboarding.credentialsRef"));
  setLabelText("ownerTeam", t("onboarding.ownerTeam"));
  setLabelText("environment", t("onboarding.environment"));
  setLabelText("status", t("onboarding.status"));
  setLabelText("outputDir", t("onboarding.outputDir"));
  setLabelText("sampleFile", t("onboarding.localSampleFile"));
  setLabelText("sampleDir", t("onboarding.sampleDir"));
  setLabelText("textParser", t("onboarding.textParser"));
  setLabelText("timeField", t("onboarding.timeField"));
  setLabelText("schemaFields", t("onboarding.fieldList"));
  setLabelText("retentionDays", t("onboarding.retentionDays"));
  setLabelText("fieldAliases", t("onboarding.fieldAliases"));
  setLabelText("templateId", t("onboarding.templateId"));
  $("templateId").placeholder = t("onboarding.templateAuto");
  $("buildConfigBtn").textContent = t("onboarding.buildConfig");
  $("previewBtn").textContent = t("onboarding.previewBundle");
  $("applyBtn").textContent = t("onboarding.applyDataAsset");
  setCheckboxLabelText(".onboarding-force", t("onboarding.forceOverwrite"));
  setText(".onboarding-config-panel h3", t("onboarding.configJson"));
  setText(".onboarding-config-panel .hint", t("onboarding.configHint"));
  setText(".onboarding-preview-panel h3", t("onboarding.previewTitle"));
  $("previewMeta").textContent = t("onboarding.notPreviewed");
  $("previewOutput").textContent = t("onboarding.waiting");
}

async function api(path, options = {}) {
  const { allowErrorPayload = false, ...fetchOptions } = options;
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...fetchOptions,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || (payload.ok === false && payload.error && !allowErrorPayload)) {
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

function splitList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseObjectField(id, fallback = {}) {
  const raw = ($(id)?.value || "").trim();
  if (!raw) return fallback;
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${id} must be a JSON object`);
  }
  return parsed;
}

function setOptions(select, values, preferred) {
  const items = Array.from(new Set([preferred, ...values].filter(Boolean)));
  select.innerHTML = items.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  if (preferred) select.value = preferred;
}

function setTextParserOptions(select, values, preferred = "") {
  const items = Array.from(new Set(values.filter(Boolean)));
  select.innerHTML = [
    `<option value="">${escapeHtml(t("onboarding.noTextParser"))}</option>`,
    ...items.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
  ].join("");
  select.value = preferred;
}

function defaultTextParser(connectorType) {
  return ({
    ssh_file: "syslog_auth",
    ssh_command: "syslog_auth",
    local_file: "syslog_auth",
    syslog_ingest: "syslog_auth",
  })[connectorType] || "";
}

function setConnectorOptions(select, values, generatedValues, runtimeCapabilities, preferred) {
  const generated = new Set(generatedValues || []);
  const items = Array.from(new Set([preferred, ...values].filter(Boolean)));
  select.innerHTML = items.map((value) => {
    const generation = generated.has(value) ? t("onboarding.canGenerate") : t("onboarding.needsTemplate");
    const runtime = runtimeLabel(runtimeCapabilities?.[value]) || "schema";
    const suffix = ` · ${generation} · ${runtime}`;
    return `<option value="${escapeHtml(value)}">${escapeHtml(value + suffix)}</option>`;
  }).join("");
  if (preferred) select.value = preferred;
}

function queryKeyForConnector(connectorType) {
  return onboardingMeta.connector_query_keys?.[connectorType] || "sls_query";
}

function connectorProfile(connectorType) {
  return onboardingMeta.connector_profiles?.[connectorType]
    || onboardingMeta.connector_profiles?.external_generic
    || {};
}

function catalogByConnector(connectorType) {
  return (onboardingMeta.connector_catalog || []).find((item) => item.connector_type === connectorType) || {};
}

function sourceLabel(value) {
  return ({
    built_in: t("onboarding.sourceBuiltIn"),
    external_config: t("onboarding.sourceExternal"),
    plugin: t("onboarding.sourcePlugin"),
  })[value] || value || t("onboarding.sourceUnknown");
}

function dependencyHint(item) {
  return currentLanguage() === "zh"
    ? (item.dependency_hint_zh || item.dependency_hint || "")
    : (item.dependency_hint || item.dependency_hint_zh || "");
}

function knownDefaultValues(fieldKey) {
  const values = new Set();
  Object.values(onboardingMeta.connector_profiles || {}).forEach((profile) => {
    const value = profile?.defaults?.[fieldKey];
    if (value !== undefined && value !== null) values.add(String(value));
  });
  return values;
}

function setProfileField(fieldKey, value) {
  const node = $(CONNECTION_FIELD_IDS[fieldKey]);
  if (!node || value === undefined || value === null) return;
  const current = String(node.value || "");
  if (node.dataset.touched === "true" && current) return;
  if (!current || knownDefaultValues(fieldKey).has(current)) {
    node.value = String(value);
  }
}

function setTemplateField(id, value) {
  const node = $(id);
  if (!node || value === undefined || value === null) return;
  if (node.dataset.touched === "true" && node.value.trim()) return;
  node.value = typeof value === "string" ? value : JSON.stringify(value);
}

function setSelectIfUntouched(id, value) {
  const node = $(id);
  if (!node || !value || node.dataset.touched === "true") return;
  if (Array.from(node.options).some((option) => option.value === value)) {
    node.value = value;
  }
}

function applyConnectionFieldVisibility(profile) {
  const fields = new Set(profile.fields || Object.keys(CONNECTION_FIELD_IDS));
  document.querySelectorAll("[data-field-key]").forEach((node) => {
    node.classList.toggle("hidden", !fields.has(node.dataset.fieldKey));
  });
}

function applyConnectorProfile(connectorType) {
  const profile = connectorProfile(connectorType);
  applyConnectionFieldVisibility(profile);
  Object.entries(profile.defaults || {}).forEach(([fieldKey, value]) => setProfileField(fieldKey, value));
  setSelectIfUntouched("assetType", profile.default_asset_type);
  setTemplateField("templateParams", (profile.template_params || []).join(", "));
  setTemplateField("templateDefaults", profile.template_defaults || TEMPLATE_GENERIC_DEFAULTS.defaults);
  setTemplateField("templateQuery", profile.default_query);
  return profile;
}

function runtimeLabel(value) {
  return ({
    live_fetch: t("onboarding.runtimeLive"),
    live_or_external_executor: t("onboarding.runtimeLiveExternal"),
    local_or_external_executor: t("onboarding.runtimeLocalExternal"),
    plugin: t("onboarding.runtimePlugin"),
    descriptor_only: t("onboarding.runtimeDescriptor"),
  })[value] || t("onboarding.runtimeUnknown");
}

function updateConnectorGuide() {
  const connectorType = $("connectorType").value;
  const profile = applyConnectorProfile(connectorType);
  if (!$("textParser").dataset.touched) {
    $("textParser").value = defaultTextParser(connectorType);
  }
  const catalog = catalogByConnector(connectorType);
  const runtime = onboardingMeta.connector_runtime_capabilities?.[connectorType] || "";
  const queryKey = queryKeyForConnector(connectorType);
  const guide = $("connectorGuide");
  if (!guide) return;
  const generated = new Set(onboardingMeta.onboarding_connector_types || []);
  const executorHint = runtime === "local_or_external_executor"
    ? t("onboarding.execLocalExternal")
    : runtime === "live_or_external_executor"
      ? t("onboarding.execLiveExternal")
      : runtime === "plugin"
        ? t("onboarding.execPlugin")
        : t("onboarding.execBuiltIn");
  const cloudwatchHint = connectorType === "aws_cloudwatch"
    ? t("onboarding.cloudwatchHint")
    : "";
  const required = Array.isArray(profile.required) && profile.required.length
    ? t("onboarding.required", { fields: profile.required.join(", ") })
    : t("onboarding.noRequired");
  const executionOrder = Array.isArray(catalog.execution_order) && catalog.execution_order.length
    ? t("onboarding.executionOrder", { order: catalog.execution_order.join(" → ") })
    : "";
  const dependencyText = dependencyHint(catalog);
  const testCommand = "python3 src/secweaver.py connector test <asset_id> --by-asset --dry-run";
  const profileHint = currentLanguage() === "zh" ? profile.hint : "";
  guide.innerHTML = `
    <div><strong>${escapeHtml(profile.label || connectorType || "-")}</strong><span>${escapeHtml(runtimeLabel(runtime))}</span></div>
    <div><strong>${escapeHtml(queryKey)}</strong><span>${generated.has(connectorType) ? t("onboarding.canGenerate") : t("onboarding.genericTemplate")}</span></div>
    <div><strong>${escapeHtml(t("onboarding.catalogSource"))}</strong><span>${escapeHtml(sourceLabel(catalog.source))}</span></div>
    <div><strong>${escapeHtml(t("onboarding.catalogDependency"))}</strong><span>${escapeHtml(dependencyText || "-")}</span></div>
    <div><strong>${escapeHtml(t("onboarding.connectivityTest"))}</strong><span title="${escapeHtml(testCommand)}">${escapeHtml(testCommand)}</span></div>
    <p>${escapeHtml([required, profileHint, executorHint, cloudwatchHint, executionOrder].filter(Boolean).join(" "))}</p>
  `;
  const queryLabel = $("queryLabel");
  if (queryLabel) {
    queryLabel.childNodes[0].textContent = `${queryKey} `;
  }
  updateConnectorCatalogSelection();
}

function connectorCatalogMatchesFilter(item) {
  const source = connectorCatalogFilter.source;
  if (source !== "all" && item.source !== source) return false;
  const query = connectorCatalogFilter.query.trim().toLowerCase();
  if (!query) return true;
  const haystack = [
    item.connector_type,
    item.query_key,
    item.runtime,
    sourceLabel(item.source),
    dependencyHint(item),
    item.description,
  ].join(" ").toLowerCase();
  return haystack.includes(query);
}

function updateConnectorCatalogSelection() {
  const selected = $("connectorType")?.value;
  document.querySelectorAll(".connector-catalog-row").forEach((row) => {
    row.classList.toggle("active", row.dataset.connectorType === selected);
  });
}

function renderConnectorCatalog(records = connectorCatalogRecords) {
  const node = $("connectorCatalog");
  if (!node) return;
  connectorCatalogRecords = records || [];
  const items = connectorCatalogRecords.filter(connectorCatalogMatchesFilter).slice().sort((a, b) => {
    const order = { built_in: 0, external_config: 1, plugin: 2 };
    const left = order[a.source] ?? 9;
    const right = order[b.source] ?? 9;
    if (left !== right) return left - right;
    return String(a.connector_type || "").localeCompare(String(b.connector_type || ""));
  });
  if (!items.length) {
    node.innerHTML = `<div class="connector-catalog-empty">${escapeHtml(t("onboarding.noCatalogMatches"))}</div>`;
    return;
  }
  node.innerHTML = `
    <div class="connector-catalog-head">
      <span>${escapeHtml(t("onboarding.catalogType"))}</span>
      <span>${escapeHtml(t("onboarding.catalogSource"))}</span>
      <span>${escapeHtml(t("onboarding.catalogRuntime"))}</span>
      <span>${escapeHtml(t("onboarding.catalogQuery"))}</span>
      <span>${escapeHtml(t("onboarding.catalogDependency"))}</span>
    </div>
    ${items.map((item) => `
      <button type="button" class="connector-catalog-row" data-connector-type="${escapeHtml(item.connector_type)}">
        <span>${escapeHtml(item.connector_type)}</span>
        <span>${escapeHtml(sourceLabel(item.source))}</span>
        <span>${escapeHtml(runtimeLabel(item.runtime))}</span>
        <span>${escapeHtml(item.query_key || "-")}</span>
        <span title="${escapeHtml(dependencyHint(item))}">${escapeHtml(dependencyHint(item) || "-")}</span>
      </button>
    `).join("")}
  `;
  updateConnectorCatalogSelection();
  node.querySelectorAll("[data-connector-type]").forEach((row) => {
    row.addEventListener("click", () => {
      const connectorType = row.dataset.connectorType;
      if (!connectorType) return;
      $("connectorType").value = connectorType;
      updateConnectorGuide();
      $("onboardingStatus").textContent = t("onboarding.connectorSelected", { connector: connectorType });
    });
  });
}

function setCredentialOptions(select, credentials, preferred) {
  const refs = new Set();
  const options = [];
  (credentials || []).forEach((item) => {
    const ref = typeof item === "string" ? item : item?.id;
    if (!ref || refs.has(ref)) return;
    refs.add(ref);
    const label = typeof item === "string"
      ? item
      : `${ref}${item.type ? ` · ${item.type}` : ""}${item.status ? ` · ${item.status}` : ""}`;
    options.push({ ref, label });
  });
  select.innerHTML = options.map((item) => `<option value="${escapeHtml(item.ref)}">${escapeHtml(item.label)}</option>`).join("");
  if (preferred && refs.has(preferred)) select.value = preferred;
}

function sourceFromForm() {
  const connectorType = $("connectorType").value;
  const assetType = $("assetType").value;
  const profile = connectorProfile(connectorType);
  const activeFields = new Set(profile.fields || Object.keys(CONNECTION_FIELD_IDS));
  const source = {
    name: $("sourceName").value.trim(),
    connector_type: connectorType,
    asset_type: assetType,
    credentials_ref: $("credentialsRef").value.trim(),
    owner_team: $("ownerTeam").value.trim(),
    environment: $("environment").value.trim(),
    status: $("status").value,
  };
  const optionalFields = {
    template_id: $("templateId").value.trim(),
    project: $("project").value.trim(),
    project_id: $("projectId").value.trim(),
    logstore: $("logstore").value.trim(),
    endpoint: $("endpoint").value.trim(),
    fallback_endpoint: $("fallbackEndpoint").value.trim(),
    executor_endpoint: $("executorEndpoint").value.trim(),
    external_endpoint: $("executorEndpoint").value.trim(),
    base_url: $("baseUrl").value.trim(),
    region: $("region").value.trim(),
    log_group: $("logGroup").value.trim(),
    log_group_id: $("logGroupId").value.trim(),
    log_stream_id: $("logStreamId").value.trim(),
    log_stream_prefix: $("logStreamPrefix").value.trim(),
    bucket: $("bucket").value.trim(),
    prefix: $("prefix").value.trim(),
    workspace_id: $("workspaceId").value.trim(),
    tenant_id: $("tenantId").value.trim(),
    topic_id: $("topicId").value.trim(),
    url: $("url").value.trim(),
    index: $("index").value.trim(),
    host: $("host").value.trim(),
    host_id: $("hostId").value.trim(),
    database: $("database").value.trim(),
    path: $("path").value.trim(),
    base_path: $("basePath").value.trim(),
    collection: $("collection").value.trim(),
    db: $("db").value.trim(),
    driver: $("driver").value.trim(),
    connection_string: $("connectionString").value.trim(),
    auth_source: $("authSource").value.trim(),
    port: $("port").value.trim(),
    engine: $("engine").value.trim(),
    };
  Object.entries(optionalFields).forEach(([key, value]) => {
    if (value && (key === "template_id" || activeFields.has(key))) source[key] = value;
  });
  const sslValue = $("ssl").value.trim();
  if (sslValue && activeFields.has("ssl")) source.ssl = sslValue === "true";
  if (sslValue && activeFields.has("secure")) source.secure = sslValue === "true";

  source.asset = {
    coverage: {
      zones: splitList($("coverageZones").value),
      apps: splitList($("coverageApps").value),
      hosts: splitList($("coverageHosts").value),
    },
    schema: {
      fields: splitList($("schemaFields").value),
      time_field: $("timeField").value.trim(),
      retention_days: Number($("retentionDays").value || 0) || 30,
    },
    field_aliases: parseObjectField("fieldAliases", {}),
  };
  const textParser = $("textParser").value.trim();
  if (textParser) source.asset.text_parser = textParser;

  const defaults = parseObjectField("templateDefaults", {});
  const sampleFile = $("sampleFile").value.trim();
  const sampleDir = $("sampleDir").value.trim();
  if (sampleFile && activeFields.has("sample_file")) source.sample_file = sampleFile;
  if (sampleDir && activeFields.has("sample_dir")) source.sample_dir = sampleDir;
  source.template = {
    params: splitList($("templateParams").value),
    defaults,
  };
  const query = $("templateQuery").value.trim();
  if (query) source.template[queryKeyForConnector(connectorType)] = query;

  return source;
}

function quickstartLabel(example) {
  const guide = quickstartGuide(example);
  const types = uniqueConnectorTypes(example).slice(0, 3).join(", ");
  return `${guide.title} · ${basename(example.file)}${types ? ` · ${types}` : ""}`;
}

function renderQuickstarts(examples) {
  const select = $("quickstartSelect");
  if (!select) return;
  select.innerHTML = (examples || [])
    .map((example, index) => `<option value="${index}">${escapeHtml(quickstartLabel(example))}</option>`)
    .join("");
  renderVendorScenarioCards(examples || []);
  updateQuickstartMeta();
}

function selectedQuickstart() {
  const examples = onboardingMeta.onboarding_examples || [];
  const index = Number($("quickstartSelect")?.value || 0);
  return examples[index];
}

function updateQuickstartMeta() {
  const example = selectedQuickstart();
  const node = $("quickstartMeta");
  if (!node) return;
  node.textContent = example
    ? t("onboarding.exampleCount", { count: example.source_count || 0 })
    : t("onboarding.noExamples");
  renderQuickstartDetails(example);
  updateVendorScenarioSelection();
}

function renderVendorScenarioCards(examples) {
  const node = $("vendorScenarioCards");
  if (!node) return;
  const vendorExamples = examples
    .map((example, index) => ({ example, index, filename: basename(example.file) }))
    .filter((item) => item.filename.includes("vendor-quickstart") || item.filename.includes("data-sources.sample"));
  node.innerHTML = vendorExamples.map(({ example, index }) => {
    const guide = quickstartGuide(example);
    const connectorTypes = uniqueConnectorTypes(example);
    return `
      <button type="button" class="vendor-scenario-item" data-quickstart-index="${index}">
        <span class="vendor-scenario-audience">${escapeHtml(guide.audience)}</span>
        <strong>${escapeHtml(guide.title)}</strong>
        <span>${escapeHtml(guide.summary)}</span>
        <em>${escapeHtml(t("onboarding.quickstartSources", { count: example.source_count || 0 }))} · ${escapeHtml(connectorTypes.slice(0, 4).join(", ") || "-")}</em>
      </button>
    `;
  }).join("");
  node.querySelectorAll("[data-quickstart-index]").forEach((button) => {
    button.addEventListener("click", () => {
      selectQuickstart(Number(button.dataset.quickstartIndex), { load: true });
    });
  });
}

function updateVendorScenarioSelection() {
  const selectedIndex = Number($("quickstartSelect")?.value || 0);
  document.querySelectorAll(".vendor-scenario-item").forEach((button) => {
    button.classList.toggle("active", Number(button.dataset.quickstartIndex) === selectedIndex);
  });
}

function renderQuickstartDetails(example) {
  const node = $("quickstartDetails");
  if (!node) return;
  if (!example) {
    node.innerHTML = `<p class="hint">${escapeHtml(t("onboarding.noExamples"))}</p>`;
    return;
  }
  const guide = quickstartGuide(example);
  const connectors = uniqueConnectorTypes(example);
  const sample = quickstartSample(example);
  const command = `python3 src/secweaver.py asset apply -f ${dataassetFilePath(example)} --dry-run`;
  node.innerHTML = `
    <div class="quickstart-detail-head">
      <div>
        <span class="vendor-scenario-audience">${escapeHtml(guide.audience)}</span>
        <strong>${escapeHtml(guide.title)}</strong>
        <p>${escapeHtml(guide.summary)}</p>
      </div>
      <code>${escapeHtml(basename(example.file))}</code>
    </div>
    <div class="quickstart-detail-meta">
      <span>${escapeHtml(t("onboarding.quickstartSources", { count: example.source_count || 0 }))}</span>
      <span>${escapeHtml(t("onboarding.quickstartConnectors"))}: ${escapeHtml(connectors.join(", ") || "-")}</span>
      <span>${escapeHtml(t("onboarding.quickstartSample"))}: ${escapeHtml(sample || "-")}</span>
    </div>
    <div class="quickstart-next">
      <strong>${escapeHtml(t("onboarding.quickstartNext"))}</strong>
      <ol>${(guide.steps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
    </div>
    <div class="quickstart-command">
      <strong>${escapeHtml(t("onboarding.quickstartCommand"))}</strong>
      <code>${escapeHtml(command)}</code>
    </div>
    <div class="quickstart-doc-path">
      <strong>${escapeHtml(t("onboarding.quickstartDoc"))}</strong>
      <code>${escapeHtml(currentLanguage() === "zh" ? "docs_user/11-onboarding-ui-walkthrough.zh-CN.md" : "docs_user/11-onboarding-ui-walkthrough.md")}</code>
    </div>
  `;
}

function selectQuickstart(index, options = {}) {
  const select = $("quickstartSelect");
  const examples = onboardingMeta.onboarding_examples || [];
  if (!select || !examples[index]) return;
  select.value = String(index);
  updateQuickstartMeta();
  if (options.load) loadQuickstart();
}

function setFieldByKey(fieldKey, value) {
  const node = $(CONNECTION_FIELD_IDS[fieldKey]);
  if (!node || value === undefined || value === null) return;
  node.value = String(value);
}

function clearConnectionFields() {
  Object.values(CONNECTION_FIELD_IDS).forEach((id) => {
    const node = $(id);
    if (node) node.value = "";
  });
}

function fillFormFromSource(source) {
  if (!source || typeof source !== "object") return;
  ["sourceName", "ownerTeam", "environment", "templateId"].forEach((id) => {
    if ($(id)) $(id).value = "";
  });
  if (source.name) $("sourceName").value = source.name;
  if (source.connector_type) $("connectorType").value = source.connector_type;
  if (source.credentials_ref) $("credentialsRef").value = source.credentials_ref;
  if (source.owner_team) $("ownerTeam").value = source.owner_team;
  if (source.environment) $("environment").value = source.environment;
  if (source.status) $("status").value = source.status;
  if (source.template_id) $("templateId").value = source.template_id;
  clearConnectionFields();
  updateConnectorGuide();
  if (source.asset_type) $("assetType").value = source.asset_type;
  const nestedConfig = source.connector?.config && typeof source.connector.config === "object"
    ? source.connector.config
    : {};
  Object.keys(CONNECTION_FIELD_IDS).forEach((fieldKey) => {
    if (source[fieldKey] !== undefined) setFieldByKey(fieldKey, source[fieldKey]);
    if (nestedConfig[fieldKey] !== undefined) setFieldByKey(fieldKey, nestedConfig[fieldKey]);
  });
  const asset = source.asset || {};
  $("textParser").value = asset.text_parser || "";
  if (asset.schema?.time_field) $("timeField").value = asset.schema.time_field;
  if (Array.isArray(asset.schema?.fields)) $("schemaFields").value = asset.schema.fields.join(", ");
  if (asset.schema?.retention_days) $("retentionDays").value = String(asset.schema.retention_days);
  if (Array.isArray(asset.coverage?.zones)) $("coverageZones").value = asset.coverage.zones.join(", ");
  if (Array.isArray(asset.coverage?.apps)) $("coverageApps").value = asset.coverage.apps.join(", ");
  if (Array.isArray(asset.coverage?.hosts)) $("coverageHosts").value = asset.coverage.hosts.join(", ");
  if (asset.field_aliases) $("fieldAliases").value = JSON.stringify(asset.field_aliases);
  const template = source.template || {};
  if (Array.isArray(template.params)) $("templateParams").value = template.params.join(", ");
  if (template.defaults) $("templateDefaults").value = JSON.stringify(template.defaults);
  const query = template[queryKeyForConnector(source.connector_type || $("connectorType").value)];
  if (query) $("templateQuery").value = query;
}

function loadQuickstart() {
  const example = selectedQuickstart();
  if (!example?.data) return;
  setConfig(example.data);
  fillFormFromSource((example.data.data_sources || [])[0]);
  $("onboardingStatus").textContent = t("onboarding.loadedExample", { file: example.file });
  updateQuickstartMeta();
}

async function previewSelectedQuickstart() {
  loadQuickstart();
  await previewConfig();
}

function buildConfigFromForm() {
  return {
    version: "1.0",
    output_dir: $("outputDir").value.trim() || "dataasset",
    data_sources: [sourceFromForm()],
  };
}

function setConfig(config) {
  $("configJson").value = JSON.stringify(config, null, 2);
}

function getConfig() {
  const parsed = JSON.parse($("configJson").value || "{}");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(t("onboarding.configObjectError"));
  }
  return parsed;
}

function renderPreview(payload) {
  const data = payload.data || {};
  const sources = data.sources || [];
  const advice = payload.advice || [];
  $("previewMeta").textContent = `${payload.mode || "preview"} · returncode ${payload.returncode}`;
  $("previewOutput").textContent = payload.output || JSON.stringify(data, null, 2) || t("onboarding.noOutput");
  const sourceCards = sources.map((source, index) => {
    const connector = source.connector || {};
    const asset = source.asset || {};
    const template = source.template || {};
    return `
      <article class="onboarding-preview-card">
        <strong>#${index + 1} ${escapeHtml(asset.data?.name || asset.data?.asset_id || "source")}</strong>
        <span>Connector: ${escapeHtml(connector.path || "-")}</span>
        <span>Asset: ${escapeHtml(asset.path || "-")}</span>
        <span>Template: ${escapeHtml(template.data?.template_id || t("onboarding.templateMissing"))}</span>
      </article>
    `;
  }).join("");
  const adviceCards = advice.map((card) => {
    const steps = card.fix_steps || [];
    const docs = card.docs || [];
    return `
      <article class="advice-card p0">
        <h4>${escapeHtml(card.priority || "P0")} · ${escapeHtml(card.message || t("onboarding.previewFail", { message: "" }).trim())}</h4>
        <div><strong>${escapeHtml(t("validation.category"))}</strong>${escapeHtml(card.category || "onboarding-config")}</div>
        ${card.root_cause ? `<div><strong>${escapeHtml(t("validation.rootCause"))}</strong>${escapeHtml(card.root_cause)}</div>` : ""}
        <div><strong>${escapeHtml(t("validation.impact"))}</strong>${escapeHtml(card.impact || t("validation.defaultImpact"))}</div>
        <div><strong>${escapeHtml(t("validation.advice"))}</strong>${escapeHtml(card.suggested_fix || t("validation.defaultFix"))}</div>
        ${steps.length ? `<ol class="advice-steps">${steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
        ${docs.length ? `<div><strong>${escapeHtml(t("validation.docs"))}</strong>${docs.map((doc) => `<code>${escapeHtml(doc)}</code>`).join(" ")}</div>` : ""}
      </article>
    `;
  }).join("");
  $("previewSummary").innerHTML = sourceCards || adviceCards || `<p class="hint">${escapeHtml(payload.error || t("onboarding.noPreview"))}</p>`;
}

async function previewConfig() {
  $("onboardingStatus").textContent = t("onboarding.previewing");
  const payload = await api("/api/onboarding/preview", {
    method: "POST",
    body: JSON.stringify({ config: getConfig() }),
    allowErrorPayload: true,
  });
  renderPreview(payload);
  $("onboardingStatus").textContent = payload.ok
    ? t("onboarding.previewDone")
    : t("onboarding.previewFail", { message: payload.error || payload.returncode });
}

async function applyConfig() {
  const confirmed = window.confirm(t("onboarding.applyConfirm"));
  if (!confirmed) return;
  $("onboardingStatus").textContent = t("onboarding.applying");
  const payload = await api("/api/onboarding/apply", {
    method: "POST",
    body: JSON.stringify({ config: getConfig(), force: $("forceApply").checked }),
    allowErrorPayload: true,
  });
  renderPreview(payload);
  $("onboardingStatus").textContent = payload.ok
    ? t("onboarding.applyDone")
    : t("onboarding.applyFail", { message: payload.error || payload.returncode });
  await loadCounts();
}

async function loadCounts() {
  const payload = await api("/api/registry");
  renderCounts(payload.data || {});
}

async function init() {
  const [metaPayload] = await Promise.all([
    api("/api/onboarding/meta?refresh=1"),
    loadCounts(),
  ]);
  const meta = metaPayload.data || {};
  onboardingMeta = meta;
  setConnectorOptions(
    $("connectorType"),
    meta.connector_types || [],
    meta.onboarding_connector_types || meta.connector_types || [],
    meta.connector_runtime_capabilities || {},
    "sls",
  );
  setOptions($("assetType"), meta.asset_types || [], "waf_alert");
  setCredentialOptions($("credentialsRef"), meta.credentials || [], "vault://sls/security-readonly");
  setTextParserOptions($("textParser"), meta.text_parsers?.length ? meta.text_parsers : DEFAULT_TEXT_PARSERS);
  renderConnectorCatalog(meta.connector_catalog || []);
  renderQuickstarts(meta.onboarding_examples || []);
  setConfig(meta.sample || buildConfigFromForm());
  updateConnectorGuide();
}

$("connectorType").addEventListener("change", updateConnectorGuide);

document.querySelectorAll("[data-field-key] input, [data-field-key] select, #assetType, #textParser, #templateQuery, #templateParams, #templateDefaults").forEach((node) => {
  node.addEventListener("input", () => {
    node.dataset.touched = "true";
  });
  node.addEventListener("change", () => {
    node.dataset.touched = "true";
  });
});
$("quickstartSelect")?.addEventListener("change", updateQuickstartMeta);
$("loadQuickstartBtn")?.addEventListener("click", loadQuickstart);
$("previewQuickstartBtn")?.addEventListener("click", () => {
  previewSelectedQuickstart().catch((error) => {
    $("onboardingStatus").textContent = t("onboarding.previewFail", { message: error.message });
    $("previewOutput").textContent = String(error.stack || error.message);
  });
});

$("connectorCatalogSearch")?.addEventListener("input", (event) => {
  connectorCatalogFilter.query = event.target.value || "";
  renderConnectorCatalog();
});

document.querySelectorAll("[data-source-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    connectorCatalogFilter.source = button.dataset.sourceFilter || "all";
    document.querySelectorAll("[data-source-filter]").forEach((node) => {
      node.classList.toggle("active", node === button);
    });
    renderConnectorCatalog();
  });
});

$("buildConfigBtn").addEventListener("click", () => {
  try {
    setConfig(buildConfigFromForm());
    $("onboardingStatus").textContent = t("onboarding.configBuilt");
  } catch (error) {
    $("onboardingStatus").textContent = t("onboarding.configBuildFail", { message: error.message });
  }
});
$("buildConfigTopBtn").addEventListener("click", () => $("buildConfigBtn").click());

$("previewBtn").addEventListener("click", () => {
  previewConfig().catch((error) => {
    $("onboardingStatus").textContent = t("onboarding.previewFail", { message: error.message });
    $("previewOutput").textContent = String(error.stack || error.message);
  });
});
$("previewTopBtn").addEventListener("click", () => $("previewBtn").click());

$("applyBtn").addEventListener("click", () => {
  applyConfig().catch((error) => {
    $("onboardingStatus").textContent = t("onboarding.applyFail", { message: error.message });
    $("previewOutput").textContent = String(error.stack || error.message);
  });
});

initOnboardingText();
init().catch((error) => {
  $("onboardingStatus").textContent = t("onboarding.loadFail", { message: error.message });
});
