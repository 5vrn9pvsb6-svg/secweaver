function assetDomainOptions(selected) {
  return ASSET_DOMAINS.map((domain) => `
    <option value="${domain}" ${domain === selected ? "selected" : ""}>${escapeHtml(`${domain} · ${t(`domain.${domain}`)}`)}</option>
  `).join("");
}

function renderAssetFields(data) {
  const schema = data.schema || {};
  const coverage = data.coverage || {};
  const selectedHosts = Array.isArray(coverage.hosts) ? coverage.hosts.filter(Boolean) : [];
  const selectedTemplates = Array.isArray(data.query_template_ids) ? data.query_template_ids.filter(Boolean) : [];
  const connectorIds = (registry.connectors || []).map((connector) => connector.id || connector.file);
  const hostIps = [...new Set([...selectedHosts, ...(registry.hosts || []).map((host) => host.host_ip).filter(Boolean)])];
  const templateIds = [...new Set([...selectedTemplates, ...(registry.templates || []).map((template) => template.id).filter(Boolean)])];
  const editing = detailMode === "edit";
  const checked = (value, selected) => selected.includes(value) ? "checked" : "";
  const readonlyValues = (values) => values.length
    ? `<div class="readonly-value-list">${values.map((value) => `<div class="readonly-value-row"><span aria-hidden="true">✓</span><span>${escapeHtml(value)}</span></div>`).join("")}</div>`
    : `<span class="hint">${escapeHtml(t("field.notConfigured"))}</span>`;
  const hostChoices = editing
    ? `<div class="compact-choice-grid">${hostIps.map((ip) => `<label class="choice-row"><input type="checkbox" data-asset-host value="${escapeHtml(ip)}" ${checked(ip, selectedHosts)}/><span>${escapeHtml(ip)}</span></label>`).join("") || `<span class="hint">${escapeHtml(t("field.noHostIps"))}</span>`}</div>`
    : readonlyValues(selectedHosts);
  const templateChoices = editing
    ? `<div class="compact-choice-grid">${templateIds.map((id) => `<label class="choice-row"><input type="checkbox" data-asset-template value="${escapeHtml(id)}" ${checked(id, selectedTemplates)}/><span>${escapeHtml(id)}</span></label>`).join("") || `<span class="hint">${escapeHtml(t("field.noQueryTemplates"))}</span>`}</div>`
    : readonlyValues(selectedTemplates);
  return `
    <div class="asset-field-grid">
      <label>${escapeHtml(t("field.assetId"))}<input id="assetIdInput" value="${escapeHtml(data.asset_id || selectedId || "")}" placeholder="asset-example" /></label>
      <label>${escapeHtml(t("field.name"))}<input id="assetNameInput" value="${escapeHtml(data.name || "")}" placeholder="${escapeHtml(t("field.name"))}" /></label>
      <label>${escapeHtml(t("field.assetType"))}<select id="assetTypeInput">${selectOptions(ASSET_TYPES, data.asset_type || "web_access_log", false)}</select></label>
      <label>${escapeHtml(t("field.connectorId"))}<select id="assetConnectorInput">${selectOptions(connectorIds, data.connector_id || "")}</select></label>
      <label>${escapeHtml(t("field.domain"))}<select id="assetDomainInput">${assetDomainOptions(data.domain || "D1")}</select></label>
      <label>${escapeHtml(t("field.ownerTeam"))}<input id="assetOwnerTeamInput" value="${escapeHtml(data.owner_team || "security-ops")}" placeholder="security-ops" /></label>
      <label>${escapeHtml(t("field.status"))}<select id="assetStatusInput">${selectOptions(ASSET_STATUSES, data.status || "draft", false)}</select></label>
      <label>${escapeHtml(t("field.environment"))}<select id="assetEnvironmentInput">${selectOptions(ENVIRONMENTS, data.environment || "production", false)}</select></label>
      <label>${escapeHtml(t("field.sensitivity"))}<select id="assetSensitivityInput">${selectOptions(ASSET_SENSITIVITIES, data.sensitivity || "internal", false)}</select></label>
      <label>${escapeHtml(t("field.textParser"))}<select id="assetTextParserInput">${selectOptions(TEXT_PARSERS, typeof data.text_parser === "string" ? data.text_parser : "")}</select></label>
      <label>${escapeHtml(t("field.timeField"))}<input id="assetTimeFieldInput" value="${escapeHtml(schema.time_field || "timestamp")}" placeholder="timestamp" /></label>
      <label>${escapeHtml(t("field.retentionDays"))}<input id="assetRetentionInput" type="number" min="1" value="${escapeHtml(schema.retention_days || 30)}" /></label>
      <label class="wide">${escapeHtml(t("field.schemaFields"))}<textarea id="assetSchemaFieldsInput" rows="3" placeholder="timestamp, src_ip, dst_ip">${escapeHtml(csvText(schema.fields || []))}</textarea></label>
      <label class="wide">${escapeHtml(t("field.tags"))}<textarea id="assetTagsInput" rows="2">${escapeHtml(csvText(data.tags || []))}</textarea></label>
      <label class="wide">${escapeHtml(t("field.description"))}<textarea id="assetDescriptionInput" rows="3">${escapeHtml(data.description || "")}</textarea></label>
    </div>
    <div class="structured-choice-section">
      <strong>${escapeHtml(t("field.coverageHosts"))}</strong><span class="hint">${escapeHtml(editing ? t("field.coverageHostsHint") : t("field.assignedCount", { count: selectedHosts.length }))}</span>
      ${hostChoices}
    </div>
    <div class="structured-choice-section">
      <strong>${escapeHtml(t("field.queryTemplates"))}</strong><span class="hint">${escapeHtml(!editing ? t("field.assignedCount", { count: selectedTemplates.length }) : "")}</span>
      ${templateChoices}
    </div>
    <p class="hint block">${escapeHtml(t("detail.fieldsSyncHint"))}</p>
  `;
}

function checkedValues(selector) {
  return Array.from(document.querySelectorAll(`${selector}:checked`)).map((input) => input.value);
}

function readAssetFields() {
  return {
    asset_id: ($("assetIdInput")?.value || "").trim(),
    name: ($("assetNameInput")?.value || "").trim(),
    asset_type: ($("assetTypeInput")?.value || "").trim(),
    connector_id: ($("assetConnectorInput")?.value || "").trim(),
    domain: ($("assetDomainInput")?.value || "").trim(),
    owner_team: ($("assetOwnerTeamInput")?.value || "").trim(),
    status: ($("assetStatusInput")?.value || "").trim(),
    environment: ($("assetEnvironmentInput")?.value || "").trim(),
    sensitivity: ($("assetSensitivityInput")?.value || "").trim(),
    text_parser: ($("assetTextParserInput")?.value || "").trim(),
    schema: {
      fields: csvValue($("assetSchemaFieldsInput")?.value || ""),
      time_field: ($("assetTimeFieldInput")?.value || "timestamp").trim(),
      retention_days: Number($("assetRetentionInput")?.value || 30),
    },
    coverage: { hosts: checkedValues("[data-asset-host]") },
    query_template_ids: checkedValues("[data-asset-template]"),
    tags: csvValue($("assetTagsInput")?.value || ""),
    description: ($("assetDescriptionInput")?.value || "").trim(),
  };
}

function mergeAssetFields(data, fields) {
  const next = {
    ...data,
    ...fields,
    schema: { ...(data.schema || {}), ...(fields.schema || {}) },
    coverage: { ...(data.coverage || {}), ...(fields.coverage || {}) },
  };
  if (!next.text_parser) delete next.text_parser;
  return next;
}

function syncAssetJsonFromFields() {
  let parsed;
  try {
    parsed = JSON.parse($("detailRawJson").value || "{}");
  } catch {
    return;
  }
  const fields = readAssetFields();
  $("detailRawJson").value = JSON.stringify(mergeAssetFields(parsed, fields), null, 2);
}

function bindAssetFieldSync() {
  ["assetIdInput", "assetNameInput", "assetTypeInput", "assetConnectorInput", "assetDomainInput", "assetOwnerTeamInput", "assetStatusInput", "assetEnvironmentInput", "assetSensitivityInput", "assetTextParserInput", "assetTimeFieldInput", "assetRetentionInput", "assetSchemaFieldsInput", "assetTagsInput", "assetDescriptionInput"].forEach((id) => {
    $(id)?.addEventListener("input", syncAssetJsonFromFields);
    $(id)?.addEventListener("change", syncAssetJsonFromFields);
  });
  document.querySelectorAll("[data-asset-host], [data-asset-template]").forEach((input) => input.addEventListener("change", syncAssetJsonFromFields));
}

function renderHostFields(data) {
  const networkIds = (registry.networks || []).map((network) => network.id || network.file || network.network_id).filter(Boolean);
  const exposure = data.exposure || {};
  const nat = data.nat || {};
  const interfaces = Array.isArray(data.interfaces) ? data.interfaces.map((item) => ({ ...item })) : [];
  if (data.management_ip && !interfaces.some((item) => item.role === "management")) {
    interfaces.push({ name: "management", ip: data.management_ip, role: "management" });
  }
  return `
    <div class="host-field-grid">
      <label>${escapeHtml(t("field.hostId"))}<input id="hostIdInput" value="${escapeHtml(data.host_id || selectedId || "")}" placeholder="host-example" /></label>
      <label>${escapeHtml(t("field.name"))}<input id="hostNameInput" value="${escapeHtml(data.name || "")}" placeholder="${escapeHtml(t("field.name"))}" /></label>
      <label>${escapeHtml(t("field.hostname"))}<input id="hostHostnameInput" value="${escapeHtml(data.hostname || "")}" placeholder="hostname" /></label>
      <label>${escapeHtml(t("field.hostIp"))}<input id="hostIpInput" value="${escapeHtml(data.host_ip || "")}" placeholder="10.0.0.80" /></label>
      <label>${escapeHtml(t("field.hostType"))}<select id="hostTypeInput">${selectOptions(HOST_TYPES, data.host_type || "server", false)}</select></label>
      <label>${escapeHtml(t("field.hostOs"))}<select id="hostOsInput">${selectOptions(HOST_OSES, data.host_os || "linux", false)}</select></label>
      <label>${escapeHtml(t("field.networkId"))}<select id="hostNetworkInput">${selectOptions(networkIds, data.network_id || "")}</select></label>
      <label>${escapeHtml(t("field.environment"))}<select id="hostEnvironmentInput">${selectOptions(ENVIRONMENTS, data.environment || "production", false)}</select></label>
      <label>${escapeHtml(t("field.status"))}<select id="hostStatusInput">${selectOptions(HOST_STATUSES, data.status || "draft", false)}</select></label>
      <label>${escapeHtml(t("field.aliases"))}<textarea id="hostAliasesInput" rows="2">${escapeHtml((data.aliases || []).join("\n"))}</textarea></label>
      <label>${escapeHtml(t("field.roles"))}<textarea id="hostRolesInput" rows="2">${escapeHtml((data.roles || []).join("\n"))}</textarea></label>
      <label>${escapeHtml(t("field.tags"))}<textarea id="hostTagsInput" rows="2">${escapeHtml((data.tags || []).join("\n"))}</textarea></label>
      <label class="wide">${escapeHtml(t("field.description"))}<textarea id="hostDescriptionInput" rows="3">${escapeHtml(data.description || "")}</textarea></label>
      <label class="wide">${escapeHtml(t("field.sourceDescription"))}<input id="hostSourceDescriptionInput" value="${escapeHtml(data.source_host_description || "")}" /></label>
      <details id="hostAdvancedOptions" class="host-advanced-options wide">
        <summary>${escapeHtml(t("host.advancedOptions"))}</summary>
        <div class="host-advanced-content">
          <section class="host-advanced-section">
            <h4>${escapeHtml(t("host.exposureSurface"))}</h4>
            <label class="host-toggle-row">
              <input id="hostInternetExposedInput" type="checkbox" ${exposure.internet_exposed ? "checked" : ""} />
              <span>${escapeHtml(t("field.internetExposed"))}</span>
            </label>
            <div id="hostExposureFields" class="host-field-grid host-advanced-grid ${exposure.internet_exposed ? "" : "hidden"}">
              <label>${escapeHtml(t("field.internetIp"))}<input id="hostInternetIpInput" value="${escapeHtml(exposure.internet_ip || "")}" /></label>
              <label>${escapeHtml(t("field.exposedPorts"))}<textarea id="hostExposedPortsInput" rows="2">${escapeHtml((exposure.exposed_ports || []).join("\n"))}</textarea></label>
            </div>
          </section>
          <section class="host-advanced-section">
            <h4>${escapeHtml(t("host.natSettings"))}</h4>
            <div class="host-field-grid host-advanced-grid">
              <label>${escapeHtml(t("field.natGateway"))}<input id="hostNatGatewayInput" value="${escapeHtml(nat.nat_gateway || "")}" /></label>
              <label>${escapeHtml(t("field.natMappingType"))}<select id="hostNatMappingInput">${selectOptions(["static", "dynamic", "snat", "dnat", "eip"], nat.mapping_type || "")}</select></label>
            </div>
          </section>
          <section class="host-advanced-section">
            <h4>${escapeHtml(t("host.interfaces"))}</h4>
            <p class="hint">${escapeHtml(t("host.interfacesHint"))}</p>
            <div id="hostInterfacesEditor" class="host-interface-list">
              ${interfaces.map((item) => hostInterfaceRowHtml(item, networkIds)).join("")}
            </div>
            <button id="addHostInterfaceBtn" class="button small" type="button">${escapeHtml(t("button.addInterface"))}</button>
          </section>
        </div>
      </details>
    </div>
    <p class="hint block">${escapeHtml(t("host.fieldsHint"))}</p>
  `;
}

function hostInterfaceRowHtml(item = {}, networkIds = []) {
  return `
    <div class="host-interface-row" data-host-interface-row>
      <label>${escapeHtml(t("field.interfaceName"))}<input data-interface-field="name" value="${escapeHtml(item.name || "")}" placeholder="eth0" /></label>
      <label>${escapeHtml(t("field.interfaceIp"))}<input data-interface-field="ip" value="${escapeHtml(item.ip || "")}" placeholder="10.0.0.10" /></label>
      <label>${escapeHtml(t("field.interfaceNetwork"))}<select data-interface-field="network_id">${selectOptions(networkIds, item.network_id || "")}</select></label>
      <label>${escapeHtml(t("field.interfaceMac"))}<input data-interface-field="mac" value="${escapeHtml(item.mac || "")}" placeholder="00:00:00:00:00:00" /></label>
      <label>${escapeHtml(t("field.interfaceRole"))}<select data-interface-field="role">${selectOptions(["primary", "management", "storage", "backup", "external", "other"], item.role || "")}</select></label>
      <button class="button small danger" type="button" data-remove-host-interface>${escapeHtml(t("button.removeInterface"))}</button>
    </div>
  `;
}

function multilineListValue(id) {
  return ($(`${id}`)?.value || "")
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function exposedPortsValue(id) {
  return multilineListValue(id).map((item) => {
    const port = Number(item);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : item;
  });
}

function readHostInterfaces() {
  return Array.from(document.querySelectorAll("[data-host-interface-row]")).map((row) => {
    const value = {};
    row.querySelectorAll("[data-interface-field]").forEach((input) => {
      const field = input.dataset.interfaceField;
      const fieldValue = input.value.trim();
      if (fieldValue) value[field] = fieldValue;
    });
    return value;
  }).filter((item) => Object.keys(item).length);
}

function readHostFields() {
  const internetExposed = Boolean($("hostInternetExposedInput")?.checked);
  return {
    host_id: ($("hostIdInput")?.value || "").trim(),
    name: ($("hostNameInput")?.value || "").trim(),
    hostname: ($("hostHostnameInput")?.value || "").trim(),
    host_type: ($("hostTypeInput")?.value || "").trim(),
    host_os: ($("hostOsInput")?.value || "").trim(),
    host_ip: ($("hostIpInput")?.value || "").trim(),
    network_id: ($("hostNetworkInput")?.value || "").trim(),
    aliases: multilineListValue("hostAliasesInput"),
    roles: multilineListValue("hostRolesInput"),
    environment: ($("hostEnvironmentInput")?.value || "").trim(),
    status: ($("hostStatusInput")?.value || "").trim(),
    exposure: {
      internet_exposed: internetExposed,
      internet_ip: internetExposed ? ($("hostInternetIpInput")?.value || "").trim() : "",
      exposed_ports: internetExposed ? exposedPortsValue("hostExposedPortsInput") : [],
    },
    nat: {
      nat_gateway: ($("hostNatGatewayInput")?.value || "").trim(),
      mapping_type: ($("hostNatMappingInput")?.value || "").trim(),
    },
    interfaces: readHostInterfaces(),
    description: ($("hostDescriptionInput")?.value || "").trim(),
    source_host_description: ($("hostSourceDescriptionInput")?.value || "").trim(),
    tags: multilineListValue("hostTagsInput"),
  };
}

function mergeHostFields(data, fields) {
  const next = {
    ...data,
    ...fields,
    exposure: { ...(data.exposure || {}), ...(fields.exposure || {}) },
    nat: { ...(fields.nat || {}) },
  };
  if (!next.exposure.internet_exposed) {
    next.exposure = { internet_exposed: false };
  }
  ["external_ip", "management_ip", "management_gateway_ip", "gateway_ip"].forEach((key) => delete next[key]);
  Object.keys(next.nat).forEach((key) => {
    if (!next.nat[key]) delete next.nat[key];
  });
  if (!Object.keys(next.nat).length) delete next.nat;
  return next;
}

function syncHostJsonFromFields() {
  let parsed;
  try {
    parsed = JSON.parse($("detailRawJson").value || "{}");
  } catch {
    return;
  }
  const fields = readHostFields();
  const next = mergeHostFields(parsed, fields);
  Object.keys(next).forEach((key) => {
    if (next[key] === "" || (Array.isArray(next[key]) && !next[key].length)) delete next[key];
  });
  $("detailRawJson").value = JSON.stringify(next, null, 2);
}

function bindHostFieldSync() {
  const toggleExposureFields = () => {
    $("hostExposureFields")?.classList.toggle("hidden", !$("hostInternetExposedInput")?.checked);
  };
  [
    "hostIdInput",
    "hostNameInput",
    "hostHostnameInput",
    "hostIpInput",
    "hostTypeInput",
    "hostOsInput",
    "hostNetworkInput",
    "hostEnvironmentInput",
    "hostStatusInput",
    "hostInternetExposedInput",
    "hostInternetIpInput",
    "hostNatGatewayInput",
    "hostNatMappingInput",
    "hostExposedPortsInput",
    "hostAliasesInput",
    "hostRolesInput",
    "hostTagsInput",
    "hostDescriptionInput",
    "hostSourceDescriptionInput",
  ].forEach((id) => {
    $(id)?.addEventListener("input", syncHostJsonFromFields);
    $(id)?.addEventListener("change", syncHostJsonFromFields);
  });
  $("hostInterfacesEditor")?.addEventListener("input", syncHostJsonFromFields);
  $("hostInterfacesEditor")?.addEventListener("change", syncHostJsonFromFields);
  $("hostInterfacesEditor")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-host-interface]");
    if (!button) return;
    button.closest("[data-host-interface-row]")?.remove();
    syncHostJsonFromFields();
  });
  $("addHostInterfaceBtn")?.addEventListener("click", () => {
    const networkIds = (registry.networks || []).map((network) => network.id || network.file || network.network_id).filter(Boolean);
    $("hostInterfacesEditor")?.insertAdjacentHTML("beforeend", hostInterfaceRowHtml({}, networkIds));
  });
  $("hostInternetExposedInput")?.addEventListener("change", toggleExposureFields);
  toggleExposureFields();
}

function ensureResourceFieldsPanel() {
  let panel = $("resourceFieldsPanel");
  if (panel) return panel;
  panel = document.createElement("section");
  panel.id = "resourceFieldsPanel";
  panel.className = "panel hidden";
  panel.innerHTML = `<h3 id="resourceFieldsTitle">${escapeHtml(t("detail.basicFields", { label: "" }))}</h3><div id="resourceFields"></div>`;
  $("detailView").querySelector(".raw-panel")?.insertAdjacentElement("beforebegin", panel);
  return panel;
}

function objectFromField(id, fallback = {}) {
  try {
    const value = JSON.parse($(id)?.value || "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

function renderConnectorFields(data) {
  const connectorTypes = [...CONNECTOR_TYPES, ...(registry.connectors || []).map((item) => item.type)].filter(Boolean);
  const credentialIds = (registry.credentials || [])
    .filter((item) => item.status === "active" || item.id === data.credentials_ref)
    .map((item) => item.id)
    .filter(Boolean);
  return `
    <div class="resource-field-grid">
      <label>${escapeHtml(t("field.connectorId"))}<input id="connectorIdInput" value="${escapeHtml(data.connector_id || selectedId || "")}" placeholder="conn-example" /></label>
      <label>${escapeHtml(t("field.name"))}<input id="connectorNameInput" value="${escapeHtml(data.name || "")}" /></label>
      <label>${escapeHtml(t("field.connectorType"))}<select id="connectorTypeInput">${selectOptions(connectorTypes, data.connector_type || "local_file", false)}</select></label>
      <label>${escapeHtml(t("field.credentialsRef"))}<select id="connectorCredentialInput">${selectOptions(credentialIds, data.credentials_ref || "")}</select></label>
      <label>${escapeHtml(t("field.status"))}<select id="connectorStatusInput">${selectOptions(CONNECTOR_STATUSES, data.status || "draft", false)}</select></label>
      <label class="wide">${escapeHtml(t("field.description"))}<textarea id="connectorDescriptionInput" rows="3">${escapeHtml(data.description || "")}</textarea></label>
      <label class="wide">${escapeHtml(t("field.configJson"))}<textarea id="connectorConfigInput" rows="8" spellcheck="false">${escapeHtml(jsonPretty(data.config || {}, {}))}</textarea></label>
      <label class="wide">${escapeHtml(t("field.constraintsJson"))}<textarea id="connectorConstraintsInput" rows="6" spellcheck="false">${escapeHtml(jsonPretty(data.constraints || {}, {}))}</textarea></label>
    </div>`;
}

function readConnectorFields() {
  return {
    connector_id: ($("connectorIdInput")?.value || "").trim(),
    name: ($("connectorNameInput")?.value || "").trim(),
    connector_type: ($("connectorTypeInput")?.value || "").trim(),
    credentials_ref: ($("connectorCredentialInput")?.value || "").trim(),
    status: ($("connectorStatusInput")?.value || "").trim(),
    description: ($("connectorDescriptionInput")?.value || "").trim(),
    config: objectFromField("connectorConfigInput", currentData?.config || {}),
    constraints: objectFromField("connectorConstraintsInput", currentData?.constraints || {}),
  };
}

function renderNetworkFields(data) {
  return `
    <div class="resource-field-grid">
      <label>${escapeHtml(t("field.networkId"))}<input id="networkIdInput" value="${escapeHtml(data.network_id || selectedId || "")}" placeholder="net-example" /></label>
      <label>${escapeHtml(t("field.name"))}<input id="networkNameInput" value="${escapeHtml(data.name || "")}" /></label>
      <label>CIDR<input id="networkCidrInput" value="${escapeHtml(data.cidr || "")}" placeholder="10.0.0.0/24" /></label>
      <label>Zone<input id="networkZoneInput" value="${escapeHtml(data.zone || "")}" placeholder="production_network" /></label>
      <label>${escapeHtml(t("field.networkType"))}<select id="networkTypeInput">${selectOptions(NETWORK_TYPES, data.network_type || "production", false)}</select></label>
      <label>${escapeHtml(t("field.trustLevel"))}<select id="networkTrustInput">${selectOptions(NETWORK_TRUST_LEVELS, data.trust_level || "internal", false)}</select></label>
      <label>${escapeHtml(t("field.gatewayIp"))}<input id="networkGatewayInput" value="${escapeHtml(data.gateway_ip || "")}" placeholder="10.0.0.1" /></label>
      <label>${escapeHtml(t("field.status"))}<select id="networkStatusInput">${selectOptions(NETWORK_STATUSES, data.status || "draft", false)}</select></label>
      <label class="wide">${escapeHtml(t("field.tags"))}<textarea id="networkTagsInput" rows="2">${escapeHtml(csvText(data.tags || []))}</textarea></label>
      <label class="wide">${escapeHtml(t("field.description"))}<textarea id="networkDescriptionInput" rows="3">${escapeHtml(data.description || "")}</textarea></label>
    </div>`;
}

function readNetworkFields() {
  return {
    network_id: ($("networkIdInput")?.value || "").trim(),
    name: ($("networkNameInput")?.value || "").trim(),
    cidr: ($("networkCidrInput")?.value || "").trim(),
    zone: ($("networkZoneInput")?.value || "").trim(),
    network_type: ($("networkTypeInput")?.value || "").trim(),
    trust_level: ($("networkTrustInput")?.value || "").trim(),
    gateway_ip: ($("networkGatewayInput")?.value || "").trim(),
    status: ($("networkStatusInput")?.value || "").trim(),
    tags: csvValue($("networkTagsInput")?.value || ""),
    description: ($("networkDescriptionInput")?.value || "").trim(),
  };
}

function renderBundleFields(data) {
  const selectedAssets = Array.isArray(data.asset_ids) ? data.asset_ids.filter(Boolean) : [];
  const selectedScenarios = Array.isArray(data.investigation_scenarios) ? data.investigation_scenarios.filter(Boolean) : [];
  const selectedRegistryTypes = Array.isArray(data.registry_covers_asset_types) ? data.registry_covers_asset_types.filter(Boolean) : [];
  const assetMap = new Map((registry.assets || []).map((item) => [item.id || item.file, item]));
  const assetItems = [...selectedAssets.filter((id) => !assetMap.has(id)).map((id) => ({ id })), ...assetMap.values()];
  const scenarioIds = [...new Set([...selectedScenarios, ...INVESTIGATION_SCENARIOS])];
  const registryTypes = [...new Set([...selectedRegistryTypes, "asset_inventory"])];
  const editing = detailMode === "edit";
  const readonlyRows = (values, labelFor = (value) => value) => values.length
    ? `<div class="readonly-value-list">${values.map((value) => `<div class="readonly-value-row"><span aria-hidden="true">✓</span><span>${escapeHtml(labelFor(value))}</span></div>`).join("")}</div>`
    : `<span class="hint">${escapeHtml(t("field.notConfigured"))}</span>`;
  const scenarioTitle = (id) => t(`scenario.${id}.title`);
  const scenarioDescription = (id) => t(`scenario.${id}.desc`);
  const scenarioText = (id) => `${id} · ${scenarioTitle(id)} — ${scenarioDescription(id)}`;
  const assetChoices = editing
    ? `<div class="compact-choice-grid">${assetItems.map((item) => { const id = item.id || item.file; return `<label class="choice-row"><input type="checkbox" data-bundle-asset value="${escapeHtml(id)}" ${selectedAssets.includes(id) ? "checked" : ""}/><span><b>${escapeHtml(id)}</b><small>${escapeHtml(item.name || item.type || "")}</small></span></label>`; }).join("")}</div>`
    : readonlyRows(selectedAssets, (id) => { const item = assetMap.get(id); return item?.name ? `${id} · ${item.name}` : id; });
  const scenarioChoices = editing
    ? `<div class="compact-choice-grid scenario-choices">${scenarioIds.map((id) => `<label class="choice-row"><input type="checkbox" data-bundle-scenario value="${escapeHtml(id)}" ${selectedScenarios.includes(id) ? "checked" : ""}/><span><b>${escapeHtml(`${id} · ${scenarioTitle(id)}`)}</b><small>${escapeHtml(scenarioDescription(id))}</small></span></label>`).join("")}</div>`
    : readonlyRows(selectedScenarios, scenarioText);
  const registryChoices = editing
    ? `<div class="compact-choice-grid">${registryTypes.map((type) => `<label class="choice-row"><input type="checkbox" data-bundle-registry-type value="${escapeHtml(type)}" ${selectedRegistryTypes.includes(type) ? "checked" : ""}/><span>${escapeHtml(type)}</span></label>`).join("")}</div>`
    : readonlyRows(selectedRegistryTypes);
  return `
    <div class="resource-field-grid">
      <label>${escapeHtml(t("field.bundleId"))}<input id="bundleIdInput" value="${escapeHtml(data.bundle_id || selectedId || "")}" placeholder="bundle-example" /></label>
      <label>${escapeHtml(t("field.name"))}<input id="bundleNameInput" value="${escapeHtml(data.name || "")}" /></label>
      <label>${escapeHtml(t("field.status"))}<select id="bundleStatusInput">${selectOptions(BUNDLE_STATUSES, data.status || "draft", false)}</select></label>
      <label class="wide">${escapeHtml(t("field.description"))}<textarea id="bundleDescriptionInput" rows="3">${escapeHtml(data.description || "")}</textarea></label>
      <label class="wide">${escapeHtml(t("field.notes"))}<textarea id="bundleNotesInput" rows="3">${escapeHtml(data.notes || "")}</textarea></label>
    </div>
    <div class="structured-choice-section"><strong>${escapeHtml(t("field.assets"))}</strong><span class="hint">${escapeHtml(editing ? t("field.assetsRequired") : t("field.assignedCount", { count: selectedAssets.length }))}</span>
      ${assetChoices}
    </div>
    <div class="structured-choice-section"><strong>${escapeHtml(t("field.investigationScenarios"))}</strong><span class="hint">${escapeHtml(!editing ? t("field.assignedCount", { count: selectedScenarios.length }) : "")}</span>
      ${scenarioChoices}
    </div>
    <div class="structured-choice-section"><strong>${escapeHtml(t("field.registryCoversAssetTypes"))}</strong><span class="hint">${escapeHtml(editing ? t("field.registryCoversHint") : t("field.assignedCount", { count: selectedRegistryTypes.length }))}</span>
      ${registryChoices}
    </div>`;
}

function readBundleFields() {
  return {
    bundle_id: ($("bundleIdInput")?.value || "").trim(),
    name: ($("bundleNameInput")?.value || "").trim(),
    status: ($("bundleStatusInput")?.value || "").trim(),
    description: ($("bundleDescriptionInput")?.value || "").trim(),
    notes: ($("bundleNotesInput")?.value || "").trim(),
    asset_ids: checkedValues("[data-bundle-asset]"),
    investigation_scenarios: checkedValues("[data-bundle-scenario]"),
    registry_covers_asset_types: checkedValues("[data-bundle-registry-type]"),
  };
}

function resourceFieldsForPage(data) {
  if (pageModule === "connector") return renderConnectorFields(data);
  if (pageModule === "network") return renderNetworkFields(data);
  if (pageModule === "bundle") return renderBundleFields(data);
  return "";
}

function readResourceFields() {
  if (pageModule === "connector") return readConnectorFields();
  if (pageModule === "network") return readNetworkFields();
  if (pageModule === "bundle") return readBundleFields();
  return {};
}

function syncResourceJsonFromFields() {
  let parsed;
  try { parsed = JSON.parse($("detailRawJson").value || "{}"); } catch { return; }
  $("detailRawJson").value = JSON.stringify({ ...parsed, ...readResourceFields() }, null, 2);
}

function bindResourceFieldSync() {
  $("resourceFields")?.querySelectorAll("input, select, textarea").forEach((control) => {
    control.addEventListener("input", syncResourceJsonFromFields);
    control.addEventListener("change", syncResourceJsonFromFields);
  });
}

function credentialRefParts(ref) {
  const cleaned = (ref || "").trim().replace(/^vault:\/\//, "").replaceAll("\\", "/");
  const parts = cleaned.split("/");
  return {
    namespace: parts[0] || "",
    name: parts.slice(1).join("/") || "",
  };
}

function yamlTypeFromContent(content) {
  const line = (content || "").split("\n").find((item) => item.trim().startsWith("type:"));
  if (!line) return "";
  return line.split(":").slice(1).join(":").trim().replace(/^['\"]|['\"]$/g, "");
}

function setYamlType(content, credentialType) {
  const typeValue = (credentialType || "").trim();
  if (!typeValue) return content;
  const lines = (content || "").split("\n");
  const typeIndex = lines.findIndex((line) => line.trim().startsWith("type:"));
  if (typeIndex >= 0) {
    lines[typeIndex] = `type: ${typeValue}`;
    return lines.join("\n");
  }
  return `type: ${typeValue}\n${content || ""}`;
}

function normalizeCredentialType(type) {
  const value = String(type || "").trim();
  return CREDENTIAL_TYPE_ALIASES[value] || value;
}

function credentialTypesFromRegistry() {
  const discovered = [];
  (registry.credentials || []).forEach((credential) => {
    const type = normalizeCredentialType(credential.type || credential.credential_type);
    if (type && type !== "unknown") discovered.push(type);
  });
  (registry.connectors || []).forEach((connector) => {
    const ref = String(connector.credentials_ref || connector.credentialsRef || "").trim();
    const namespace = ref.startsWith("vault://") ? ref.replace("vault://", "").split("/")[0] : "";
    const inferred = normalizeCredentialType(namespace || connector.connector_type);
    if (inferred) discovered.push(inferred);
  });
  return discovered;
}

function credentialTypeOptions(selected = "") {
  const normalizedSelected = normalizeCredentialType(selected);
  const builtInCommon = CREDENTIAL_BUILTIN_COMMON_TYPES;
  const builtInGeneric = CREDENTIAL_BUILTIN_GENERIC_TYPES;
  const builtInSet = new Set([...builtInCommon, ...builtInGeneric]);
  const externalTypes = [...new Set([...credentialTypesFromRegistry(), normalizedSelected].filter(Boolean))]
    .filter((type) => !builtInSet.has(type));
  const optionHtml = (type) => `<option value="${escapeHtml(type)}" ${type === normalizedSelected ? "selected" : ""}>${escapeHtml(type)}</option>`;
  const groupHtml = (label, types) => types.length
    ? `<optgroup label="${escapeHtml(label)}">${types.map(optionHtml).join("")}</optgroup>`
    : "";
  return [
    `<option value="" ${normalizedSelected ? "" : "selected"} disabled>${escapeHtml(t("credential.selectType"))}</option>`,
    groupHtml(t("credential.groupCommon"), builtInCommon),
    groupHtml(t("credential.groupGeneric"), builtInGeneric),
    groupHtml(t("credential.groupExternal"), externalTypes),
  ]
    .join("");
}

function credentialTemplateFor(type) {
  const normalizedType = normalizeCredentialType(type);
  if (CREDENTIAL_TYPE_TEMPLATES[normalizedType]) return CREDENTIAL_TYPE_TEMPLATES[normalizedType];
  return `type: ${normalizedType || "custom"}\n# ${t("credential.customTemplateHint")}\ntoken: "REPLACE_ME"\n`;
}

const CREDENTIAL_SECRET_FIELDS = new Set([
  "access_key_secret", "secret_access_key", "session_token", "client_secret", "access_token",
  "secret_key", "private_key", "password", "token", "key_value", "api_key", "api_secret", "app_key",
  "security_token", "keytab",
]);

const CREDENTIAL_TEXTAREA_FIELDS = new Set(["private_key", "keytab"]);
const CREDENTIAL_SELECT_FIELDS = {
  auth_method: ["key", "password", "bearer", "basic", "api_key"],
  placement: ["header", "query"],
};

function credentialScalarValue(rawValue) {
  const value = String(rawValue || "").trim().replace(/\s+#.*$/, "");
  if (!value) return "";
  if (value.startsWith('"') && value.endsWith('"')) {
    try { return JSON.parse(value); } catch (_error) { return value.slice(1, -1); }
  }
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replaceAll("''", "'");
  return value;
}

function credentialYamlFields(content, includeCommented = false) {
  const lines = String(content || "").split("\n");
  const fields = {};
  for (let index = 0; index < lines.length; index += 1) {
    const source = includeCommented ? lines[index].replace(/^\s*#\s?/, "") : lines[index];
    if (!includeCommented && /^\s*#/.test(lines[index])) continue;
    const match = source.match(/^\s*([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
    if (!match || match[1] === "type") continue;
    const key = match[1];
    const rawValue = match[2];
    if ((rawValue === "|" || rawValue === ">") && !includeCommented) {
      const block = [];
      while (index + 1 < lines.length && /^\s+/.test(lines[index + 1])) {
        block.push(lines[index + 1].replace(/^\s{2}/, ""));
        index += 1;
      }
      fields[key] = block.join("\n");
    } else if (!(key in fields) || !includeCommented) {
      fields[key] = credentialScalarValue(rawValue);
    }
  }
  return fields;
}

function credentialFieldKeys(type, content) {
  const templateFields = credentialYamlFields(credentialTemplateFor(type), true);
  const contentFields = credentialYamlFields(content);
  return [...new Set([...Object.keys(templateFields), ...Object.keys(contentFields)])];
}

function credentialFieldLabel(key) {
  const translated = t(`credential.input.${key}`);
  if (translated !== `credential.input.${key}`) return translated;
  return key.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function credentialFieldControl(key, value) {
  const label = escapeHtml(credentialFieldLabel(key));
  const fieldId = `credentialValue-${key}`;
  const common = `id="${escapeHtml(fieldId)}" data-credential-value="${escapeHtml(key)}"`;
  if (CREDENTIAL_SELECT_FIELDS[key]) {
    return `<label>${label}<select ${common}>${selectOptions(CREDENTIAL_SELECT_FIELDS[key], value, true)}</select></label>`;
  }
  if (CREDENTIAL_TEXTAREA_FIELDS.has(key)) {
    return `<label class="wide">${label}<textarea ${common} rows="5" spellcheck="false">${escapeHtml(value)}</textarea></label>`;
  }
  const inputType = CREDENTIAL_SECRET_FIELDS.has(key) ? "password" : "text";
  return `<label>${label}<input ${common} type="${inputType}" value="${escapeHtml(value)}" autocomplete="off" /></label>`;
}

function renderCredentialValueFields(type, content) {
  if (!type) return `<p class="hint">${escapeHtml(t("credential.selectTypeHint"))}</p>`;
  if (type === "custom") return `<p class="hint">${escapeHtml(t("credential.customYamlHint"))}</p>`;
  const values = credentialYamlFields(content);
  const templateValues = credentialYamlFields(credentialTemplateFor(type), true);
  const keys = credentialFieldKeys(type, content);
  if (!keys.length) return `<p class="hint">${escapeHtml(t("credential.noInputFields"))}</p>`;
  return keys.map((key) => credentialFieldControl(key, values[key] ?? templateValues[key] ?? "")).join("");
}

function yamlCredentialValue(value) {
  const text = String(value ?? "");
  if (text.includes("\n")) return `|\n${text.split("\n").map((line) => `  ${line}`).join("\n")}`;
  return JSON.stringify(text);
}

function setYamlCredentialField(content, key, value) {
  const lines = String(content || "").split("\n");
  const fieldPattern = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}\\s*:`);
  const start = lines.findIndex((line) => fieldPattern.test(line) && !/^\s*#/.test(line));
  const replacement = `${key}: ${yamlCredentialValue(value)}`;
  if (start < 0) return `${String(content || "").trimEnd()}\n${replacement}\n`;
  let end = start + 1;
  if (/^\s*[A-Za-z_][\w-]*\s*:\s*[|>]\s*$/.test(lines[start])) {
    while (end < lines.length && /^\s+/.test(lines[end])) end += 1;
  }
  lines.splice(start, end - start, replacement);
  return lines.join("\n");
}

function refreshCredentialValueFields() {
  const root = $("credentialValueFields");
  if (!root) return;
  const type = normalizeCredentialType(($("credentialTypeInput")?.value || "").trim());
  root.innerHTML = renderCredentialValueFields(type, $("detailRawJson")?.value || "");
  root.querySelectorAll("[data-credential-value]").forEach((control) => {
    control.disabled = detailMode !== "edit";
    const sync = () => {
      $("detailRawJson").value = setYamlCredentialField($("detailRawJson").value, control.dataset.credentialValue, control.value);
    };
    control.addEventListener("input", sync);
    control.addEventListener("change", sync);
  });
}

function renderCredentialFields(data) {
  const credentialType = normalizeCredentialType(data.credential_type || yamlTypeFromContent(data.content) || "");
  return `
    <div class="credential-field-grid">
      <label>${escapeHtml(t("field.credentialType"))}<select id="credentialTypeInput">${credentialTypeOptions(credentialType)}</select></label>
      <label>${escapeHtml(t("field.credentialId"))}<input id="credentialIdInput" value="${escapeHtml(data.credential_id || selectedId || "")}" placeholder="vault://mysql/credential-name" /></label>
    </div>
    <div class="credential-value-section">
      <h4>${escapeHtml(t("credential.valueFields"))}</h4>
      <div id="credentialValueFields" class="credential-field-grid">${renderCredentialValueFields(credentialType, data.content || "")}</div>
    </div>
    <p class="hint block">${escapeHtml(t("credential.fieldHint"))}</p>
  `;
}

function readCredentialFields() {
  const rawRef = ($("credentialIdInput")?.value || "").trim();
  const parts = credentialRefParts(rawRef);
  return {
    credential_id: rawRef,
    namespace: parts.namespace,
    name: parts.name,
    credential_type: normalizeCredentialType(($("credentialTypeInput")?.value || "").trim()),
    status: "active",
    example_file: parts.namespace && parts.name ? `examples/${parts.namespace}/${parts.name}.yaml` : "",
    secret_file: parts.namespace && parts.name ? `secrets/${parts.namespace}/${parts.name}.enc.yaml` : "",
  };
}

function bindCredentialFieldSync() {
  const idInput = $("credentialIdInput");
  const typeInput = $("credentialTypeInput");
  const syncIdNamespace = (type) => {
    if (!isCreating || !idInput || !type) return;
    const parts = credentialRefParts(idInput.value);
    const name = parts.name || idInput.dataset.generatedName || `credential-${Date.now()}`;
    idInput.dataset.generatedName = name;
    idInput.value = `vault://${type}/${name}`;
  };
  const applyTypeTemplate = () => {
    const selectedType = normalizeCredentialType(typeInput?.value);
    if (!selectedType) return;
    const currentContent = $("detailRawJson")?.value || "";
    const currentType = normalizeCredentialType(yamlTypeFromContent(currentContent));
    const selectedTemplate = credentialTemplateFor(selectedType);
    const currentTemplate = credentialTemplateFor(currentType);
    const shouldReplace = !currentContent.trim() || currentContent.trim() === currentTemplate.trim() || confirm(t("credential.typeReplaceConfirm"));
    if (shouldReplace) {
      $("detailRawJson").value = selectedTemplate;
      syncIdNamespace(selectedType);
      refreshCredentialValueFields();
    } else {
      typeInput.value = currentType || selectedType;
    }
  };
  typeInput?.addEventListener("change", applyTypeTemplate);
  $("detailRawJson")?.addEventListener("change", refreshCredentialValueFields);
}

function correlationJoinIds() {
  const data = pageModule === "correlation" ? currentData : correlationContext;
  const source = data || {};
  return new Set([
    ...(source.internal_joins || []).map((join) => join.id).filter(Boolean),
    ...(source.cross_source_joins || []).map((join) => join.id).filter(Boolean),
  ]);
}

function registryBundleIds() {
  return new Set((registry.bundles || []).map((bundle) => bundle.bundle_id || bundle.id || bundle.file).filter(Boolean));
}

function timeWindowOptions(selected = "") {
  const windows = Object.keys(currentData?.time_windows || {});
  return selectOptions(windows, selected, false);
}

function renderDiagnostics(items) {
  const cards = items.length ? items : [{ level: "ok", text: t("editor.referenceOk") }];
  return `
    <div class="structured-diagnostics">
      ${cards.map((item) => `<span class="diag-chip ${escapeHtml(item.level || "info")}">${escapeHtml(item.text)}</span>`).join("")}
    </div>
  `;
}

function correlationDiagnostics(data) {
  const windows = data.time_windows || {};
  const joins = [...(data.internal_joins || []), ...(data.cross_source_joins || [])];
  const ids = joins.map((join) => join.id).filter(Boolean);
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
  const missingWindow = joins.filter((join) => join.time_window && !windows[join.time_window]).map((join) => join.id || t("editor.unnamed"));
  const missingKeys = joins
    .filter((join) => !Array.isArray(join.path) && (!Array.isArray(join.join_keys) || !join.join_keys.length))
    .map((join) => join.id || t("editor.unnamed"));
  const missingTrust = joins.filter((join) => !Number.isInteger(join.priority) || !join.confidence?.reason).map((join) => join.id || t("editor.unnamed"));
  return [
    { level: "info", text: t("editor.windowCount", { count: Object.keys(windows).length }) },
    { level: "info", text: t("editor.internalJoinCount", { count: data.internal_joins?.length || 0 }) },
    { level: "info", text: t("editor.crossJoinCount", { count: data.cross_source_joins?.length || 0 }) },
    ...[...new Set(duplicateIds)].map((id) => ({ level: "warn", text: t("editor.duplicateJoin", { id }) })),
    ...missingWindow.map((id) => ({ level: "warn", text: t("editor.missingWindow", { id }) })),
    ...missingKeys.map((id) => ({ level: "warn", text: t("editor.missingKeys", { id }) })),
    ...missingTrust.map((id) => ({ level: "warn", text: t("editor.missingTrust", { id }) })),
  ];
}

function allCorrelationJoins(data) {
  return [
    ...(data.internal_joins || []).map((join) => ({ ...join, _section: "internal" })),
    ...(data.cross_source_joins || []).map((join) => ({ ...join, _section: "cross" })),
  ];
}

function priorityBand(priority) {
  const value = Number(priority || 0);
  if (value >= 90) return { label: t("editor.priorityHigh"), className: "high" };
  if (value >= 70) return { label: t("editor.priorityMid"), className: "mid" };
  return { label: t("editor.priorityLow"), className: "low" };
}

function confidenceRange(confidence = {}) {
  if (!confidence || typeof confidence !== "object") return "-";
  const base = confidence.base ?? "-";
  const max = confidence.max ?? "-";
  return `${base} → ${max}`;
}

function renderCorrelationExplainPanel(data) {
  const joins = allCorrelationJoins(data).sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0));
  const assetTypes = [...new Set(joins.flatMap((join) => [join.from_asset_type, join.to_asset_type]).filter(Boolean))].sort();
  const pathJoins = joins.filter((join) => Array.isArray(join.path) && join.path.length);
  const strongJoins = joins.filter((join) => Number(join.priority || 0) >= 90);
  const fetchCovered = joins.filter((join) => join.fetch_plan).length;
  const topJoins = joins.slice(0, 8);
  return `
    <section class="structured-section correlation-explain">
      <div class="structured-section-head">
        <div><h4>${escapeHtml(t("editor.visualTitle"))}</h4><p class="hint">${escapeHtml(t("editor.visualHint"))}</p></div>
        <span class="pill muted">${escapeHtml(data.version ? `v${data.version}` : "matrix")}</span>
      </div>
      <div class="correlation-stats">
        <div><strong>${joins.length}</strong><span>Join</span></div>
        <div><strong>${assetTypes.length}</strong><span>${escapeHtml(t("editor.assetType"))}</span></div>
        <div><strong>${strongJoins.length}</strong><span>${escapeHtml(t("editor.priorityHigh"))}</span></div>
        <div><strong>${fetchCovered}/${joins.length}</strong><span>${escapeHtml(t("editor.fetchPlan"))}</span></div>
      </div>
      <div class="correlation-graph" aria-label="Correlation join graph">
        <div class="correlation-node-rail">
          ${assetTypes.map((type) => `<span class="correlation-node">${escapeHtml(type)}</span>`).join("")}
        </div>
        <div class="correlation-edge-list">
          ${topJoins.map((join) => {
            const band = priorityBand(join.priority);
            return `
              <article class="correlation-edge ${escapeHtml(band.className)}">
                <div class="correlation-edge-main">
                  <span class="correlation-endpoint">${escapeHtml(join.from_asset_type || "?")}</span>
                  <span class="correlation-arrow">→</span>
                  <span class="correlation-endpoint">${escapeHtml(join.to_asset_type || "?")}</span>
                </div>
                <div class="correlation-edge-meta">
                  <strong>${escapeHtml(join.id || "-")}</strong>
                  <span>P${escapeHtml(join.priority ?? "-")} · ${escapeHtml(band.label)} · ${escapeHtml(confidenceRange(join.confidence))}</span>
                </div>
                <p>${escapeHtml(join.confidence?.reason || join.purpose || "-")}</p>
              </article>
            `;
          }).join("") || `<p class="hint block">${escapeHtml(t("editor.noJoin"))}</p>`}
        </div>
      </div>
      ${pathJoins.length ? `
        <div class="path-join-strip">
          ${pathJoins.map((join) => `<span>${escapeHtml(join.id)}：${escapeHtml((join.path || []).join(" → "))}</span>`).join("")}
        </div>
      ` : ""}
    </section>
  `;
}

function renderTimeWindowEditor(data) {
  const windows = data.time_windows || {};
  const entries = Object.entries(windows);
  return `
    <section class="structured-section">
      <div class="structured-section-head">
        <div><h4>${escapeHtml(t("editor.timeWindows"))}</h4><p class="hint">${escapeHtml(t("editor.timeWindowsHint"))}</p></div>
        <button class="button secondary small" type="button" data-structured-action="add-time-window">${escapeHtml(t("editor.addTimeWindow"))}</button>
      </div>
      <div class="structured-grid compact">
        ${entries.map(([id, window]) => `
          <div class="structured-card time-window-card" data-time-window="${escapeHtml(id)}">
            <label class="wide">ID<input data-window-field="id" value="${escapeHtml(id)}" /></label>
            <label>${escapeHtml(t("editor.beforeMinutes"))}<input type="number" data-window-field="before_minutes" value="${escapeHtml(window.before_minutes ?? "")}" /></label>
            <label>${escapeHtml(t("editor.afterMinutes"))}<input type="number" data-window-field="after_minutes" value="${escapeHtml(window.after_minutes ?? "")}" /></label>
            <label>${escapeHtml(t("editor.beforeHours"))}<input type="number" data-window-field="before_hours" value="${escapeHtml(window.before_hours ?? "")}" /></label>
            <label>${escapeHtml(t("editor.afterHours"))}<input type="number" data-window-field="after_hours" value="${escapeHtml(window.after_hours ?? "")}" /></label>
            <label class="wide">${escapeHtml(t("editor.purpose"))}<input data-window-field="use" value="${escapeHtml(window.use || "")}" /></label>
          </div>
        `).join("") || `<p class="hint block">${escapeHtml(t("editor.noTimeWindows"))}</p>`}
      </div>
    </section>
  `;
}

function renderJoinEditor(section, joins = []) {
  const title = section === "internal_joins" ? t("editor.internalJoins") : t("editor.crossSourceJoins");
  const action = section === "internal_joins" ? "add-internal-join" : "add-cross-join";
  return `
    <section class="structured-section">
      <div class="structured-section-head">
        <div><h4>${escapeHtml(title)}</h4><p class="hint">${escapeHtml(t("editor.joinHint"))}</p></div>
        <button class="button secondary small" type="button" data-structured-action="${escapeHtml(action)}">${escapeHtml(t("editor.addItem", { label: title }))}</button>
      </div>
      <div class="structured-card-list">
        ${joins.map((join, index) => `
          <div class="structured-card join-card" data-join-section="${escapeHtml(section)}" data-join-index="${index}">
            <div class="structured-card-head">
              <strong>${escapeHtml(join.id || `${title}-${index + 1}`)}</strong>
              <span class="pill muted">${escapeHtml(join.from_asset_type || "?")} → ${escapeHtml(join.to_asset_type || "?")}</span>
            </div>
            <div class="structured-grid">
              <label>ID<input data-join-field="id" value="${escapeHtml(join.id || "")}" /></label>
              <label>${escapeHtml(t("editor.fromAssetType"))}<input data-join-field="from_asset_type" value="${escapeHtml(join.from_asset_type || "")}" /></label>
              <label>${escapeHtml(t("editor.toAssetType"))}<input data-join-field="to_asset_type" value="${escapeHtml(join.to_asset_type || "")}" /></label>
              <label>${escapeHtml(t("editor.timeWindow"))}<select data-join-field="time_window">${timeWindowOptions(join.time_window || "")}</select></label>
              <label>${escapeHtml(t("editor.priority"))}<input type="number" min="1" max="100" data-join-field="priority" value="${escapeHtml(join.priority ?? "")}" /></label>
              <label>${escapeHtml(t("editor.confidenceBase"))}<input type="number" min="0" max="1" step="0.01" data-confidence-field="base" value="${escapeHtml(join.confidence?.base ?? "")}" /></label>
              <label>${escapeHtml(t("editor.confidenceMax"))}<input type="number" min="0" max="1" step="0.01" data-confidence-field="max" value="${escapeHtml(join.confidence?.max ?? "")}" /></label>
              <label>${escapeHtml(t("editor.optionalKeyIncrement"))}<input type="number" min="0" max="1" step="0.01" data-confidence-field="optional_key_increment" value="${escapeHtml(join.confidence?.optional_key_increment ?? 0.05)}" /></label>
              <label class="wide">${escapeHtml(t("editor.purpose"))}<input data-join-field="purpose" value="${escapeHtml(join.purpose || "")}" /></label>
              <label class="wide">${escapeHtml(t("editor.confidenceReason"))}<input data-confidence-field="reason" value="${escapeHtml(join.confidence?.reason || "")}" /></label>
              <label class="wide">${escapeHtml(t("editor.confidenceSignals"))}<textarea rows="2" data-confidence-field="signals" placeholder="host exact, short time window">${escapeHtml(csvText(join.confidence?.signals || []))}</textarea></label>
              <label>${escapeHtml(t("editor.scenarios"))}<textarea rows="2" data-join-field="scenarios" placeholder="S1, S2">${escapeHtml(csvText(join.scenarios || []))}</textarea></label>
              <label>${escapeHtml(t("editor.skills"))}<textarea rows="2" data-join-field="skills" placeholder="traceability-analysis">${escapeHtml(csvText(join.skills || []))}</textarea></label>
              <label>${escapeHtml(t("editor.fetchParams"))}<textarea rows="2" data-join-field="fetch_params" placeholder="src_ip, dst_ip">${escapeHtml(csvText(join.fetch_params || []))}</textarea></label>
              <label class="wide">${escapeHtml(t("editor.joinKeysJson"))}<textarea rows="7" data-join-json="join_keys" spellcheck="false">${escapeHtml(jsonPretty(join.join_keys, []))}</textarea></label>
            </div>
          </div>
        `).join("") || `<p class="hint block">${escapeHtml(t("editor.noItems", { label: title }))}</p>`}
      </div>
    </section>
  `;
}

function renderCorrelationEditor(root) {
  currentData.time_windows ||= {};
  currentData.internal_joins ||= [];
  currentData.cross_source_joins ||= [];
  root.innerHTML = `
    ${renderCorrelationExplainPanel(currentData)}
    ${renderDiagnostics(correlationDiagnostics(currentData))}
    ${renderTimeWindowEditor(currentData)}
    ${renderJoinEditor("internal_joins", currentData.internal_joins)}
    ${renderJoinEditor("cross_source_joins", currentData.cross_source_joins)}
  `;
  bindCorrelationEditor(root);
}

function bindCorrelationEditor(root) {
  root.querySelectorAll("[data-window-field]").forEach((input) => {
    input.addEventListener("input", () => {
      const card = input.closest("[data-time-window]");
      const oldId = card?.dataset.timeWindow;
      if (!oldId) return;
      const field = input.dataset.windowField;
      const windows = currentData.time_windows || {};
      if (field === "id") {
        const nextId = input.value.trim();
        if (!nextId || nextId === oldId || windows[nextId]) return;
        windows[nextId] = windows[oldId] || {};
        delete windows[oldId];
        [...(currentData.internal_joins || []), ...(currentData.cross_source_joins || [])].forEach((join) => {
          if (join.time_window === oldId) join.time_window = nextId;
        });
        syncCurrentDataToRaw();
        renderStructuredEditor();
        return;
      }
      windows[oldId] ||= {};
      if (["before_minutes", "after_minutes", "before_hours", "after_hours"].includes(field)) {
        const value = numericOrEmpty(input.value);
        if (value === "") delete windows[oldId][field];
        else windows[oldId][field] = value;
      } else {
        windows[oldId][field] = input.value.trim();
      }
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-join-field]").forEach((input) => {
    const eventName = input.tagName === "SELECT" ? "change" : "input";
    input.addEventListener(eventName, () => {
      const card = input.closest("[data-join-section]");
      const join = currentData[card.dataset.joinSection]?.[Number(card.dataset.joinIndex)];
      if (!join) return;
      const field = input.dataset.joinField;
      if (["scenarios", "skills", "fetch_params"].includes(field)) join[field] = csvValue(input.value);
      else if (field === "priority") join[field] = Number(input.value);
      else join[field] = input.value.trim();
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-confidence-field]").forEach((input) => {
    const eventName = input.tagName === "SELECT" ? "change" : "input";
    input.addEventListener(eventName, () => {
      const card = input.closest("[data-join-section]");
      const join = currentData[card.dataset.joinSection]?.[Number(card.dataset.joinIndex)];
      if (!join) return;
      join.confidence ||= { base: 0.8, max: 0.9, optional_key_increment: 0.05, reason: "" };
      const field = input.dataset.confidenceField;
      if (["base", "max", "optional_key_increment"].includes(field)) {
        join.confidence[field] = Number(input.value);
      } else if (field === "signals") {
        join.confidence[field] = csvValue(input.value);
      } else {
        join.confidence[field] = input.value.trim();
      }
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-join-json]").forEach((input) => {
    input.addEventListener("input", () => {
      const card = input.closest("[data-join-section]");
      const join = currentData[card.dataset.joinSection]?.[Number(card.dataset.joinIndex)];
      if (!join) return;
      try {
        join[input.dataset.joinJson] = JSON.parse(input.value || "[]");
        syncCurrentDataToRaw();
      } catch (error) {
        $("detailStatus").textContent = t("editor.joinKeysError", { message: error.message });
      }
    });
  });
  root.querySelectorAll("[data-structured-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.structuredAction;
      if (action === "add-time-window") {
        let id = "new_window";
        let index = 1;
        while (currentData.time_windows?.[id]) id = `new_window_${index++}`;
        currentData.time_windows ||= {};
        currentData.time_windows[id] = { before_minutes: 10, after_minutes: 10, use: t("editor.newTimeWindow") };
      }
      if (action === "add-internal-join" || action === "add-cross-join") {
        const section = action === "add-internal-join" ? "internal_joins" : "cross_source_joins";
        currentData[section] ||= [];
        currentData[section].push({
          id: `${section.replace("_joins", "")}_new_${currentData[section].length + 1}`,
          from_asset_type: "",
          to_asset_type: "",
          join_keys: [{ left: "", right: "", match: "exact" }],
          time_window: Object.keys(currentData.time_windows || {})[0] || "",
          priority: section === "internal_joins" ? 80 : 70,
          confidence: {
            base: 0.8,
            max: 0.9,
            optional_key_increment: 0.05,
            reason: t("editor.newJoinReason"),
            signals: ["exact key", "time window"]
          },
          purpose: "",
          scenarios: [],
          skills: ["traceability-analysis"],
        });
      }
      syncCurrentDataToRaw();
      renderStructuredEditor();
    });
  });
}

function scenarioTimeWindowOptions(selected = "") {
  const windows = new Set();
  const matrix = pageModule === "correlation" ? currentData : correlationContext;
  Object.keys(matrix?.time_windows || {}).forEach((id) => windows.add(id));
  ["trace_default", "alert_confirmation_fetch", "alert_context", "attack_success"].forEach((id) => windows.add(id));
  return selectOptions([...windows], selected, true);
}

function scenarioDiagnostics(data) {
  const joinIds = correlationJoinIds();
  const bundleIds = registryBundleIds();
  const patterns = data.patterns || {};
  const warnings = [];
  Object.entries(patterns).forEach(([id, pattern]) => {
    (pattern.recommended_chain || []).forEach((joinId) => {
      if (joinIds.size && !joinIds.has(joinId)) warnings.push({ level: "warn", text: t("editor.unknownJoin", { id, join: joinId }) });
    });
    if (pattern.bundle_id && bundleIds.size && !bundleIds.has(pattern.bundle_id)) {
      warnings.push({ level: "warn", text: t("editor.unknownBundle", { id, bundle: pattern.bundle_id }) });
    }
  });
  return [
    { level: "info", text: t("editor.scenarioCount", { count: Object.keys(patterns).length }) },
    { level: "info", text: t("editor.priorityCount", { count: data.scenario_priority?.length || 0 }) },
    ...warnings,
  ];
}

function renderScenarioEditor(root) {
  currentData.patterns ||= {};
  currentData.scenario_priority ||= [];
  const patternEntries = Object.entries(currentData.patterns);
  root.innerHTML = `
    ${renderDiagnostics(scenarioDiagnostics(currentData))}
    <section class="structured-section">
      <div class="structured-section-head">
        <div><h4>${escapeHtml(t("editor.scenarioPatterns"))}</h4><p class="hint">${escapeHtml(t("editor.scenarioHint"))}</p></div>
        <button class="button secondary small" type="button" data-scenario-action="add-pattern">${escapeHtml(t("editor.addScenario"))}</button>
      </div>
      <div class="structured-card-list">
        ${patternEntries.map(([id, pattern], index) => `
          <div class="structured-card scenario-card" data-pattern-id="${escapeHtml(id)}">
            <div class="structured-card-head">
              <strong>${escapeHtml(id)}</strong>
              <span class="pill muted">${escapeHtml(pattern.label || t("editor.unnamedScenario"))}</span>
            </div>
            <div class="structured-grid">
              <label>${escapeHtml(t("editor.patternId"))}<input data-pattern-field="id" value="${escapeHtml(id)}" /></label>
              <label>${escapeHtml(t("editor.label"))}<input data-pattern-field="label" value="${escapeHtml(pattern.label || "")}" /></label>
              <label>${escapeHtml(t("editor.investigationWindow"))}<select data-pattern-field="investigation_window">${scenarioTimeWindowOptions(pattern.investigation_window || "")}</select></label>
              <label>${escapeHtml(t("field.bundleId"))}<input data-pattern-field="bundle_id" value="${escapeHtml(pattern.bundle_id || "")}" /></label>
              <label>${escapeHtml(t("editor.anchorField"))}<input data-anchor-field="field" value="${escapeHtml(pattern.anchor?.field || "")}" /></label>
              <label>${escapeHtml(t("editor.anchorFrom"))}<input data-anchor-field="from" value="${escapeHtml(pattern.anchor?.from || "")}" /></label>
              <label>${escapeHtml(t("editor.secondary"))}<input data-anchor-field="secondary" value="${escapeHtml(pattern.anchor?.secondary || "")}" /></label>
              <label>${escapeHtml(t("editor.anchorVariants"))}<input data-anchor-list="field_variants" value="${escapeHtml(csvText(pattern.anchor?.field_variants || []))}" /></label>
              <label>${escapeHtml(t("editor.fallbackAssetTypes"))}<input data-anchor-list="fallback_asset_types" value="${escapeHtml(csvText(pattern.anchor?.fallback_asset_types || []))}" /></label>
              <label class="wide">${escapeHtml(t("editor.recommendedChain"))}<textarea rows="3" data-pattern-list="recommended_chain" placeholder="waf_to_web_access_by_ip, web_access_to_host_exec">${escapeHtml(csvText(pattern.recommended_chain || []))}</textarea></label>
            </div>
            <details class="structured-more">
              <summary>${escapeHtml(t("editor.layeredCoverage"))}</summary>
              <div class="structured-grid">
                <label>${escapeHtml(t("editor.layer1Assets"))}<textarea rows="2" data-pattern-list="layer1_assets">${escapeHtml(csvText(pattern.layer1_assets || []))}</textarea></label>
                <label>${escapeHtml(t("editor.layer2Assets"))}<textarea rows="2" data-pattern-list="layer2_assets">${escapeHtml(csvText(pattern.layer2_assets || []))}</textarea></label>
              </div>
            </details>
            <p class="hint block">${escapeHtml(t("editor.priorityPosition", { position: index + 1 }))}</p>
          </div>
        `).join("") || `<p class="hint block">${escapeHtml(t("editor.noPatterns"))}</p>`}
      </div>
    </section>
  `;
  bindScenarioEditor(root);
}

function bindScenarioEditor(root) {
  const patternFor = (node) => currentData.patterns?.[node.closest("[data-pattern-id]")?.dataset.patternId];
  root.querySelectorAll("[data-pattern-field]").forEach((input) => {
    const eventName = input.tagName === "SELECT" ? "change" : "input";
    input.addEventListener(eventName, () => {
      const card = input.closest("[data-pattern-id]");
      const oldId = card?.dataset.patternId;
      const pattern = currentData.patterns?.[oldId];
      if (!pattern) return;
      const field = input.dataset.patternField;
      if (field === "id") {
        const nextId = input.value.trim();
        if (!nextId || nextId === oldId || currentData.patterns[nextId]) return;
        currentData.patterns[nextId] = pattern;
        delete currentData.patterns[oldId];
        currentData.scenario_priority = (currentData.scenario_priority || []).map((pair) => Array.isArray(pair) && pair[1] === oldId ? [pair[0], nextId] : pair);
        syncCurrentDataToRaw();
        renderStructuredEditor();
        return;
      }
      pattern[field] = input.value.trim();
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-pattern-list]").forEach((input) => {
    input.addEventListener("input", () => {
      const pattern = patternFor(input);
      if (!pattern) return;
      pattern[input.dataset.patternList] = csvValue(input.value);
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-anchor-field], [data-anchor-list]").forEach((input) => {
    input.addEventListener("input", () => {
      const pattern = patternFor(input);
      if (!pattern) return;
      pattern.anchor ||= {};
      if (input.dataset.anchorField) pattern.anchor[input.dataset.anchorField] = input.value.trim();
      if (input.dataset.anchorList) pattern.anchor[input.dataset.anchorList] = csvValue(input.value);
      syncCurrentDataToRaw();
    });
  });
  root.querySelectorAll("[data-scenario-action]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.scenarioAction !== "add-pattern") return;
      let id = "S_new_pattern";
      let index = 1;
      while (currentData.patterns?.[id]) id = `S_new_pattern_${index++}`;
      currentData.patterns ||= {};
      currentData.patterns[id] = {
        label: t("editor.newScenario"),
        investigation_window: "trace_default",
        anchor: { field: "", from: "params.value", field_variants: [] },
        recommended_chain: [],
        bundle_id: "",
      };
      currentData.scenario_priority ||= [];
      currentData.scenario_priority.push(["S_new", id]);
      syncCurrentDataToRaw();
      renderStructuredEditor();
    });
  });
}

function applyStructuredEditorMode(root) {
  const canEdit = pageConfig.editable && detailMode === "edit";
  root.querySelectorAll("input, select, textarea, button").forEach((control) => { control.disabled = !canEdit; });
}

function renderStructuredEditor() {
  const panel = $("structuredEditorPanel");
  const root = $("structuredEditor");
  if (!panel || !root) return;
  if (!["correlation", "scenario"].includes(pageModule) || !currentData) {
    panel.classList.add("hidden");
    root.innerHTML = "";
    return;
  }
  panel.classList.remove("hidden");
  $("structuredEditorTitle").textContent = pageModule === "correlation" ? t("editor.correlationTitle") : t("editor.scenarioTitle");
  $("structuredEditorHint").textContent = pageModule === "correlation"
    ? t("editor.correlationHint")
    : t("editor.scenarioEditorHint");
  if (pageModule === "correlation") renderCorrelationEditor(root);
  if (pageModule === "scenario") {
    renderScenarioEditor(root);
    ensureCorrelationContext().then((context) => {
      if (context && pageModule === "scenario" && currentData) {
        renderScenarioEditor(root);
        applyStructuredEditorMode(root);
      }
    });
  }
  applyStructuredEditorMode(root);
}
