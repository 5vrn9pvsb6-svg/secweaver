function activeTotalText(items = []) {
  const total = items.length;
  const active = items.filter((item) => item.status === "active").length;
  return `${active}/${total}`;
}

function renderCounts() {
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

function itemSearchText(item) {
  return `${item.id || ""} ${item.file || ""} ${item.name || ""} ${item.type || ""} ${item.status || ""} ${item.environment || ""} ${item.domain || ""} ${item.connector_id || ""} ${item.owner_team || ""} ${item.host_os || ""} ${item.host_ip || ""} ${item.network_id || ""} ${item.cidr || ""} ${item.gateway_ip || ""} ${(item.tags || []).join?.(" ") || ""}`.toLowerCase();
}

function saveConnectivityState() {
  localStorage.setItem(CONNECTIVITY_STORAGE_KEY, JSON.stringify(connectivityAssetStatus));
}

function assetNameCell(item, itemId) {
  const status = pageModule === "asset" ? connectivityAssetStatus[itemId] : undefined;
  const mark = status === "ok"
    ? `<span class="connectivity-mark connectivity-ok" title="${escapeHtml(t("action.connectivityOk"))}" aria-label="${escapeHtml(t("action.connectivityOk"))}">✓</span>`
    : status === "failed"
      ? `<span class="connectivity-mark connectivity-failed" title="${escapeHtml(t("action.connectivityFailed"))}" aria-label="${escapeHtml(t("action.connectivityFailed"))}">×</span>`
      : "";
  return `<span class="asset-name-cell">${mark}<span>${escapeHtml(item.name || pageConfig.label)}</span></span>`;
}

function markConnectivityResult(assetId, ok) {
  if (!assetId) return;
  connectivityAssetStatus[assetId] = ok ? "ok" : "failed";
  saveConnectivityState();
  renderList();
}

function rowActionButtons(itemId, item = null) {
  if (pageModule === "asset") {
    return `
      <button class="button tiny ghost icon-action" type="button" data-action="test" data-id="${escapeHtml(itemId)}" title="${escapeHtml(t("button.test"))}" aria-label="${escapeHtml(t("button.test"))}">C</button>
      <button class="button tiny ghost icon-action" type="button" data-action="discover" data-id="${escapeHtml(itemId)}" title="${escapeHtml(t("button.discover"))}" aria-label="${escapeHtml(t("button.discover"))}">F</button>
      <button class="button tiny ghost" type="button" data-action="view" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.view"))}</button>
      <button class="button tiny ghost" type="button" data-action="edit" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.edit"))}</button>
      <button class="button tiny danger" type="button" data-action="delete" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.delete"))}</button>
    `;
  }
  if (pageModule === "credential") {
    const statusAction = item?.status === "active"
      ? `<button class="button tiny ghost" type="button" data-action="deactivate" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.deactivate"))}</button>`
      : item?.status === "disabled"
        ? `<button class="button tiny ghost" type="button" data-action="activate" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.activate"))}</button>`
        : "";
    return `
      ${statusAction}
      <button class="button tiny ghost" type="button" data-action="edit" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.edit"))}</button>
      <button class="button tiny danger" type="button" data-action="delete" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.delete"))}</button>
    `;
  }
  return `
    <button class="button tiny ghost" type="button" data-action="edit" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.edit"))}</button>
    ${pageConfig.deletable ? `<button class="button tiny danger" type="button" data-action="delete" data-id="${escapeHtml(itemId)}">${escapeHtml(t("button.delete"))}</button>` : ""}
  `;
}

function tableEmptyRow(colspan) {
  return `<tr><td colspan="${colspan}" class="hint empty-list">${escapeHtml(t("list.empty", { label: pageConfig.label }))}</td></tr>`;
}

function titledCell(value, fallback = "-") {
  const text = value === undefined || value === null || value === "" ? fallback : String(value);
  return `<td title="${escapeHtml(text)}">${escapeHtml(text)}</td>`;
}

function titledPillCell(value, className = "muted", fallback = "-") {
  const text = value === undefined || value === null || value === "" ? fallback : String(value);
  return `<td title="${escapeHtml(text)}"><span class="pill ${escapeHtml(className)}">${escapeHtml(text)}</span></td>`;
}

function renderAssetList(pageItems, filtered, totalPages) {
  $("moduleList").innerHTML = `
    <div class="native-table-scroll">
      <table class="native-list-table asset-native-table">
        <colgroup><col style="width:14%"><col style="width:16%"><col style="width:11%"><col style="width:6%"><col style="width:15%"><col style="width:10%"><col style="width:8%"><col style="width:20%"></colgroup>
        <thead><tr>
          <th>${escapeHtml(t("table.idFile"))}</th><th>${escapeHtml(t("table.name"))}</th><th>${escapeHtml(t("table.type"))}</th><th>${escapeHtml(t("table.domain"))}</th><th>${escapeHtml(t("table.connector"))}</th><th>${escapeHtml(t("table.ownerTeam"))}</th><th>${escapeHtml(t("table.status"))}</th><th>${escapeHtml(t("table.actions"))}</th>
        </tr></thead>
        <tbody>
          ${pageItems.map((item) => {
            const itemId = item.id || item.file;
            const active = itemId === selectedId ? " active" : "";
            return `
              <tr class="native-list-row${active}" data-row-id="${escapeHtml(itemId)}" role="button" tabindex="0">
                ${titledCell(itemId)}
                <td title="${escapeHtml(item.name || pageConfig.label)}">${assetNameCell(item, itemId)}</td>
                ${titledPillCell(item.type || pageModule)}
                ${titledCell(item.domain)}
                ${titledCell(item.connector_id)}
                ${titledCell(item.owner_team)}
                ${titledPillCell(item.status || "unknown", item.status === "active" ? "" : "warn", "unknown")}
                <td><span class="row-actions">${rowActionButtons(itemId, item)}</span></td>
              </tr>
            `;
          }).join("") || tableEmptyRow(8)}
        </tbody>
      </table>
    </div>
    ${paginationHtml(filtered.length, totalPages)}
  `;
}

function tagsText(tags) {
  return Array.isArray(tags) ? tags.join(", ") : (tags || "-");
}

function renderNetworkList(pageItems, filtered, totalPages) {
  $("moduleList").innerHTML = `
    <div class="native-table-scroll">
      <table class="native-list-table network-native-table">
        <colgroup><col style="width:17%"><col style="width:16%"><col style="width:16%"><col style="width:15%"><col style="width:18%"><col style="width:8%"><col style="width:10%"></colgroup>
        <thead><tr>
          <th>${escapeHtml(t("table.idFile"))}</th><th>${escapeHtml(t("table.name"))}</th><th>${escapeHtml(t("table.cidr"))}</th><th>${escapeHtml(t("table.gateway"))}</th><th>${escapeHtml(t("table.tags"))}</th><th>${escapeHtml(t("table.status"))}</th><th>${escapeHtml(t("table.actions"))}</th>
        </tr></thead>
        <tbody>
          ${pageItems.map((item) => {
            const itemId = item.id || item.file;
            const active = itemId === selectedId ? " active" : "";
            return `
              <tr class="native-list-row${active}" data-row-id="${escapeHtml(itemId)}" role="button" tabindex="0">
                <td><strong>${escapeHtml(itemId)}</strong></td>
                <td>${escapeHtml(item.name || "-")}</td>
                <td>${escapeHtml(item.cidr || "-")}</td>
                <td>${escapeHtml(item.gateway_ip || "-")}</td>
                <td>${escapeHtml(tagsText(item.tags))}</td>
                <td><span class="pill ${item.status === "active" ? "" : "warn"}">${escapeHtml(item.status || "unknown")}</span></td>
                <td><span class="row-actions">${rowActionButtons(itemId)}</span></td>
              </tr>
            `;
          }).join("") || tableEmptyRow(7)}
        </tbody>
      </table>
    </div>
    ${paginationHtml(filtered.length, totalPages)}
  `;
}

function renderHostList(pageItems, filtered, totalPages) {
  $("moduleList").innerHTML = `
    <div class="native-table-scroll">
      <table class="native-list-table host-native-table">
        <colgroup><col style="width:20%"><col style="width:15%"><col style="width:9%"><col style="width:15%"><col style="width:18%"><col style="width:9%"><col style="width:14%"></colgroup>
        <thead><tr>
          <th>${escapeHtml(t("table.idFile"))}</th><th>${escapeHtml(t("table.name"))}</th><th>${escapeHtml(t("table.os"))}</th><th>${escapeHtml(t("table.ip"))}</th><th>${escapeHtml(t("table.network"))}</th><th>${escapeHtml(t("table.status"))}</th><th>${escapeHtml(t("table.actions"))}</th>
        </tr></thead>
        <tbody>
          ${pageItems.map((item) => {
            const itemId = item.id || item.file;
            const active = itemId === selectedId ? " active" : "";
            return `
              <tr class="native-list-row${active}" data-row-id="${escapeHtml(itemId)}" role="button" tabindex="0">
                ${titledCell(itemId)}
                ${titledCell(item.name)}
                ${titledPillCell(item.host_os)}
                ${titledCell(item.host_ip)}
                ${titledCell(item.network_id)}
                ${titledPillCell(item.status || "unknown", item.status === "active" ? "" : "warn", "unknown")}
                <td><span class="row-actions">${rowActionButtons(itemId)}</span></td>
              </tr>
            `;
          }).join("") || tableEmptyRow(7)}
        </tbody>
      </table>
    </div>
    ${paginationHtml(filtered.length, totalPages)}
  `;
}

function renderGenericList(pageItems, filtered, totalPages) {
  if (pageModule === "credential") {
    renderCredentialList(pageItems, filtered, totalPages);
    return;
  }
  $("moduleList").innerHTML = `
    <div class="native-table-scroll">
      <table class="native-list-table generic-native-table">
        <colgroup><col style="width:28%"><col style="width:28%"><col style="width:16%"><col style="width:12%"><col style="width:16%"></colgroup>
        <thead><tr>
          <th>${escapeHtml(t("table.idFile"))}</th><th>${escapeHtml(t("table.name"))}</th><th>${escapeHtml(t("table.type"))}</th><th>${escapeHtml(t("table.status"))}</th><th>${escapeHtml(t("table.actions"))}</th>
        </tr></thead>
        <tbody>
          ${pageItems.map((item) => {
            const itemId = item.id || item.file;
            const active = itemId === selectedId ? " active" : "";
            return `
              <tr class="native-list-row${active}" data-row-id="${escapeHtml(itemId)}" role="button" tabindex="0">
                <td><strong>${escapeHtml(itemId)}</strong></td>
                <td>${assetNameCell(item, itemId)}</td>
                <td><span class="pill muted">${escapeHtml(item.type || pageModule)}</span></td>
                <td><span class="pill ${item.status === "active" ? "" : "warn"}">${escapeHtml(item.status || "unknown")}</span></td>
                <td><span class="row-actions">${rowActionButtons(itemId)}</span></td>
              </tr>
            `;
          }).join("") || tableEmptyRow(5)}
        </tbody>
      </table>
    </div>
    ${paginationHtml(filtered.length, totalPages)}
  `;
}

function renderCredentialList(pageItems, filtered, totalPages) {
  $("moduleList").innerHTML = `
    <div class="native-table-scroll">
      <table class="native-list-table generic-native-table">
        <colgroup><col style="width:42%"><col style="width:20%"><col style="width:16%"><col style="width:22%"></colgroup>
        <thead><tr>
          <th>${escapeHtml(t("table.idFile"))}</th><th>${escapeHtml(t("table.type"))}</th><th>${escapeHtml(t("table.status"))}</th><th>${escapeHtml(t("table.actions"))}</th>
        </tr></thead>
        <tbody>
          ${pageItems.map((item) => {
            const itemId = item.id || item.file;
            const active = itemId === selectedId ? " active" : "";
            return `
              <tr class="native-list-row${active}" data-row-id="${escapeHtml(itemId)}" role="button" tabindex="0">
                <td><strong>${escapeHtml(itemId)}</strong></td>
                <td><span class="pill muted">${escapeHtml(item.type || pageModule)}</span></td>
                <td><span class="pill ${item.status === "active" ? "" : "warn"}">${escapeHtml(item.status || "unknown")}</span></td>
                <td><span class="row-actions">${rowActionButtons(itemId, item)}</span></td>
              </tr>
            `;
          }).join("") || tableEmptyRow(4)}
        </tbody>
      </table>
    </div>
    ${paginationHtml(filtered.length, totalPages)}
  `;
}

function paginationHtml(totalCount, totalPages) {
  return `
    <div class="pagination-bar">
      <span>${escapeHtml(t("pagination.text", { total: totalCount, page: currentPage, pages: totalPages, size: PAGE_SIZE }))}</span>
      <div class="pagination-actions">
        <button class="button tiny ghost" type="button" data-page-action="prev" ${currentPage <= 1 ? "disabled" : ""}>${escapeHtml(t("pagination.prev"))}</button>
        <button class="button tiny ghost" type="button" data-page-action="next" ${currentPage >= totalPages ? "disabled" : ""}>${escapeHtml(t("pagination.next"))}</button>
      </div>
    </div>
  `;
}

function bindListEvents() {
  document.querySelectorAll("#moduleList [data-row-id]").forEach((row) => {
    row.addEventListener("click", () => loadDetail(row.dataset.rowId, "view"));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        loadDetail(row.dataset.rowId, "view");
      }
    });
  });
  document.querySelectorAll("#moduleList [data-action]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const action = button.dataset.action;
      const id = button.dataset.id;
      if (action === "create") createNew();
      if (action === "view" && id) loadDetail(id, "view");
      if (action === "edit" && id) loadDetail(id, "edit");
      if (action === "delete" && id) deleteDetail(id);
      if (action === "deactivate" && id) setCredentialOperationalStatus(id, "disabled");
      if (action === "activate" && id) setCredentialOperationalStatus(id, "active");
      if (action === "test" && id) runAssetAction(id, "test_connection");
      if (action === "discover" && id) runAssetAction(id, "discover_format");
    });
  });
  document.querySelectorAll("#moduleList [data-page-action]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.pageAction === "prev") currentPage -= 1;
      if (button.dataset.pageAction === "next") currentPage += 1;
      renderList();
    });
  });
}

function renderList() {
  const items = registry[pageConfig.registryKey] || [];
  const query = ($("moduleSearch")?.value || "").trim().toLowerCase();
  const filtered = items.filter((item) => itemSearchText(item).includes(query));
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  currentPage = Math.min(Math.max(1, currentPage), totalPages);
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageItems = filtered.slice(start, start + PAGE_SIZE);
  if (pageModule === "asset") {
    renderAssetList(pageItems, filtered, totalPages);
  } else if (pageModule === "host") {
    renderHostList(pageItems, filtered, totalPages);
  } else if (pageModule === "network") {
    renderNetworkList(pageItems, filtered, totalPages);
  } else {
    renderGenericList(pageItems, filtered, totalPages);
  }
  bindListEvents();
}
