"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Execute the real save path with synthetic DOM/API state. Skipping only the
// page bootstrap avoids network access and never opens a user's local Vault.
function form({ saveError = null } = {}) {
  const elements = new Map();
  const calls = [];
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        value: "", textContent: "", dataset: {},
        listeners: {},
        addEventListener(event, listener) { this.listeners[event] = listener; },
        querySelectorAll() { return []; },
      });
    }
    return elements.get(id);
  };
  const context = vm.createContext({
    document: { body: { dataset: { module: "credential" } }, getElementById: element },
    window: { SW_I18N: { t: (key, params = {}) => params.message ? `${key}: ${params.message}` : key } },
    localStorage: { getItem() { return null; }, setItem() {} },
    confirm: () => true,
    fetch: async (url, options) => {
      assert.equal(url, "/api/object");
      const payload = JSON.parse(options.body);
      calls.push(payload);
      return {
        ok: !saveError,
        json: async () => saveError ? { ok: false, error: saveError } : { id: payload.data.credential_id, file: "synthetic.enc.yaml" },
      };
    },
  });
  const root = path.resolve(__dirname, "../..");
  for (const name of ["module-page-utils.js", "module-page-config.js", "module-page-editors.js", "module-page.js"]) {
    let source = fs.readFileSync(path.join(root, "dataasset-ui", name), "utf8");
    if (name === "module-page.js") {
      const bootstrap = source.lastIndexOf("\ninitPage();");
      assert.ok(bootstrap > 0, "page bootstrap marker must exist");
      source = source.slice(0, bootstrap);
    }
    vm.runInContext(source, context, { filename: name });
  }
  vm.runInContext("loadRegistry = async () => {}; loadDetail = async () => {};", context);
  element("credentialTypeInput").value = "aliyun_ram";
  element("detailRawJson").value = 'type: aliyun_ram\naccess_key_secret: "SYNTHETIC_ONLY"\n';
  return { context, element, calls };
}

async function check() {
  // Namespace is a storage grouping, not the YAML type. Existing references
  // must reach the API unchanged, including custom groups and nested names.
  for (const [ref, type] of [
    ["vault://sls/sls-proxy-query", "aliyun_ram"],
    ["vault://db/ai-readonly", "mysql"],
    ["vault://waf/api-readonly", "http_api"],
    ["vault://ssh/readonly-web-01", "ssh"],
    ["vault://custom-group/team/query", "aliyun_ram"],
    ["vault://aliyun_ram/new-query", "aliyun_ram"],
  ]) {
    const { context, element, calls } = form();
    element("credentialIdInput").value = ref;
    element("credentialTypeInput").value = type;
    vm.runInContext(`selectedId = ${JSON.stringify(ref)}; isCreating = false;`, context);
    await context.saveDetail();
    assert.equal(calls.length, 1, `save must accept ${ref} with type ${type}`);
    assert.equal(calls[0].data.credential_id, ref);
    assert.equal(calls[0].original_id, ref);
    assert.ok(calls[0].data.content.startsWith(`type: ${type}\n`));
  }

  // Invalid paths must fail before posting synthetic secrets to the API.
  for (const ref of ["", "sls/query", "vault://sls", "vault://sls/", "vault://sls/../query", "vault://./query", "vault://sls/team//query"]) {
    const { context, element, calls } = form();
    element("credentialIdInput").value = ref;
    await context.saveDetail();
    assert.equal(calls.length, 0, `invalid reference must not be posted: ${ref}`);
    assert.equal(element("detailStatus").textContent, "credential.invalidRef");
  }

  const missingType = form();
  missingType.element("credentialIdInput").value = "vault://sls/query";
  missingType.element("credentialTypeInput").value = "";
  await missingType.context.saveDetail();
  assert.equal(missingType.calls.length, 0);
  assert.equal(missingType.element("detailStatus").textContent, "credential.typeRequired");

  // Initialization failures remain visible without discarding entered values,
  // allowing the user to initialize locally and retry the same form.
  const failed = form({ saveError: "Vault not initialized; initialize the empty local Vault first" });
  failed.element("credentialIdInput").value = "vault://sls/sls-proxy-query";
  await failed.context.saveDetail();
  assert.equal(failed.calls.length, 1);
  assert.ok(failed.element("detailStatus").textContent.includes("Vault not initialized"));
  assert.equal(failed.element("credentialIdInput").value, "vault://sls/sls-proxy-query");
  assert.ok(failed.element("detailRawJson").value.includes("SYNTHETIC_ONLY"));

  // Opening an existing credential must wire the initial value controls, not
  // just controls recreated after changing type; otherwise saves use old YAML.
  const initial = form();
  initial.element("credentialIdInput").value = "vault://sls/sls-proxy-query";
  vm.runInContext('isCreating = false; detailMode = "edit";', initial.context);
  const controls = ["access_key_id", "access_key_secret"].map((key) => {
    const control = initial.element(`credentialValue-${key}`);
    control.dataset.credentialValue = key;
    control.value = `SYNTHETIC_${key}`;
    return control;
  });
  initial.element("credentialValueFields").querySelectorAll = () => controls;
  initial.context.bindCredentialFieldSync();
  for (const control of controls) {
    assert.equal(typeof control.listeners.input, "function");
    assert.equal(typeof control.listeners.change, "function");
    control.listeners.input();
    control.listeners.change();
  }
  await initial.context.saveDetail();
  assert.equal(initial.calls.length, 1);
  assert.ok(initial.calls[0].data.content.includes('access_key_id: "SYNTHETIC_access_key_id"'));
  assert.ok(initial.calls[0].data.content.includes('access_key_secret: "SYNTHETIC_access_key_secret"'));

  // Only untouched automatically suggested IDs follow type selection. User
  // input and existing references remain stable, preserving Connector links.
  for (const creating of [true, false]) {
    const { context, element } = form();
    vm.runInContext(`isCreating = ${creating}; detailMode = "edit";`, context);
    element("credentialIdInput").value = "vault://sls/sls-proxy-query";
    context.bindCredentialFieldSync();
    element("credentialTypeInput").listeners.change();
    assert.equal(element("credentialIdInput").value, "vault://sls/sls-proxy-query");
  }
  const suggested = form();
  vm.runInContext('isCreating = true; detailMode = "edit";', suggested.context);
  suggested.element("detailRawJson").value = "";
  suggested.context.bindCredentialFieldSync();
  suggested.element("credentialTypeInput").listeners.change();
  assert.match(suggested.element("credentialIdInput").value, /^vault:\/\/aliyun_ram\/credential-\d+$/);
  const name = suggested.element("credentialIdInput").value.split("/").pop();
  suggested.element("credentialTypeInput").value = "mysql";
  suggested.element("credentialTypeInput").listeners.change();
  assert.equal(suggested.element("credentialIdInput").value, `vault://mysql/${name}`);
  suggested.element("credentialIdInput").value = "vault://db/team-query";
  suggested.element("credentialTypeInput").value = "postgresql";
  suggested.element("credentialTypeInput").listeners.change();
  assert.equal(suggested.element("credentialIdInput").value, "vault://db/team-query");
  console.log("credential-form: save, initial value sync, invalid references and ID preservation passed");
}

check().catch((error) => { console.error(error); process.exitCode = 1; });
