# SecWeaver Data Source Onboarding Wizard

A lightweight local DataAsset Studio that turns frequent DataAsset onboarding and editing work into forms, with validation suggestions and demo report viewing.

> Note: `dataasset-ui/` is the default open-source UI implementation, not the only possible implementation. Contributors may improve existing pages, add pages, or rewrite the whole UI on top of the same DataAsset/API contracts. See [`docs_dev/25-ui-contribution-guide.md`](../docs_dev/25-ui-contribution-guide.md).

## Start

Run `make quickstart` as described in the [quickstart](../docs_user/00-security-operator-quickstart.md) to prepare Python. Edit `dataasset/` by default. For isolation, copy it to `dataasset_my/` and set `DATAASSET_ROOT` using the [UI walkthrough](../docs_user/11-onboarding-ui-walkthrough.md).

From the project root:

```bash
.venv/bin/python dataasset-ui/server.py
```

Then open:

```text
http://127.0.0.1:8765
```

To use a different port:

```bash
DATAASSET_UI_PORT=8777 .venv/bin/python dataasset-ui/server.py
```

To switch to a private real-asset directory such as `dataasset_my/`:

```bash
DATAASSET_ROOT=dataasset_my DATAASSET_UI_PORT=8777 .venv/bin/python dataasset-ui/server.py
```

If `DATAASSET_ROOT` is not set, the UI reads the cleaned release directory
`dataasset/`.

The enterprise workspace has two separate entries: **secweaver-agent → One-command installation** installs collectors; **Agent configuration** provides query AK/SK. The local UI retains a development/compatibility preview of installation templates. Copy production commands from the enterprise workspace.

For development previews, explicitly set the variables below using platform-provided values; these examples are placeholders:

```bash
SECWEAVER_AGENT_BOOTSTRAP_URL=https://updates.example.com/secweaver-agent/install.sh \
SECWEAVER_AGENT_VERSION=YOUR_AGENT_VERSION \
SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID \
SECWEAVER_LICENSE_SERVER_URL=https://agent-gateway.example.com \
SECWEAVER_LOGTAIL_ENROLLMENT_ID=YOUR_ALIYUN_MACHINE_GROUP_ID \
SECWEAVER_LOGTAIL_ALIUID=1234567890123456 \
.venv/bin/python dataasset-ui/server.py
```

| Purpose | Endpoint source |
|---|---|
| SaaS SLS queries | `https://sls-proxy.id-net.cn:30443`; there is currently no independent fallback. See [SLS Proxy onboarding](../docs_user/30-sls-proxy-onboarding.md) |
| Agent installation and authorization | Use the workspace-issued command and the Agent Gateway endpoint embedded in Bootstrap; the public Agent configuration example uses `https://agent-gateway.id-net.cn:30443` |

`SECWEAVER_LICENSE_SERVER_URL` is the authorization endpoint in the install preview, not the local query Connector endpoint. The development preview retains a historical default; explicitly supply the platform-provided authorization endpoint when checking a template. Do not infer production failover settings from the preview. Production endpoints require trusted HTTPS.

The platform supplies enterprise and machine-group identifiers. Proxy AK/SK are query credentials; the local UI stores user-created credential references, does not issue keys, and does not render them into install commands. Copying is disabled when required preview parameters are missing or the enterprise ID, enrollment ID, or HTTPS URL is invalid. The Alibaba Cloud UID is read-only and is not added to client install arguments.

## Current capabilities

### Data source onboarding

- Open `onboarding.html` from the top navigation
- Keep a development/compatibility preview of Quick Host Agent Install; production install commands come from enterprise workspace → secweaver-agent → One-command installation
- Fill common source fields in a form, then generate an ops-owned `data_sources` config
- Preview generated connector, asset, and query template output through the same `secweaver asset apply --dry-run` logic used by CLI
- Write generated files to `dataasset/connectors/`, `dataasset/assets/`, and `dataasset/query-templates/templates.json`
- Keep advanced control by editing the config JSON before preview/apply
- Form fields come from the Connector Catalog and validation cross-checks required fields against Connector Schema; AWS S3, Azure, GCP, Tencent CLS, Huawei LTS, and Splunk expose their required connection fields directly
- Refresh connector registry/catalog metadata when loading `/api/onboarding/meta?refresh=1`; call `POST /api/connectors/reload` to refresh runtime connector metadata explicitly

### Asset management

- Read `dataasset/assets/*.json` asset list
- Read `dataasset/hosts/*.json` for coverage.hosts source-IP matching and topology display
- Read `dataasset/connectors/*.json` for `connector_id` dropdown
- Read `dataasset/query-templates/templates.json` for `query_template_ids` selection
- Edit and save individual asset JSON files

### Host management

- Query and search `dataasset/hosts/*.json`
- Add hosts
- Edit host basics, network addresses, roles, and tags
- Save to `dataasset/hosts/<host_id>.json`
- Delete host JSON files

### Validation

- JSON object saves (including the legacy `/api/asset` and `/api/host` routes) check the selected root's Schema before replacing a file. Active objects additionally run the registry's reference and go-live checks; active Bundles/Assets affected by an Asset or Connector edit are checked as well. Invalid saves return HTTP 400 and leave the previous file intact.
- Studio JSON saves/deletes and CLI `asset init/apply/rollback/promote` serialize writes using the ignored `.dataasset-write.lock.tmp` in the selected `DATAASSET_ROOT`. A competing edit waits up to 10 seconds and then fails; each JSON file is replaced atomically. A multi-file onboarding batch is still not a transaction.
- Save-time checks do not replace full-root validation or live connectivity testing. After editing related objects, run the strict gate and the appropriate connector test.
- Prefer `.venv/bin/python` at the project root to run `src/dataasset/validate.py`
- Fall back to the Python that started the UI server if `.venv/bin/python` is missing
- Run `src/dataasset/validate.py`
- Run `validate.py --sync-catalog`
- Support `validate.py --json` for structured gate results consumed by UI/CI
- Support `validate.py --strict` to treat warnings as blocking
- Support `validate.py --only-active` to check active-object go-live gates only
- UI “Strict gate” button is equivalent to `--json --strict --only-active`
- UI “Runtime Readiness” runs `--json --runtime-ready` and separately shows
  registry validation, Bundle graph state, and blockers; it never decrypts credentials or contacts a backend
- Convert `ERROR/WARN` into simple operational fix-suggestion cards
- Active assets use stricter go-live gates: templates, coverage.hosts, retention, owner, required evidence fields, and correlation-matrix Join reachability
- Credential lifecycle status accepts only `active` and `disabled`; unknown values fail instead of being treated as usable

### Demo reports

- One-click run: `python3 src/secweaver.py demo all`
- Read sample output from `examples/reports/*.json`
- Show key conclusions from completeness, alert confirmation, traceability, and risk-identification demos
- Display verdict, confidence, summary, data gaps, and output file paths

## SLS Proxy Project Selection

On Linux/macOS with Python 3.10+, select `sls_proxy` in the onboarding form and fill the authorized `project` and `logstore` pair. Project is optional: empty or omitted uses the server default. Preview the generated Connector before applying; verify `config.project` and `config.logstore`, then test a known event as described in the [SLS Proxy guide](../docs_user/30-sls-proxy-onboarding.md).

Explicit Project selection requires the updated client SDK adapter and Go Proxy 0.6.0-rc.14/schema 10 or later, an operator-configured Project route, and an enterprise resource grant. Client selection cannot create resources or grant access. Keep the Proxy endpoint unchanged; do not add a Project hostname prefix, `region`, or `enterprise_id`. Do not remove Project to bypass an authorization or compatibility error. Direct SLS retains its existing Project behavior.

## Design constraints

- Server listens on `127.0.0.1` only, for local configuration editing.
- Read/write only within the current DataAsset root: `dataasset/` by default, or the directory selected through `DATAASSET_ROOT`.
- Asset and host forms are supported today; connector, bundle, and network forms can be added later.
- Demo report viewing is supported; correlation visualization can be enhanced later.
- Review the JSON preview on the right before saving.
- Review changes via Git diff after fixes.

## UI Contribution and Rewrite

Contributors can work at three levels:

- **Incremental UI edits**: HTML/JS/CSS, forms, error hints, and i18n copy.
- **New UI modules**: connector, bundle, network, correlation, scenario, or fetch-plan pages wired through `shared-nav.js`.
- **Full UI rewrite**: use a new frontend stack while keeping `DATAASSET_ROOT`, the DataAsset directory layout, `asset apply`, `validate.py --json/--diagnose`, and `credentials_ref` contracts.

When extending backend APIs, prefer reusing `src/secweaver.py` and `src/dataasset/validate.py` from `server.py`. Do not implement a second onboarding or validation engine in the UI layer.
Keep `server.py` focused on HTTP routes; put onboarding, credentials, registry, topology, and validation behavior in `dataasset_ui_services/`.

Frontend module pages are split by responsibility:

| File | Responsibility |
|---|---|
| `module-page-config.js` | Shared module definitions, default templates, asset/host/credential enum values |
| `module-page-utils.js` | DOM helpers, API wrapper, detail summary, modal helpers, JSON/YAML sync helpers |
| `module-page-list.js` | Registry counters, searchable tables, pagination, row actions |
| `module-page-editors.js` | Asset, host, credential, correlation, and scenario structured editors |
| `module-page.js` | Page state, detail load/save/delete, asset actions, and page initialization |

Styles are also split by responsibility. `style.css` stays as the stable entrypoint for HTML pages and imports:

| File | Responsibility |
|---|---|
| `styles/00-base.css` | Design tokens, reset, typography, topbar, title bar, shared shell |
| `styles/01-layout-nav.css` | Workbench grid, sidebar, panels, resource navigation |
| `styles/02-dashboard-topology.css` | Dashboard cards and topology visualization |
| `styles/03-forms-lists.css` | Status cards, forms, tables, registry lists, pagination |
| `styles/04-detail-editor.css` | Detail modal, buttons, pills, summaries, structured editors |
| `styles/05-correlation-validation.css` | Correlation explanation, advice/report cards, validation output |
| `styles/06-onboarding.css` | Onboarding flow, vendor catalog, connector catalog, preview panels |
| `styles/07-utilities-responsive.css` | Empty states, utilities, responsive overrides |

## Recommended workflow

```text
Open Data Source Onboarding
  → Fill source basics / connection / parser / coverage / template params
  → Generate config
  → Preview connector / asset / template
  → Apply to write DataAsset files
  → Run validation
  → Fix P0/P1 per suggestions
  → Generate demo report
  → test_connector.py connectivity test
  → Git diff review
```

## Real data and release boundaries

ES verifies certificates by default and supports private CAs. Incomplete queries appear
in fetch summaries and reports. Generated evidence IDs now use v2; sensitive source-log
fields still require explicit masking. See [release, compatibility, migration and masking guidance](../docs_user/community-release-and-data-safety.md).

## External ES Operator

ES deployment is optional and maintained in the independent private
`secweaver-es-operator` project. Before starting Studio, configure trusted local
paths in the server environment (never via an HTTP request):

```bash
SECWEAVER_PORTABLE_ROOT=/path/to/secweaver-es-operator \
SECWEAVER_PORTABLE_RUNTIME=/path/to/operator-runtime make ui
```

`SECWEAVER_PORTABLE_COMMAND` optionally selects a specific executable or launcher;
otherwise Studio uses the project's launcher, then `bin/secweaver-portable`.
Runtime defaults to `<operator-root>/runtime`. Paths may be absolute or relative
to the Community repository root. Studio forwards its selected `DATAASSET_ROOT`
to the CLI. Without explicit settings it retains the old in-repository lookup;
when the Operator is absent, deployment endpoints report unavailable while other
Studio functions remain usable. Requires a compatible Operator CLI and its
runtime prerequisites; this does not install or start ES automatically. Verify
with `/api/portable/status` (`doctor` before initialization, `status` afterwards).

The enrollment form targets enterprise/platform/architecture installer profiles,
with Filebeat, Fluent Bit or SecWeaver Shipper selection (Operator validates platform
support). Revoke uses an enrollment key from `secweaver-portable list-enrollments`,
not a host name; close affects only the selected profile's future ES bootstrap.
Neither operation revokes Agent Gateway identities/tokens. Configure
`SECWEAVER_AGENT_CONTROL_URL` (HTTPS origin) and `SECWEAVER_AGENT_ENROLLMENT_TOKEN`
in Studio's startup environment; do not store tokens in frontend files. Agent
update signing may additionally require `SECWEAVER_AGENT_UPDATE_PUBLIC_KEY`.
Operator 0.3.20's CLI is the verified baseline. After changing this adapter or
upgrading Operator, run (from Community root):

```bash
SECWEAVER_OPERATOR_TEST_COMMAND=/absolute/path/secweaver-es-operator/bin/secweaver-portable make test-operator-contract
```

This read-only parser contract check requires Python and a native Operator binary;
it never initializes OpenSearch or issues credentials. Real registration, shipping
and revocation still require a disposable deployment acceptance test.
