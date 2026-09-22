# Changelog

## Unreleased

- Fixed direct shared-Skill imports by deferring the SLS TLS helper's PEP 604
  annotation evaluation, preventing an import-time `TypeError` before Skill
  validation runs. The documented runtime remains Python 3.10+.

- `make setup` and `make quickstart` now stop before dependency installation when
  the selected Python interpreter or existing virtual environment is below 3.10,
  with a remediation message for selecting a newer interpreter.

- Document the Operator repository's checked-in Community contract lock and the
  exact-clean-checkout workflow used by its required lifecycle CI.

- Documentation checks now validate same-page and cross-file Markdown anchors,
  including explicit IDs and duplicate headings. Missing bilingual Skill
  references were added, Community data-foundation boundaries no longer expose
  internal delivery names, and the English host-persistence configuration now
  matches the documented Linux defaults.

- Offline showcase runs now write readable per-case Markdown and a batch summary
  by default alongside JSON, including when `--json` formats console output.
  Report write failures fail the case; reruns replace both artifacts. Agent-host
  requests include evidence review and final readable reports without a follow-up
  prompt. Automatic CLI reports are labeled as structured results, not AI reviews.

- Added a single catalog entry for every top-level Skill, including workflow kind,
  CLI visibility, documentation, and optional output Schema. Deterministic Skill
  outputs now have domain Schemas composed with the shared v1 envelope, and the
  committed offline reports are regenerated and contract-tested. Both prompt-analysis
  fetch fixtures now follow the v1 envelope and its golden report is Schema-checked.
- Fixed `secweaver skill` forwarding when wrapper or Skill options precede the
  `--` separator; documented examples with mixed options now run as shown.
- Aligned the shared output Schema with optional `completeness_precheck: null`
  and added an offline evidence-fetch-to-risk handoff contract test.
- `evidence-fetch -i` now replays completed offline evidence without silently
  refetching or discarding its original raw/retained counts; explicit `--fetch`
  still refreshes from configured connectors.
- Skill runtime outputs now carry a backward-compatible `contract_version: 1.0`
  envelope and reject explicit version/Skill conflicts or malformed shared evidence
  containers. Fetch summaries expose a common conclusion boundary for failed,
  partial, truncated, unqueried, empty, and planning-only evidence.
- Log-format discovery apply now accepts only its matching discovery Asset, stages
  and Schema-validates all affected objects before writing, and shares the
  DataAsset registry lock with Studio and CLI writers.
- Connector HTTP transport now rejects remote cleartext endpoints, redirects, and
  disabled TLS verification before credentials are sent; HTTP API and Splunk gain
  private-CA support. Invalid Vault references become structured readiness blockers,
  relative CA paths cannot escape the selected registry, and onboarding profiles now
  round-trip through Connector Schema before CLI writes.
- DataAsset now requires verified TLS for every Elasticsearch Connector, folds
  object validation failures into Bundle runtime readiness, exposes readiness
  in Studio, validates credential lifecycle states, closes known Host nested
  objects, and provides a preview-first shared-contract synchronization command.
- DataAsset validation adds a static `--runtime-ready` Bundle execution gate,
  explicit multi-root `shared` / `override` / `root_owned` policy enforcement,
  and closed Asset/Bundle/Host/Network top-level schemas with an `extensions`
  escape hatch. Live connectivity remains a separate Skill check.
- Removed the remaining Elasticsearch Agent Health Asset, Connector, query
  templates, and evidence contract from the intelligent-agent registry. Collection
  and index configuration remain available for operational diagnostics.
- Consolidated DataAsset onboarding documentation: the complete lifecycle now lives in
  `docs_user/03-configure-data-sources`, field discovery and normalization in `20`,
  validation triage in `09`, and `16` is a short routing FAQ.
- Agent 0.3.31 updates packaged documentation links after the historical assessment
  move. Runtime behavior, configuration, and schemas are unchanged.
- Moved dated developer assessments 10, 11, 16, 22, and 28 into
  `docs_dev/history/`, added a bilingual history index, and relabeled inbound
  links so historical scores and TODOs are not presented as current behavior.
- Agent 0.3.30 replaces live-environment addresses in packaged test fixtures with
  RFC 5737 documentation addresses. Runtime behavior and schemas are unchanged.
- Community release scanning now rejects known internal acceptance networks across
  public docs, Skills, examples, Attack Lab sources, and test fixtures. Public
  examples use documentation addresses; Attack Lab uses an isolated synthetic subnet.
  Risk and trace report metadata now uses repository-relative paths, and CI/export
  rerun release scanning after demo reports are regenerated. The scanner also rejects
  common local checkout paths, and the Agent P0 verification helper now resolves its
  source directory at runtime instead of embedding a contributor workspace path.
- Risk identification uses source event time and replay-resistant native evidence
  IDs (v3), removes duplicate source events before thresholds, and exposes a
  duplicate-reference audit. Query summaries reconcile pre-fetch gaps and use
  explicit truncation metadata rather than merged row totals.
- Exec detection and persistence policy distinguish probes, backups and inbound
  transfer receivers from execution/writes/exfiltration candidates. Whitelist
  downgrades synchronize alert delivery and preserve mandatory policy alerts.

- Host-risk S5 bundles now query their declared assets without a D1 bootstrap
  dependency; empty trace bootstraps no longer suppress bundle fallback.
  Fetch reports distinguish registry readiness, observed evidence and unqueried
  assets. Connectivity checks separate successful connections from data presence.
- Empty alert batches preserve fetch statistics and independent gateway scanning;
  discovery CLI eligibility errors now give a concise argument error. Bilingual
  skills clarify snapshot evidence and deterministic detector coverage limits.
- Agent 0.3.29 deduplicates Linux container PIDs across cgroup controllers before
  counting and limiting the PID list. No schema change, package publication or
  deployed-Agent upgrade is implied by this source change.

- Contributor documentation now distinguishes Python setup from full CI toolchain
  prerequisites, consistently uses the virtual-environment interpreter, and runs
  UI regressions with unittest. Prompt-only skills have a separate contribution,
  discovery and evidence-based evaluation workflow alongside deterministic CLI skills.

- Align bilingual skill references with current deterministic behavior: neutral
  DNS/network context, attack-type-specific success evidence and matrix windows,
  and final command-risk decisions after policy and whitelist processing.
  Command examples now include reproducible parent-engine inputs and outputs.
- Correct credential-script working directories, connector-test commands and
  discovery mapping examples; clarify read-only derived correlation fields.
  Separate maintainer release navigation from live-data guidance and make
  Community deployment scope explicit in the mode tables.
- Agent 0.3.28 updates packaged README role navigation; no runtime behavior changes.
  This source version change does not imply a new package was built or published.

- Community documentation separates concepts, configuration references, skill
  selection, operating workflows, and maintainer release acceptance. English
  operations, detection labels, and standalone-update instructions now include
  actionable steps; private security reports can be sent to 415451@qq.com.
- Field-reference generation uses the public asset Schema as its coverage source,
  includes all 24 current asset types, and rejects unknown specification types.
- Corrected TLS failover, JSON policy maintenance, masking, and Community skill
  scope descriptions. Historical lab narratives are not release evidence; the
  unversioned Agent P0 report is excluded from Community archives.
- Agent 0.3.27 updates packaged ES navigation and standalone update examples;
  canonical versioning and signed manifests replace stale version overrides.
  The standalone sample disables managed server policy only for that mode and
  requires a stable device identity; managed deployments retain server policy.

- Community onboarding accepts optional SLS Proxy Project names consistently in
  schema and runtime. Proxy probes and signed SDK queries now verify TLS by
  default, support asset-root-relative CA bundles, reject ambiguous flags and
  stop on certificate failures instead of falling back.
- Completeness matches explicit target host sets as full/partial/none without
  requiring an extra zone declaration or overclaiming multi-host coverage.
- Trace reports retain DNS/session joins as neutral network_activity with no
  automatic ATT&CK label or execution proof. Generic egress no longer implies
  exfiltration/T1048.003; entry-point merges retain the selected candidate's note.

- Agent 0.3.26 removes operational-health asset onboarding from the bilingual
  public guides. Collector health telemetry remains an operations concern,
  outside the AI agent's DataAsset registry and investigation bundles.
- Community release preparation: CI demo output now uses a temporary directory,
  and published report examples use relative paths enforced by the release scan.
- Elasticsearch discovery and fetch verify TLS by default, reject non-boolean
  verification flags, and reject fetch redirects. Studio forwards the policy and
  its browser wizard requires verification. Explicit boolean false remains limited
  to dedicated discovery diagnostics; live Connector fetch and activation require true.
- ES timeout, early termination, failed shards and result limits now survive as
  query-integrity metadata, including cached queries and standalone evidence-fetch.
  Reports and completeness prechecks expose gaps without discarding positive evidence.
- Generated evidence IDs use source-scoped v2 identities independent of result order;
  regenerate reports using old generated references. Explicit IDs remain unchanged.
- SLS-to-ES migration now requires explicit source/config/mapping arguments and rejects
  unknown mappings. Added bilingual release, TLS, masking and migration guidance.

- Unified connector plugin discovery, CLI checks and runtime execution through
  `src/dataasset/plugin_contract.py`: required raw manifest fields, contained
  entrypoints, a shared 30-second timeout and whole-response event/meta validation.
  Static `--no-exec` checks still validate executable paths; malformed rows fail
  instead of being silently discarded.
- Separated scenario evidence planning/fetching from shared Skill input adapters
  and cross-Skill execution in `_shared/skill_runtime`, preserving historical
  CLI/import entries. All four `prepare.py --run-skill` modes now assess, and the
  default completeness/trace bundle is the shipped `bundle-incident-trace-default`.

- Agent 0.3.24 release archives now include an `elasticsearch/` directory with
  the standalone create-only ES initializer, its index template, Filebeat
  example, and bilingual package instructions. The helper remains independent
  of the private ES Operator and server source.
- Agent 0.3.25 keeps the public Agent doctor focused on SLS Logtail identity
  checks and publishes self-managed ES guidance through the standalone
  `elasticsearch/` package. Private ES Operator diagnostics and delivery packages
  remain in the internal release pipeline.

## Unreleased: DataAsset SLS Proxy Project Selection

- SLS Proxy Connectors and onboarding forms now accept optional `project` with `logstore`. Requests sign the selector without changing the Proxy host; empty Project retains default-project compatibility. Explicit selection requires Go Proxy 0.6.0-rc.14 / schema 10 and enterprise resource authorization. Direct SLS connectors are unchanged.

All notable changes to the SecWeaver Community edition are documented in this file.

<!-- private-delivery: Historical server records are available only in the internal source checkout. -->
Private server implementation and delivery history is maintained separately in
the internal source checkout. Each private module keeps its own changelog next
to the implementation, and those module paths are excluded from Community
archives. Client connectors, Skills, DataAsset, and open-source Agent changes
remain here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Agent 0.3.22: Linux token-only installation now obtains enterprise and update
  device IDs from one successful enrollment. Preserve default CLI output, add
  installer identity output, reject conflicting IDs, and explicitly preserve
  registration state/key paths. Add TLS retry and Bash installation regressions;
  existing 0.3.19 packages must not be overwritten.

- Corrected bilingual source-onboarding JSON examples and added Schema/template
  regressions. Real-data guides now consistently select a private local asset root,
  distinguish administrator-prepared SaaS from self-operated Community clients,
  and explain client OS limits and script-versus-AI report locations. Shortened the
  source guide by linking to Agent installation/upgrade manuals. Documented the
  ES wizard's current certificate-verification limitation and provided a draft,
  explicit-TLS Agent ES DataAsset configuration for the manual onboarding path.
- Aligned public onboarding documentation with the offline-first experience and
  SaaS client responsibilities. Updated Attack Lab collection to the unified Agent
  and restricted log exports without truncation, corrected CI guidance, and added
  executable documentation regressions. Agent 0.3.20 reserves a new package identity
  for the updated bilingual engineering/health documentation; runtime and parser
  contracts are unchanged, and no new Agent binaries are published by this change.
- Fixed invalid UTF-8 in the README architecture SVG and adjusted labels to
  prevent text overlap when the diagram is rendered.

### Added

- Added a public standalone Agent-to-Elasticsearch integration with create-only
  template initialization, a fresh-install Linux Agent script, six-log Filebeat
  routing, least-privilege setup guidance, and read-only ingestion verification.
  SaaS SLS Proxy remains the recommended path; ES Operator remains private.
- Added a credential-free offline AI Showcase with five routed cases covering a
  confirmed WebShell attack, a false positive, WebShell-to-SSH lateral movement,
  reverse-shell risk, and a blocking evidence gap. The new `offline-showcase`
  Skill lets Codex and other supported hosts run the default case from the single
  prompt `Run the SecWeaver offline showcase.`

### Changed

- Offline Showcase now explicitly delegates evidence analysis and final Markdown
  reporting to the selected analysis Skill. Attack-chain and host-risk cases use
  `traceability-analysis` and `risk-identification`; runner verification alone
  is not considered a completed AI investigation.
- `make quickstart` now creates thin local adapters for Codex, Cursor, Claude
  Code, OpenClaw, and WorkBuddy after dependency setup, DataAsset validation,
  and offline demos. `make ai-setup HOST=all` provides the same idempotent
  all-host setup while preserving the refusal to overwrite user-owned files.
- Removed the private-only `portable-build` and `portable-check` targets, their
  ES Operator variables, and the Portable dependency from public `make ci`.
  Portable build and package gates now belong exclusively to the internal
  delivery pipeline that contains `src/es-operator`.
- Clarified Community release boundaries: `src/server`, `src/es-operator`, and
  `src/secweaver-server` are private delivery modules and are excluded from
  Community archives, CI, and SBOM generation. Public Agent clients connect to
  the hosted Agent Gateway or use the packaged self-managed Elasticsearch
  integration without requiring those server sources.

## [0.3.21] - 2026-09-05

### Added

- Open-sourced the Attack Lab (`attack_test/`): four reproducible attack-chain
  environments (SQLi + path traversal with WAF alert confirmation, command
  injection with memory WebShell C2, fileless data exfiltration, and web
  compromise to SSH lateral movement) with deployment, attack-simulation, and
  ownership-aware scoped-cleanup scripts.
- Added fail-closed lab guardrails shared by every script: an explicit
  acknowledgement environment variable, a deployment-host marker requirement
  (container or `/etc/secweaver-lab-host`), an attack-target allowlist, and
  automatic backup of every mutated system configuration into a single
  restore-on-teardown directory.
- Added `teardown-lab.sh` to stop lab services, remove lab users/applications/
  memory-WebShell remnants, and restore backed-up nginx, SSH, MariaDB, and
  SELinux configuration without deleting pre-existing users or cron jobs.
- Added Chinese/English case narratives (`Case1`–`Case4`) replacing the
  internal-only PDF reports, and an Attack Lab entry in both READMEs.

### Fixed

- The changelog version parser now only accepts pure SemVer release headings,
  so independently versioned component entries (for example ES Operator) can
  no longer shadow the Community release identity.
- Replaced demo credentials that matched real AWS access-key formats with
  unambiguous non-functional placeholders, and scrubbed internal hostnames,
  WAF domains, and attacker IPs from all public Attack Lab sources.
- Made archive-membership tests source-checkout aware so the history-free
  Community archive can complete its own verification suite, and added the
  public-document command checker to the exact extracted-archive gates.
- Wired `WISID_COOKIE` into every WAF attack variant and documented that the
  WAF hostname must be present in the explicit target allowlist.
- Made Attack Lab cleanup ownership-aware: it restores recorded file absence,
  preserves pre-existing users and cron jobs, removes only marked persistence,
  and rolls back only firewall rules introduced by the lab.
- Aligned the shared Case 1/Case 3 MariaDB schemas and removed stale WAF attack
  references to the undeployed `shop_db`, so the documented co-hosted deployment
  order and both attack variants use the same lab database.

## [0.3.20] - 2026-09-02

### Added

- Added `make ai-setup HOST=codex|cursor|claude|openclaw|workbuddy` to generate
  non-destructive repository-local host adapters. Every adapter routes to the
  canonical `src/skills/` tree instead of copying Skill implementations, and
  existing user-owned host configuration is never overwritten.
- Added English and Chinese screen-by-screen host setup, verification prompts,
  expected results, troubleshooting, and an explicit local-project boundary for
  the WorkBuddy adapter.

## [0.3.19] - 2026-09-01

### Changed

- Unified the SecWeaver Community release identity on `0.3.19` across package
  metadata, CLI output, the source SBOM, and the release changelog. The bundled
  SecWeaver Agent retains its independent `0.3.19` component version.
- The elevated Windows service installer now enables successful Audit Process
  Creation by locale-independent subcategory GUID and includes command-line data
  in Security 4688 events. Installation aborts before stopping an existing Agent
  if either policy cannot be configured; uninstall does not revert host audit policy.

## [0.3.18] - 2026-09-01

### Fixed

- Fixed the Windows service callback ABI so `secweaver-agent.exe` no longer panics during
  package commands or service startup on Windows Server 2019 and later. The callback adapters
  provide the uintptr-sized return and parameters required by Go's Windows syscall trampoline.

### Added

- SecWeaver Agent now emits a default private operations-health JSONL stream with jittered
  five-minute snapshots and immediate lifecycle/module/license/audit transition records.
  The stream reuses the 0600 rotating writer and disk budget, includes persistence failure/recovery
  and low-cost Go runtime counters, and ES/Filebeat/native shipper/Fluent Bit routing plus ES and
  SLS DataAssets are included.

- Clarified public ES/OpenSearch and SaaS SLS Proxy onboarding. Public examples now document the
  production Proxy primary/fallback endpoints, the built-in connector list includes `sls_proxy`,
  and host-state documentation no longer points to the excluded `dataasset_es/` deployment catalog.
- Added an English standalone Agent update-server guide and updated English
  documentation links to use it; the existing Chinese detailed guide remains available.
- Public deployment documentation now contains only capability boundaries and how to
  obtain the separately delivered Portable/Operator packages. Private installer commands
  and runbooks stay under `docs_my`, while the README Quick Start uses only archived CLI,
  DataAsset, demo, and Agent paths. `check_public_doc_commands.py` is part of `make docs-check`
  and rejects unmarked private-source command references in public Markdown.
- Added deterministic third-party notices and a CycloneDX 1.6 source SBOM for
  declared Python and Agent Go dependencies, plus a CI freshness gate.
- Public DataAsset validation now treats matching credential examples as the
  expected secret-free state, and the S1/S2 correlation metadata declares every
  Join used by its recommended chain.

- SecWeaver Agent now supports a Docker container workload profile. Every Linux
  release archive carries a non-root, read-only Dockerfile, Compose profile,
  and namespace-scoped configuration for process and state snapshots. The
  profile persists its device identity in a named volume, uses a read-only host
  machine-ID fingerprint component, disables in-container self-update, and
  rejects auditd-backed listener execution and host-persistence modules rather
  than claiming host-security coverage.
- Traceability asset-list fetches now perform bounded two-phase lateral
  discovery. They query SSH authentication by each source host, derive accepted
  target hosts, and then fetch target-side authentication, execution, network,
  and file evidence. `data_access.second_hop_impact_fetch` records the discovery
  tasks, target tasks, and resolved target hosts for auditability.
- D1 and S4 live fetches now provide bounded fallback queries when indexed
  attacker-IP or upstream-target lookups fail or return no rows. Gateway access
  can fall back to the active investigation window without widening D2 host
  queries, while WAF candidates are constrained by correlated source IP or by
  target, gateway host, and normalized path. The fallback reason, templates,
  candidate count, and matched count are exposed in `data_access` metadata.
- SecWeaver Agent now enforces a host-wide disk budget for Agent-managed rotating
  collector and update logs. The default policy reserves 512 MiB of filesystem
  free space, caps managed output at 2 GiB, checks every 30 seconds, prunes excess
  numeric backups, and stops snapshot output before standard and realtime evidence.
  The strict configuration schema exposes `disk_budget` and all packaged Linux and
  Windows examples carry the production defaults.
- Agent Prometheus telemetry now covers authorization checks and the shared Linux
  audit transport, including reader availability and failures, processed lines,
  subscriber backlog, retired subscribers, and evidence-overwrite counts. Audit
  reader and overflow transitions also appear in bounded status diagnostics.
- SecWeaver Agent upgrades now verify Ed25519-signed manifests and binaries.
  Linux and Windows installations retain the previous binary until the new version
  passes module-health probation, with automatic rollback on startup, restart,
  version-mismatch, or module-health failure.
- Agent rollout identity now fails closed on the immutable enrolled `device_id` instead
  of defaulting to hostname. Update safety adds strict SemVer 2.0.0 ordering, stale-lock
  recovery, bounded backup retention, pre-download disk-space checks, signed public-key
  rotation and revocation, and signed emergency-stop manifests.
- Managed Agent updates now fail closed unless the control plane grants a sufficiently
  long-lived upgrade lease, use bounded exponential backoff with stable jitter and HTTP
  `Retry-After`, and report successful activation without leaving systemd in a transient
  failed state. Native Linux systemd and Windows SCM CI jobs cover healthy upgrade and
  health-failure rollback paths.
- Agent update downloads now stream into bounded temporary files with cancellation, disk
  preflight, fsync-backed replacement, retry classification, and manifest anti-replay state.
  Signed manifests can authorize version-scoped emergency rollback, rotate or revoke signing
  keys, and optionally require Windows Authenticode publisher certificates.
- Post-update probation now requires healthy modules and fresh collector output. A changed or
  paused server policy, expired lease, shutdown, stalled output, restart, or activation failure
  cancels or rolls back the update instead of leaving an unobserved partial deployment.

- Historical behavior (superseded by the Unreleased TLS default fix): ES connectors
  defaulted to `tls_verify: false` for private HTTPS endpoints, while
  production deployments can explicitly enable verification with `tls_verify: true`
  and a CA file or system trust store; live-fetch metadata marks unverified connections.
- Linux `audit-port-execmon` now supports an embedded eBPF CO-RE process-tree backend
  on amd64 and arm64. `auto` mode prefers bounded fork/exec/exit tracking in kernel
  maps and falls back to the existing audit backend when BTF, tracepoints, policy,
  or verifier requirements are unavailable; preflight and doctor report the actual
  capability and fallback conditions.
- SecWeaver Agent can expose an optional loopback Prometheus endpoint for Agent
  identity, uptime, module health, restart counts, process IDs, and consecutive
  failures. Metrics configuration is covered by the strict JSON Schema and is
  available through both Linux and Windows service entrypoints.
- Added a cross-platform native `secweaver-shipper` for Linux amd64/arm64/loong64
  and Windows amd64/arm64. It tails Agent JSON Lines with rotation-safe file
  identities, stores cursors and a bounded 2 GiB queue in bbolt, uses authenticated
  TLS Bulk ingestion, and acknowledges deterministic document IDs only after ES
  accepts them.

### Changed

- SecWeaver Agent `0.3.13` hardens cross-distribution netstat listener
  discovery. The parser locates the first address-shaped field before the
  case-insensitive LISTEN token and searches subsequent columns for PID/program
  ownership instead of relying on fixed offsets. It accepts standard net-tools,
  BusyBox-style wildcard addresses, bracketed and unbracketed IPv6, missing PID
  columns, extra vendor columns, and process labels containing spaces or colons.
  Raw TCP LISTEN, parsed, and rejected row counts are tracked per invocation;
  any rejected row forces bounded procfs completion and emits a diagnostic
  instead of silently accepting a partial result.
- SecWeaver Agent `0.3.12` changes listener reconciliation to a netstat-first
  path. A successful `netstat -tlnp` result with complete PID ownership no
  longer builds a global socket-inode map; `/proc/<pid>/fd` is scanned only
  when netstat fails, returns no listeners, or omits a relevant PID. The
  fallback reads 128 FDs per batch, pauses between batches, caps each round at
  32,768 FDs, and never starts a second full scan for individual inode misses.
  The production listener reconciliation interval remains five minutes.
- SecWeaver Agent `0.3.11` makes `doctor` transport-aware. Product-owned ES
  Filebeat, Fluent Bit, and native shipper configurations take precedence when
  Logtail also exists on the host; ES diagnostics validate the shipper service,
  configuration, and enrollment credential file, while SLS-only
  `/etc/ilogtail/user_defined_id` and AliUid checks no longer fail ES hosts.
- SecWeaver Agent `0.3.10` changes the default non-eBPF fallback from historical
  per-PID/PPID audit expansion to a bounded audit backend. It installs a fixed
  exec/clone rule set per architecture, propagates listener ownership in userspace,
  filters unrelated host events before accumulation, and retains `audit_pid` only
  as an explicit compatibility backend.

- Moved Portable laptop, OpenSearch Linux server, and SLS Proxy Operator manuals
  to the private `docs_my/` delivery boundary; Community documentation now points
  to the separately delivered package instead of linking to unavailable files.
- Added recursive export attributes for private roots so nested files remain
  excluded from Git archives, not only the directory entries.

- `make open-source-export` now requires a clean Git worktree and verifies the
  exact history-free archive in a temporary extraction (release scan, links,
  strict validation, policy sync, tests, demos, and SBOM) before publishing it.
- Public CI and Make targets no longer invoke the excluded SLS Proxy server;
  server configuration references point to the separately delivered package.

- The community source archive now includes the complete `secweaver-agent`
  source, tests, generic packaging, and integration documentation so users can
  build and audit the host evidence producer. The separately delivered
  `dataasset_sls_proxy` and `src/es-operator` roots remain excluded, with export
  attributes, release scanning, and regression tests enforcing that boundary.
- WAF-only S4 and D1 bootstrapping now prefer the canonical public
  `asset-secweaver-gateway-access` web-access asset. Private registries may
  resolve their legacy gateway ID through the compatibility alias, and
  `SECWEAVER_S4_GATEWAY_ASSET_ID` provides an explicit deployment override. A
  live query failure remains visible and never silently switches logstores.
- Cross-source correlation now uses one canonical IP normalizer for WAF,
  gateway, traceability, fetch summaries, and attacker-IP intelligence. It
  removes export-added quotes, strips IPv4 ports, rejects placeholders and
  invalid values, and applies the normalized value to IP joins while preserving
  the original evidence payload.
- Alert-confirmation summaries and Markdown reports now distinguish unavailable
  gateway data, a populated gateway with no matching source/path request, and a
  matching request outside the tight time window. Time-window fallback rows from
  unrelated source IPs remain available for gateway miss scanning but cannot
  trigger host-side D2 retrieval.
- SecWeaver Agent release identity advances from `0.3.7` to `0.3.10` for Linux
  enrollment CA persistence, Docker workload support, and bounded audit fallback.
  Linux, Windows, portable deployment, host snapshot, and signed-update documentation now
  consistently references the canonical `0.3.10` release instead of stale
  package examples.
- Agent authorization startup and scheduled checks now keep the service alive for
  transient DNS, network, HTTP 408/425/429, and server failures with stable jitter
  and exponential backoff from 5 seconds to 5 minutes. Permanent configuration or
  authorization failures still fail closed; invalid local configuration exits 78,
  and the Linux unit excludes that status from restart while disabling systemd's
  permanent start-rate latch.
- Agent heartbeat and remote configuration loops keep collectors active during
  transient Data Cloud outages. Remote configuration retries use stable per-device
  jitter and bounded exponential backoff from one to 15 minutes, avoiding a
  fleet-wide reconnect burst when the control plane recovers.
- Agent status persistence now coalesces rapid lifecycle updates through one
  asynchronous writer, performs filesystem IO outside the state mutex, retries
  failed writes, records persistence attempts and errors, and performs a final
  shutdown flush. `/live` reports HTTP availability, while `/health` now reflects
  module readiness, authorization, audit-reader diagnostics, and status-file
  persistence rather than returning a static response.
- Windows-supervised collectors now receive a cooperative stdin shutdown request,
  retain a 15-second forced-stop fallback, and run in kill-on-close Job Objects so
  module descendants cannot survive an Agent exit. Standalone module stdin behavior
  remains unchanged, and Unix children continue to stop through `SIGTERM`.
- Agent release builds now inject the canonical `VERSION` into both the root command
  and `audit-port-execmon -version`. Cross-platform update artifacts default to
  `ed25519-sha256` digest signatures; raw Ed25519 artifact signatures require an
  explicit legacy compatibility override.
- Consolidated Linux Agent binaries, configuration, state, logs, and shipper files
  under `/opt/secweaver-agent`, and Windows files under
  `C:\ProgramData\SecWeaver\Agent`. Installers preserve registration identity and
  state during migration; `config migrate-layout` rewrites only known legacy
  SecWeaver-owned paths, and uninstall distinguishes program removal from `--purge`.
- Changed `host-process-snapshot` from a full snapshot every ten minutes to an
  initial/daily baseline plus ten-minute `process_start`, `process_exit`, and
  `process_change` deltas. PID reuse is separated with `pid+start_time`, state is
  atomically persisted, baselines retain `command_hash`, and DataAsset/ES/SLS query
  contracts now expose the new event and change fields.
- Agent child modules that consume the same Linux audit log now share one parent
  demultiplexer with bounded per-subscriber queues, audit-ID routing, rotation
  recovery, and replay backlogs. Audit rule updates are serialized outside the read
  path, grouped transactionally under a hard rule budget, reconciled periodically,
  and throttled through staged backlog/lost-record pressure states.
- Agent release versioning now has one `VERSION` source. Signed cross-builds and
  packages record the source commit and fingerprint, reject dirty Agent source by
  default, and include the production configuration example and provenance
  sidecars in release artifacts. Release gates now also reject changed Agent source
  or package content under an unchanged version, environment-only version overrides,
  and attempts to bypass version identity with dirty-build overrides.
- Built-in Agent collectors now publish a module-owned descriptor for supported
  platforms, flags, output paths, audit subscriptions, and entrypoints. The
  supervisor consumes this narrow contract instead of parsing collector-private
  JSON or duplicating audit-key policy, and duplicate module names fail during
  registry construction.
- Split `audit-port-execmon` and `host-persistence` monoliths into lifecycle-focused
  source files for configuration, transport, parsing, state, reconciliation, rule
  ownership, worker queues, and platform behavior. Existing configuration fields,
  defaults, output paths, event schemas, and single-binary deployment remain
  compatible.
- Unified Security 4688 and Sysmon 1/3/11/23 conversion behind one internal Windows
  evidence classifier, so the default risk reader and standalone compatibility
  reader emit the same `host_exec`, `host_connect`, and `host_file_op` contracts.
- Replaced the disconnected audit listener-health counters with production-path
  atomic parser counters and monitor-owned rule, queue, budget, and pressure
  snapshots. Module shutdown now emits one coherent `audit runtime stats` diagnostic
  record without claiming those local counters are parent Prometheus series.

### Fixed

- Fixed sustained high CPU in `audit_filter_syscall` on kernels where eBPF CO-RE
  cannot load, including older kernels without `/sys/kernel/btf/vmlinux`. The
  default audit fallback no longer grows hundreds of PID/PPID rules as listener
  process trees fork and exit, while startup rollback and shutdown cleanup own the
  new fixed rules transactionally.

- SSH `Accepted` evidence derived from `syslog_risk_alert` now recovers missing
  source IP, user, and port fields from the raw message, preserves the source
  rule and raw behavior, and carries those verification fields into the report
  evidence index. Asset-list traces no longer report missing lateral login
  evidence merely because the first fetch was scoped to the entry host.
- Initial-access reverse lookup now normalizes and enforces the requested
  attacker IP before selecting victim-host WAF or gateway candidates. This
  prevents a same-target event from another source, or a parser-added quote or
  port, from being attributed to the investigated attacker.
- Linux Agent installation now validates and atomically persists the enrollment
  bootstrap CA before existing configuration is loaded. It writes the current
  `/opt/secweaver-agent/shipper/ca.crt` path and the historical
  `/opt/secweaver-agent/etc/shipper/ca.crt` compatibility path, and rewrites a
  temporary `--update-ca-file` reference to the durable path before the outer
  enrollment command deletes its temporary file.
- Reworked the shared audit reader lifecycle so initial-open failures, missing log
  paths, rotation reopen failures, and exhausted retry loops remain observable and
  recover without permanently disabling the demultiplexer. Fixed-size subscriber
  rings now account for every overwritten line, report the affected audit IDs at a
  bounded rate, retire broken subscribers, and allow supervisor restart/replay
  without blocking the audit read path on status-file IO.
- Status-file write failures no longer disappear behind successful in-memory state
  changes or hold the supervisor lock during disk IO. Readiness fails explicitly
  while persistence is unavailable and clears after a successful retry.
- Corrected eBPF execution evidence that previously emitted `has_tty=false` when TTY
  state had not been observed. `has_tty` is now tri-state and omitted when unknown;
  eBPF events also best-effort enrich `auid`, `auid_name`, `cwd`, and `tty` from
  procfs so downstream WebShell, RCE, and SSH analysis does not treat missing session
  context as negative evidence.
- Hardened audit collection against PID reuse, partial rule installation, blocked
  `auditctl`, continuous high-volume logs, inode-changing rotation, delayed watch
  creation, stale actor correlation, reader failure, and unclean shutdown. Failed
  cleanup remains accounted for and is retried instead of silently losing rule
  ownership.
- Agent event logs and retained numeric backups are now always regular files with
  mode `0600`; startup repairs permissions created by older releases and rejects
  symlink or special-file backups rather than following them during rotation.
- Agent update HTTP transport now applies explicit dial, TLS handshake, response
  header, keepalive, idle connection, and overall request timeouts even when the
  process-wide default transport has been replaced.
- Agent configuration now rejects simultaneous Windows process-evidence ownership
  by `windows-eventlog-risk-json` and `windows-process-execmon`. Operators can retain
  the standalone reader only by explicitly disabling the unified reader's
  `-evidence-output`, preventing duplicate Event Log queries, duplicate evidence,
  independent cursor drift, and competing writers to the same output file.
- Keep company-private source roots trackable in the internal GitLab while
  excluding them from history-free community archives. Release policy now also
  treats `dataasset_sls_proxy/` as private and no longer relies on whole-root
  `.gitignore` entries that hide newly added internal source files.
- Remove both `secweaver-agent.service` and `secweaver-agent-shipper.service`
  during Agent uninstall, including their enablement links and unit files.

### Security

- The eBPF backend filters in kernel space and reports only process lifecycle events
  belonging to explicitly tracked listener trees. Tracked PID count, per-CPU perf
  memory, argument count, argument length, audit rule count, queues, and reconciliation
  work are bounded to prevent host-wide collection or unbounded resource growth.
- Native shipper input cannot select arbitrary ES indices: validated `asset_type` and
  `event_type` values map through an allow-list, credentials stay in service
  environment files, TLS 1.2 or newer is required, and retry-safe document IDs prevent
  duplicate ingestion after ambiguous Bulk responses.
- Windows collector-generated PowerShell activity is now suppressed only when the
  SHA-256 of the complete marked script matches a registered built-in collector.
  Reusing the marker or appending commands no longer allows unrelated PowerShell
  activity to bypass risk classification.

## [0.3.0] - 2026-07-17

This release expands SecWeaver from a configuration-first analysis platform into
an installable, governed security data foundation. It adds four delivery modes,
Agent integration with managed services, broader host and DNS evidence, and
one-click onboarding for customer-managed Elasticsearch/OpenSearch.

### Added

- **Four security data-foundation delivery modes**: portable laptop
  ES-compatible, persistent Linux server ES-compatible, customer-managed
  Elasticsearch/OpenSearch, and SecWeaver Data Cloud managed SLS. Added public
  installation guides, operator selection criteria, ownership boundaries, and
  common real-data acceptance checks.
- Optional separately distributed `secweaver-portable` control plane for laptop delivery, including
  strict TLS, OpenSearch lifecycle management, per-host enrollment and revocation,
  Linux/Windows installer generation, disk-buffered Fluent Bit shipping,
  declarative DataAsset registration, diagnostics, and verified backup/restore.
- **Customer-managed Elasticsearch/OpenSearch onboarding** in DataAsset Studio.
  Operators can probe a cluster, discover indices and Data Streams, inspect
  `_field_caps`, select a time field, preview redacted sample fields, save Basic
  or API Key credentials through SOPS, and generate an active Connector, Asset,
  and bounded time-range query template without hand-editing JSON.
- Built-in `sls_proxy` Connector with official SLS protocol compatibility,
  DataAsset templates, and catalog examples. Client configuration contains only
  Proxy `endpoint`, authorized `logstore`, and a Proxy credential reference.
- **Agent module registry and supervisor** with module descriptors, independent
  child processes, restart policy, status snapshots, config schema validation,
  atomic config updates, `config` commands, preflight checks, and a machine-readable
  `doctor` command for customer support and platform health checks.
- Signed Agent update pipeline with Ed25519 manifest and binary verification,
  scheduled checks, rollout controls, bounded transport, staged installation,
  rollback, cross-platform release packaging, and a Bootstrap installer that can
  carry trusted release and Logtail metadata.
- Cross-platform `host-process-snapshot` and `host-state-snapshot` collectors.
  They add process ancestry and resource context, listening sockets, identity and
  login changes, services/scheduled tasks, kernel modules, namespaces, cgroups,
  containers, baselines, and change events under the unified Agent.
- New host process, socket, identity, service, and kernel-context DataAssets,
  SLS Connectors, query templates, field contracts, bundles, and investigation
  coverage metadata.
- DNS risk detection for NXDOMAIN bursts, DGA-like domains, uncommon TLDs, DNS
  tunneling, DoH, and DoT, with ATT&CK mappings, configurable JSON rules, source
  completeness requirements, and explicit warnings that DNS evidence does not
  replace firewall/NTA/proxy session evidence.
- Extended traceability correlation for process, socket, identity, service,
  kernel/container, and DNS evidence, including richer host impact summaries and
  partial-evidence explanations.
- DataAsset Studio workflows for portable deployment and customer-managed ES,
  including responsive layouts, English/Chinese text, credential selection,
  deployment status, host enrollment, and actionable connection errors.
- CI gates for Agent formatting, vet, unit/race tests and builds, plus portable
  Go tests, shell contract checks, ES fetch regression tests, and documentation
  entrypoint validation.

### Changed

- `secweaver-agent` now requires a valid top-level 16-character `enterprise_id`.
  The Linux installer requires `--enterprise-id`, writes it atomically through the
  Agent config API, and the shared JSON Lines output boundary adds it to every
  collector event.
- Refactored the Agent entrypoint, update client, configuration commands, output
  boundary, Windows service integration, and collectors into smaller control-plane,
  registry, supervisor, transport, and module packages with architecture tests.
- Unified legacy audit/syslog and all newer host collectors behind one Agent
  program, one configuration contract, one packaging flow, and one service model.
- Expanded the default host-risk and incident-trace bundles, canonical field
  catalog, evidence minimums, scenario requirements, and query templates for new
  host-state and DNS assets.
- Risk identification and data-source completeness now distinguish primary and
  auxiliary evidence, account for new host snapshots, and report investigation
  limits when network session sources are absent.
- Removed physical SLS `region` and `project` configuration from client Connectors.
  In this release, client-signed logical project values serve official SDK protocol
  compatibility only and cannot select an upstream route.
- Expanded the English/Chinese operator documentation with Agent collection,
  Data Cloud, WEB Shield, DNS, portable laptop, Linux server, customer ES, SLS
  Proxy, troubleshooting, deployment ownership, and acceptance guidance.

### Fixed

- Ensured `enterprise_id` is present in syslog risk output and all other Agent
  module events by enforcing it at the shared output boundary instead of relying
  on each collector implementation.
- Stopped legacy standalone collector services during Agent installation to avoid
  duplicate writers and inconsistent event schemas after migration.
- Hardened process and state snapshot collection around disappearing `/proc`
  entries, incomplete scans, sensitive command-line arguments, and false deletion
  events caused by partial collection.
- Preserved Windows event cursor state and improved Windows service, process,
  event-risk, installer, and uninstall behavior under the unified Agent model.
- Prevented inherited ES onboarding templates from retaining an undeclared
  `src_ip` term when generating generic time-range queries.

### Security

- Remote Elasticsearch/OpenSearch endpoints must use HTTPS; plain HTTP is allowed
  only for loopback development. Private CAs are supported without permitting
  `tls_verify=false`, endpoint credentials are rejected, redirects are blocked,
  response sizes are bounded, and sensitive sample fields are redacted.
- SLS Proxy client activation rejects non-loopback HTTP endpoints; client
  configuration contains Proxy credentials rather than physical SLS RAM credentials.
- Agent remote updates and remote configuration are fail-closed and require
  Ed25519 signatures by default. Unsigned input is restricted to explicit local
  development paths.
- Added command-line secret redaction, secure runtime path permissions, atomic
  credential/config writes, archive traversal checks, and Git exclusions for
  generated certificates, secrets, enrollment bundles, and data directories.

### Upgrade Notes

- Add a valid 16-character `enterprise_id` to every Agent configuration before
  upgrading; startup now fails when it is missing or invalid.
- Configure the trusted Ed25519 public key before enabling remote update or remote
  configuration. The old unsigned remote update flow is no longer accepted.
- Remove physical SLS `region` and `project` from `sls_proxy` client Connectors;
  keep only `endpoint`, `logstore`, and the Proxy credential reference.
- Customer-managed ES onboarding is read-only. Sending new Agent data into a
  customer cluster still requires the customer's Fluent Bit, Filebeat, Vector,
  or collection platform to implement the SecWeaver Data Contract.

## [0.2.0] - 2026-07-12

This release turns the initial SecWeaver prototype into an extensible,
configuration-first community platform for developers and security operators.

### Added

- **Configuration-first DataAsset onboarding** with `secweaver asset apply`, reusable
  onboarding profiles, JSON Schema validation, dry-run support, field overrides,
  parser settings, coverage configuration, and template parameters.
- **Pluggable connector architecture** with built-in connectors, Python plugins,
  external executors, and local-sample connectors. New connector types can be
  registered without modifying the core dispatcher.
- Built-in connector support and onboarding examples for SLS, SSH, agent streams,
  HTTP APIs, Elasticsearch, local files, syslog, object storage, AWS CloudWatch,
  AWS S3 Logs, Azure Monitor, GCP Logging, Tencent CLS, Huawei LTS, Splunk,
  ClickHouse, Hive, and common database families.
- Lazy-loaded vendor SDK integrations and per-database fetch modules, keeping
  optional cloud and database dependencies outside the core runtime path.
- Connector catalog, SDK strategy matrix, vendor examples, external executor
  examples, plugin templates, diagnostics, and connectivity checks.
- **DataAsset Studio onboarding workflow** for assets, connectors, credentials,
  parsers, correlation rules, and scenarios, including English and Chinese UI.
- Productized correlation and scenario editors with schema-aware validation,
  field suggestions, priority, confidence, explanations, and visual rule summaries.
- `correlation-matrix.schema.json` and enhanced correlation matching, trace
  explanations, field aliases, coverage controls, and operator-facing examples.
- `DATAASSET_ROOT` support for switching between the public sample registry and
  an operator-owned private asset directory without changing application code.
- **Unified `secweaver-agent`** with independently maintained collector modules,
  cross-platform builds, release packages, SHA256 manifests, update, rollback,
  and staged rollout support.
- Host persistence, Linux audit/syslog, Windows event log, and Windows process
  collection modules under the single-agent installation model.
- Configuration error diagnostics for DataAssets, connectors, credentials,
  correlation rules, scenarios, and onboarding input.
- GitHub Issue templates, pull request template, contributor quickstart,
  developer guide, UI contribution guide, connector plugin guide, operator
  quickstart, FAQ, and vendor onboarding walkthroughs.
- Open-source release gate, documentation link checker, strict policy sync check,
  expanded regression suite, and offline release demos.

### Changed

- Split developer and architecture documentation into `docs_dev/`, and security
  operator documentation into `docs_user/`, with numbered reading paths and
  English/Chinese entry points.
- Refactored the CLI, validation diagnostics, DataAsset UI server, UI modules and
  styles, alert confirmation engine, traceability engine, and agent collectors
  into smaller ownership-focused modules.
- Split generic database fetching into independent implementations for MySQL,
  PostgreSQL, Oracle, SQL Server, SQLite, ClickHouse, Hive, MongoDB, and Redis.
- Moved DataAsset validation, catalog, connector-test, credential, and plugin
  programs from asset registries into `src/dataasset/`. `DATAASSET_ROOT` now
  selects configuration only, while `SECWEAVER_PLUGIN_ROOT` independently selects
  operator-owned plugin code.
- Moved repository release and documentation maintenance programs from the root
  `scripts/` directory into `src/scripts/`, with Make and CI entrypoints updated.
- Replaced the separate `audit-port-execmon` and `syslog-risk-json` programs with
  modules compiled and packaged as one `secweaver-agent` binary.
- Expanded traceability and alert-confirmation analysis with gateway evidence,
  target impact, timeline coverage, host normalization, and Markdown reports.
- Updated public examples and DataAsset inventory to use synthetic, sanitized,
  configuration-driven samples.
- Expanded the open-source boundary, contribution workflow, architecture guides,
  operator workflow, and extension documentation.

### Removed

- Legacy `docs/` layout, replaced by `docs_dev/` and `docs_user/`.
- Legacy standalone tools under `tools/audit-port-execmon/` and
  `tools/syslog-risk-json/`, replaced by `src/tools/secweaver-agent/`.
- Production-derived host, network, and report samples that are not suitable for
  the public community distribution.

### Security

- Added an open-source release scanner for private paths, generated archives,
  environment markers, credential patterns, and contributor metadata placeholders.
- Added a validation gate that rejects program and executable files under public
  or operator-owned DataAsset roots.
- Kept credentials behind `vault://` references and encrypted or local secret
  stores; public examples contain placeholders only.
- Added read-only connector guidance, bounded external executors, parser limits,
  and safer release packaging checks.

## [0.1.0] - 2026-07-06

Initial development baseline. This version was not published as a public release tag.

### Added

- **DataAsset framework**: assets, connectors, hosts, networks, bundles, query templates, JSON Schema, `validate.py`, `catalog sync`.
- **Correlation Matrix** and **Scenario Patterns** (S1–S7 investigation templates).
- **Skills**: `dataasset-validation-advisor`, `data-source-completeness`, `alert-confirmation`, `traceability-analysis`, `risk-identification`, `log-format-discovery`, and related submodules.
- **CLI** (`src/secweaver.py`): `validate`, `catalog`, `demo`, `skill`, `report`.
- **Offline demos** and sample reports under `examples/`.
- **Operator docs** (English-first): `docs_user/01`–`10` (+ `*.zh-CN.md` mirrors).
- **DataAsset Studio** (`dataasset-ui/`): local registry editor and topology view.
- **Host collector**: `src/tools/secweaver-agent` with built-in `audit-port-execmon` and `syslog-risk-json` modules.
- **CI**: GitHub Actions — validate, unit tests, offline demos (`make ci`).
- **License**: Apache-2.0.

### Community scope (this release)

- Local framework, synthetic demo data, example credentials (`REPLACE_ME`, `vault://` refs only).
- No multi-tenant RBAC, enterprise connectors, SOAR write-back, or proprietary rule packs.
