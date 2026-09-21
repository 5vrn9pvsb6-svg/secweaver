**Languages:** English (this page) | [简体中文](14-platform-introduction.zh-CN.md)

# AI-Native Security Analysis and Traceability Platform

> Turn security operations expertise into reusable AI Skills; let multi-source security data truly participate in analysis, confirmation, and traceability.

---

This optional product overview is not an installation or configuration reference. Scope reviewed: 2026-09-18. Start with the [quickstart](00-security-operator-quickstart.md); see [architecture](../docs_dev/06-secweaver-architecture-and-features.md) for implementation boundaries.

## 1. Platform Positioning: An AI Analysis Execution Platform for Security Operations

SecWeaver is an AI-native security analysis and traceability investigation platform for security operations.

It is not a simple chatbot, nor a single log query tool. It unifies data assets, expert experience, analysis workflows, and tool execution so AI can complete security analysis tasks within clear boundaries.

**One-line positioning:**

> Define data assets, codify security Skills, and let AI execute analysis, confirmation, and traceability.

Core goals:

- Reduce heavy reliance on individual experience for security analysis
- Codify expert SOPs as reusable Skills
- Automatically correlate multi-source evidence: alerts, logs, host behavior, network connections
- Help security teams confirm alerts faster, identify risks, and reconstruct attack chains

---

## 2. Why Such a Platform Is Needed

Traditional security operations face three long-standing problems.

### Too many alerts; manual confirmation is costly

WAF, IDS, EDR, firewalls, and SIEM continuously generate alerts, but most require human judgment:

- False positive or real attack?
- Was the attack successful?
- Did it reach the host?
- Is there subsequent lateral movement?

### Plenty of data, but hard to truly correlate

Security data is scattered across systems:

- WAF / WEB access logs
- SSH / system authentication logs
- Host command execution logs
- Host active egress logs
- DNS / firewall / network traffic logs
- CMDB / host asset information

This data becomes an analyzable evidence chain only after unified registration, field normalization, time-window alignment, and explicit Join rules.

### Expert experience is hard to replicate

Security experts know how to judge attack success, trace from IP to host, and follow commands to egress—but that knowledge often lives in people's heads or scattered documents.

The platform codifies this as:

- Executable Skills
- Auditable workflows
- Reusable correlation rules
- A continuously improvable data asset system

---

## 3. Six Core Capabilities

SecWeaver builds six capabilities around the key security operations loop.

| Capability | Role |
|---|---|
| Data asset management | Unified management of log sources, connectors, credentials, hosts, correlation matrix |
| Security Skill codification | Package expert analysis experience as reusable, auditable Skills |
| Data source completeness analysis | Judge whether current data is sufficient for alert confirmation and traceability |
| Risk identification | Triage host command execution, active egress, and similar behaviors |
| Traceability analysis | Reconstruct attack chains across WAF, WEB, host, SSH, firewall, and other data |
| Alert confirmation | Judge false positive vs. attempt vs. real attack, and confirm success |

---

## 4. Data Assets Are the Foundation of AI Analysis

Whether AI can produce reliable security analysis depends first on what data it can see, whether that data is trustworthy, whether fields are consistent, whether time can be aligned, and whether evidence can be correlated. Logs, alerts, host behavior, network connections, identity, and asset information in security operations are just scattered text and records for AI unless asset-managed; only when registered as standardized data assets do they become retrievable, verifiable, correlatable, reusable analysis context.

Therefore, data assets are not a simple "data source inventory"—they are the foundation of AI security analysis.

They determine:

- What data AI knows is available
- What security semantics each data type represents
- Which connector to use to pull evidence
- Which fields can confirm alerts, locate hosts, and reconstruct attack chains
- Whether the platform can judge data sufficiency before analysis, avoiding blind queries and misjudgment

The platform abstracts security operations data into five core object types.

| Core object | Description | Problem solved |
|---|---|---|
| Asset | Data source asset: what data exists, which security domain, which hosts or apps | Which data AI should use |
| Connector | How to connect to a data source | How to pull logs or evidence |
| Credentials | Credential reference: which secret to use | Secret security and permission boundaries |
| Host | Key host registry | Unified host identity, zone, role, IP |
| Correlation Matrix | Cross-source correlation matrix | How evidence Joins, time windows, which scenarios |

### Data asset correlation determines whether an evidence chain can form

A single data source usually answers a local question: WAF sees attack requests, WEB logs see access context, host logs see command execution, network logs see egress, SSH logs see lateral login. Real security analysis must string these together into a complete chain from "alert" to "host behavior" to "impact scope."

For example, confirming a Web attack requires correlating:

```text
WAF alert
  → WEB access log
  → Host command execution
  → Host active egress
  → SSH login / lateral movement
  → Affected hosts and business scope
```

Without data asset correlation, AI can only read log fragments separately and conclusions stay at "possibly related." With explicit asset relationships, field mappings, Join rules, and time windows, AI can give explainable, reviewable judgments: attack success, entry point, commands executed, egress occurred, hosts affected.

This is SecWeaver's core design: standardize data assets first, correlate them second, then let AI complete analysis, confirmation, and traceability on a trusted evidence chain.

---

## 5. Data Onboarding Separated from Operations

The platform uses GitOps + form wizards + validate release gates so data onboarding shifts from "developers change code" to "operators configure; platform validates and executes automatically."

### Operators are responsible for

- Registering hosts and key assets
- Configuring data source assets and connectors
- Configuring field normalization and query templates
- Running validation and connectivity tests
- Promoting data sources from draft to active

### The platform is responsible for

- Providing a standardized data asset model
- Validating configuration completeness, usability, and release readiness
- Executing fetch per connector and query template
- Automatic field normalization, masking, and evidence standardization
- Cross-source correlation per correlation-matrix
- Delivering usable evidence to AI Skills for analysis, confirmation, and traceability

This division makes onboarding controllable: operators maintain configuration per platform standards; the platform turns configuration into executable, auditable, reusable security analysis capability.

### Currently Supported Connector Types

Connectors describe how the platform connects to data sources. The configuration model supports the types below, grouped by maturity into "direct fetch execution" and "onboarding / extension reserved."

| External data source type | Platform config type | Applicable sources | Current capability |
|---|---|---|---|
| Alibaba Cloud SLS | `sls` | SLS Project / LogStore | Live fetch supported; parameterized `sls_query` by time window, IP, host, etc. |
| Elasticsearch / OpenSearch | `es` | ES / OpenSearch log indices | Live fetch supported; `es_query` Query DSL |
| SSH file logs | `ssh_file` | Remote Linux / Windows host log files | SSH read of text logs: auth.log, syslog, nginx access, etc. |
| Local file / offline samples | `local_file` | Local text logs, offline samples, demo data | Local text file read; offline validation, replay, demos |
| MySQL read-only DB | `database_ro` + `config.engine=mysql` | CMDB, bastion, audit DB, business security DB | Read-only SQL with parameter binding |
| MariaDB read-only DB | `database_ro` + `config.engine=mariadb` | Same as MySQL | Same as MySQL |
| PostgreSQL read-only DB | `database_ro` + `config.engine=postgresql` | CMDB, asset DB, audit DB, data warehouse | Read-only SQL; `sslmode` etc. |
| HTTP / REST API | `http_api` | WAF, SIEM, ticketing or security product APIs | REST fetch; template defines method, path, body |
| AWS CloudWatch Logs | `aws_cloudwatch` | Cloud app logs, CloudTrail, VPC Flow Logs | Extension connector; `cloudwatch_query` template |
| AWS S3 log archive | `aws_s3_logs` | ALB / CloudFront / CloudTrail / security product S3 logs | Extension connector; `object_query` for prefix/filter |
| Azure Monitor | `azure_monitor` | Log Analytics Workspace, Azure security logs | Extension connector; KQL queries |
| Google Cloud Logging | `gcp_logging` | GCP project logs, audit logs, VPC Flow Logs | Extension connector; `gcp_logging_filter` |
| Tencent Cloud CLS | `tencent_cls` | Tencent Cloud log service topics | Extension connector; `cls_query` |
| Huawei Cloud LTS | `huawei_lts` | Huawei Cloud log streams | Extension connector; `lts_query` |
| Splunk | `splunk` | Enterprise SIEM / Splunk indexes | Extension connector; `splunk_search` SPL |
| ClickHouse | `clickhouse` | Large-scale log detail tables, traffic/audit detail | Extension connector; read-only `sql` |
| Hive | `hive` | Data lake, offline log warehouse, long retention | Extension connector; read-only `sql` |
| Agent ingest stream | `agent_stream` | Agent ingest and collection pipeline sink | In connector model; describes agent ingest and downstream sink |
| SSH command collection | `ssh_command` | Controlled SSH command execution collection | In template/connector enum; future strict command whitelist |
| Syslog push ingest | `syslog_ingest` | Network devices, hosts, gateways pushing Syslog | Reserved passive ingest connector |
| Object storage log archive | `object_storage` | OSS / S3 batch or archived logs | Reserved for batch/archive/offline replay |

Among these, `sls`, `es`, `ssh_file`, `local_file`, `http_api`, and MySQL / MariaDB / PostgreSQL read-only DBs have generic fetch execution. Database types use `database_ro` with `config.engine` for the specific engine. AWS CloudWatch, AWS S3 Logs, Azure Monitor, GCP Logging, Tencent CLS, Huawei LTS, Splunk, ClickHouse, and Hive are in the extension connector system; each query template renders fetch requests; customers supply credentials, endpoints, and execution dependencies.

---

## 6. Field Normalization: Different Logs, Same Language

Different log sources may name the same semantic field completely differently.

For example:

| Log source field | Platform canonical field |
|---|---|
| ip / client_ip / remote_addr | src_ip |
| time / __time__ / @timestamp | timestamp |
| host_name / hostname | host |
| trace_id | alert_id |

SecWeaver handles field differences via field_aliases and shared field inventory.

Benefits:

- Skills need not care about each log source's raw field names
- Completeness checks use canonical fields
- correlation-matrix Joins use unified semantics
- New sources only need field mapping, not code changes

---

## 7. Correlation Matrix: Cross-Source Evidence Join Contract

The Correlation Matrix is the platform's correlation brain. It defines:

- Which data sources can correlate
- Which fields to Join on
- Within what time window
- Which investigation scenarios use which correlation chains
- How to supplement correlated evidence during fetch

For example:

```text
WAF alert → WEB access log → host command execution → host egress → SSH lateral
```

AI no longer "guesses correlation" by intuition—it analyzes within an explicit Join contract.

Key value:

- Reproducible cross-source analysis
- Auditable attack chain reconstruction
- New sources quickly join correlation chains
- Expert experience codified as machine-executable rules

---

## 8. Release Gates: Operator Configuration That Is Independent, Controlled, and Releasable

The platform provides validate release gates to avoid "configuration writes but does not work."

Gate checks include:

- JSON Schema pass
- active assets have owner, retention, query template
- active asset coverage.hosts contains only log source IPs
- evidence required fields reachable via schema.fields or field_aliases
- query template matches connector_type and asset_type
- bundle does not reference non-active assets
- correlation-matrix Join fields reachable
- anchor-patterns reference real Join chains

Three modes:

```bash
validate.py
validate.py --json
validate.py --json --strict --only-active
```

Strict mode treats warnings as blocking issues for pre-release checks.

---

## 9. Scenario One: Data Source Completeness Analysis

Before traceability, the platform judges whether current data is sufficient.

It answers:

- Is WAF / WEB / host / SSH / DNS / firewall data present?
- Do key fields exist?
- Does retention cover the investigation window?
- Are coverage source IPs and field normalization usable?
- Is evidence sufficient to confirm an attack chain?

Value:

> Know what's missing before analysis—avoid blind investigation.

---

## 10. Scenario Two: Risk Identification

The platform can perform AI risk identification on host behavior data.

Typical data:

- Command execution by externally listening processes
- Host active egress
- File operation behavior
- Interactive TTY commands
- listener_pid / listener_port / process information

Typical risks:

- WebShell command execution
- Reverse shell
- Malicious tool download
- External C2 connections
- High-risk commands from external entry processes

Operators select assets and Skills; AI applies codified rules for high-risk command identification and evidence attribution.

---

## 11. Scenario Three: Attack Traceability Analysis

When an external attacker IP or alert time is known, the platform automatically performs cross-source traceability.

Example chain:

```text
External attacker IP
  → WAF alert
  → WEB access log
  → Host command execution
  → Host active egress
  → SSH lateral login
  → Impacted host scope
```

Platform output:

- First likely compromise entry
- Attack timeline
- Command execution evidence
- Lateral movement path
- Affected host list
- Missing data notes
- Follow-up remediation recommendations

---

## 12. Scenario Four: Alert Confirmation

For WAF / WEB / IDS alerts, the platform performs two-layer confirmation.

### Layer one: Is the alert itself valid?

- Is the payload clearly malicious?
- Does the rule hit real attack semantics?
- Could it be false positive or scan noise?

### Layer two: Was the attack successful?

- Is there matching WEB access context?
- Did host command execution occur?
- Egress, file writes, lateral login?
- Is there a verifiable evidence chain?

Output conclusions:

```text
false positive / attempt / real attack / attack success / need more data to confirm
```

---

## 13. Implemented Engineering Capabilities

The platform already has a basic closed loop from data onboarding to AI analysis.

| Module | Status |
|---|---|
| dataasset directory model | Implemented |
| Asset / Connector / Host / Bundle management | Implemented |
| SOPS Vault credential boundary | Implemented |
| SLS / ES / SSH file / local file / MySQL / MariaDB / PostgreSQL / HTTP API fetch | Implemented |
| AWS / Azure / GCP / Tencent / Huawei logs, Splunk, ClickHouse, Hive extension connectors | In model and execution entry |
| evidence normalizer + field_aliases | Implemented |
| correlation-matrix v1.1 | Implemented |
| data-source-completeness Skill | Implemented |
| alert-confirmation Skill | Implemented |
| traceability-analysis Skill | Implemented |
| risk-identification Skill | Implemented |
| validate release gates | Implemented |
| Minimal local UI / form wizard | Implemented |

---

## 14. Platform Architecture Overview

```text
Operator configuration layer
  hosts / assets / connectors / bundles / query-templates / correlation-matrix
        ↓
Release gate layer
  validate.py --json --strict --only-active
        ↓
Data access layer
  template_select / vault / fetch / normalizer / field_inventory
        ↓
Correlation analysis layer
  correlation_engine / field_resolver / join_edges / fetch_plan
        ↓
AI Skill layer
  completeness / risk identification / traceability / alert confirmation
        ↓
Delivery layer
  conclusions / evidence chains / timelines / gaps / remediation recommendations
```

---

## 15. Core Customer Value

### Faster alert confirmation

From manual line-by-line triage to AI auto-pulling context, cross-validation, and conclusions.

### More complete attack chain reconstruction

String WAF, WEB, host, SSH, network egress into an explainable timeline.

### Lower operations barrier

Data asset model, form wizards, and release gates let operators onboard and maintain data sources independently.

### Easier expert experience codification

Solidify expert workflows as Skills and correlation-matrix—not personal tribal knowledge.

### Stronger extensibility

Clear extension points for new data sources, fields, Joins, and scenarios.

---

## 16. Target Customers and Landing Scenarios

For teams with some security data foundation who want better analysis efficiency and operations automation.

Typical customers:

- Enterprise SOC
- Cloud security operations teams
- Red/blue exercise support teams
- Major-event and incident response teams
- Organizations with WAF / IDS / EDR / SIEM but lacking automatic correlation

Typical landing scenarios:

- WAF alert secondary confirmation
- WebShell attack confirmation
- External IP traceability
- Host high-risk command identification
- Reverse shell / C2 egress identification
- SSH lateral movement analysis
- Security data source completeness assessment

---

## 17. Product scope and direction

| Scope | Current role |
|---|---|
| Community | DataAsset, Skills, CLI, local DataAsset Studio, collection Agent, offline examples |
| Managed SaaS | Enterprise Workbench → Agent Configuration provides onboarding; servers, tenant management, and commercial control planes are not shipped in Community |
| Future direction | Richer collaboration, approval, and operations experiences are directions, not feature or delivery-date commitments for this archive |

Local DataAsset Studio already provides configuration capabilities; describing all UI as a future phase is inaccurate. Use the archive, module READMEs, and CHANGELOG to determine what is delivered.

## 18. Summary

SecWeaver's core is not "let AI analyze logs arbitrarily"—it builds a controllable, auditable, extensible AI security operations platform.

Through:

- Data asset definition
- Field normalization
- Release gates
- Cross-source correlation matrix
- Reusable security Skills
- AI orchestration execution

security teams organize scattered data, tools, and expert experience into sustainable security analysis capability.

> From single alerts to complete evidence chains; from personal experience to platform capability; from manual triage to AI-assisted security operations.