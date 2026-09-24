# SecWeaver Developer Documentation

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

This directory is for developer contributors, maintainers, architects, and integration authors. Operator and SOC usage guides live in [`docs_user/`](../docs_user/README.md).

## Start Here

| Document | Description |
|---|---|
| [01-new-contributor-quickstart.md](01-new-contributor-quickstart.md) | First-day path for developer contributors |
| [02-developer-guide.md](02-developer-guide.md) | Contributor change map, Skill manifest workflow, and test matrix |
| [03-community-add-asset-connector.md](03-community-add-asset-connector.md) | How to contribute an asset and connector |
| [04-connector-plugins.md](04-connector-plugins.md) | Connector plugin manifest, protocol, and validation |
| [05-external-connector-executors.md](05-external-connector-executors.md) | External executor examples and contracts |
| [25-ui-contribution-guide.md](25-ui-contribution-guide.md) | UI contribution, page extension, and full UI rewrite contracts |

## Community Release Maintenance

Use the [release checklist](community-release-checklist.md) to prepare a clean HEAD, verify the public archive and record outstanding real-platform checks. User configuration and data boundaries are covered in [data safety guidance](../docs_user/community-release-and-data-safety.md).

## Agent Development And Release

Find operational topics in the [Agent topic index](../src/tools/secweaver-agent/docs/README.md).

| Document | Description |
|---|---|
| [`secweaver-agent` engineering manual](../src/tools/secweaver-agent/README.md) | Build, configuration, module development, signed updates, key rotation, emergency stop, and rollback behavior |
| [26-secweaver-agent-device-identity-and-enrollment-design.md](26-secweaver-agent-device-identity-and-enrollment-design.md) | Immutable device identity, enrollment protocol, quotas, and revocation model |
| [30-agent-behavior-learning-design.md](30-agent-behavior-learning-design.md) | 24-hour behavior learning design, first implementation boundaries, evidence retention, and release acceptance |
| [Real-service upgrade integration tests](../src/tools/secweaver-agent/integration/service-upgrade/README.md) | Linux systemd and Windows SCM N-1 to N failure and automatic rollback tests |

## Architecture And Planning

| English | 中文 |
|---|---|
| [06-secweaver-architecture-and-features.md](06-secweaver-architecture-and-features.md) | [06-secweaver-architecture-and-features.zh-CN.md](06-secweaver-architecture-and-features.zh-CN.md) |
| [08-secweaver-architecture.svg](08-secweaver-architecture.svg) | Architecture diagram |

## DataAsset Design

| English | 中文 |
|---|---|
| [09-data-asset-design.md](09-data-asset-design.md) | [09-data-asset-design.zh-CN.md](09-data-asset-design.zh-CN.md) |
| [12-agent-collection-and-evidence-spec.md](12-agent-collection-and-evidence-spec.md) | [12-agent-collection-and-evidence-spec.zh-CN.md](12-agent-collection-and-evidence-spec.zh-CN.md) |
| [23-sls-proxy-multi-tenant-design.md](23-sls-proxy-multi-tenant-design.md) | [23-sls-proxy-multi-tenant-design.zh-CN.md](23-sls-proxy-multi-tenant-design.zh-CN.md) |
| [26-secweaver-agent-device-identity-and-enrollment-design.md](26-secweaver-agent-device-identity-and-enrollment-design.md) | [26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md](26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md) |

## Skill And Engine Design

| English | 中文 |
|---|---|
| [13-data-source-completeness-skill-design.md](13-data-source-completeness-skill-design.md) | [13-data-source-completeness-skill-design.zh-CN.md](13-data-source-completeness-skill-design.zh-CN.md) |
| [14-alert-confirmation-skill-design.md](14-alert-confirmation-skill-design.md) | [14-alert-confirmation-skill-design.zh-CN.md](14-alert-confirmation-skill-design.zh-CN.md) |
| [15-traceability-analysis-skill-design.md](15-traceability-analysis-skill-design.md) | [15-traceability-analysis-skill-design.zh-CN.md](15-traceability-analysis-skill-design.zh-CN.md) |
| [17-risk-identification-skill-design.md](17-risk-identification-skill-design.md) | [17-risk-identification-skill-design.zh-CN.md](17-risk-identification-skill-design.zh-CN.md) |
| [18-risk-identification-engine-design.md](18-risk-identification-engine-design.md) | [18-risk-identification-engine-design.zh-CN.md](18-risk-identification-engine-design.zh-CN.md) |
| [19-behavior-policy-engine-design.md](19-behavior-policy-engine-design.md) | [19-behavior-policy-engine-design.zh-CN.md](19-behavior-policy-engine-design.zh-CN.md) |
| [20-log-format-discovery-design.md](20-log-format-discovery-design.md) | [20-log-format-discovery-design.zh-CN.md](20-log-format-discovery-design.zh-CN.md) |
| [21-trace-profile-design.md](21-trace-profile-design.md) | [21-trace-profile-design.zh-CN.md](21-trace-profile-design.zh-CN.md) |
| [29-scenario-pattern-runtime-and-evolution.md](29-scenario-pattern-runtime-and-evolution.md) | [29-scenario-pattern-runtime-and-evolution.zh-CN.md](29-scenario-pattern-runtime-and-evolution.zh-CN.md) |

## Current Correlation Contracts

- [Correlation matrix concepts](../docs_user/04-correlation-matrix.md)
- [Cross-source fields and runtime constraints](../docs_user/21-cross-source-field-correlation.md)
- [Correlation matrix Schema](../dataasset/schema/correlation-matrix.schema.json)

## Historical Assessments

These documents are isolated under [`history/`](history/README.md) to preserve design evolution without presenting dated scores and TODOs as current implementation status. Scores, findings, and version status are not current release commitments; use current schemas, user guides, and code for implementation and configuration.

| English | 中文 |
|---|---|
| [10-data-asset-design-evaluation.md](history/10-data-asset-design-evaluation.md) | [10-data-asset-design-evaluation.zh-CN.md](history/10-data-asset-design-evaluation.zh-CN.md) |
| [11-data-object-model-evaluation.md](history/11-data-object-model-evaluation.md) | [11-data-object-model-evaluation.zh-CN.md](history/11-data-object-model-evaluation.zh-CN.md) |
| [16-traceability-analysis-architecture-evaluation.md](history/16-traceability-analysis-architecture-evaluation.md) | [16-traceability-analysis-architecture-evaluation.zh-CN.md](history/16-traceability-analysis-architecture-evaluation.zh-CN.md) |
| [22-correlation-matrix-design-evaluation.md](history/22-correlation-matrix-design-evaluation.md) | [22-correlation-matrix-design-evaluation.zh-CN.md](history/22-correlation-matrix-design-evaluation.zh-CN.md) |
| [28-secweaver-agent-audit-design.md](history/28-secweaver-agent-audit-design.md) | [28-secweaver-agent-audit-design.zh-CN.md](history/28-secweaver-agent-audit-design.zh-CN.md) |

## Public Integration Boundaries for Optional Managed Services

Community local analysis and connections to self-managed data sources do not depend on private server documentation. For managed services, use these public contracts:

- [SLS Proxy client contract and security boundaries](23-sls-proxy-multi-tenant-design.md): query protocol, credential references, and failure behavior.
- [Agent device identity and enrollment protocol](26-secweaver-agent-device-identity-and-enrollment-design.md): client identity, enrollment, and revocation expectations.

These documents describe client integration behavior; they do not include managed server implementations or production deployment manuals.

## Directory Rule

- `docs_dev/`: current developer, architecture, design, contribution, plugin, and integration documents.
- `docs_dev/history/`: dated assessments retained for decision history; not a current implementation backlog.
- `docs_user/`: security operator, SOC analyst, platform administrator, onboarding, and day-to-day usage documents.
- `docs_ai/`: optional, task-scoped context for intelligent agents; runtime contracts remain in `dataasset/` and workflow instructions remain in `src/skills/`.
- There is no separate `docs_public/` tree. The three directories above are the public documentation set; private product, server, and delivery materials, along with internal review originals, stay outside the Community archive.
