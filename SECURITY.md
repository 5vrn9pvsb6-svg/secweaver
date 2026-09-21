# Security Policy

**Languages:** English (this page) | [简体中文](SECURITY.zh-CN.md)

## Supported Versions

The open-source edition of SecWeaver is intended for local development, research, demos, and self-managed security operations workflows.

Security fixes are handled on the main branch until a formal release policy is published.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability that may expose sensitive information, credentials, exploit details, or deployment-specific security weaknesses.

Report privately to the maintainers at [415451@qq.com](mailto:415451@qq.com). Do not post exploit details or sensitive data in public issues; send a minimal, sanitized reproduction first.

When reporting, include:

- Affected component or file path.
- Reproduction steps or proof of concept.
- Impact assessment.
- Whether the issue involves credentials, private logs, or customer data.

## Secret Handling

Do not commit real credentials, API keys, tokens, private keys, production logs, customer data, or internal network inventories.

The repository should only contain:

- Example credentials with placeholders such as `REPLACE_ME` or `YOUR_*`.
- `vault://...` references instead of plaintext secrets.
- Synthetic demo logs and documentation samples.
- Sanitized asset, host, network, and connector examples.

## Open Source Boundary

The Community edition focuses on local framework capabilities: DataAsset definitions, validation, examples, basic Skills, CLI, and local demo workflows.

Enterprise-only capabilities should not be submitted to the open-source repository unless intentionally accepted by maintainers, including:

- Customer-specific connector implementations.
- Proprietary detection rule packs.
- Multi-tenant RBAC and audit backends.
- Production credential storage integrations.
- SOAR actions that mutate production systems.
- Private threat intelligence or customer investigation reports.
