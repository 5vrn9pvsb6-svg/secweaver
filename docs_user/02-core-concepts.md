# 02. Core Concepts

**Languages:** English (this page) | [简体中文](02-core-concepts.zh-CN.md)

This page explains the most important concepts in SecWeaver. Once you understand them, most of the configuration under `dataasset/` will make sense.

---

## Overall relationships

Start with this relationship diagram:

```text
Asset ──connector_id──→ Connector ──credentials_ref──→ Credentials
  │
  ├── coverage.hosts(IP) ──→ Host ──network_id──→ Network
  │
  ├── query_template_ids ──→ Query Template
  │
  └── asset_type ──→ Correlation Matrix / Scenario Pattern
```

In short:

- `Asset` describes what the data is.
- `Connector` describes how to connect to the data.
- `Credentials` stores real secrets.
- `Host` identifies a machine.
- `Network` identifies which segment an IP belongs to.
- `Query Template` defines how to query.
- `Bundle` packages multiple assets into one investigation bundle.
- `Scenario Pattern` tells the AI what to query first for a given question type.
- `Correlation Matrix` tells the system how different evidence types relate.

---

## Asset: logical data asset

Directory: `dataasset/assets/`

`Asset` is the core object. It answers:

```text
What is this data?
What type does it belong to?
Which fields does it have?
Which hosts or zones does it cover?
Which connector fetches it?
Which query templates apply?
```

For example:

```text
asset-waf-prod-01.json
```

might represent “production WAF alert data.”

Common `asset_type` values:

| asset_type | Meaning | Typical use |
|---|---|---|
| `waf_alert` | WAF alert | Alert confirmation, external IP traceability |
| `web_access_log` | Web access log | Whether attack requests reached the application |
| `host_exec` | Host command execution | Whether the attack reached a host |
| `host_connect` | Host outbound connection | C2, data exfiltration |
| `host_file_op` | File operations | WebShell or dropped files |
| `ssh_auth` | SSH login | Lateral movement, account compromise |
| `firewall_log` | Firewall log | Cross-segment access verification |
| `dns_log` | DNS log | Outbound domain analysis |
| `network_traffic_audit` | Network traffic audit | Data exfiltration analysis |
| `db_audit` | Database audit | Sensitive data access confirmation |
| `asset_inventory` | Asset inventory | Hostname, IP, ownership |

---

## Connector

Directory: `dataasset/connectors/`

`Connector` answers:

```text
How do we connect to this data source?
SLS, ES, database, SSH file, or local file?
What is the connection address?
Project name, index name, table name?
What is the credentials reference?
```

Note: connectors must not contain plaintext passwords.

Correct approach:

```json
{
  "connector_id": "conn-sls-waf-prod",
  "connector_type": "sls",
  "credentials_ref": "vault://sls/security-readonly"
}
```

Incorrect approach:

```json
{
  "access_key_secret": "plaintext password"
}
```

---

## Credentials

Directory: `dataasset/credentials/`

Credentials store real secrets, for example:

- SLS AccessKey
- Database username and password
- SSH private key
- API token

When configuring operations, only put `credentials_ref` in the Connector—do not write real secrets into `connectors/*.json`.

Benefits:

- Configuration files can be committed safely.
- AI does not see secrets.
- Permission boundaries are clearer.
- You can swap in a Vault implementation later.

---

## Host

Directory: `dataasset/hosts/`

`Host` registers important machines, for example:

- Web servers
- Application servers
- Database servers
- Bastion hosts
- Gateway hosts

It answers:

```text
What is this machine called?
What is its IP?
Which zone does it belong to?
Which network segment is it bound to?
Is it exposed to the public internet?
Which ports are open?
```

Why Host matters:

Many investigations center on hosts:

- Which machine did a web request ultimately reach?
- Which host ran a suspicious command?
- Did that machine connect to other internal hosts?
- Did it move from DMZ into the production network?

---

## Network

Directory: `dataasset/networks/`

`Network` describes network segments, for example:

```text
Production web segment
Production DB segment
DMZ segment
Office network segment
Cloud VPC segment
```

It answers:

```text
Which CIDR does this IP belong to?
What zone is this segment?
Is it exposed to the public internet?
What is the trust level?
```

Network is important for lateral movement and data exfiltration.

For example:

```text
DMZ → production DB segment
```

That direction is more sensitive than ordinary internal access.

---

## Query Template

Directory: `dataasset/query-templates/`

`Query Template` answers:

```text
For a given data type, what does the actual query look like?
Which parameters are required?
```

For example:

```text
Query WAF alerts by src_ip + time_start + time_end
Query host commands by host + time_start + time_end
Query SSH logins by user + time_start + time_end
```

For operators, the key points are:

- Assets must reference appropriate `query_template_ids`.
- Parameters required by templates must match what investigation scenarios can supply.
- Field names must match actual log fields or field mappings.

---

## Bundle

Directory: `dataasset/bundles/`

A `Bundle` is a collection of assets.

For example, a “minimum alert confirmation bundle” might include:

```text
WAF alert
Web access log
Host command execution
Host outbound connection
File operations
```

Its role:

- Avoid manually picking assets for each investigation of a given type.
- Ensure investigations use a consistent data scope.
- Let AI fetch related evidence in one pass.

---

## Scenario Pattern

Directory: `dataasset/scenarios/`

`Scenario Pattern` tells the AI:

```text
For a given problem type, which field should we start from?
Which data should we query first?
What correlation chain should we follow?
What is the default time window?
Which bundle should we use?
```

For example:

- External IP traceability: start from `src_ip`.
- Lateral movement: start from `host_ip` or `user`.
- Data exfiltration: start from `host`, `dst_ip`, or `domain`.

This does not restrict the AI—it gives the AI a reliable investigation playbook.

For more detail, see: [05. Scenario Pattern Deep Dive: Telling the AI What to Query First](05-scenario-patterns.md).

---

## Correlation Matrix

File: `dataasset/assets/correlation-matrix.json`

`Correlation Matrix` answers:

```text
How do different evidence types relate?
Which fields are used for joins?
How large is the time window?
How are evidence edges created after a successful join?
```

For example:

```text
WAF alert.src_ip = Web access log.src_ip
Web access log.host = Host command.host
SSH login.host_ip = Host asset.ip
```

What the AI ultimately sees is not a pile of unrelated logs, but:

```text
evidence_bundles + join_edges + data_gaps
```

That helps the AI produce more trustworthy conclusions.

For more detail, see: [04. Correlation Matrix Deep Dive: How Evidence Is Linked](04-correlation-matrix.md).

---

## Evidence

`Evidence` is an event fetched from a log source and normalized.

A single evidence record typically includes:

- `evidence_id`
- `timestamp`
- `src_ip`
- `dst_ip`
- `host`
- `user`
- `url`
- `command`
- `action`
- Other fields relevant to the scenario

Different log sources may use different field names, so field mapping normalizes them to unified fields.

---

## The three most important statuses

Many objects have a `status`:

| status | Meaning | Usable for formal investigations |
|---|---|---|
| `discovery` | New log format being discovered | No |
| `draft` | Configured or pending validation | Usually no |
| `active` | Validated and ready to use | Yes |

For new configuration, start with `draft` and change to `active` after validation passes.

---

## Next steps

Continue with: [03. How to Configure Data Sources](03-configure-data-sources.md)
