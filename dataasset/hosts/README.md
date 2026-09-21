# Key Host Registry Field Reference (hosts/)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

`dataasset/hosts/` stores key host and logical host definitions the platform cares about. It answers: who is this machine, what is its primary address, which network does it belong to, what role does it play, and is it exposed externally?

Current unified host model:

```text
host.host_ip: primary host address; should be an IP whenever possible.
host.aliases: aliases, legacy names, FQDNs, and host_name values that may appear in logs.
host.interfaces: optional; fill only for multi-NIC / multi-address scenarios.
asset.coverage.hosts: log-source IPs only; do not put aliases/hostname here.
```

Assets no longer use `host_binding`. Host relationships are expressed mainly through:

- `asset.coverage.hosts`: array of log-source IPs for asset coverage and topology matching
- `connector.config.host_id`: optional; labels the actual collection target for single-host connectors only
- `host.network_id` / `host.interfaces[].network_id`: maps host addresses to network segments

## 1. File naming and basic rules

| Item | Rule | Example |
|---|---|---|
| File path | `dataasset/hosts/host-{slug}.json` | `dataasset/hosts/host-web-01.json` |
| Primary key | `host_id` matches the file name stem | In `host-web-01.json`, set `"host_id": "host-web-01"` |
| ID format | Must match `^host-[a-z0-9-]+$` | `host-db-01`, `host-bastion-dmz` |
| Secrets | No passwords, private keys, or AccessKeys | Credentials live only in credentials/Vault |

`hosts/` is a security-investigation host index, not a full enterprise CMDB. Register only hosts referenced by security data sources, connectors, or traceability chains.

## 2. Field overview

| Field | Required | Type | Summary |
|---|---:|---|---|
| `host_id` | yes | string | Globally unique host ID; matches file name |
| `name` | yes | string | Display name for humans |
| `hostname` | yes | string | Short hostname for display and log `host` / `host_name` matching |
| `host_type` | yes | string | Host / device category |
| `status` | yes | string | Lifecycle status |
| `host_os` | no | string | OS or device system type |
| `host_ip` | no | string | Primary host address; should be an IP whenever possible |
| `network_id` | no | string | Network for the primary address |
| `interfaces` | no | object[] | Optional; use for multiple interfaces or a separate management network; use `role=management` for management interfaces |
| `nat` | no | object | Gateway and mapping type for complex NAT / EIP paths only |
| `exposure` | no | object | External exposure summary |
| `aliases` | no | string[] | Aliases, legacy names, FQDNs, and host_name values from logs |
| `roles` | no | string[] | Business or technical role tags |
| `environment` | no | string | Environment: production / staging / development |
| `description` | no | string | Ops / security investigation notes |
| `tags` | no | string[] | Free-form tags |

## 3. Key field details

### 3.1 `host_ip`

`host_ip` is the primary host address. Prefer a real IP.

Recommended:

```json
{
  "host_ip": "198.51.100.2"
}
```

Not recommended:

```json
{
  "host_ip": "web-01"
}
```

If you only have a hostname for now, keep `hostname` and add `host_ip` once the IP is confirmed.

### 3.2 `aliases`

`aliases` records aliases, legacy names, FQDNs, and `host_name` values that may appear in logs.

Recommended:

```json
{
  "aliases": [
    "gateway",
    "gateway.internal.example"
  ]
}
```

Do not put hostname or business names into `asset.coverage.hosts` for compatibility. Coverage holds log-source IPs only.

### 3.3 `interfaces`

`interfaces` is optional. Use it for multi-NIC, multi-address, cross-segment, or management/production network separation.

A typical single-NIC host needs only:

```json
{
  "host_ip": "192.0.2.5",
  "network_id": "net-prod-web"
}
```

Multi-NIC example:

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip": "192.0.2.5",
      "network_id": "net-prod-web",
      "role": "primary"
    },
    {
      "name": "eth1",
      "ip": "192.0.2.15",
      "network_id": "net-management",
      "role": "management"
    }
  ]
}
```

Do not add a separate `management_ip`. Put the management interface in `interfaces` and resolve its gateway through its `network_id`. The business gateway is likewise resolved from the host's Network instead of being repeated on the Host.

### 3.4 `exposure`

`exposure` summarizes host-level external exposure. Network-level `internet_exposed` is no longer maintained.

```json
{
  "exposure": {
    "internet_exposed": true,
    "internet_ip": "116.62.158.63",
    "exposed_ports": [443, 80]
  }
}
```

Detailed evidence should still come from `host_connect`, firewall logs, NTA, cloud security groups, and similar sources.

### 3.5 `nat`

Normal EIP / DNAT cases do not need duplicate public and private addresses. Use `exposure.internet_ip` for the public entry and `host_ip` or `interfaces[].ip` for the internal address. Add NAT metadata only for a complex path:

```json
{
  "nat": {
    "nat_gateway": "nat-gateway-prod",
    "mapping_type": "dnat"
  }
}
```

Legacy `nat.public_ip`, `nat.private_ip`, `external_ip`, `management_ip`, `management_gateway_ip`, and Host-level `gateway_ip` are read-only compatibility fields and should not be added.

## 4. Relationship to assets and connectors

### 4.1 Asset → Host

Assets no longer use host-binding fields.

Asset host coverage is expressed only through log-source IPs:

```json
{
  "coverage": {
    "hosts": ["198.51.100.2"]
  }
}
```

The platform matches these IPs against:

- `host.host_ip`
- `host.interfaces[].ip`

### 4.2 Connector → Host

Single-host connectors may use `config.host_id` to label the physical collection target:

```json
{
  "connector_id": "conn-ssh-web-01-auth",
  "connector_type": "ssh_file",
  "config": {
    "host": "192.0.2.5",
    "host_id": "host-web-01"
  }
}
```

Do not set `config.host_id` on aggregated SLS or platform-level connectors.

### 4.3 Host → Network

Hosts link to their primary segment via `network_id`:

```json
{
  "host_ip": "192.0.2.5",
  "network_id": "net-prod-web"
}
```

For multi-NIC hosts, declare per-interface networks in `interfaces[].network_id`.

## 5. Minimal example

```json
{
  "host_id": "host-demo-gateway-01",
  "name": "Gateway 主机",
  "hostname": "gateway-host",
  "host_type": "server",
  "host_os": "linux",
  "host_ip": "198.51.100.2",
  "network_id": "net-demo-web-edge",
  "aliases": [
    "gateway",
    "gateway.internal.example"
  ],
  "roles": [
    "syslog-source"
  ],
  "environment": "production",
  "status": "active",
  "tags": [
    "secweaver"
  ]
}
```

## 6. Validation rules

`validate.py` checks in particular:

- `host_id` matches the file name
- `network_id` references exist
- parseable `host_ip` falls within the referenced network CIDR
- `interfaces[].network_id` references exist
- `interfaces[].ip` falls within the referenced network CIDR
- `exposure.exposed_ports` are valid ports
- `asset.coverage.hosts` contains IPs only

## 7. Common mistakes

| Mistake | Cause | Fix |
|---|---|---|
| Putting `web-01` in `coverage.hosts` | coverage allows log-source IPs only | Use the actual source IP; put `web-01` in `host.aliases` |
| Empty `interfaces: []` on a single-NIC host | Adds no information | Omit the field |
| Using a hostname for `host_ip` | Primary address cannot be used for CIDR checks | Add the real IP when possible |
| Setting `config.host_id` on aggregated SLS connectors | Implies a single-host data source | Use only on single-host connectors |
