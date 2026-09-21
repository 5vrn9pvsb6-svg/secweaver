# SecWeaver Internal DNS Query Logging Guide

**Languages:** English (this page) | [简体中文](27-internal-dns-logging.zh-CN.md)

This guide explains how to centralize internal DNS queries and onboard them as a SecWeaver `dns_log` asset for traceability, C2/domain analysis, lateral-movement investigation, and completeness governance.

## Goals

Per-host resolver debug logs and packet captures are not suitable long-term audit sources. Direct clients to internal resolvers and record queries centrally.

The solution must:

1. Record queries from internal hosts.
2. Preserve the real `client_ip` for correlation with host, Web, and network evidence.
3. Produce structured records compatible with `dns_log`.
4. Support staged rollout and rollback.
5. Refuse recursive queries from non-internal networks.

## Recommended architecture

```text
Linux / Windows / servers / container nodes
        |
        | DHCP option 6 / resolver configuration
        v
Internal resolver pair (Unbound or BIND)
        |
        | query log or dnstap
        v
Logtail / Vector / Filebeat / Fluent Bit
        |
        v
SLS / Elasticsearch / Kafka
        |
        v
SecWeaver dns_log asset
```

Deploy at least two resolvers, for example `10.0.0.53` and `10.0.0.54`. Avoid a generic L4 load balancer that hides client addresses. If a front end is required, use a DNS-aware component such as dnsdist and log at that layer or preserve identity with a supported protocol.

| Environment | Recommended component |
|---|---|
| Small/medium recursive DNS | Unbound |
| Existing named operations | BIND |
| High-QPS auditing | Unbound/BIND with dnstap |
| Routing, rate limiting, central front end | dnsdist |

## Option selection

Start with text query logs, complete the ingestion and SecWeaver query path, then move to dnstap when throughput requires it.

Recommended sequence:

1. Use Unbound text query logs to prove the path.
2. Ship them with Vector, Filebeat, or Fluent Bit to SLS or Elasticsearch.
3. Validate querying, correlation, and reports through the `dns_log` asset.
4. Move to dnstap or a dnsdist front end only when QPS requires it.

## SecWeaver field contract

| Field | Requirement | Meaning |
|---|---|---|
| `client_ip` | Required | Internal querying host |
| `timestamp` | Required | Query time |
| `query` | Required | Queried domain |
| `response` | Strongly recommended | Returned addresses/names, preferably an array |
| `query_type` | Recommended | A, AAAA, CNAME, TXT, and so on |
| `rcode` | Recommended | NOERROR, NXDOMAIN, SERVFAIL, and so on |
| `evidence_id` | Recommended | Stable deduplication and trace ID |

```json
{
  "asset_type": "dns_log",
  "timestamp": "2026-07-09T10:20:30Z",
  "client_ip": "192.0.2.92",
  "server_ip": "10.0.0.53",
  "query": "example.com.",
  "qname": "example.com.",
  "query_type": "A",
  "rcode": "NOERROR",
  "response": ["93.184.216.34"],
  "latency_ms": 8,
  "protocol": "udp",
  "evidence_id": "dns-20260709-102030-192.0.2.92-example.com-A"
}
```

Relevant repository definitions are `dataasset/assets/asset-dns-internal-prod.json`, `dataasset/configure/evidence-minimum-fields.json`, and `dataasset/query-templates/templates.json`.

## Unbound example

Install Unbound and create `/etc/unbound/unbound.conf.d/secweaver-dns.conf`:

```conf
server:
  interface: 0.0.0.0
  port: 53
  access-control: 10.0.0.0/8 allow
  access-control: 172.16.0.0/12 allow
  access-control: 192.168.0.0/16 allow
  access-control: 0.0.0.0/0 refuse
  access-control: ::0/0 refuse
  logfile: "/var/log/unbound/query.log"
  log-queries: yes
  log-replies: yes
  log-time-ascii: yes
  verbosity: 1
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  qname-minimisation: yes

forward-zone:
  name: "."
  forward-addr: 223.5.5.5
  forward-addr: 119.29.29.29
```

```bash
sudo unbound-checkconf
sudo systemctl enable --now unbound
dig @10.0.0.53 example.com A
sudo tail -f /var/log/unbound/query.log
```

Restrict `access-control` to actual internal CIDRs. Route private zones to internal authorities. At high QPS, rotate text logs or adopt dnstap.

## BIND example

```conf
logging {
  channel query_log {
    file "/var/log/named/query.log" versions 10 size 100m;
    severity info;
    print-time yes;
    print-category yes;
    print-severity yes;
  };
  category queries { query_log; };
};

options {
  recursion yes;
  allow-recursion { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
  allow-query { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
};
```

Use `rndc querylog on` only for temporary activation; production should use persistent configuration and rotation.

## SLS ingestion

1. Create a Logstore such as `secweaver-dns-internal` or `dns-query`.
2. Parse and index `client_ip`, `query`, `qname`, `query_type`, `rcode`, `server_ip`, `response`, and `timestamp`.
3. Use `timestamp` as the event-time field.
4. Set the real connector and Logstore in `asset-dns-internal-prod.json`.
5. Keep the Connector and Asset in `draft` until real records pass query and field validation.

For Elasticsearch, use an index such as `secweaver-dns-*`, map address fields to `ip`, and map names/types/codes and response arrays to `keyword`.

## Client cutover

Prefer DHCP option 6 for managed clients. For static Linux servers, update NetworkManager or the active resolver manager; verify `resolvectl status` on systems using `systemd-resolved`. Evaluate CoreDNS, NodeLocal DNSCache, and Pod DNS policies before changing Kubernetes nodes. Avoid bulk manual edits to `/etc/resolv.conf`, because DHCP clients, cloud-init, NetworkManager, or `systemd-resolved` may overwrite it.

## Rollout plan

Roll out in four phases: 1-3 test hosts, a low-risk production group, one network segment at a time, then full deployment. Prefer DHCP option 6 or managed resolver configuration over manually editing `/etc/resolv.conf`.

Monitor QPS, P50/P95/P99 latency, NXDOMAIN/SERVFAIL/timeouts, cache hit rate, ingestion latency, and `client_ip` preservation.

## Rollback

Rollback must restore the previous DHCP/resolver settings. Keep the old resolver available for at least one observation cycle and roll back only affected segments.

## Security requirements

- Never expose recursion to the Internet.
- Allow internal UDP/TCP 53 only and restrict resolver administration.
- Treat query logs as sensitive behavioral data with access and retention controls.
- Sanitize internal domains and SaaS usage before exporting records.

## SecWeaver development and use cases

The resulting asset supports host-to-domain explanation, victim query history, suspicious/DGA/dynamic-DNS/mining-pool detection, and network-level completeness checks. A future `dns-log-json` Agent module can normalize Unbound, BIND, dnsmasq, and dnstap into the same `dns_log` JSON Lines contract; this is a development recommendation, not a currently shipped collection module.

See also [SecWeaver data system quickstart](29-secweaver-data-system-quickstart.md) and [Data source completeness](15-data-source-completeness.md).
