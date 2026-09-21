# SLS Proxy Community Contract and Security Boundaries

**Languages:** English (this page) | [简体中文](23-sls-proxy-multi-tenant-design.zh-CN.md)

This document defines the public client contract and security expectations for connecting SecWeaver Community to the managed SLS Proxy. The Community archive includes the `sls_proxy` connector, schemas, examples, and client tests. It does not include the proxy server, control plane, production credentials, or server deployment tooling.

## Public integration contract

Community clients configure:

- `connector_type: sls_proxy`;
- the HTTPS endpoint and an optional fallback endpoint;
- a credential reference for the Proxy API key;
- the logical Logstore used by each asset.

The managed service configuration matches the public connector example:

```json
{
  "name": "SecWeaver managed SLS Proxy",
  "endpoint": "https://sls-proxy.id-net.cn:30443",
  "fallback_endpoint": "https://sls-proxy.id-net.cn:30443"
}
```

The example uses the same address for both fields. The client deduplicates them into one endpoint; this does not provide an independent fallback or high availability. Set a different `fallback_endpoint` only when the operator provides a compatible independent endpoint.

Start from [`conn-sls-proxy-demo.json`](../dataasset/connectors/conn-sls-proxy-demo.json) and follow the [SLS Proxy onboarding guide](../docs_user/30-sls-proxy-onboarding.md). Do not embed a Proxy API key in Git-tracked JSON.

## Security invariants

Any compatible SLS Proxy service must enforce these externally observable properties:

1. Authenticate the client before querying the upstream data source.
2. Bind tenant identity on the server; never trust a tenant identifier supplied in query parameters.
3. Inject mandatory tenant filters after parsing the request and reject expressions that cannot be constrained safely.
4. Use a separate server-held upstream credential; never forward the client API key to upstream SLS.
5. Apply query time, result size, concurrency, and rate limits.
6. Return generic authentication failures while keeping detailed reasons in controlled audit logs.
7. Revoke a client key without requiring changes to Community DataAsset files.
8. Use valid HTTPS certificates. Clients must not disable certificate verification.

The Proxy API key proves access to the proxy; it is not an Alibaba Cloud AccessKey and must not be used as one.

## Data isolation expectations

Community can verify the client protocol and normalized response contract, but it cannot prove a managed service's server-side tenant isolation. Service operators must separately test cross-tenant denial, filter rewriting, key revocation, audit coverage, and upstream credential containment.

Users should treat empty results as an evidence state, not proof of isolation. Isolation verification requires positive and negative tests with two controlled tenants.

## Compatibility and failure behavior

- If an independent fallback endpoint is configured, it must expose the same client contract as the primary.
- A client may retry the fallback only for connection failures, timeouts, or retriable server failures; authentication and validation failures must not be retried as failover.
- Certificate, trust-chain, hostname, and other TLS/SSL failures stop the request; do not switch endpoints or disable verification. Repair trust using the [TLS/CA onboarding guide](../docs_user/30-sls-proxy-onboarding.md).
- Queries must remain bounded by the requested investigation window.
- When all configured endpoints are unavailable, Skills must report a data gap instead of producing a clean security verdict.

## Public and private ownership

| Community repository | Managed/private delivery |
|---|---|
| Connector schema and examples | Proxy server implementation |
| Client request and response handling | Tenant/control database |
| DataAsset and query templates | KMS/HSM and upstream SLS credentials |
| Client-side contract tests | Server isolation and deployment tests |
| User onboarding documentation | Operator CLI, backup, and production deployment |

This boundary is intentional: the open repository provides everything needed to connect a compatible client, while server implementation and operations are delivered and validated independently.
