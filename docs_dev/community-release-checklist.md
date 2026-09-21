# Community Release Checklist

[English / 简体中文](community-release-checklist.zh-CN.md)

For release maintainers. See [real-data safety](../docs_user/community-release-and-data-safety.md) for query integrity, TLS, and masking requirements.

## Independence and release verification

Community contains DataAsset, Skills, CLI, DataAsset Studio and the host collector Agent.
Local synthetic investigations need no private server. Self-managed sources require your own
services, read-only accounts and network access. SaaS SLS Proxy requires the hosted service
and its credentials. Public archives exclude private servers and internal Git history.

Maintainers run these commands from a committed, clean checkout:

```bash
make docs-check
make open-source-export OUTPUT=/tmp/secweaver-community.tar.gz
```

Export reads `HEAD`; uncommitted changes, including private documentation, block export.
Do not discard unfinished work to pass this check. CI writes demo outputs to a temporary
directory so timestamps and local paths do not dirty tracked examples. Published example
reports use repository-relative paths; the release scanner rejects user home paths in them.
Runtime investigation reports may still contain absolute paths: review them before sharing.

Release acceptance includes docs, SBOM, strict validation, tests, offline cases and Studio
startup inside the public archive; dependency installation on a fresh machine; Agent service
upgrade tests on target Linux/Windows systems; and read-only acceptance against target data
sources. Cross-compilation does not prove native operation, and Attack Lab syntax checks do
not prove Docker scenarios ran. Maintainers must configure an available private reporting
channel in the [security policy](../SECURITY.md) before a formal release.


## Acceptance Record

The exporter runs release scanning, documentation checks, SBOM checks, strict asset validation, policy synchronization, public Python tests and offline demos inside the archive, then scans the demo-regenerated reports again. Release scanning also checks public docs, Skills, examples, source, and test fixtures for known internal acceptance networks and common local checkout paths; real acceptance hosts must use documentation addresses and file references must be repository-relative or resolved at runtime before archiving. These do not replace full CI or real-system acceptance. Record each item for every release; partial success is not full acceptance:

| Item | Evidence to record |
|---|---|
| Source and artifacts | Committed revision, Community/Agent versions and archive SHA-256 |
| Automated gates | Commands, exit codes and logs for `make ci` and archive verification; omitted gates and reasons |
| First-use experience | Fresh dependency installation, offline examples and Studio startup |
| Agent platforms | Actual Linux/Windows service install, upgrade and failed-upgrade rollback versions/results |
| Live data | Authorized read-only acceptance scope, outcome and gaps; no credentials |

## Historical material

The internal P0 verification report is excluded from Community and is not release evidence. The four Attack Lab cases are historical scenario narratives. Acceptance must record the current archive version, synthetic inputs, and test results.
