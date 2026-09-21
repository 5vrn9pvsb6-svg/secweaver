# Third-Party Notices

SecWeaver Community is licensed under Apache-2.0. The source tree declares the
third-party dependencies below. Copyright remains with their respective owners.
License identifiers use SPDX syntax; consult each upstream distribution for its
complete license text and notices.

This inventory is generated from `requirements-data-access.txt`,
`src/tools/secweaver-agent/go.mod`.
Python entries are declared direct dependencies
with version constraints, not a complete environment-specific transitive lock.
The CycloneDX source SBOM records the same limitation explicitly.

| Ecosystem | Package | Declared version | Scope | SPDX license |
|---|---|---|---|---|
| `golang` | `github.com/beorn7/perks` | `v1.0.1` | `indirect` | `MIT` |
| `golang` | `github.com/cespare/xxhash/v2` | `v2.2.0` | `indirect` | `MIT` |
| `golang` | `github.com/cilium/ebpf` | `v0.16.0` | `direct` | `MIT` |
| `golang` | `github.com/prometheus/client_golang` | `v1.19.1` | `direct` | `Apache-2.0` |
| `golang` | `github.com/prometheus/client_model` | `v0.5.0` | `direct` | `Apache-2.0` |
| `golang` | `github.com/prometheus/common` | `v0.48.0` | `indirect` | `Apache-2.0` |
| `golang` | `github.com/prometheus/procfs` | `v0.12.0` | `indirect` | `Apache-2.0` |
| `golang` | `go.uber.org/goleak` | `v1.3.0` | `direct` | `MIT` |
| `golang` | `golang.org/x/exp` | `v0.0.0-20230224173230-c95f2b4c22f2` | `indirect` | `BSD-3-Clause` |
| `golang` | `golang.org/x/mod` | `v0.16.0` | `direct` | `BSD-3-Clause` |
| `golang` | `golang.org/x/sys` | `v0.20.0` | `direct` | `BSD-3-Clause` |
| `golang` | `google.golang.org/protobuf` | `v1.33.0` | `indirect` | `BSD-3-Clause` |
| `pypi` | `aliyun-log-python-sdk` | `>=0.9.47` | `direct` | `MIT` |
| `pypi` | `jsonschema` | `>=4.21.0` | `direct` | `MIT` |
| `pypi` | `paramiko` | `>=3.4.0` | `direct` | `LGPL-2.1-or-later` |
| `pypi` | `psycopg` | `>=3.1.18; extras=binary,pool` | `direct` | `LGPL-3.0-only` |
| `pypi` | `pymysql` | `>=1.1.0` | `direct` | `MIT` |
