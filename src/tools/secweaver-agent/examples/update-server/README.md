# Standalone Update Server Example

English | [简体中文](README.zh-CN.md)

This example upgrades an **already installed standalone Agent** using a static HTTPS server and binaries. The default manifest is unsigned and protected by HTTPS plus artifact SHA-256/size checks; configure a public key and signing key to enable signed manifests. Managed SaaS/ES deployments still require server eligibility and leases; do not copy this example's `require_server_policy: false` into them.

## Prerequisites and platforms

The build machine needs Go (see module `go.mod`), Python 3, Bash, and a clean Git checkout. An offline-protected Ed25519 release key is optional. Cross-build targets are Linux amd64/arm64/loong64 and Windows amd64/arm64. The nginx and client paths here are Linux examples. Windows needs its own installation paths and actual SCM upgrade, restart, and health-rollback acceptance; cross-compilation is not runtime acceptance.

For initial installation, authorization, and collection, see the [Agent README](../../README.md). This example does not create managed enterprise installation commands or deploy SaaS servers.

## Build update files

Increment and commit `../../VERSION` before a new package build after Agent source, packaged configuration, or documentation changes. The canonical file owns the version: no environment-only override and no different bytes under an existing version. See [release.env.example](release.env.example). Start the following commands at the repository root:

```bash
cd src/tools/secweaver-agent
UPDATE_BASE_URL="https://updates.example.com/secweaver-agent/releases/$(cat VERSION)" \
UPDATE_MANIFEST_GENERATION="${RELEASE_GENERATION:?Set a fresh monotonic integer}" \
UPDATE_MANIFEST_EXPIRES_AT="${RELEASE_EXPIRES_AT:?Set a future RFC3339 UTC expiry}" \
UPDATE_ARTIFACT_SIGNATURE_FORMAT=ed25519-sha256 \
UPDATE_ROLLOUT_PERCENTAGE=10 \
UPDATE_DOWNLOAD_SPREAD_SECONDS=3600 \
./scripts/build-cross.sh
```

The command above produces an unsigned manifest. To enable signing, create the key once with
`go run ./cmd/update-sign -generate-key /secure/path/update-signing.key`, then set
`UPDATE_SIGNING_PRIVATE_KEY_FILE` for the build and configure clients with the generated `.pub` key.
Omitting the key keeps the default HTTPS plus SHA-256 mode.

When signing is enabled, keep the private key mode `0600`; never upload it to the static server or repository. Distribute its `.pub` key to clients through a trusted installation channel. Each new signed manifest needs a larger generation and valid expiry; never sign different content with the same generation. Current artifact signatures default to `ed25519-sha256`; legacy-client transitions need separate compatibility verification. Fix key or version-gate failures rather than bypassing checks.

## Static-server layout

Build output is in the Agent's `dist/`. Copy `secweaver-agent_<VERSION>_<platform>` binaries (`.exe` for Windows) into the matching immutable version directory, then atomically replace the stable manifest:

```text
/srv/secweaver-agent-updates/
├── stable/update-manifest.json
└── releases/<VERSION>/secweaver-agent_<VERSION>_<platform>
```

Use the [nginx configuration](nginx-secweaver-agent-updates.conf) with a valid certificate. Verify every manifest download URL resolves to the matching version, size, and SHA-256. Retain `dist/SOURCE.commit` and `dist/SOURCE.sha256` as build records. Keep signing private keys out of the static directory.

## Client configuration

Merge the `update` block from [client-config.example.json](client-config.example.json) into the installed configuration; preserve existing modules and collection paths. Assign each device a stable unique `device_id`. Add `public_key` only when the published manifest is signed. Use `/secweaver-agent/stable/update-manifest.json` consistently.

`require_server_policy=false` is standalone-only. `enabled=false` disables automatic network checks; `auto_install=false` allows an initial check-only rollout. See the example for health timeout, lock, backup, and disk-space limits. The default six-hour interval does not promise an immediate upgrade after publication.

## Rollout and acceptance

Start with `0% + allow_device_ids`, then increase to 10%, 30%, 50%, and 100%. `deny_device_ids` takes precedence; `download_spread_seconds` spreads downloads by stable device identity. Changed manifest content requires a new signature and larger generation.

Run the default unsigned check below. Add `-public-key BASE64_ED25519_PUBLIC_KEY` when the release is signed:

```bash
secweaver-agent update check \
  -manifest-url https://updates.example.com/secweaver-agent/stable/update-manifest.json \
  -device-id swd_IMMUTABLE_DEVICE_ID
```

`rollout_deferred` means the device is outside rollout, not an installation failure. `update_available` means a version is available, not installed. On an authorized test host, verify installation, service restart, continued collection, and health-failure rollback before expanding rollout. Stop and repair certificate, signature, or expiry failures; do not disable verification.
