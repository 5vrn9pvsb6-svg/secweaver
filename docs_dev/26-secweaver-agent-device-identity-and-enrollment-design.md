# SecWeaver Agent Device Identity: Public Client Contract

**Languages:** English (this page) | [简体中文](26-secweaver-agent-device-identity-and-enrollment-design.zh-CN.md)

This document describes the public Agent-side identity and enrollment contract.
The Agent implementation and local lifecycle behavior are available in Community.
Managed enrollment services, quota administration, control-plane storage, and
operator tooling are outside the Community repository scope.

## Identity properties

- A device identity is generated once and persisted outside the replaceable program directory.
- Normal restarts and upgrades reuse the same identity and do not create a new device.
- The private key never leaves the device. Enrollment sends only the public key and bounded device metadata.
- Upgrade and uninstall procedures must not silently overwrite or delete the identity directory.
- If local identity state is lost, the Agent creates a new identity; the service may require an operator to replace the previous device record.

The canonical Agent package version is read from [`VERSION`](../src/tools/secweaver-agent/VERSION). Documentation examples must not be interpreted as the currently installed version.

## Enrollment boundary

Managed enrollment uses a short-lived or usage-limited enrollment token to register the Agent public key. After successful enrollment, normal requests use device-bound signatures rather than repeatedly sending the enrollment token.

The client must:

1. generate its key pair locally;
2. protect identity files with operating-system permissions;
3. validate HTTPS certificates;
4. sign the exact request method, path, timestamp, nonce, and body digest required by the protocol;
5. reject configuration or update responses whose signature or target identity is invalid;
6. avoid logging enrollment tokens, private keys, or complete authorization headers.

The service must reject expired tokens, replayed nonces, excessive clock skew,
disabled devices, and signatures made by revoked keys. These are protocol
requirements; managed service implementation and storage are outside the
Community repository scope.

## Lifecycle expectations

| Event | Expected Agent behavior |
|---|---|
| Process or host restart | Reuse device identity |
| Signed Agent upgrade | Preserve device identity and local rollback state |
| Hardware change | Keep identity; report bounded observations according to configuration |
| Identity directory loss | Generate a new identity and require service-side reconciliation |
| Virtual-machine cloning | Remove template identity before first boot so each clone enrolls independently |
| Device/key revocation | Stop accepting managed configuration and update responses for that identity |

Hardware observations must avoid raw secrets and should minimize persistent hardware identifiers. They are risk signals, not sole authentication factors.

## Community verification

Community contributors can verify local identity persistence, file permissions,
signing, upgrade preservation, rollback behavior, and malformed-response handling
with the Agent tests. End-to-end managed enrollment requires access to an
authorized test tenant and test credentials; those service-side resources are not
included in the Community repository.

See the [`secweaver-agent` engineering manual](../src/tools/secweaver-agent/README.md) for build and test commands, and the [Data Cloud customer quickstart](../docs_user/29-secweaver-data-system-quickstart.md) for the managed installation path.
