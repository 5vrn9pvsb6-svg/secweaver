# Credentials (Local SOPS Vault)

**Languages:** English (this page) | [简体中文](README.zh-CN.md)

Connector JSON files contain **only** `credentials_ref`. Real secrets live in **SOPS-encrypted files**.

```text
vault://sls/security-readonly
    ↓
secrets/sls/security-readonly.enc.yaml   ← local only, not in Git
.age/key.txt                             ← local private key, never commit
examples/sls/security-readonly.yaml      ← placeholder template in repo, safe to commit
```

Intelligent agents pass **only the ref**. The platform decrypts via `src/dataasset/credentials/resolve.py` and injects credentials into connectors. Secrets never enter the prompt.

The committed public registry intentionally contains no `secrets/*.enc.yaml` files.
`secweaver.py validate` accepts an active connector when its `credentials_ref` has
a matching placeholder under `examples/`; custom DataAsset roots still warn until
their local encrypted credential exists. Live fetch always requires initialized,
non-placeholder credentials.

The optional `credential-status.json` accepts only `vault://namespace/name` keys
and `active` or `disabled` values; see `schema/credential-status.schema.json`.
Validation, Studio, and runtime reject malformed references or unknown states
instead of silently treating them as active; reference paths cannot contain `.`
or `..` segments.

---

## Quick start (3 steps)

Run all commands from the repository root; do not change into `dataasset/credentials/`.
Use `dataasset/` directly by default, or optionally copy to `dataasset_my/` for isolation. Paths such as `secrets/`, `examples/`, and `.age/` are relative to `credentials/` under the selected root. Keep real ciphertext and private keys local; never commit them.

### 1. Prepare the local environment

Use a Linux/macOS POSIX terminal or WSL2 with Python 3.10+ and Make. Windows users
must first complete the [WSL2 quickstart](../../docs_user/00-security-operator-quickstart.md);
native Windows is not a supported Community credential-client environment. CLI
initialization requires Bash 4+, `sops`, `age`, and `age-keygen`. On macOS with Homebrew installed:

```bash
brew install bash sops age
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
bash --version
```

Confirm Bash is version 4 or newer. On Linux, install the tools through your local package
management process. Without Homebrew, have an administrator provide executables on PATH;
do not run brew commands blindly. Then prepare the default asset directory:

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

For isolation, optionally run this before saving; preserve an existing directory:

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

Use the same selected root for UI, CLI, and the AI agent. In new terminals, set `DATAASSET_ROOT` and activate the virtual environment again; specify the root to desktop agents. Alternatively, run `make ui` to initialize/edit credentials; the UI also requires SOPS/age.

### 2. Initialize the local Vault

Only initialize a new local Vault; preserve existing keys and SOPS policy:

```bash
bash src/dataasset/credentials/sops-vault.sh init
```

`init` generates the local age private key `.age/key.txt` and `.sops.yaml`.
Full `bootstrap` is unnecessary: it encrypts all placeholder templates, not usable sources.

### 3. Edit the credential you actually use

```bash
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
bash src/dataasset/credentials/sops-vault.sh get vault://sls/security-readonly
```

Replace placeholders in the editor; SOPS re-encrypts on save. `get` is redacted by default.
This example is a direct SLS read credential. SaaS queries use platform-issued Proxy Keys;
follow [SLS Proxy onboarding](../../docs_user/30-sls-proxy-onboarding.md) for the right ref.
Do not mix RAM and Proxy Keys. See below for ES credential fields.

---

## ref-to-file mapping

| credentials_ref | Encrypted file | Example template |
|---|---|---|
| `vault://sls/security-readonly` | `secrets/sls/security-readonly.enc.yaml` | `examples/sls/security-readonly.yaml` |
| `vault://ssh/readonly-web-01` | `secrets/ssh/readonly-web-01.enc.yaml` | `examples/ssh/readonly-web-01.yaml` |
| `vault://ssh/readonly-bastion` | `secrets/ssh/readonly-bastion.enc.yaml` | `examples/ssh/readonly-bastion.yaml` |
| `vault://ssh/demo-web-exec` | `secrets/ssh/demo-web-exec.enc.yaml` | `examples/ssh/demo-web-exec.yaml` |
| `vault://db/ai-readonly` | `secrets/db/ai-readonly.enc.yaml` | `examples/db/ai-readonly.yaml` |
| `vault://waf/api-readonly` | `secrets/waf/api-readonly.enc.yaml` | `examples/waf/api-readonly.yaml` |
| `vault://es/security-readonly` | `secrets/es/security-readonly.enc.yaml` | `examples/es/security-readonly.yaml` |
| `vault://threat-intel/virustotal` | `secrets/threat-intel/virustotal.enc.yaml` | `examples/threat-intel/virustotal.yaml` |

To add a new ref, create a matching YAML under `credentials/examples/` in the selected asset root, then run `bash src/dataasset/credentials/sops-vault.sh edit vault://...`.

---

## Common commands

These commands retain the asset root and virtual environment selected above:

```bash
bash src/dataasset/credentials/sops-vault.sh list
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
bash src/dataasset/credentials/sops-vault.sh get vault://sls/security-readonly
```

`resolve.py` and the Vault `resolve` subcommand inject real secrets into the data access layer;
`get --show-secrets` also prints plaintext. They are not user acceptance steps.
Do not put their output in AI prompts, screenshots, or tickets. Validate real access with
the read-only query tests in [source configuration](../../docs_user/03-configure-data-sources.md).

Environment variables (optional):

| Variable | Description |
|---|---|
| `SOPS_AGE_KEY_FILE` | Path to age private key; default `credentials/.age/key.txt` |
| `SOPS_CONFIG` | Default `credentials/.sops.yaml` |

---

## Secret field conventions

### SLS (`type: aliyun_ram`)

```yaml
type: aliyun_ram
access_key_id: "LTAIxxxx"
access_key_secret: "xxxx"
# security_token: ""   # STS optional
```

### SSH (`type: ssh`)

```yaml
type: ssh
username: readonly
auth_method: key   # or password
private_key: "REPLACE_ME_WITH_LOCAL_SOPS_ENCRYPTED_PRIVATE_KEY"
password: ""
```

### MySQL (`type: mysql`)

```yaml
type: mysql
username: ai_readonly
password: "xxxx"
```

### PostgreSQL (`type: postgresql`)

```yaml
type: postgresql
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` must be `postgresql` (credential `type: postgres` / `pg` is also accepted).

### Oracle / PLSQL (`type: oracle` or `type: plsql`)

```yaml
type: oracle
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` may be `oracle` or `plsql`. Configure `connector.config.dsn`, or provide `host`, `port`, and `database` / `service_name`.

### SQL Server (`type: sqlserver` or `type: mssql`)

```yaml
type: sqlserver
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` may be `sqlserver` or `mssql`. Live fetch uses optional dependency `pyodbc`.

### SQLite (`type: sqlite`)

```yaml
type: sqlite
```

SQLite usually does not need a username/password. Use `connector.config.path` or `connector.config.database` for the read-only database file.

### MongoDB (`type: mongodb`)

```yaml
type: mongodb
username: readonly
password: "xxxx"
```

Live fetch uses optional dependency `pymongo`.

### Redis (`type: redis`)

```yaml
type: redis
password: "xxxx"
```

Live fetch uses optional dependency `redis`.

### WAF API (`type: http_api`)

```yaml
type: http_api
auth_method: bearer
token: "xxxx"
```

### VirusTotal (`type: virustotal`)

```yaml
type: virustotal
token: "xxxx"
```

### Elasticsearch (`type: es`)

```yaml
type: es
username: es_readonly
password: "xxxx"
# or api_key: "id:secret"
```

---

## Git and security rules

| Safe to commit | Never commit |
|---|---|
| `examples/` (placeholders only) | Any file under `secrets/` (including SOPS ciphertext) |
| `.sops.yaml` (public key only) | `.age/key.txt` (private key) |
| `credentials_ref` (in connector JSON) | Plaintext AccessKey / password |

Follow the quickstart above: initialize only the local copy and edit the credentials you use. Do not generate ciphertext in the public directory.

To share ciphertext across a team: distribute the age private key or encrypted `secrets/` package through a secure channel. **Do not** commit to a public Git repo.

---

## Relationship to connectors

Example from `connectors/conn-sls-waf-prod.json`:

```json
{
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "project": "YOUR_SLS_PROJECT",
    "logstore": "waf-alert"
  }
}
```

- **config**: non-sensitive connection parameters; safe to edit in plaintext
- **credentials_ref**: points to encrypted files under `secrets/`
- **AI**: sees only the ref, never the secret
