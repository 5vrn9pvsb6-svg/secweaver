# 凭证（本地 SOPS Vault）

连接器 JSON 里**只写** `credentials_ref`，真实密钥存放在 **SOPS 加密文件**中。

```text
vault://sls/security-readonly
    ↓
secrets/sls/security-readonly.enc.yaml   ← 仅本机，不进 Git
.age/key.txt                             ← 本机私钥，绝不提交
examples/sls/security-readonly.yaml      ← 仓库内占位模板，可提交
```

智能体 **只传 ref**，平台用 `src/dataasset/credentials/resolve.py` 解密后注入连接器，密钥不进 prompt。

公开仓有意不提交任何 `secrets/*.enc.yaml`。当公开 DataAsset 根中的 active connector
能在 `examples/` 找到与 `credentials_ref` 对应的占位模板时，`secweaver.py validate`
不会把缺少本地密文视为 warning；自定义 DataAsset 根仍会告警，直到本地密文就绪。
实时查询始终要求已初始化且不含占位值的真实凭据。

可选的 `credential-status.json` 只允许 `vault://namespace/name` 键以及 `active`、
`disabled` 两种状态，契约见 `schema/credential-status.schema.json`。未知状态或非法引用会让
校验、Studio 和运行时失败，不会被静默当作 active；引用路径不允许包含 `.`、`..` 段。

---

## 快速开始（3 步）

全部命令从仓库根目录执行，不要切换到 `dataasset/credentials/`。
默认直接使用 `dataasset/`，也可复制到 `dataasset_my/` 隔离。下文 `secrets/`、`examples/` 和 `.age/` 均相对于所选资产根目录的 `credentials/`；真实密文和私钥只保存在本地，不提交 Git。

### 1. 准备本地环境

使用 Linux/macOS POSIX 终端、Python 3.10+ 和 Make。CLI 初始化需要 Bash 4+，
以及 `sops`、`age`、`age-keygen`。macOS 已有 Homebrew 时可执行：

```bash
brew install bash sops age
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
bash --version
```

确认 Bash 为 4 或更新版本；Linux 按本机软件包管理流程安装这些工具。
不使用 Homebrew 时由管理员提供可执行文件并加入 PATH，不要直接套用 brew 命令。
然后准备默认资产目录：

```bash
make quickstart
source .venv/bin/activate
export DATAASSET_ROOT=dataasset
```

需要隔离时，在写入前选择以下可选步骤；已有目录不覆盖：

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
```

UI、CLI 和智能体使用同一个所选资产根目录。新终端重新设置 `DATAASSET_ROOT` 并激活虚拟环境；桌面智能体需明确指定该目录。也可运行 `make ui` 在凭证页完成初始化和编辑，UI 同样需要 SOPS/age。

### 2. 初始化本机 Vault

仅对尚未初始化的本地 Vault 执行，不重建已有密钥或覆盖已有 SOPS 策略：

```bash
bash src/dataasset/credentials/sops-vault.sh init
```

`init` 生成本机 age 私钥 `.age/key.txt` 与 `.sops.yaml`。
不必执行全量 `bootstrap`；它会加密整套占位模板，并不代表这些数据源已接入。

### 3. 编辑实际使用的凭证

```bash
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
bash src/dataasset/credentials/sops-vault.sh get vault://sls/security-readonly
```

编辑器中替换占位值，保存后 SOPS 自动重新加密；`get` 默认脱敏。
这里只示范直连 SLS 的只读凭证。SaaS 查询使用平台签发的 Proxy Key，
按 [SLS Proxy 接入](../../docs_user/30-sls-proxy-onboarding.zh-CN.md)选择对应 ref，
不要把 RAM Key 与 Proxy Key 混用。ES 凭证类型见下文。

---

## ref 与文件映射

| credentials_ref | 加密文件 | 示例模板 |
|---|---|---|
| `vault://sls/security-readonly` | `secrets/sls/security-readonly.enc.yaml` | `examples/sls/security-readonly.yaml` |
| `vault://ssh/readonly-web-01` | `secrets/ssh/readonly-web-01.enc.yaml` | `examples/ssh/readonly-web-01.yaml` |
| `vault://ssh/readonly-bastion` | `secrets/ssh/readonly-bastion.enc.yaml` | `examples/ssh/readonly-bastion.yaml` |
| `vault://ssh/demo-web-exec` | `secrets/ssh/demo-web-exec.enc.yaml` | `examples/ssh/demo-web-exec.yaml` |
| `vault://db/ai-readonly` | `secrets/db/ai-readonly.enc.yaml` | `examples/db/ai-readonly.yaml` |
| `vault://waf/api-readonly` | `secrets/waf/api-readonly.enc.yaml` | `examples/waf/api-readonly.yaml` |
| `vault://es/security-readonly` | `secrets/es/security-readonly.enc.yaml` | `examples/es/security-readonly.yaml` |
| `vault://threat-intel/virustotal` | `secrets/threat-intel/virustotal.enc.yaml` | `examples/threat-intel/virustotal.yaml` |

新增 ref：在所选资产目录的 `credentials/examples/` 建同名路径 YAML → `bash src/dataasset/credentials/sops-vault.sh edit vault://...`

---

## 常用命令

以下命令沿用前文 `DATAASSET_ROOT` 和虚拟环境：

```bash
bash src/dataasset/credentials/sops-vault.sh list
bash src/dataasset/credentials/sops-vault.sh edit vault://sls/security-readonly
bash src/dataasset/credentials/sops-vault.sh get vault://sls/security-readonly
```

`resolve.py` 和 Vault 的 `resolve` 子命令是数据访问层的密钥注入接口，会输出真实凭证；
`get --show-secrets` 也会显示明文。它们不是用户验收步骤，不要把输出交给 AI、截图或工单。
真实接入验收应使用[数据源指南](../../docs_user/03-configure-data-sources.zh-CN.md)中的只读查询测试。

环境变量（可选）：

| 变量 | 说明 |
|---|---|
| `SOPS_AGE_KEY_FILE` | age 私钥路径，默认 `credentials/.age/key.txt` |
| `SOPS_CONFIG` | 默认 `credentials/.sops.yaml` |

---

## 密钥字段约定

### SLS（`type: aliyun_ram`）

```yaml
type: aliyun_ram
access_key_id: "LTAIxxxx"
access_key_secret: "xxxx"
# security_token: ""   # STS 可选
```

### SSH（`type: ssh`）

```yaml
type: ssh
username: readonly
auth_method: key   # 或 password
private_key: |
  REPLACE_ME_WITH_LOCAL_SOPS_ENCRYPTED_PRIVATE_KEY
password: ""
```

### MySQL（`type: mysql`）

```yaml
type: mysql
username: ai_readonly
password: "xxxx"
```

### PostgreSQL（`type: postgresql`）

```yaml
type: postgresql
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` 须为 `postgresql`（亦接受凭证 `type: postgres` / `pg`）。

### Oracle / PLSQL（`type: oracle` 或 `type: plsql`）

```yaml
type: oracle
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` 可为 `oracle` 或 `plsql`。可配置 `connector.config.dsn`，或填写 `host`、`port`、`database` / `service_name`。

### SQL Server（`type: sqlserver` 或 `type: mssql`）

```yaml
type: sqlserver
username: ai_readonly
password: "xxxx"
```

`connector.config.engine` 可为 `sqlserver` 或 `mssql`。live fetch 使用可选依赖 `pyodbc`。

### SQLite（`type: sqlite`）

```yaml
type: sqlite
```

SQLite 通常不需要用户名密码。通过 `connector.config.path` 或 `connector.config.database` 指向只读数据库文件。

### MongoDB（`type: mongodb`）

```yaml
type: mongodb
username: readonly
password: "xxxx"
```

live fetch 使用可选依赖 `pymongo`。

### Redis（`type: redis`）

```yaml
type: redis
password: "xxxx"
```

live fetch 使用可选依赖 `redis`。

### WAF API（`type: http_api`）

```yaml
type: http_api
auth_method: bearer
token: "xxxx"
```

### VirusTotal（`type: virustotal`）

```yaml
type: virustotal
token: "xxxx"
```

### Elasticsearch（`type: es`）

```yaml
type: es
username: es_readonly
password: "xxxx"
# 或 api_key: "id:secret"
```

---

## Git 与安全规则

| 可提交 | 禁止提交 |
|---|---|
| `examples/`（仅占位符） | `secrets/` 下任何文件（含 SOPS 密文） |
| `.sops.yaml`（仅公钥） | `.age/key.txt`（私钥） |
| `credentials_ref`（connector JSON） | AccessKey / 密码明文 |

按上方快速开始，仅在本地副本初始化 Vault，再编辑实际使用的凭证；不要在公开目录生成密文。

团队共享密文时：通过安全渠道分发 age 私钥或加密后的 `secrets/` 包，**不要**提交到公开 Git。

---

## 与 connectors 的关系

`connectors/conn-sls-waf-prod.json` 示例：

```json
{
  "credentials_ref": "vault://sls/security-readonly",
  "config": {
    "project": "YOUR_SLS_PROJECT",
    "logstore": "waf-alert"
  }
}
```

- **config**：非敏感连接参数，可明文编辑
- **credentials_ref**：指向 `secrets/` 加密文件
- **AI**：只见 ref，不见 secret
