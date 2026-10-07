# 凭证（本地 SOPS Vault）

连接器 JSON 里**只写** `credentials_ref`，真实密钥存放在 **SOPS 加密文件**中。
引用格式是 `vault://namespace/name`：`namespace` 用于分组目录，不是 YAML 的 `type`。
例如 `vault://sls/sls-proxy-query` 的类型为 `aliyun_ram`，`vault://db/ai-readonly`
可以使用 `mysql`。UI 和 CLI 均保留原引用，无需重命名或修改 Connector。

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

使用 Linux/macOS POSIX 终端或 WSL2、Python 3.10+ 和 Make。Windows 用户须先完成
[WSL2 快速上手](../../docs_user/00-security-operator-quickstart.zh-CN.md)；原生 Windows
不是受支持的 Community 凭证客户端环境。CLI 初始化需要 Bash 3.2+、`sops` 和
`age-keygen`（由 age 提供）。macOS 已有 Homebrew 时可执行：

```bash
brew install sops age
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
```

支持 macOS 自带 Bash；Linux 按本机软件包管理流程安装这些工具。
不使用 Homebrew 时由管理员提供可执行文件并加入 PATH，不要直接套用 brew 命令。
然后准备默认资产目录：

```bash
export DATAASSET_ROOT=dataasset
make quickstart
source .venv/bin/activate
```

需要隔离时，应在 quickstart **之前**选择下列资产目录，替代默认步骤。应复制全新的
公开资产样例，不复制已有本机私钥或真实凭证的目录；已有目录不覆盖：

```bash
if [ ! -e dataasset_my ]; then
  cp -R dataasset dataasset_my
fi
export DATAASSET_ROOT=dataasset_my
make quickstart
```

UI、CLI 和智能体使用同一个所选资产根目录。新终端重新设置 `DATAASSET_ROOT` 并激活虚拟环境；桌面智能体需明确指定该目录。初始化后可运行 `make ui` 在凭证页编辑，UI 同样需要 SOPS/age；保存不会自动初始化 Vault。

### 2. 确认本机 Vault

Community 0.3.24+ 的默认 quickstart 自动初始化所选 Vault，成功后无需另行 `init`。
使用 `make setup`、旧版 quickstart 或 `SKIP_VAULT=1` 时，可执行同一幂等入口：

```bash
bash src/dataasset/credentials/sops-vault.sh init
```

空 Vault 缺少策略或使用原样的公开占位模板时，`init` 生成本机 age 私钥 `.age/key.txt`
（权限 `600`）与 `.sops.yaml`。已有密钥复用，不重新生成；已有非占位策略逐字节保留，
仅通过原生 SOPS 验证，外部密钥仍受支持。
不必执行全量 `bootstrap`；它会加密整套占位模板，并不代表这些数据源已接入。

Community 0.3.25+ 仅分发 `.sops.yaml.example`，不分发运行时 `.sops.yaml`。
全新克隆在初始化前没有运行时策略属于正常情况，quickstart 会在本地生成。
Git 和源码归档均排除该策略、`.age/`（包括锁和探针）及 `secrets/`，
自定义资产根目录也遵守相同边界。

**生命周期与失败处理：** `quickstart.py` 和 Bash `init` 入口共用
`src/dataasset/credentials/init_vault.py`。持久的 `.age/init.lock` 锁串行化初始化操作，
候选文件在私有临时目录中生成，合成探针加密/解密成功后先刷盘并原子发布密钥，再发布策略。
失败会清理候选文件；两步发布间中断时保留已发布的密钥，下次可安全复用。初始化运行时
不要删除锁文件。已有 `secrets/*.enc.yaml` 却缺少有效策略、自定义策略含占位符、密钥/
策略无效、工具缺失或原生加密操作超过 30 秒时，停止而不修改已有密钥和策略。
程序不自动安装系统软件包，也不读取真实凭证。

默认合成探针路径为 `vault://sls/sls-proxy-query`；已有策略仅允许其他路径时，可指定：

```bash
make quickstart VAULT_CHECK_REF=vault://es/private-query
# 不重新运行完整 quickstart 时：
bash src/dataasset/credentials/sops-vault.sh init --check-ref vault://es/private-query
```

`make quickstart SKIP_VAULT=1` / `quickstart.py --skip-vault` 仅跳过 Vault 步骤并明确警告，
用于零凭证离线 demo，不能因此保存凭证或执行真实查询。`make setup` 仍只准备 Python。

若 UI 保存时报 `unknown recipient type: "REPLACE_WITH_YOUR_AGE_PUBLIC_KEY"`，
说明当前资产根下的 `.sops.yaml` 仍是未初始化的公开模板；刷新浏览器不能修复。
先在同一个 `DATAASSET_ROOT` 初始化 Vault，再重新保存；UI 每次保存都会读取本地策略，无需重启。
已有密文时不要新建密钥或覆盖策略，应恢复原策略和对应私钥。
`.age/key.txt` 必须安全备份，丢失后将无法解密已保存的凭证；私钥不得提交 Git 或公开分享。

Community 0.3.23 起，UI 保存和 ES 接入向导在写入真实凭证临时文件前执行只读检查，
使用非敏感探针验证当前 ref 对应的 SOPS 策略能否加密、解密，不读取已有凭证。
缺少/不可读策略、占位公钥、缺少 SOPS、策略错误、密钥无法解密或检查超过 30 秒时停止保存，
保留表单输入和已有文件。不会自动初始化、覆盖策略或生成新密钥。
外部 `SOPS_AGE_KEY_FILE`、SOPS 原生密钥发现和高级策略格式仍交给 SOPS 验证；
不强制要求本地 `.age/key.txt`，但 UI 必须能够解密探针。
超时后 UI 会终止该检查独占进程组中的 Bash/SOPS 子进程，不影响其他保存请求。

也可在同一环境中手动检查指定 ref：

```bash
bash src/dataasset/credentials/sops-vault.sh check vault://sls/sls-proxy-query
```

UI 检查有 30 秒总超时；直接运行 CLI `check` 不设置总超时，外部密钥服务场景按需使用进程超时工具。
检查通过不等于实际数据源已连通，也不能替代保存时后续加密错误的处理。

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
| `.sops.yaml.example`（仅占位符） | 本机 `.sops.yaml` 和 `.age/` 下所有文件 |
| `credentials_ref`（connector JSON） | AccessKey / 密码明文 |

按上方快速开始，在所选本机 Vault 中初始化并编辑实际凭证。运行时策略、密钥和
密文可以保存在本机 `dataasset/` 工作副本，但不得进入公开 Git 或源码归档。
策略里的 age recipient 是公钥，不是私钥，但属于本机环境标识；发布门禁按路径
阻止运行时文件进入发行内容，不依赖文件是否含真实密钥。

忽略规则不会取消已有文件的跟踪。已经跟踪的运行时策略应**仅从索引移除，保留本机文件**：

```bash
git rm --cached -- dataasset/credentials/.sops.yaml
git check-ignore dataasset/credentials/.sops.yaml
make release-scan
```

自定义资产根使用相应路径。在拉取取消策略跟踪的新版本之前，先安全备份原策略与
匹配私钥；若 Git 更新删除了原来跟踪的策略，恢复原策略。不要用占位模板覆盖已初始化
策略，也不要为已有密文生成替代密钥。已有密文却缺少策略时程序会主动阻止初始化，
应恢复原材料并针对实际 ref 再运行 `sops-vault.sh check`。

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
