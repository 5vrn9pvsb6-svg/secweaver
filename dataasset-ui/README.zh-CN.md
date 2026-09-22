# SecWeaver 数据源接入向导

这是一个轻量本地 DataAsset Studio，用于把 DataAsset 接入和高频编辑动作表单化，并提供校验建议与 demo 报告查看。

> 说明：`dataasset-ui/` 是当前开源默认 UI 实现，不是唯一实现。开发者可以改现有页面、新增页面，也可以基于同一套 DataAsset/API 契约重写整套 UI。贡献规范见 [`docs_dev/25-ui-contribution-guide.zh-CN.md`](../docs_dev/25-ui-contribution-guide.zh-CN.md)。

## 启动

先按[快速上手](../docs_user/00-security-operator-quickstart.zh-CN.md)运行 `make quickstart`，准备 Python 环境。默认编辑 `dataasset/`；如需隔离配置，按[UI 图文教程](../docs_user/11-onboarding-ui-walkthrough.zh-CN.md)复制到 `dataasset_my/` 并设置 `DATAASSET_ROOT`。

在项目根目录执行：

```bash
.venv/bin/python dataasset-ui/server.py
```

然后打开：

```text
http://127.0.0.1:8765
```

如需换端口：

```bash
DATAASSET_UI_PORT=8777 .venv/bin/python dataasset-ui/server.py
```

如需切换到私有真实资产目录，例如 `dataasset_my/`：

```bash
DATAASSET_ROOT=dataasset_my DATAASSET_UI_PORT=8777 .venv/bin/python dataasset-ui/server.py
```

未设置 `DATAASSET_ROOT` 时默认读取发布目录 `dataasset/`。

企业工作台提供两个不同入口：**“secweaver-agent → 一键安装”**用于安装采集端，**“智能体配置”**用于获取查询 AK/SK。本地 UI 只保留安装模板的开发/兼容预览，生产环境应复制企业工作台生成的命令。

开发预览时可显式填写环境变量；下面均为占位示例，应替换为平台提供的配置：

```bash
SECWEAVER_AGENT_BOOTSTRAP_URL=https://updates.example.com/secweaver-agent/install.sh \
SECWEAVER_AGENT_VERSION=YOUR_AGENT_VERSION \
SECWEAVER_ENTERPRISE_ID=YOUR_16_CHAR_ID \
SECWEAVER_LICENSE_SERVER_URL=https://agent-gateway.example.com \
SECWEAVER_LOGTAIL_ENROLLMENT_ID=YOUR_ALIYUN_MACHINE_GROUP_ID \
SECWEAVER_LOGTAIL_ALIUID=1234567890123456 \
.venv/bin/python dataasset-ui/server.py
```

| 用途 | 地址来源 |
|---|---|
| SaaS SLS 查询 | `https://sls-proxy.id-net.cn:30443`；当前没有独立备用入口，配置见 [SLS Proxy 指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md) |
| Agent 安装与授权 | 使用企业工作台签发的安装命令和 Bootstrap 内置的 Agent Gateway 地址；公开 Agent 配置示例为 `https://agent-gateway.id-net.cn:30443` |

`SECWEAVER_LICENSE_SERVER_URL` 是安装预览中的授权地址，不是本地查询 Connector 的 endpoint。开发预览保留历史默认值；验证模板时应显式传入平台提供的授权地址，不应据此推断生产主备配置。所有生产地址均需受信任 HTTPS。

企业 ID 和机器组标识由平台提供。Proxy AK/SK 只用于查询，本地 UI 保存用户创建的查询凭证引用，不签发密钥，也不把它们渲染到安装命令中。预览参数缺失或企业 ID、机器组标识、HTTPS URL 无效时不能复制命令。阿里云 UID 只读展示，不拼入客户机安装参数。

## 当前能力

### 数据源接入

- 从顶部导航进入 `onboarding.html`
- 保留“主机 Agent 快速安装”开发/兼容预览；生产安装命令来自企业工作台的“secweaver-agent → 一键安装”
- 在表单中填写常见数据源字段，再生成运营维护的 `data_sources` 配置
- 通过和 CLI 相同的 `secweaver asset apply --dry-run` 逻辑预览 connector、asset 和 query template
- 确认后写入 `dataasset/connectors/`、`dataasset/assets/` 和 `dataasset/query-templates/templates.json`
- 高阶运营仍可在预览/写入前直接微调配置 JSON
- Connector 类型会显示运行方式：`live_fetch` 表示平台内置执行，`live_or_external_executor` 表示内置执行且可接外部执行器，`local_or_external_executor` 表示可填本地样本或外部执行器 endpoint
- 表单字段来自 Connector Catalog，并由校验器与 Connector Schema 的必填字段交叉检查；AWS S3、Azure、GCP、腾讯 CLS、华为 LTS 和 Splunk 可直接填写各自必填连接参数
- 数据源接入页加载 `/api/onboarding/meta?refresh=1`，会刷新 connector registry / catalog 缓存；也可以调用 `POST /api/connectors/reload` 手动刷新运行时 connector 元数据
- `aws_cloudwatch` 可配合 `examples/executors/aws_cloudwatch_executor.py` 使用，不需要把 `boto3` 安装到核心平台环境

### Asset 管理

- 读取 `dataasset/assets/*.json` 资产列表
- 读取 `dataasset/hosts/*.json` 用于 coverage.hosts 来源 IP 匹配和拓扑展示
- 读取 `dataasset/connectors/*.json` 用于 `connector_id` 下拉
- 读取 `dataasset/query-templates/templates.json` 用于 `query_template_ids` 勾选
- 编辑并保存单个 asset JSON

### Host 管理

- 查询和搜索 `dataasset/hosts/*.json`
- 新增 host
- 编辑 host 基础信息、网络地址、角色、标签
- 保存到 `dataasset/hosts/<host_id>.json`
- 删除 host JSON

### 校验

- JSON 对象保存（包括旧的 `/api/asset`、`/api/host` 入口）会先按所选资产根的 Schema 校验；active 对象还会检查注册表引用与上线规则，修改 Asset/Connector 时也会检查受影响的 active Bundle/Asset。校验失败返回 HTTP 400，旧文件保持原样。
- Studio 的 JSON 保存/删除与 CLI `asset init/apply/rollback/promote` 共用所选 `DATAASSET_ROOT` 内被 Git 忽略的 `.dataasset-write.lock.tmp`；竞争编辑最多等待 10 秒，单个 JSON 文件使用原子替换。批量接入跨多个文件仍不是事务。
- 保存前检查不能代替全目录严格校验或真实连通性测试；修改关联对象后继续运行严格门禁和相应的 Connector 测试。
- 优先使用项目根目录 `.venv/bin/python` 运行 `src/dataasset/validate.py`
- 如果 `.venv/bin/python` 不存在，才回退到启动 UI 服务的 Python
- 运行 `src/dataasset/validate.py`
- 运行 `validate.py --sync-catalog`
- 支持 `validate.py --json` 输出结构化门禁结果，供 UI/CI 消费
- 支持 `validate.py --strict` 将 warning 也作为阻塞项
- 支持 `validate.py --only-active` 只检查 active 对象上线门禁
- UI 的“严格门禁”按钮等价于 `--json --strict --only-active`
- UI 的“运行就绪”按钮执行 `--json --runtime-ready`，分别展示资产根基础校验、
  Bundle 依赖图状态和 blocker；它不会解密凭证或访问后端
- 将 `ERROR/WARN` 转成简单的运营修复建议卡片
- active 资产按上线门禁处理：模板、coverage.hosts、retention、owner、evidence 必需字段、correlation-matrix Join 可达性会被更严格检查
- 凭证生命周期状态只接受 `active`、`disabled`；未知值会被拒绝，不会被静默视为可用

### Demo 报告

- 一键运行 `python3 src/secweaver.py demo all`
- 读取 `examples/reports/*.json` 样例输出
- 展示数据源完整性、告警确认、溯源分析、风险识别四类 demo 的关键结论
- 展示 verdict、confidence、summary、data gaps 和输出文件路径

## SLS Proxy Project 配置

在 Linux/macOS、Python 3.10+ 环境中，接入表单选择 `sls_proxy` 后填写已授权的 `project` 与 `logstore` 组合。Project 可选，省略或留空时使用服务端默认值。应用前预览生成的 Connector，确认 `config.project` 和 `config.logstore`，再按 [SLS Proxy 接入指南](../docs_user/30-sls-proxy-onboarding.zh-CN.md)验收一条真实事件。

显式指定 Project 需要更新后的客户端 SDK 适配器、Go Proxy 0.6.0-rc.14/schema 10 或更新版本，以及管理员配置的 Project 路由和企业资源授权。客户端选择不能创建资源或获得额外权限。Proxy 入口保持不变，不拼接 Project 域名前缀、不填写 `region` 或 `enterprise_id`，也不要为绕过权限或兼容性错误删除 Project。直连 SLS 的 Project 行为不变。

## 设计约束

- 服务只监听 `127.0.0.1`，用于本地配置编辑。
- 只读写当前 DataAsset 根目录：默认 `dataasset/`，或启动时通过 `DATAASSET_ROOT` 指定的目录。
- 当前已支持 asset 与 host 表单；connector、bundle、network 后续可以继续加表单。
- 当前已支持 demo 报告查看；关联关系可视化后续可以继续增强。
- 保存前建议先查看右侧 JSON 预览。
- 修复后仍应通过 Git diff 审阅变更。

## UI 贡献与重写

贡献者可以选择三种粒度：

- **增量改现有 UI**：修改 HTML/JS/CSS、表单、错误提示、国际化文案。
- **新增 UI 模块**：增加 connector、bundle、network、correlation、scenario 或 fetch plan 页面，并接入 `shared-nav.js`。
- **重写 UI**：使用新的前端技术栈，但保留 `DATAASSET_ROOT`、DataAsset 目录结构、`asset apply`、`validate.py --json/--diagnose` 和 `credentials_ref` 契约。

扩展后端 API 时优先在 `server.py` 中复用 `src/secweaver.py` 和 `src/dataasset/validate.py`，不要在 UI 层重写另一套配置生成或校验逻辑。
`server.py` 只放 HTTP 路由；onboarding、credentials、registry、topology、validation 等业务逻辑放在 `dataasset_ui_services/`。

模块页前端已按职责拆分：

| 文件 | 职责 |
|---|---|
| `module-page-config.js` | 共享模块定义、默认模板、资产/主机/凭证枚举 |
| `module-page-utils.js` | DOM 辅助、API wrapper、详情摘要、弹窗辅助、JSON/YAML 同步辅助 |
| `module-page-list.js` | 资产注册表计数、搜索表格、分页和行操作 |
| `module-page-editors.js` | Asset、Host、Credential、Correlation、Scenario 的结构化编辑器 |
| `module-page.js` | 页面状态、详情加载/保存/删除、资产动作和页面初始化 |

样式也已按职责拆分。`style.css` 保持为 HTML 页面的稳定入口，并按顺序导入：

| 文件 | 职责 |
|---|---|
| `styles/00-base.css` | 设计变量、reset、排版、顶部栏、标题区和共享页面壳 |
| `styles/01-layout-nav.css` | Workbench 栅格、侧边栏、面板和资源导航 |
| `styles/02-dashboard-topology.css` | Dashboard 卡片和拓扑可视化 |
| `styles/03-forms-lists.css` | 状态卡片、表单、表格、注册表列表和分页 |
| `styles/04-detail-editor.css` | 详情弹窗、按钮、标签、摘要和结构化编辑器 |
| `styles/05-correlation-validation.css` | 关联解释、建议/报告卡片和校验输出 |
| `styles/06-onboarding.css` | 数据源接入流程、厂商场景、connector catalog 和预览面板 |
| `styles/07-utilities-responsive.css` | 空状态、通用工具类和响应式覆盖 |

## 推荐流程

```text
进入数据源接入
  → 填写基础信息 / 连接参数 / 解析器 / 覆盖范围 / 模板参数
  → 生成配置
  → 预览 connector / asset / template
  → 写入 DataAsset 文件
  → 运行校验
  → 按建议修复 P0/P1
  → 生成 Demo 报告
  → test_connector.py 连通测试
  → Git diff 审阅
```

## 真实数据与发布边界

ES 默认校验证书，支持私有 CA；查询不完整状态会进入取数摘要和报告。
自动证据 ID 已升级为 v2；源日志敏感字段仍需显式配置 masking。
发布检查、兼容性、迁移参数与脱敏示例见[使用说明](../docs_user/community-release-and-data-safety.zh-CN.md)。

## 外部 ES Operator

ES 部署为可选能力，由独立私有项目 `secweaver-es-operator` 维护。
启动 Studio 前，在服务端环境配置可信本地路径；HTTP 请求不能指定可执行程序：

```bash
SECWEAVER_PORTABLE_ROOT=/path/to/secweaver-es-operator \
SECWEAVER_PORTABLE_RUNTIME=/path/to/operator-runtime make ui
```

可选 `SECWEAVER_PORTABLE_COMMAND` 指定具体二进制或启动脚本；否则优先使用项目根目录
启动器，再查找 `bin/secweaver-portable`。运行目录默认是 `<operator-root>/runtime`。
路径可用绝对路径，或相对 Community 根目录的路径。Studio 向 CLI 传递所选 `DATAASSET_ROOT`。
未显式配置时兼容旧仓库内路径；Operator 缺失时部署接口返回不可用，其他 Studio 功能继续工作。
需要兼容版本的 Operator CLI 及其运行依赖；此配置不会自动安装或启动 ES。
可通过 `/api/portable/status` 验证（未初始化时执行 `doctor`，初始化后执行 `status`）。

安装表单按企业、平台和架构选择安装配置，支持选择 Filebeat、Fluent Bit 或 SecWeaver
Shipper（具体平台支持由 Operator 校验）。吊销需填写 `secweaver-portable list-enrollments`
返回的 enrollment key，不再使用主机名；关闭只影响所选配置后续的 ES 凭据接入。
两者都不撤销 Agent Gateway 设备身份或令牌。请在 Studio 启动环境中配置
`SECWEAVER_AGENT_CONTROL_URL`（HTTPS origin）及 `SECWEAVER_AGENT_ENROLLMENT_TOKEN`，
不要将令牌写入前端文件。Agent 升级签名可能还需 `SECWEAVER_AGENT_UPDATE_PUBLIC_KEY`。
当前验证基线为 Operator 0.3.20 的 CLI。修改适配器或升级 Operator 后，在 Community 根目录执行：

```bash
SECWEAVER_OPERATOR_TEST_COMMAND=/absolute/path/secweaver-es-operator/bin/secweaver-portable make test-operator-contract
```

该只读参数契约检查需要 Python 和本机可运行的 Operator 二进制，不初始化 OpenSearch、
不签发凭据。真实注册、上传及吊销仍需在可丢弃部署环境中验收。
