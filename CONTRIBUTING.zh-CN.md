# 参与 SecWeaver 贡献

**语言：** [English](CONTRIBUTING.md) | 简体中文（本文）

感谢你帮助改进 SecWeaver。

## 如何参与

```text
想法或问题
  → 搜索已有 Issue / Discussion
  → 提交 Issue（使用模板）或发起 Discussion
  → Fork → 创建分支 → 修改 → make ci → Pull Request
  → 维护者评审 → 合并 → 更新 CHANGELOG / 发布说明
```

| 渠道 | 用途 |
|---|---|
| 仓库 Issues | Bug、功能、文档缺口、DataAsset 示例请求 |
| 仓库 Discussions（启用时） | 使用问题、场景设计、编码前 RFC |
| Pull Request | 所有要合并的代码、示例、文档和测试 |
| [SECURITY.zh-CN.md](SECURITY.zh-CN.md) | 安全漏洞，必须私下报告，不要发公开 Issue |

Issue 和 PR 模板位于 [`.github/`](.github/)。

维护者常用标签：`bug`、`enhancement`、`documentation`、`dataasset`、`good first issue`。

如果你刚接触仓库，先阅读[新贡献者快速开始](docs_dev/01-new-contributor-quickstart.zh-CN.md)。

## 贡献范围

适合的开源贡献包括：

- 改进 DataAsset schema。
- 脱敏的 asset、connector、host、network、bundle 和查询模板示例。
- 基础 Skill 和确定性辅助脚本。
- 离线 demo 输入及预期输出。
- 文档、接入指南和排障说明。
- CLI、校验、数据访问、解析器和 Skill 测试。

请不要提交：

- 真实凭证、Token、私钥、生产 vault 文件或 API Secret。
- 未明确脱敏的客户日志、生产调查报告或内部 IP 清单。
- 专有企业 Connector 实现。
- 客户专用检测规则、allowlist 或响应剧本。
- 没有明确安全/ dry-run 边界、会对生产系统执行破坏性 SOAR 操作的代码。

## 提交 Pull Request 前

### 代码与注释规范

代码注释是合并要求，不是可选的清理工作。当行为不能从代码结构直接看懂时，
每次代码变更都必须同时新增或更新注释。

- 说明设计意图和实现原因，不要把每条语句翻译成注释。
- 明确记录并发与锁归属、生命周期及顺序假设、资源上限、性能权衡、兼容处理、安全边界、重试、回滚和降级行为。
- 按语言惯例为导出 API 编写文档。
- 行为变化时同步更新或删除过时注释。测试不能替代不变量和运行假设的说明。
- 简单 accessor 和直接赋值不需要叙述；重复语法的注释不满足要求。

非显然逻辑缺少注释或注释误导时，PR 还不能合并。全仓规则也记录在 [`AGENTS.md`](AGENTS.md)，
自动化编码任务在编辑前会遵守它。

工具和平台要求见[开发环境说明](docs_dev/01-new-contributor-quickstart.zh-CN.md#环境与命令约定)。仅准备 Python 环境不足以运行完整门禁；还需 Go/race 编译工具链。局部检查和跳过项应如实记录，不能写成完整 CI 通过。

运行与 CI 相同的检查：

```bash
make ci
```

可选的本地检查（不等价于完整 CI 门禁）：

```bash
.venv/bin/python src/secweaver.py validate
.venv/bin/python tests/run_tests.py
.venv/bin/python src/secweaver.py demo all
make docs-check
make sbom-check
```

`make ci` 会执行完整门禁，包括依赖准备、发布扫描、文档、SBOM、Agent、Attack Lab、
DataAsset 校验、规则同步、测试和 demo。以上命令假设 `make setup` 已创建 `.venv`，不能替代完整门禁。

测试目录和 CLI/demo 回归要求见 [`tests/README.zh-CN.md`](tests/README.zh-CN.md)。
贡献者改动地图和测试矩阵见 [`docs_dev/02-developer-guide.zh-CN.md`](docs_dev/02-developer-guide.zh-CN.md)。
新增资产及其 Connector 的完整流程见 [`docs_dev/03-community-add-asset-connector.zh-CN.md`](docs_dev/03-community-add-asset-connector.zh-CN.md)。

## 数据和凭证卫生

敏感值使用 `REPLACE_ME`、`YOUR_SLS_PROJECT` 或 `vault://...` 等占位符。示例需要真实形态时，
使用 RFC 5737 / RFC 3849 合成地址、合成主机名和虚构事件 ID。发布扫描会在整个公开候选中拒绝已知内部验收网段和常见本机工作区路径，不能把真实测试主机地址或贡献者本地检出路径复制到文档、Skill、样例、源码或测试夹具中。

不要包含 `.DS_Store`、本地表格、临时导出、解密后的 vault 文件或生成的私有报告。

## 贡献示例 DataAsset

**脱敏模板**是最有价值的社区贡献之一。它们帮助用户接入 SLS、ES、SSH、Splunk、数据库和文件源，
同时不暴露真实环境。

### 文件放置位置

| 要添加的内容 | 放置位置 | 是否进入 `catalog.json` |
|---|---|---|
| Connector 模板 | `dataasset/examples/connectors/conn-<vendor>-<purpose>-example.json` | 否，仅作参考 |
| 字段参考/可复制资产 | `dataasset/examples/reference-assets.json` 或 `examples/` 下的新文件 | 否 |
| **离线 demo registry** 的组成部分 | `dataasset/assets/`、`dataasset/connectors/`、`dataasset/hosts/`、`dataasset/networks/` | 是，必须通过完整 `validate` 且保持合成数据 |
| 查询模板 | `dataasset/query-templates/` | 被 active asset 引用时是 |
| Bundle 编排 | `dataasset/bundles/` | 是，只能引用 demo asset ID |

**新贡献者默认路径：**先放到 `dataasset/examples/`。维护者可以在后续 PR 中将经过审查的示例提升到 demo registry。

命名示例：

- Connector：`conn-sls-example.json`、`conn-splunk-example.json`、`conn-ssh-file-example.json`
- Asset：`asset-<source>-<purpose>-demo.json`
- Host：`host-<role>-demo.json`，使用合成 `host_ip`
- Network：`net-demo-<zone>.json`，公开示例使用 RFC 5737 文档网段

现有示例见 [`dataasset/examples/connectors/`](dataasset/examples/connectors/)。

### 必须遵守的内容规则

1. **凭证**：使用类似 `"credentials_ref": "vault://sls/security-readonly"` 的引用，绝不提交明文 Secret。不要提交 `dataasset/credentials/secrets/`（仅供本地 SOPS 使用）。
2. **Endpoint**：使用 `YOUR_SLS_PROJECT`、`YOUR_ES_INDEX`、`example.log.aliyuncs.com` 等占位符。
3. **IP 和主机名**：IPv4 使用 RFC 5737 文档地址段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），IPv6 使用 RFC 3849 的 `2001:db8::/32`，主机名使用明显的合成名称。公开 `dataasset/` 不使用 RFC1918 地址；不得使用客户公网 IP 或批量内部清单。
4. **状态**：新 Connector 使用 `"status": "draft"`，新 Asset 使用 `"status": "discovery"` 或 `"draft"`；需要明确停用时使用 `"disabled"`。`inactive` 不是当前 Schema 的合法值。只有经过维护者审查并由 `make ci` 覆盖的离线 demo 才能使用 `active`。
5. **描述**：新增 JSON 对象时，`description` 字段优先使用英文。

### 工作流程

```bash
# 1. 复制最接近的已有示例
cp dataasset/examples/connectors/conn-sls-example.json \
   dataasset/examples/connectors/conn-vendor-foo-example.json

# 2. 修改 ID、connector_type、config、credentials_ref

# 3. 校验（examples 目录不一定在 catalog 中；修改 registry 资产时必须校验）
.venv/bin/python src/secweaver.py validate

# 4. 提交 PR 前运行完整 CI 门禁
make ci
```

如果新增或修改 registry 资产（如 `dataasset/assets/`）：

```bash
.venv/bin/python src/secweaver.py catalog sync
.venv/bin/python src/secweaver.py validate
```

发布开源归档前，先提交预期改动并保持 Git 工作区干净，再运行：

```bash
make open-source-export OUTPUT=/tmp/secweaver-community.tar.gz
```

导出器会打包 `HEAD`，并在提取出的归档中重新执行公开门禁。

### PR 检查清单（示例 DataAsset）

- [ ] 文件位于 `dataasset/examples/`（除非已同意修改 demo registry）
- [ ] `connector_id` / `asset_id` 唯一，并以 `-example` 或 `-demo` 结尾
- [ ] 不包含 `secrets/`、`.env` 或生产主机名（例如真实云实例名）
- [ ] `make ci` 通过
- [ ] PR 简述说明它帮助哪个场景模式（S1–S8）或 Skill

### 适合新贡献者的任务

- 为尚未覆盖的日志平台添加 `conn-<vendor>-example.json`
- 为新的 demo 区域添加合成 host 和 network
- 为 alert-confirmation 或 traceability 扩展离线输入及预期 `join_edges`
- 在 `docs_user/03-configure-data-sources.zh-CN.md` 中补充一种 Connector 类型

如果希望编码前得到维护者反馈，请使用 **Example DataAsset** 模板提交 Issue。

## 许可证

除非另有明确说明，贡献内容按仓库 [Apache License 2.0](LICENSE) 接受。

## 国际化

- 面向用户的开源入口以英文为主。
- 中文副本使用 `*.zh-CN.md`，并与英文文件放在同一目录（如 `docs_dev/`、`docs_user/`、`dataasset/`、Skills 等）。
- 开发、设计、架构、贡献、插件和集成文档放在 **`docs_dev/`**。
- 安全运营、SOC 分析师、平台管理员、接入和日常使用文档放在 **`docs_user/`**。
- DataAsset 目录 README、Skill（`SKILL.md`、`rules.md` 等）、示例和工具文档遵循同样的双语命名。
- DataAsset Studio 的界面文案放在 `dataasset-ui/i18n.js` 的 `en` 和 `zh` 字典中。
- 欢迎贡献 UI；只要保持 DataAsset 文件布局、`DATAASSET_ROOT`、`asset apply`、`validate.py --json/--diagnose` 和 `credentials_ref` 契约不变，社区可以改进 `dataasset-ui/`、新增页面或重写 UI。详见 [`docs_dev/25-ui-contribution-guide.zh-CN.md`](docs_dev/25-ui-contribution-guide.zh-CN.md)。
- Markdown 报告模板位于 `src/report_markdown.py`，除非明确加入本地化支持，否则保持英文。

## 文档与发布要求

遵循 [AGENTS.md](AGENTS.md)：每次代码变更必须同步行为文档和中英文版本，注释非显然的实现意图，并执行对应检查。Agent 打包内容变更必须在构建新包前更新 canonical `VERSION`，不得复用已发布版本。未能运行的检查需说明原因，局部测试不等同于 `make ci`。
