# 开发者指南

**语言：** 简体中文（本文） | [English](02-developer-guide.md)

这份指南面向想参与 SecWeaver 但还不熟悉全仓库结构的贡献者。

## 贡献入口地图

| 目标 | 从这里开始 | 同步更新 | 必跑检查 |
|---|---|---|---|
| 新增脱敏数据源示例 | `dataasset/examples/` | 必要时更新 `CONTRIBUTING.zh-CN.md` 清单 | `.venv/bin/python src/secweaver.py validate` |
| 生成 connector + asset 配置 | `.venv/bin/python src/secweaver.py asset apply -f dataasset/onboarding/examples/data-sources.sample.json --dry-run` | 缺模板时更新 `dataasset/onboarding/` | `.venv/bin/python src/secweaver.py validate --only-active` |
| 新增或暴露确定性 Skill | `src/skills/<skill>/` | `src/skills/manifest.json`、examples、tests | `.venv/bin/python src/secweaver.py list`、`.venv/bin/python tests/run_tests.py` |
| 新增或修改纯提示词 Skill | `src/skills/<skill>/` | `src/skills/manifest.json`、双语工作流、技能索引、离线证据及输出验收 | `.venv/bin/python src/secweaver.py list`，以及下方纯提示词贡献流程 |
| 修改 demo 行为 | `examples/<skill>/`、`examples/reports/`、`tests/fixtures/` | 路径变化时更新 `src/skills/manifest.json` | `.venv/bin/python src/secweaver.py demo all` |
| 修改或重写 UI | `dataasset-ui/`，或新的前端目录 | [25-ui-contribution-guide.zh-CN.md](25-ui-contribution-guide.zh-CN.md)、`dataasset-ui/README.zh-CN.md` | `.venv/bin/python -m unittest tests.test_dataasset_ui`、手动 UI smoke |
| 修改 DataAsset schema 或校验 | `dataasset/schema/`、`src/dataasset/validate.py`、`src/dataasset/validate_lib/` | `docs_dev/09-data-asset-design.zh-CN.md`、测试 | `.venv/bin/python src/secweaver.py validate --json` |
| 修改主机 agent 或新增采集模块 | `src/tools/secweaver-agent/` | `src/tools/secweaver-agent/README.zh-CN.md`、`docs_dev/12-agent-collection-and-evidence-spec.zh-CN.md` | `make agent-check` |
| 修改报告渲染 | `src/report_markdown.py` | `examples/reports/`、报告测试 | `.venv/bin/python src/secweaver.py report markdown --demo all` |

## 本地环境

工具、支持平台与完整 CI 前置条件统一见[新贡献者快速开始](01-new-contributor-quickstart.zh-CN.md#环境与命令约定)。以下命令从仓库根目录执行，显式使用虚拟环境解释器，无需 `source activate`。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-data-access.txt
.venv/bin/python src/secweaver.py list
```

常用检查：

```bash
make validate
make test
make demo
make release-scan
make docs-check
```

`make ci` 是常规本地门禁。`make release-scan` 是开源发布卫生检查，用于发现密钥、私有标记和不应进入公开仓的文件。
`make docs-check` 检查公开文档的本地链接和私有交付命令引用。直接运行链接脚本只覆盖其中一项，不能替代整个目标。局部检查用于开发迭代；提交前完整门禁及未运行项说明见[贡献者入口](01-new-contributor-quickstart.zh-CN.md)。

## 新增一个 CLI 可见 Skill

当 Skill 有确定性脚本，并且希望通过 `secweaver skill` 或 `secweaver demo` 运行时，走这条路径。

1. 创建 `src/skills/<skill>/SKILL.md`，并把确定性脚本放在 `src/skills/<skill>/scripts/`。
2. 在 `examples/<skill>/` 下新增合成离线输入。
3. 在 `src/skills/manifest.json` 注册该 Skill。
4. 在 `tests/test_secweaver_cli.py` 或 Skill 附近补 CLI/demo 回归测试。
5. 运行：

```bash
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py skill <skill-name> -i examples/<skill>/<case>.json
.venv/bin/python tests/run_tests.py
```

Manifest 字段说明：

| 字段 | 作用 |
|---|---|
| `key` | CLI 内部短名，例如 `risk` |
| `name` | 对外 Skill 名称，例如 `risk-identification` |
| `kind` | Skill 类型，例如 `assessment`、`prompt` 或 `router` |
| `cli_visible` | 是否允许通过 `secweaver skill` 执行；纯提示词和路由 Skill 设为 `false` |
| `aliases` | `secweaver skill` 和 `secweaver demo` 接受的额外名称 |
| `script` | 可选的确定性 Python 入口；工作流型 Skill 不配置 |
| `docs` | `SKILL.md` 路径 |
| `output_schema` | 对外提供稳定 JSON 契约时使用的可选 Schema |
| `demo.input` / `demo.output` | 可选的内置离线 demo 路径 |

## 新增或修改纯提示词 Skill

纯提示词 Skill 由智能体读取工作流并分析证据，不需要为研判本身创建 Python 入口。以 [prompt-risk-analysis](../src/skills/prompt-risk-analysis/SKILL.zh-CN.md) 为现有参考；取数可复用 `evidence-fetch`，离线开发直接使用合成证据。

1. 在 `src/skills/<skill>/SKILL.md` 定义名称、触发范围、输入、必要工作流、输出和证据边界；维护对应中文镜像。较长的提示词、契约或参考资料按需拆分并从入口链接。
2. 在 `src/skills/manifest.json` 添加统一目录项：`kind` 设为 `prompt`，`cli_visible` 设为 `false`，填写规范 `docs` 路径，不配置 `script`。同时在 `src/skills/README.md` / `README.zh-CN.md` 和用户技能目录登记可发现入口。薄适配器先读取该索引，再选择技能；不要为每种智能体复制一套内容。通过[智能体配置指南](../docs_user/38-ai-agent-host-setup.zh-CN.md)加载后，用明确点名技能的请求验证它实际读取了新入口。
3. 在 `examples/<skill>/` 准备固定合成输入和验收说明，至少覆盖应识别的行为、正常行为反例、证据不足三类情形。标明支持的结论、不能推断的内容、证据引用和缺口；避免将黄金报告当成模型必须逐字复述的答案。
4. 需要结构化输出时定义输出 Schema 并验证样例；对跨语言契约与关键判断边界补相应检查。仅修改措辞时无需新增照抄文案的测试。修改现有 `prompt-risk-analysis` 可运行：

```bash
.venv/bin/python -m unittest tests.test_prompt_risk_analysis_contract tests.test_prompt_risk_analysis_skill_parity
make docs-check
```

这两个测试只覆盖现有技能的契约/样例/双语约定，不会自动发现新技能，也不运行模型。新技能应补自己的验证入口，并在验收说明中写出命令。

5. 在所用智能体中用相同固定输入复核正例、反例和缺数据场景。记录技能版本/提交、智能体及模型、输入文件、提示词、输出与通过/失败原因。重点核对证据引用真实存在、正常行为未误报、缺证据时保留未知、网络活动未直接升级为外传、未将模型判断冒充确定性 `policy_rule_id` 命中。既有输入或文案不涉及某项时，按技能实际契约选取验证点。
6. PR 中附脱敏后的复核摘要及已知限制。自动测试通过不等于模型研判质量通过；没有运行模型复核时明确标注待验证。

`src/skills/manifest.json` 是所有顶层 Skill 的单一目录。纯提示词 Skill 会出现在 `secweaver list` 中，便于智能体和用户发现其 `SKILL.md`；由于它没有脚本且 `cli_visible` 为 `false`，不能用 `secweaver skill <name>` 执行。只有增加稳定的确定性入口后，才配置 `script`、将 `cli_visible` 设为 `true`，并按上一节补齐 CLI 和 demo 验收。

## 新增数据源配置

运营同学应优先通过配置接入，而不是改代码。先尝试无代码路径：

```bash
.venv/bin/python src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
```

`asset apply` 读取带 `data_sources` 数组的 JSON 配置，并写入 `dataasset/connectors/`、`dataasset/assets/` 和 `dataasset/query-templates/templates.json`。运营可以直接填写通用字段，再通过 `connector`、`asset`、`template` 三段做深度覆盖，例如嵌套 connector config、`text_parser`、`schema.fields`、`field_aliases`、`coverage`、查询 `params` 和模板 `defaults`。单个数据源仍可继续使用 `asset init` 命令参数。

运营配置生命周期命令：

```bash
.venv/bin/python src/secweaver.py asset diff -f dataasset/onboarding/examples/data-sources.sample.json
.venv/bin/python src/secweaver.py asset promote --asset asset-demo-waf-sls --params '{"src_ip":"203.0.113.10"}' --dry-run
.venv/bin/python src/secweaver.py asset rollback -f dataasset/onboarding/examples/data-sources.sample.json --dry-run
```

如果某类 connector 或 asset 形态无法通过模板生成，优先完善 manifest 的 `onboarding_template` 所指目录，再写特殊说明。内置 connector 的 query key、runtime、依赖策略、模板选择和 Studio profile 统一维护在 `dataasset/configure/connector-catalog.json`；配置型外部 connector 的同组字段放 `dataasset/configure/external-connectors.json`；插件在自己的 `plugin.json` 中维护。不要新增平行的 Python 常量或 UI profile 文件。插件提交前运行 `.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/<name>`。示例必须使用合成数据，凭证只写 `vault://...` 引用，提 PR 前运行 `.venv/bin/python src/secweaver.py validate --strict` 和 `make release-scan`。

如果确实要贡献核心内置 connector，保持“一个 connector 一个 `*_fetch.py`”：新增独立 fetch 文件后，在 `src/skills/_shared/data-access/connector_fetch_dispatch.py` 或 `extended_fetch.py` 的策略表登记，不要在 `fetch.py` 主流程继续追加 `if/elif` 分支。`fetch.py` 只负责加载配置、渲染模板、解析凭证、调用 dispatcher 和归一化事件。

CLI 入口 `src/secweaver.py` 只保留命令注册和高层分发；资产接入生命周期（`asset init/apply/diff/rollback/promote`）维护在 `src/secweaver_cli/asset_commands.py`。新增资产接入能力时优先改这个模块和 `dataasset/onboarding/`，不要把生成逻辑重新塞回 CLI 入口文件。

插件发现、CLI 校验和执行共用 `src/dataasset/plugin_contract.py`，不要在 CLI
或执行器重复维护 manifest/路径/响应规则。证据传输和场景取数扩展放在
`src/skills/_shared/data-access/`；Skill 输入适配、完整性预检和跨 Skill 流程
放在 [`src/skills/_shared/skill_runtime/`](../src/skills/_shared/skill_runtime/README.zh-CN.md)，
不要放回底层取数模块。原 `skill_input.py`、`prepare.py`、`run_pipeline.py`
仅保留兼容入口。修改这些边界时运行 `tests.test_plugin_contract` 和
`tests.test_skill_runtime`。

DataAsset 校验也保持同样的拆分方式：`src/dataasset/validate.py` 只作为兼容 CLI 的编排入口；可复用校验辅助、结构化报告和面向运营的诊断文案放在 `src/dataasset/validate_lib/`。例如修改 `--diagnose` 的分类、优先级、负责人或修复步骤时，优先改 `validate_lib/diagnostics.py`。

确定性 Skill 也按同样原则维护：历史脚本只保留为兼容 CLI 的薄入口，业务逻辑放到 `scripts/` 下的独立包里。例如 `src/skills/alert-confirmation/scripts/confirm.py` 只负责命令/导入兼容；payload 真实性判断放 `alert_confirmation/layer1.py`，D2 成功确认放 `alert_confirmation/success.py`，网关漏检逻辑放 `alert_confirmation/gateway.py`，整体编排放 `alert_confirmation/engine.py`，Markdown/批量输出放 `alert_confirmation/report.py`。溯源也采用同样拆分：`src/skills/traceability-analysis/scripts/correlate.py` 是兼容入口，初始入口、执行链、横向移动、verdict/report 辅助和整体编排放在 `traceability_analysis/`。

主机侧采集也按同样原则维护：`src/tools/secweaver-agent/main.go` 只作为统一客户端 supervisor，新采集模块放到 `src/tools/secweaver-agent/pkg/<module>/`。现有 `audit-port-execmon` 内部已经拆成配置、监听/procfs 发现、进程树监控、audit 规则管理、audit 日志解析和输出辅助；新增采集能力时沿用这个布局，不要继续把逻辑塞进一个大文件。

社区贡献“一个资产 + 一个 connector”的完整步骤见：[community-add-asset-connector.zh-CN.md](03-community-add-asset-connector.zh-CN.md)。

## 修改或重写 UI

UI 是开放贡献面，不限于修现有页面。贡献者可以：

- 改善 `dataasset-ui/` 现有页面、布局、表单、错误提示和国际化。
- 新增 connector、bundle、network、correlation、scenario、fetch plan 等页面。
- 扩展 `dataasset-ui/server.py` 本地 API；复杂逻辑放到 `dataasset-ui/dataasset_ui_services/` 对应服务模块。
- 基于 React/Vue/Svelte/桌面壳等重写整套 UI。

重写 UI 时要保持这些平台契约：

- 通过 `DATAASSET_ROOT` 选择当前资产目录。
- 读写 DataAsset 标准目录结构。
- 数据源接入复用 `src/secweaver.py asset apply/diff/promote/rollback`。
- 校验复用 `src/dataasset/validate.py --json/--diagnose`。
- 凭证只写 `credentials_ref`，不要写明文密钥。
- 用户可见文案同步中英文或说明暂未国际化范围。

详细规范见：[UI 贡献与重写指南](25-ui-contribution-guide.zh-CN.md)。

## Pull Request 清单

- 改动有清晰归属：DataAsset、Skill、CLI、文档、示例或测试。
- 代码与注释必须同步提交。新增或实质修改的非显然逻辑，必须注释设计意图、约束和失败语义；缺失或误导性注释属于阻断合并的问题。
- 新的贡献者入口能从 `README.zh-CN.md`、`CONTRIBUTING.zh-CN.md`、`docs_dev/README.zh-CN.md` 或本指南找到。
- 所有新增顶层 Skill 均已注册到 `src/skills/manifest.json`；只有存在稳定脚本入口的 Skill 才设置 `cli_visible: true`。
- 新示例为合成数据，不包含凭证、内部主机名、客户日志或批量内网资产清单。
- 本地通过 `.venv/bin/python src/scripts/release_scan.py`、`.venv/bin/python src/secweaver.py validate` 和 `.venv/bin/python tests/run_tests.py`。`make ci` 会先跑发布门禁，再跑校验、测试和 demo。

## 评审预期

小 PR 更容易被快速评审。无关格式化、生成产物和示例数据变更尽量拆开，除非测试夹具要求它们一起提交。

注释必须说明“为什么”，而不是逐行复述“做了什么”。并发与锁归属、生命周期、顺序假设、资源上限、性能取舍、兼容逻辑、安全边界、重试、回滚和降级策略必须显式注释。修改行为时必须同步更新或删除过期注释；测试不能替代对设计不变量和运行假设的说明。简单 getter、直接赋值不需要无效旁白，仅复述语法的注释不算达标。仓库级强制规则见 [`AGENTS.md`](../AGENTS.md)。
