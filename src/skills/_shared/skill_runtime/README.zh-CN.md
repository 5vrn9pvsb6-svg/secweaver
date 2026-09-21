# 共用 Skill 运行层

**语言：** 简体中文（本文） | [English](README.md)

本包位于证据访问层之上，负责输入适配和跨 Skill 执行。它是仓库内的 Python
共用代码，不是独立服务或智能体适配器。源码仓和 Community 归档共用同一实现。

## 模块职责

| 位置 | 负责 | 不负责 |
|---|---|---|
| `src/dataasset/plugin_contract.py` | 插件 manifest、路径、超时、响应格式 | 厂商 SDK、Skill 调用 |
| `../data-access/` | 资产/Vault、Connector 取数、归一化；`scenario_fetch.py` 负责计划与有界扩展 | 具体 Skill Python 导入或研判调用 |
| `inputs.py` | 资产包参数、各 Skill 输入、完整性预检 | 厂商取数、研判规则 |
| `contracts.py`、`schemas/` | 版本化 Skill envelope 和共享结构校验 | 领域结论 Schema、Connector 配置 |
| `execution.py` | 调用目录中声明的研判入口，不触发 CLI 报告/Webhook 输出 | 证据取数、重复研判规则 |
| `pipeline.py`、`prepare.py` | 显式流程顺序、CLI 输入/结果输出 | Connector 传输细节 |
| 各 Skill 的 `scripts/` 包 | 规则、结论、可选信息增强 | 插件契约副本 |

完整目录见 [`../../manifest.json`](../../manifest.json)。运行层从这个文件加载研判入口，
CLI 可见性和文档检查也复用同一份目录。每个确定性 Skill 都在自己的
`SKILL.md` 旁维护领域输出 Schema；Schema 组合共享 envelope，并针对仓库内离线
报告校验。新增确定性 Skill 前，至少要补一个目录项、一个输出 Schema 和一个契约
测试，才能视为可运行入口。

依赖方向为 CLI/Skill 入口 -> runtime -> data access -> DataAsset 配置/契约。
运行层也调用规范 Skill 引擎；底层 data-access 不得反向调用运行层。声明式关联/
trace profile 数据继续共享，但不导入具体 Skill 的 Python 实现。

## 命令与默认值

Linux、macOS、Windows 源码环境使用 Python 3.10+，从仓库根目录运行原兼容入口
（按平台选择虚拟环境解释器）：

```bash
# 仅资产元数据；不研判、不解密 Vault、不取证据。
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default --pretty

# 元数据研判；准备后的 payload 增加 skill_result。
python3 src/skills/_shared/data-access/prepare.py \
  --bundle bundle-incident-trace-default --run-skill completeness --pretty

# 默认使用仓库内的 bundle-incident-trace-default。
python3 src/skills/_shared/data-access/run_pipeline.py completeness --pretty
```

`prepare.py` 必须指定 `--bundle ID`，不支持 `--from-bundle`。不传 `--run-skill`
时，仅输出完整性输入元数据；传 `--run-skill completeness|traceability|alert|risk`
时，构建对应输入并运行规范研判，增加 `skill_result`。溯源/告警模式现在也会研判，
不再仅构建 payload。不会隐式发送通知或写报告文件。

流水线默认资产包：完整性/溯源为 `bundle-incident-trace-default`，告警为
`bundle-alert-confirm-min`，风险为 `bundle-host-risk-default`。历史的
`bundle-trace-oss-demo` 未随仓库发布。资产包是数据源配置，不是离线攻击日志；
无外部数据源时通过 [离线样例](../../../../examples/README.zh-CN.md) 体验研判结果。

实时取证据必须显式传 `--fetch`，配置资产并安装 `requirements-data-access.txt`
中的对应依赖；使用 Vault 的数据源还需要 SOPS 与解密身份。`--dry-run` 预览请求，
不解密 Vault。Skill 可选信息增强沿用原行为；在 `--params` 中指定
`resolve_attacker_ip_profile: false` 可禁用溯源 IP 情报查询。上述纯元数据命令
不需要真实凭证。本次分层不要求修改 Agent 客户端、Go 服务、数据库 Schema 或包版本。

## 版本化 Skill envelope

共享 builder 和 `assess_payload()` 会输出 `contract_version: "1.0"` 以及规范的
`skill` 标识。原有未带版本的 v1 输入继续兼容，进入共享边界时会补齐字段。
显式未知版本、Skill 标识冲突，或 `params`、`evidence_bundles`、`fetch_summary`、
`completeness_precheck` 结构错误，会在取数或研判前失败。未运行预检时，该字段可缺省
或为 `null`；提供预检结果时必须是对象。公共机器可读结构见
[`schemas/skill-envelope.schema.json`](schemas/skill-envelope.schema.json)。各 Skill 仍自主管理领域字段和结论语义。

## 兼容与验证

原 Skill CLI 参数、流水线模式和输出键继续保留。`skill_input` 是
`skill_runtime.inputs` 的模块别名，不复制代码，两种导入共享适配器状态。
新增代码直接导入 `skill_runtime.inputs`；规范脚本入口按源码位置设置搜索路径，
不依赖 cwd 或 `DATAASSET_ROOT`。当前不承诺独立 wheel 安装。

测试拦截取数时，mock `fetch.fetch_bundle_evidence` 或
`fetch.fetch_correlation_plan_evidence`，不要再 mock `skill_input` 中的取数函数。
模块加载失败会恢复原 `sys.modules` 注册；每次研判重载入口/规则目录，普通依赖
仍使用 Python 正常缓存。流程同步执行，不进行并发模块加载。

安装仓库开发依赖后运行：

```bash
.venv/bin/python -m unittest tests.test_skill_runtime tests.test_plugin_contract -v
.venv/bin/python -m unittest src/skills/_shared/data-access/tests/test_traceability_asset_cli.py -v
make test
make docs-check
```

测试覆盖依赖方向、envelope 兼容性、Skill 目录完整性、领域输出 Schema、四种
Skill 离线结论一致性、历史命令、加载回滚，以及插件 CLI/运行时契约一致性。
