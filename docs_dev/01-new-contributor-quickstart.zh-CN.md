# 新贡献者快速开始

**语言：** [English](01-new-contributor-quickstart.md) | 简体中文（本文）

这份文档是给开发贡献者的最短入口：不用先读完整个仓库，先知道怎么跑起来、应该改哪里、提交前跑什么。

## 环境与命令约定

从包含 `Makefile` 的仓库根目录执行。Python 开发和离线体验使用 Linux/macOS 的 POSIX 终端、Python 3.10+、venv/pip 和 Make；Fork、分支及提交需要 Git，首次安装依赖需要包下载网络。原生 Windows PowerShell 不适用本文的 `.venv/bin/python` 和 Make 命令；Windows Agent 的支持与此开发路径不同，WSL 路径尚未完成端到端验收。

全文使用 `.venv/bin/python` 调用项目 Python，**不要求激活虚拟环境**。创建 `.venv` 后仍运行系统 `python3`，可能找不到装在虚拟环境里的依赖。
`make setup` 和 `make quickstart` 会在安装依赖前检查指定解释器及已有 `.venv`；两者都必须是 Python 3.10 或更高版本。

| 目标 | 额外要求 |
|---|---|
| Python、文档、DataAsset 或现有轻量 UI 的本地检查 | 无需 Go、Node.js、SaaS 账号或生产凭证；新增前端构建链时自行说明其依赖 |
| `make agent-check` / 完整 `make ci` | Go 版本满足 [go.mod](../src/tools/secweaver-agent/go.mod)（当前 1.22），gofmt、Bash，以及 Go race 支持的宿主和 C 编译工具链；需能下载 Go modules |
| Attack Lab Compose 检查 | Docker + Compose 插件；缺少 Docker 时该检查会打印跳过提示，不能记为本地已通过 |
| 真实服务升级或攻击实验 | 独立的授权测试环境；普通文档贡献不需要在开发机安装主机采集服务或执行攻击实验 |

首次准备可检查 `python3 --version`、`make --version`、`git --version`；跑完整门禁前再检查 `go version`、`gofmt -h`、`cc --version`、`bash --version` 和 `docker compose version`。工具版本可用不等于环境已验收；公开 CI 的主要开发检查基线是 Ubuntu，服务升级另有 Linux/Windows 作业。

## 前 15 分钟

改代码前先跑一次本地检查：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-data-access.txt
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py validate
```

如果你希望用 Makefile：

```bash
make quickstart
```

提 PR 前运行：

```bash
make ci
```

`make ci` 会执行依赖安装、发布扫描、文档与 SBOM 检查、Agent 和 Attack Lab 检查、
DataAsset 校验、规则同步、测试及离线 demo。手工选择其中几项不等价于完整门禁。

按改动类型先跑下表的局部检查；提 PR 时记录完整 `make ci` 的结果。工具不足或当前平台无法运行时，在 PR 中逐项列出未运行检查及原因，由维护者核对 CI 结果，不能把局部检查写成完整通过。真实 systemd/Windows SCM 升级是独立 CI 作业，不属于本地 `make ci`。

## 选择你的贡献路径

| 我想做... | 从这里开始 | 主要文档 | 建议检查 |
|---|---|---|---|
| 修改文档或样例 | `docs_dev/`、`docs_user/`、`examples/` | [CONTRIBUTING.zh-CN.md](../CONTRIBUTING.zh-CN.md) | `make docs-check`、`make release-scan` |
| 新增脱敏 connector 或资产示例 | `dataasset/examples/` | [community-add-asset-connector.zh-CN.md](03-community-add-asset-connector.zh-CN.md) | `.venv/bin/python src/secweaver.py validate` |
| 让运营通过配置生成 connector + asset + query template | `dataasset/onboarding/` | [developer-guide.zh-CN.md](02-developer-guide.zh-CN.md) | `.venv/bin/python src/secweaver.py asset apply -f dataasset/onboarding/examples/data-sources.sample.json --dry-run` |
| 新增不适合放进核心的 connector | `src/dataasset/plugins/connectors/` | [connector-plugins.zh-CN.md](04-connector-plugins.zh-CN.md) | `.venv/bin/python src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/<name>` |
| 新增外置执行器示例 | `examples/`、`docs_dev/`、可选本地脚本 | [external-connector-executors.zh-CN.md](05-external-connector-executors.zh-CN.md) | `.venv/bin/python src/dataasset/test_connector.py <asset_id> --by-asset --plan --dry-run` |
| 修改、新增或重写 UI | `dataasset-ui/` 或新的前端目录 | [ui-contribution-guide.zh-CN.md](25-ui-contribution-guide.zh-CN.md) | `.venv/bin/python -m unittest tests.test_dataasset_ui`、手动打开 UI smoke |
| 新增或修改确定性 Skill | `src/skills/<skill>/` | [确定性 CLI 贡献](02-developer-guide.zh-CN.md#新增一个-cli-可见-skill) | `.venv/bin/python src/secweaver.py list` 和 `.venv/bin/python tests/run_tests.py` |
| 新增或修改纯提示词 Skill | `src/skills/<skill>/`、`examples/<skill>/` | [纯提示词技能贡献](02-developer-guide.zh-CN.md#新增或修改纯提示词-skill) | 文档、输出契约及双语检查；再用固定证据做智能体正例/反例复核 |
| 给 secweaver-agent 增加功能 | `src/tools/secweaver-agent/` | [Agent 工程手册](../src/tools/secweaver-agent/README.zh-CN.md) | `make agent-check` |
| 修改 schema 或校验逻辑 | `dataasset/schema/`、`src/dataasset/validate.py`、`src/dataasset/validate_lib/` | [data-asset-design.zh-CN.md](09-data-asset-design.zh-CN.md) | `.venv/bin/python src/secweaver.py validate --json` |

## 推荐的第一个 PR

- 在 `dataasset/examples/connectors/` 增加一个脱敏 connector 示例。
- 在 `dataasset/onboarding/examples/` 增加一个新的 quickstart。
- 改善 `dataasset-ui/onboarding.html` 的表单体验、错误提示或国际化文案。
- 给 `docs_user/09-operations-troubleshooting.zh-CN.md` 补一项排错说明，或给 `docs_user/16-data-source-onboarding-faq.zh-CN.md` 补一个短答案。
- 在 `tests/test_secweaver_cli.py` 给已有 CLI 行为补回归测试。
- 改善英文或中文文档，并保持同目录双语文件同步。
- 改文档后运行 `make docs-check` 检查本地 Markdown 链接。

## 第一个文档 PR：最小闭环

1. Fork 仓库并在自己的 clone 中创建工作分支，例如 `git switch -c docs/first-contribution`；本地已有修改时先确认分支和工作区，保留原有工作。
2. 选择一个明确问题，例如修正数据源 FAQ 的一条说明，同时修改对应 `.md` 和 `.zh-CN.md`。这一步不需要修改运行时代码或真实资产。
3. 从仓库根目录检查：

```bash
make docs-check
make release-scan
git diff --check
git diff --stat
```

4. 成功标准：文档检查 0 issue、发布扫描 0 error，差异只包含预期修改；有 warning 时解释原因。涉及命令时在公开合成输入上核验，不能只检查文字。
5. 按上方前置条件运行 `make ci`，在 PR 中写明问题、修改、验证结果及未运行项；提交前按 `git diff` 审阅，选择明确文件提交，推送自己的 Fork 后创建 PR。不要把生成报告、真实配置或凭证带入提交。

## 数据安全规则

- 不要提交真实凭证、Token、私钥、解密后的 vault 文件、客户日志或内部调查报告。
- 使用 `REPLACE_ME`、`YOUR_SLS_PROJECT`、`vault://namespace/name` 这类占位符。
- 使用合成 IP 和主机名。公开示例优先使用 RFC 5737 文档地址段，例如 `203.0.113.0/24`。
- 新示例默认先放 `dataasset/examples/`，除非维护者同意提升到 active demo registry。
- 涉及数据、示例、文档或脚本的 PR，提交前跑 `make release-scan`。

## 常用入口

- [CONTRIBUTING.zh-CN.md](../CONTRIBUTING.zh-CN.md)：贡献流程、PR 预期和数据卫生要求。
- [developer-guide.zh-CN.md](02-developer-guide.zh-CN.md)：DataAsset、Skill、demo、schema、报告和测试分别改哪里。
- [community-add-asset-connector.zh-CN.md](03-community-add-asset-connector.zh-CN.md)：新增一个资产和它的 connector 的完整手册。
- [connector-plugins.zh-CN.md](04-connector-plugins.zh-CN.md)：适合 SDK 或自定义本地逻辑的插件模式。
- [external-connector-executors.zh-CN.md](05-external-connector-executors.zh-CN.md)：适合核心外运行的外置执行器协议。
- [ui-contribution-guide.zh-CN.md](25-ui-contribution-guide.zh-CN.md)：UI 页面扩展、API 契约和整套 UI 重写说明。
- [tests/README.zh-CN.md](../tests/README.zh-CN.md)：测试布局和回归预期。
