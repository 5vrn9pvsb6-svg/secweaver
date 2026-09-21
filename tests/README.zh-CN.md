# SecWeaver 测试说明

**语言：** [English](README.md) | 简体中文（本文）

这是开源版本的统一测试入口。从仓库根目录执行，先运行 `make setup`；直接调用脚本时使用 `.venv/bin/python`，无需激活虚拟环境。完整 CI 所需的其他工具见[开发环境与命令约定](../docs_dev/01-new-contributor-quickstart.zh-CN.md#环境与命令约定)。

只运行现有 UI 回归测试时，使用 `.venv/bin/python -m unittest tests.test_dataasset_ui`，不需要 pytest。

```bash
make test
# 或
.venv/bin/python tests/run_tests.py -v
```

## 覆盖范围

| 目录 | 重点 |
|---|---|
| `tests/` | CLI 和离线 demo 回归 |
| `src/skills/_shared/data-access/tests/` | 数据访问、解析和归一化 |
| `src/skills/data-source-completeness/scripts/tests/` | 数据完整性技能 |
| `src/skills/risk-identification/**/tests/` | 风险识别技能 |
| `src/skills/log-format-discovery/scripts/tests/` | 日志格式发现与应用逻辑 |
| `src/skills/traceability-analysis/scripts/tests/` | 溯源关联和报告 |
| `src/skills/alert-confirmation/scripts/tests/` | 告警确认判定逻辑 |
| `src/skills/evidence-fetch/tests/` | 证据获取技能 |

## 主要回归套件

- `tests/test_public_onboarding_docs.py`：首次使用指南、案例路由、只读发现、SaaS/SLS/ES 查询预览、Attack Lab 中当前 Agent 日志路径、符合实际 Schema 的中英文 JSON 代码块、私有资产目录说明、客户端平台和输出限制，以及启用 TLS 校验的 Agent ES 模板。
- `tests/test_agent_elasticsearch.py`：公开 ES 初始化、幂等、覆盖/重定向/TLS 保护、入库检查、日志路由和导出边界。
- `tests/test_secweaver_cli.py`：`validate`、`list`、`discover-format`、`demo`、`skill`。
- `tests/test_skill_catalog_and_output_contracts.py`：统一 Skill 目录、领域输出 Schema、全部 27 份清单内离线评估输入的 `_meta` 结论/规则/Join 校验、批量查询缺口、SSH 九次/十次临界对照、告警与溯源证据扰动、6 份格式发现原始样本及 WAF/主机执行归一化预览、仓库 Demo、两份提示词研判取证样例和严格的黄金报告契约校验。
- `tests/test_report_markdown.py`：JSON 到 Markdown 渲染和 `report markdown` CLI。
- `tests/test_ai_host_setup.py`：单个/全部智能体适配器生成、幂等、全智能体预检和覆盖保护。
- `tests/test_ai_showcase.py`：离线案例目录完整性、禁用 IP 在线情报/通知的边界，以及端到端预期结论。

Demo 预期结论字段维护在 `tests/fixtures/demo_expectations.json`。
评估输入的预期字段放在对应 `examples/*/*.json` 的 `_meta` 中；测试要求四个评估目录下的每个 JSON 都登记在 `examples/ai-showcase/cases.json`。该清单是公开案例数量的单一事实来源，新增未登记样例会直接失败。
溯源样例回归会禁用 IP 情报请求和外部通知。

## CI

GitHub Actions 通过 [ci.yml](../.github/workflows/ci.yml) 的多个作业覆盖根目录 `make ci` 门禁，另外运行 Linux systemd 和 Windows SCM 服务升级作业；本地 `make ci` 不执行这两类服务升级。缺少 Docker 时，本地 Compose 校验会提示跳过，应记录为未运行，不能记作通过。

`tests/run_tests.py` 发现并运行上述公开 Python 套件，不会自动发现私有 SLS Proxy 测试。私有服务测试在服务端代码库中维护和运行。测试入口会固定把仓库根目录加入 Python 导入路径，因此 `unittest` 切换发现目录时，公开测试仍可稳定使用 `src.dataasset` 等绝对导入。

公开工作流校验发布卫生、文档链接、供应链元数据、开源 Agent、Attack Lab 脚本、DataAsset 配置、行为策略同步、单元测试和离线 demo。demo 生成后会再次运行发布扫描，防止重写后的公开报告在首次扫描之后引入本地路径或凭证。私有 Portable 构建和打包门禁只在包含相应源码的内部代码库运行。PostgreSQL migration 和 SLS Proxy 服务集成测试属于内部服务端代码库，不在公开工作流中引用。
