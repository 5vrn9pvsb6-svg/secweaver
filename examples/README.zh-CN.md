# SecWeaver 示例数据（examples）

**语言：** [English README](README.md) | 简体中文（本文）

项目根目录下的 **官方示例库**：为各 Skill 提供可复现的离线测试输入。

与生产配置的关系：

| 目录 | 用途 |
|---|---|
| [`dataasset/`](../dataasset/) | 公开配置契约与合成示例；本地可按接入指南配置真实资产 |
| [`examples/`](.) | 离线测试 payload（evidence_bundles、调查参数、日志样本） |
| [`src/skills/`](../src/skills/) | Skill 实现与 CLI 脚本 |

## 目录结构

```text
examples/
├── README.md                      # 本文件
├── ai-showcase/                   # 智能体零数据源体验入口
├── alert-confirmation/            # 告警确认（S4）
├── data-source-completeness/      # 数据源完整性预检
├── log-format-discovery/          # 新日志格式发现样本
├── prompt-risk-analysis/          # 纯提示词研判的取证输入和黄金报告
├── risk-identification/           # 主机与 DNS 风险识别（S5/S8）
├── reports/                       # CLI 生成的完整样例输出报告
└── traceability/                  # 溯源分析跨源拼链（S1/S2/S3）
```

## 技能链示例

```text
data-source-completeness
        │
        ├──▶ alert-confirmation ──(success)──▶ traceability
        ├──▶ traceability
        └──▶ risk-identification ──(P0)──▶ traceability

log-format-discovery ──▶ dataasset（discovery → draft → active）
```

## 快速运行

零凭证 智能体体验：运行 `make quickstart`，使用 Codex 或其他支持的智能体打开当前
仓库，然后输入“运行 SecWeaver 离线案例”。案例清单见
[离线 AI Showcase](ai-showcase/README.zh-CN.md)。

```bash
# 一键运行全部 demo，并生成完整样例输出报告 JSON
python3 src/secweaver.py demo all

# 也可以单独运行某个 demo
python3 src/secweaver.py demo completeness
python3 src/secweaver.py demo alert
python3 src/secweaver.py demo risk
python3 src/secweaver.py demo traceability

# 四份 demo JSON 写入指定目录，目录名可以包含点号
python3 src/secweaver.py demo all -o /tmp/secweaver-offline.v1
```

`demo all` 的 `-o` 始终表示目录（不存在时创建），已存在的普通文件会被拒绝。
单个 Demo 的 `-o` 可以是 JSON 文件名或已存在的目录，目录名可以包含点号。

格式发现已封装到 `secweaver` CLI，推荐用离线样本体验：

```bash
# 对 discovery 资产跑格式发现（使用 examples 样本）
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample

# 查看 discovery 队列（底层脚本）
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
```

未提供 `-i` / `--text` 时，CLI 会先通过 `asset test` 拉取在线样本再跑发现。需要 `--prompt`、`-o` 等高级参数时，可直接调用底层脚本：

```bash
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample \
  --pretty -o /tmp/discovery-report.json
```

## 各 Skill 测试数据

想了解**每份样例模拟的事件、预期结果和证据边界**，先读[离线样例逐例说明](CASE-CATALOG.zh-CN.md)。

四个可执行评估 Skill 合计 **27 份不同的离线输入**。27 个 Showcase 案例各覆盖其中一份输入，
4 份 Demo 报告是输出，不计入输入案例。纯提示词研判有 2 份 fetch 输入与 1 份经
Schema 校验的黄金报告；格式发现另有 6 份原始日志样本，均覆盖格式识别回归。

| Skill | 目录 | 场景数 |
|---|---|---|
| 智能体 Showcase | [ai-showcase/](ai-showcase/) | 27 个路由案例（默认全量运行） |
| 数据源完整性 | [data-source-completeness/](data-source-completeness/) | 8 份可执行输入 |
| 告警确认 | [alert-confirmation/](alert-confirmation/) | 5 份可执行输入 |
| 风险识别 | [risk-identification/](risk-identification/) | 11 份可执行输入（执行、外连、账号、外传、白名单、SSH 临界反例、持久化、DNS） |
| 溯源分析 | [traceability/](traceability/) | 3 份可执行输入 |
| 样例输出报告 | [reports/](reports/) | 4 个 demo 输出 |
| 纯提示词风险分析 | [prompt-risk-analysis/](prompt-risk-analysis/) | 2 份 fetch 输入 + 1 份 JSON 黄金报告 |
| 格式发现 | [log-format-discovery/](log-format-discovery/) | 6 份原始样本 |

从仓库根目录执行全部离线评估输入，核对 `_meta` 预期结论与输出 Schema，并核对
6 份原始日志样本的格式识别及 WAF/主机执行归一化预览；无需凭证或网络访问：

```bash
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v
```

纯提示词技能的黄金报告只校验结构，不能证明模型推理质量或可重复性；连接器实时拉取、
外部通知投递仍需单独做集成测试。
离线回归另对告警与溯源样例做证据移除/关联键扰动，验证结论在证据不足时降级；
这不能替代真实环境中的误报率、召回率评估。

## 维护规范

1. 示例 JSON 使用 **canonical** 字段（与 fetch 归一化后一致）
2. 每个 JSON 含 `_meta`：`scenario_label`、`expected_*` 预期结论
3. 新增场景后运行对应 Skill 脚本及离线示例回归验证
4. 不在此目录存放凭证或生产 connector 配置

## 相关文档

- [跨源字段关联说明](../docs_user/21-cross-source-field-correlation.md)
- [Skills 总览](../src/skills/README.md)
- [数据源资产设计](../docs_dev/09-data-asset-design.md)
