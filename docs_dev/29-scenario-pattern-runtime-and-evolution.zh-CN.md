# 场景模式运行时与演进

**语言：** [English](29-scenario-pattern-runtime-and-evolution.md) | 简体中文（本文）

本文面向 DataAsset、关联分析和 Skill 维护者，记录 Scenario Pattern 的运行时实现、
配置同步边界和可继续演进的部分。安全运营人员应先阅读
[场景模式用户指南](../docs_user/22-scenario-patterns.zh-CN.md)。

本文不是发布验收记录。当前能力以代码、`dataasset/scenarios/anchor-patterns.json`
和完整性场景定义为准；修改后必须运行本文末尾的验证命令。

## 1. 运行时实现映射

| 能力 | 实现入口 | 行为 |
|---|---|---|
| Pattern 配置 | `dataasset/scenarios/anchor-patterns.json` | 独立保存场景锚点、调查窗、Bundle 和 Join 链 |
| Pattern 加载 | `load_anchor_patterns()` | 加载并提供规范化 Pattern 注册表 |
| 场景选择 | `anchor_pattern_for_scenarios()` | 按场景和 `scenario_priority` 选择 Pattern |
| 参数解析 | `resolve_anchor_params()` | 根据 anchor 和调查窗补齐缺少的时间参数 |
| 取数计划 | `plan_fetch()` | 从 Bundle 与 Join `fetch_plan` 生成 `correlation_fetch_plan` |
| 计划执行 | `fetch_scenario_evidence()` / `fetch_correlation_plan_evidence()` | 按计划取数；计划不可用时允许受约束的 Bundle 回退 |
| Join 执行 | `run_recommended_chain()` / `correlate_bundles()` | 按 `recommended_chain` 产生 `join_edges` 和 `data_gaps` |
| 静态校验 | `src/dataasset/validate.py` | 校验 Schema、Join、时间窗、Bundle 和资产覆盖 |

运行时不会让模型自行发明 Join。Pattern 只引用
`correlation-matrix.json` 中已经注册且可以审计的 Join。

## 2. 当前场景覆盖

| 场景 | Pattern ID | 锚点 | 推荐资产 | 默认 Bundle |
|---|---|---|---|---|
| S3 横向移动 | `S3_lateral_movement` | `host_ip` / `user` / `src_ip` | `ssh_auth`、`firewall_log`、`host_exec`、`asset_inventory` | `bundle-incident-trace-default` |
| S6 账号失陷 | `S6_account_compromise` | `user` + `src_ip` | `ssh_auth`、`host_exec` | `bundle-incident-trace-default` |
| S7 数据外传 | `S7_data_exfiltration` | `host` / `dst_ip` / `domain` | `host_connect`、`dns_log`、`network_traffic_audit`、`db_audit` | `bundle-data-exfiltration-default` |

S3 和 S6 复用默认溯源 Bundle，避免为同一 SSH/主机证据链建立重复配置。
S7 使用独立 Bundle，因为它依赖 DNS、全流量和数据库审计等 D4/D7 数据源。
配置存在不等于数据源已经可用；Connector 仍须完成真实查询验收。

## 3. Schema 与引用校验

[anchor-patterns.schema.json](../dataasset/schema/anchor-patterns.schema.json) 要求顶层
`version` 和 `patterns`。每个 Pattern 必须包含 `label`、非空
`recommended_chain` 和 `bundle_id`，并约束 `anchor`、`scenario_priority` 等字段。

校验器还检查：

- Join ID 存在于内部或跨源 Join 注册表。
- `bundle_id` 存在且覆盖 Join 链所需的 asset type。
- composite Join 递归展开后的资产仍由 Bundle 覆盖。
- anchor 字段、anchor 来源和 layer asset type 符合已注册契约。
- `fallback_asset_types` 由 Bundle 覆盖。
- Pattern 场景与 Bundle 的 `investigation_scenarios` 一致。

## 4. 完整性分析同步边界

完整性分析支持 S1-S8，并使用 `anchor_pattern_for_scenarios()` 与
`resolve_anchor_params()` 选择 Pattern 和补齐参数。但是，P0/P1/P2 数据要求仍由
`src/skills/data-source-completeness/scenarios.json` 定义，不会从全部
`recommended_chain` 自动推导。

修改 Pattern 的 Join 链时，必须同时检查：

1. 完整性场景是否要求新增的证据类型。
2. Bundle 是否包含 Join 链和 fallback 所需资产。
3. 查询模板是否具备时间、主机和租户范围限制。
4. 正例、反例和缺数据样例是否仍得到预期 verdict。

## 5. 回退与资源边界

`plan_fetch()` 依赖每个 Join 的 `fetch_plan`。计划缺失或不完整时，运行时可能回退到
Bundle 取数。回退用于保持兼容性，不代表可以忽略授权和资源上限。新增或修改 Join 时应
优先补齐有界的 `fetch_plan`，并验证查询时间窗、limit 和资产范围。

`anchor` 仍包含部分语义配置，并非每个字段都参与自动锚点提取。复杂横向 BFS 也没有
完全由矩阵表达；告警确认的少数路径仍保留固定 Join 调用。维护者扩展这些路径时，应逐步
复用 Pattern API，并保持旧输入和离线样例兼容。

## 6. 报告证据契约

关键结论应引用 `join_edges`，未完成的路径应保留在 `data_gaps`：

```json
{
  "conclusion": "攻击疑似打穿 Web 主机",
  "supporting_join_edges": [
    "waf_to_web_access_by_ip:waf-001->web-001",
    "web_access_to_host_exec:web-001->exec-001"
  ],
  "remaining_data_gaps": [
    "no_match:d2_exec_connect_same_listener"
  ]
}
```

模型可以解释证据，但不能把缺失的 Join 或未返回的事件补写成事实。

## 7. 可演进方向

- 从 Join 链生成完整性要求的候选差异，仍由维护者审核后写入场景定义。
- 将复杂横向扩展和告警确认中的固定 Join 逐步统一到 Pattern API。
- 扩大 anchor 自动提取覆盖，同时保留显式参数优先级和可审计来源。

这些方向不代表当前版本承诺；只有代码、配置、双语文档和回归测试同时完成后，才能标记为支持。

## 8. 验证

从仓库根目录运行：

```bash
make validate
.venv/bin/python -m unittest discover -s src/skills/_shared/data-access/tests -p 'test_correlation*.py' -v
.venv/bin/python -m unittest discover -s src/skills/traceability-analysis/scripts/tests -p 'test_correlation_trace.py' -v
make docs-check
```

如果测试模块名称后续调整，以仓库中覆盖 `anchor_patterns`、`scenario_fetch`
和 correlation 的当前测试为准，并同步更新本文中英文版本。
