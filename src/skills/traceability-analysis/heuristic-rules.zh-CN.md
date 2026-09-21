# traceability heuristic-rules 运营说明

**语言：** [English](heuristic-rules.md) | 简体中文（本文）

> 文件：[heuristic-rules.json](heuristic-rules.json)  
> 加载器：`scripts/heuristic_rules.py`  
> **完整配置清单与编写流程**：[traceability-analysis 运营配置编写指南](../../../docs_user/25-traceability-analysis-ops-config-guide.zh-CN.md)

## 用途

将 **TigerSec 特化 heuristic**（syslog 横向、目标机高危 exec 互证、exec 推断横向、has_tty 置信度、confidence 加成）从 Python 抽到 JSON，**运营调规则一般只改本文件**，无需发版改代码。

Matrix 跨源 Join 与 **时间窗分钟数** 均在 [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) → `time_windows`。  
本文件各 heuristic 块仅可写 **`time_window`**（引用 matrix 中的窗口 id，默认 `lateral_movement`），**勿**再写 `window_before_min` / `window_after_min` / `lookback_before_anchor_min`。

## 常用修改

| 需求 | 改哪里 |
|------|--------|
| 调高/调低 likely_lateral 门槛 | `target_exec_lateral.min_high_risk_events`、`min_risk_categories` |
| **扩大/缩小 heuristic 互证时间窗** | **`correlation-matrix.json` → `time_windows.lateral_movement`**（`before_minutes` / `after_minutes`） |
| 某 heuristic 改用其他 matrix 窗 | 对应块 `"time_window": "attack_success"` 等（id 须在 matrix 存在） |
| 新增「高危命令」模式 | `target_exec_lateral.high_risk_exec_rules[]` 加 `{id, pattern, category, flags, enabled}` |
| syslog 算登录成功的事件 | `ssh_auth_result.syslog_success_event_types` |
| syslog 确认横向置信度 | `syslog_lateral.confirmed_lateral.confidence` |
| exec 推断横向置信度 | `lateral_from_exec.confidence` |
| WebShell has_tty 入口置信度 | `initial_access_exec_inferred.confidence_non_interactive` |
| overall +0.03 加成 | `confidence_adjustments.likely_lateral_boost` |
| 临时关闭某 heuristic | 对应块 `"enabled": false` |
| BFS 跳数 / SSH 横向置信度 | `policy.bfs_lateral` |
| 裁决档位 | `policy.verdict_rules` |
| 执行链互证秒数 | `policy.execution_chain`（分钟窗引用 matrix `host_behavior_chain`） |
| SSH 监听器 / Web 端口 | `policy.listener`（Web 进程名见 `exec-rules.json` `web_listeners`） |

## 示例：降低目标主机互证门槛（更敏感）

以下为要修改的两个字段；在现有 `target_exec_lateral` 对象内更新，保留其他配置：

```json
{ "min_high_risk_events": 2, "min_risk_categories": 1 }
```

## 示例：新增传输行为候选规则

```json
{
  "id": "network-transfer-scp",
  "pattern": "\\bscp\\b.*@",
  "category": "network_activity",
  "flags": "i",
  "enabled": true
}
```

`scp` 可能用于正常上传、下载或内部运维。此示例只演示模式配置，不证明外传；也不建议把宽泛模式直接加入生产高危互证列表。启用前应结合实际目的地、方向、数据和上下文收窄匹配，并测试正常传输负例。

## 验证

```bash
.venv/bin/python src/skills/traceability-analysis/scripts/tests/test_heuristic_rules.py
.venv/bin/python src/skills/traceability-analysis/scripts/correlate.py --no-notify \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json -o /tmp/trace-test.json
```

从仓库根目录运行以上离线命令；修改启发式 JSON 后重跑 `correlate.py` 验证分析结果。`evidence-fetch` 只负责取数，不能验证启发式裁决。对新增规则同时保留应命中与不应命中的样例；通常无需修改 Python。

## 时间窗对照（matrix 为分钟源）

| matrix id | 默认 before/after | 用途 |
|-----------|-------------------|------|
| `lateral_movement` | 30m / 120m | syslog、target_exec、lateral_from_exec |
| `host_behavior_chain` | 5m / 5m | `policy.execution_chain` 锚点回看 |
| `attack_success` | 5m / 30m | 告警确认二层行为 |

秒级互证：`policy.execution_chain.connect_near_seconds`、`file_op_near_seconds`；`policy.bfs_lateral.firewall_near_seconds`。

## 与 rules.zh-CN.md 关系

- `rules.zh-CN.md`：判定逻辑说明（给人读）
- `heuristic-rules.json`：引擎实际执行的阈值与模式（给程序读）

两者应同步更新；以 JSON 为准。
