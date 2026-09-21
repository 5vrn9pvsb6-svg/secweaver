# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 6 | 3 | 2 | 2 | 1 | incomplete |

| 数据类型 | 记录数 |
|---|---|
| web\_access\_log | 3 |
| host\_exec | 0 |
| host\_connect | 0 |
| host\_file\_op | 0 |
| waf\_alert | 3 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

| 数据资产 | 类型 | 查询 | 成功 | 失败 | 累计取数 | 保留 | 去重 | 窗口过滤 |
|---|---|---|---|---|---|---|---|---|
| asset-host-exec-web | host\_exec | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| asset-web-access-web | web\_access\_log | 1 | 1 | 0 | 3 | 3 | 0 | 0 |

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T03:00:00+08:00 | 2026-06-21T16:10:00+08:00 | 未提供 |

## 混合告警批次与查询缺口

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s4-batch-mixed-with-query-gap；Skill：alert-confirmation。

### 结论

批量告警 3 条；误报 1；扫描 1；真实攻击 1；确认成功 0

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 未提供 | 未提供 | 0.65 | partial\_live\_evidence |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 告警真实性与攻击结果

| 告警 | 真实性 | 攻击结果 | 成功证据 | 原始置信度 | 建议动作 |
|---|---|---|---|---|---|
| WAF-BATCH-SCAN-001 | 扫描／探测（scanning\_or\_probe） | 成功与否未知（success\_unknown） | \[\] | 0.68 | 仅记录，扫描探测 |
| WAF-BATCH-SQLI-001 | 规则判为真实攻击（confirmed\_attack） | 已拦截（blocked） | \[\] | 0.75 | 记录并观察，WAF 已拦截 |
| WAF-BATCH-FP-001 | 误报（false\_positive） | 不适用（not\_applicable） | \[\] | 0.7 | 关闭告警（误报） |

WAF-BATCH-SCAN-001：无有效 payload，仅规则/generic 命中。活动级结果：成功与否未知（success\_unknown）。

WAF-BATCH-SQLI-001：检测到 sqli 攻击特征: ' OR,  OR 1=1, --。活动级结果：成功与否未知（success\_unknown）。

WAF-BATCH-FP-001：匹配误报模式: uuid\_param。活动级结果：成功与否未知（success\_unknown）。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T03:00:09+08:00 | web\_access\_log | web-batch-scan-001 | 未提供 | 来源：203.0.113.77；路径：/admin/login；响应状态：404 |
| 2026-06-21T03:00:10+08:00 | primary\_alert | WAF-BATCH-SCAN-001 | web-01 | 来源：203.0.113.77；方法：GET；路径：/admin/login；载荷：；动作：logged |
| 2026-06-21T14:30:04+08:00 | web\_access\_log | web-batch-sqli-001 | 未提供 | 来源：203.0.113.10；路径：/api/user?id=1' OR 1=1--；响应状态：403 |
| 2026-06-21T14:30:05+08:00 | primary\_alert | WAF-BATCH-SQLI-001 | web-01 | 来源：203.0.113.10；方法：GET；路径：/api/user?id=1' OR 1=1--；载荷：id=1' OR 1=1--；动作：blocked |
| 2026-06-21T16:00:00+08:00 | web\_access\_log | web-batch-fp-001 | 未提供 | 来源：198.51.100.20；路径：/api/order/detail?order\_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890；响应状态：200 |
| 2026-06-21T16:00:01+08:00 | primary\_alert | WAF-BATCH-FP-001 | web-01 | 来源：198.51.100.20；方法：GET；路径：/api/order/detail；载荷：a1b2c3d4-e5f6-7890-abcd-ef1234567890；动作：logged |

### 数据缺口与结论边界

- host\_exec query failed
- 无 host\_exec/connect/file\_op/host\_persistence，无法确认是否打穿或留驻
- 告警缺少 payload 字段

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/alert-confirmation/s4-batch-mixed-with-query-gap.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s4-batch-mixed-with-query-gap.json>)
