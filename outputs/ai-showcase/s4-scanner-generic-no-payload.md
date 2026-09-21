# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 2 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| web\_access\_log | 1 |
| host\_exec | 0 |
| host\_connect | 0 |
| host\_file\_op | 0 |
| waf\_alert | 1 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 未提供 | 未提供 | 2026-06-21T03:00:00+08:00 |

## 无载荷的扫描器告警

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s4-scanner-generic-no-payload；Skill：alert-confirmation。

### 结论

扫描／探测（scanning\_or\_probe） / 成功与否未知（success\_unknown）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.6 | 0.6 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 告警真实性与攻击结果

| 告警 | 真实性 | 攻击结果 | 成功证据 | 原始置信度 | 建议动作 |
|---|---|---|---|---|---|
| WAF-20260621-scan-001 | 扫描／探测（scanning\_or\_probe） | 成功与否未知（success\_unknown） | \[\] | 0.6 | 仅记录，扫描探测 |

WAF-20260621-scan-001：无有效 payload，仅规则/generic 命中。活动级结果：成功与否未知（success\_unknown）。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T03:00:09+08:00 | web\_access\_log | web-scan-001 | 未提供 | 来源：203.0.113.77；路径：/admin/login；响应状态：404 |
| 2026-06-21T03:00:10+08:00 | primary\_alert | WAF-20260621-scan-001 | web-01 | 来源：203.0.113.77；方法：GET；路径：/admin/login；载荷：；动作：logged |

### 数据缺口与结论边界

- 无 host\_exec/connect/file\_op/host\_persistence，无法确认是否打穿或留驻
- 告警缺少 payload 字段

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/alert-confirmation/s4-scanner-generic-no-payload.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s4-scanner-generic-no-payload.json>)
