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
| 未提供 | 未提供 | 2026-06-21T16:00:00+08:00 |

## 识别请求参数误报

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：false-positive-parameter；Skill：alert-confirmation。

### 结论

误报（false\_positive） / 不适用（not\_applicable）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.8 | 0.8 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 告警真实性与攻击结果

| 告警 | 真实性 | 攻击结果 | 成功证据 | 原始置信度 | 建议动作 |
|---|---|---|---|---|---|
| WAF-20260621-099 | 误报（false\_positive） | 不适用（not\_applicable） | \[\] | 0.8 | 关闭告警（误报） |

WAF-20260621-099：匹配误报模式: uuid\_param。活动级结果：成功与否未知（success\_unknown）。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T16:00:00+08:00 | web\_access\_log | web-fp-001 | 未提供 | 来源：198.51.100.20；路径：/api/order/detail?order\_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890；响应状态：200 |
| 2026-06-21T16:00:01+08:00 | primary\_alert | WAF-20260621-099 | web-01 | 来源：198.51.100.20；方法：GET；路径：/api/order/detail；载荷：a1b2c3d4-e5f6-7890-abcd-ef1234567890；动作：logged |

### 数据缺口与结论边界

- 无 host\_exec/connect/file\_op/host\_persistence，无法确认是否打穿或留驻

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/alert-confirmation/s4-false-positive-uuid-param.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/false-positive-parameter.json>)
