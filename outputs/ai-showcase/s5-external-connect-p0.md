# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 2 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| host\_exec | 0 |
| host\_connect | 2 |
| host\_file\_op | 0 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T11:00:00+08:00 | 2026-06-21T12:00:00+08:00 | 未提供 |

## Web 监听进程主动外连

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s5-external-connect-p0；Skill：risk-identification。

### 结论

检测到需调查的风险行为（high\_risk\_detected）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 未提供 | 未提供 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 风险项与规则

| 主机 | 等级 | 规则判定 | 证据 | 规则 | 策略 | 需告警 | ATT&CK | 建议动作 |
|---|---|---|---|---|---|---|---|---|
| web-01 | P0 | confirmed\_attack | \["connect-c2-001"\] | \["external\_c2\_connect"\] | CONNECT-C2-001 | 是 | \["T1071.001", "T1071"\] | investigate\_and\_contain |
| web-01 | P0 | confirmed\_attack | \["connect-c2-002"\] | \["external\_c2\_connect"\] | DEFAULT-ALERT | 是 | \["T1071.001"\] | isolate\_host\_and\_investigate |

实际模块：\["connect"\]；覆盖：insufficient。

| 统计 | 值 |
|---|---|
| total\_events\_scanned | 2 |
| risk\_items | 2 |
| p0 | 2 |
| p1 | 0 |
| p2 | 0 |
| p3 | 0 |
| alert\_required | 2 |
| alert\_suppressed | 0 |
| policy\_hits | 2 |
| top\_incidents | 2 |
| ssh\_brute\_waves | 0 |
| top\_hosts | \["web-01"\] |
| top\_risk\_tags | \["command\_and\_control", "active\_connect"\] |
| top\_mitre\_techniques | \["T1071.001", "T1071"\] |

| 白名单 | 动作 | 原因 |
|---|---|---|

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T11:05:33+08:00 | host\_connect | connect-c2-001 | web-01 | 目的：198.51.100.99；目的端口：4444 |
| 2026-06-21T11:05:35+08:00 | host\_connect | connect-c2-002 | web-01 | 目的：198.51.100.99；目的端口：443 |

### 数据缺口与结论边界

- host\_exec sparse
- host\_exec: no events in window
- host\_file\_op: missing — exec context boost degraded
- host\_persistence: missing — persistence risks degraded

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/risk-identification/s5-external-connect-p0.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s5-external-connect-p0.json>)
