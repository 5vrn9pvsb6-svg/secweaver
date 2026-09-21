# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 1 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| syslog\_risk\_alert | 1 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-23T09:00:00+08:00 | 2026-06-23T10:00:00+08:00 | 未提供 |

## 异常 root SSH 登录

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s6-root-ssh-login-p1；Skill：risk-identification。

### 结论

检测到需调查的风险行为（high\_risk\_detected）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 未提供 | 未提供 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 风险项与规则

| 主机 | 等级 | 规则判定 | 证据 | 规则 | 策略 | 需告警 | ATT&CK | 建议动作 |
|---|---|---|---|---|---|---|---|---|
| app-01 | P1 | suspicious | \["syslog-root-login-001"\] | \["root\_ssh\_login"\] | DEFAULT-ALERT | 是 | \["T1021.004", "T1078"\] | manual\_review\_5m |

实际模块：\["syslog"\]；覆盖：insufficient。

| 统计 | 值 |
|---|---|
| total\_events\_scanned | 1 |
| risk\_items | 1 |
| p0 | 0 |
| p1 | 1 |
| p2 | 0 |
| p3 | 0 |
| alert\_required | 1 |
| alert\_suppressed | 0 |
| policy\_hits | 1 |
| top\_incidents | 1 |
| ssh\_brute\_waves | 0 |
| top\_hosts | \["app-01"\] |
| top\_risk\_tags | \["initial\_access"\] |
| top\_mitre\_techniques | \["T1021.004", "T1078"\] |

| 白名单 | 动作 | 原因 |
|---|---|---|

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-23T09:17:12+08:00 | syslog\_risk\_alert | syslog-root-login-001 | app-01 | 来源：203.0.113.88；用户：root；消息：Accepted publickey for root from 203.0.113.88 port 52341 ssh2 |

### 数据缺口与结论边界

- host\_exec missing
- host\_exec: missing — required for scenario S6
- host\_file\_op: missing — exec context boost degraded
- host\_persistence: missing — persistence risks degraded

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/risk-identification/s6-root-ssh-login-p1.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s6-root-ssh-login-p1.json>)
