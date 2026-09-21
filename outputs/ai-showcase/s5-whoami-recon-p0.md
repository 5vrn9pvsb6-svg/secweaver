# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 1 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| host\_exec | 1 |
| host\_connect | 0 |
| host\_file\_op | 0 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T13:00:00+08:00 | 2026-06-21T14:00:00+08:00 | 未提供 |

## Web 进程 shell 侦察

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s5-whoami-recon-p0；Skill：risk-identification。

### 结论

检测到需调查的风险行为（high\_risk\_detected）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 未提供 | 未提供 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 风险项与规则

| 主机 | 等级 | 规则判定 | 证据 | 规则 | 策略 | 需告警 | ATT&CK | 建议动作 |
|---|---|---|---|---|---|---|---|---|
| web-01 | P0 | confirmed\_attack | \["exec-recon-001"\] | \["external\_listener\_shell\_exec", "internal\_recon"\] | WEB-SHELL-001 | 是 | \["T1059.004", "T1190", "T1082", "T1046", "T1505.003"\] | isolate\_host\_and\_investigate |

实际模块：\["exec"\]；覆盖：partial。

| 统计 | 值 |
|---|---|
| total\_events\_scanned | 1 |
| risk\_items | 1 |
| p0 | 1 |
| p1 | 0 |
| p2 | 0 |
| p3 | 0 |
| alert\_required | 1 |
| alert\_suppressed | 0 |
| policy\_hits | 1 |
| top\_incidents | 1 |
| ssh\_brute\_waves | 0 |
| top\_hosts | \["web-01"\] |
| top\_risk\_tags | \["shell\_execution", "web\_process\_abuse", "discovery"\] |
| top\_mitre\_techniques | \["T1059.004", "T1190", "T1082", "T1046", "T1505.003"\] |

| 白名单 | 动作 | 原因 |
|---|---|---|

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T13:10:00+08:00 | host\_exec | exec-recon-001 | web-01 | 命令：\['/bin/sh', '-c', 'whoami'\] |

### 数据缺口与结论边界

- host\_file\_op: missing — exec context boost degraded
- host\_persistence: missing — persistence risks degraded

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/risk-identification/s5-whoami-recon-p0.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s5-whoami-recon-p0.json>)
