# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

只有 2 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-23T08:00:00+08:00 | 2026-06-23T12:00:00+08:00 | 未提供 |

## 账号调查缺少认证日志

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s6-not-traceable-missing-auth；Skill：data-source-completeness。

### 结论

缺少关键数据源，溯源受阻（not\_traceable）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.39 | 未提供 | 未提供 | 未提供 |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 数据源能力

| 可溯源 | 具备打穿确认能力 | 下一技能受阻 | 下一技能 |
|---|---|---|---|
| 否 | 否 | 是 | traceability\_analysis |

| 需求 | 优先级 | 状态 | 缺口 |
|---|---|---|---|
| 认证日志 | P0 | missing | \["not\_registered"\] |
| 登录后命令执行 | P1 | ready | \[\] |
| 登录后持久化变更 | P1 | ready | \[\] |
| 防火墙日志 | P1 | missing | \["not\_registered"\] |

| 接入顺序 | 数据源 | 缺失影响 | 采集建议 |
|---|---|---|---|
| 1 | 认证日志 | 无法从 syslog-risk-json 派生 SSH 登录、PAM 认证与 root 会话证据 | secweaver-agent syslog-risk-json 采集 /var/log/secure、/var/log/auth.log、messages 并派生 SSH 认证证据 |
| 2 | 防火墙日志 | 无法可视化内网连接路径（如 WEB→SSH） | 防火墙 syslog 或 NetFlow，保留五元组与时间戳 |

### 原始证据时间线

本例没有实际事件；只评估登记数据源。

| 数据源 | 类型 | 覆盖 | 字段 |
|---|---|---|---|
| asset-host-exec-app | host\_exec | \["any"\] | \["host", "command", "timestamp"\] |
| asset-host-persistence-app | host\_persistence | \["any"\] | \["host", "path", "action", "timestamp"\] |

### 数据缺口与结论边界

- 缺少 P0 数据源: 认证日志
- 认证日志: missing \['not\_registered'\]
- 防火墙日志: missing \['not\_registered'\]

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/data-source-completeness/s6-not-traceable-missing-auth.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s6-not-traceable-missing-auth.json>)
