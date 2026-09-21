# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

只有 4 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-24T01:00:00+08:00 | 2026-06-24T05:00:00+08:00 | 未提供 |

## 外传调查缺少流量体量

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s7-partial-missing-traffic-volume；Skill：data-source-completeness。

### 结论

数据源部分齐备，结论受缺口限制（partial\_traceable）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.75 | 未提供 | 未提供 | 未提供 |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 数据源能力

| 可溯源 | 具备打穿确认能力 | 下一技能受阻 | 下一技能 |
|---|---|---|---|
| 是 | 否 | 否 | traceability\_analysis |

| 需求 | 优先级 | 状态 | 缺口 |
|---|---|---|---|
| 外连/代理日志 | P0 | ready | \[\] |
| 敏感文件操作 | P0 | ready | \[\] |
| 外传/C2 域名 DNS 查询 | P1 | ready | \[\] |
| 外传流量体量（全流量/防火墙） | P1 | missing | \["not\_registered"\] |
| 打包/传输命令 | P1 | ready | \[\] |

| 接入顺序 | 数据源 | 缺失影响 | 采集建议 |
|---|---|---|---|
| 1 | 外传流量体量（全流量/防火墙） | 缺少全流量会话时难以还原非防火墙路径与外传体量 | NDR/TAP 全流量审计，保留五元组、协议、字节数/会话 ID |

### 原始证据时间线

本例没有实际事件；只评估登记数据源。

| 数据源 | 类型 | 覆盖 | 字段 |
|---|---|---|---|
| asset-host-connect-db | host\_connect | \["any"\] | \["host", "dst\_ip", "timestamp"\] |
| asset-host-file-db | host\_file\_op | \["any"\] | \["host", "path", "action", "timestamp"\] |
| asset-dns-internal | dns\_log | \["any"\] | \["client\_ip", "query", "timestamp"\] |
| asset-host-exec-db | host\_exec | \["any"\] | \["host", "command", "timestamp"\] |

### 数据缺口与结论边界

- 外传流量体量（全流量/防火墙）: missing \['not\_registered'\]
- DNS 查询日志已参与域名/C2/DGA 解释，但不能替代 firewall/NTA/proxy 的会话路径、方向、字节数和代理动作证据。
- S1/S3/S7/S8 仍受网络侧证据缺口限制：外传流量体量（全流量/防火墙）；DNS 只能补充域名解析，不能单独证明完整链路或外传体量。

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/data-source-completeness/s7-partial-missing-traffic-volume.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s7-partial-missing-traffic-volume.json>)
