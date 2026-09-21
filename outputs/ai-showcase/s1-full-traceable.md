# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

只有 9 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T08:00:00+08:00 | 2026-06-21T20:00:00+08:00 | 未提供 |

## 溯源数据源齐备

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s1-full-traceable；Skill：data-source-completeness。

### 结论

登记数据源齐备，可开始取证（full\_traceable）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 1.0 | 未提供 | 未提供 | 未提供 |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 数据源能力

| 可溯源 | 具备打穿确认能力 | 下一技能受阻 | 下一技能 |
|---|---|---|---|
| 是 | 是 | 否 | traceability\_analysis |

| 需求 | 优先级 | 状态 | 缺口 |
|---|---|---|---|
| WEB/WAF 日志 | P0 | ready | \[\] |
| WEB 服务器进程命令执行 | P0 | ready | \[\] |
| SSH/syslog 认证日志 | P0 | ready | \[\] |
| WEB 服务器主动外连 | P1 | ready | \[\] |
| 防火墙/全流量内网连接 | P1 | ready | \[\] |
| DNS 查询日志 | P1 | ready | \[\] |
| WEB 服务器文件操作 | P2 | ready | \[\] |
| 资产清单 | P2 | ready | \[\] |

| 接入顺序 | 数据源 | 缺失影响 | 采集建议 |
|---|---|---|---|

### 原始证据时间线

本例没有实际事件；只评估登记数据源。

| 数据源 | 类型 | 覆盖 | 字段 |
|---|---|---|---|
| asset-waf-prod-01 | waf\_alert | \["web\_zone"\] | \["src\_ip", "timestamp", "url", "payload", "action"\] |
| asset-web-access-prod | web\_access\_log | \["web\_zone"\] | \["src\_ip", "timestamp", "url", "status"\] |
| asset-secweaver-host-exec | host\_exec | \["web\_hosts"\] | \["host", "command", "timestamp", "listener\_port", "listener\_process"\] |
| asset-ssh-internal | ssh\_auth | \["internal\_ssh"\] | \["host", "src\_ip", "user", "result", "timestamp"\] |
| asset-secweaver-host-connect | host\_connect | \["web\_hosts"\] | \["host", "dst\_ip", "dst\_port", "timestamp"\] |
| asset-fw-dmz-internal | firewall\_log | \["dmz\_to\_internal"\] | \["src\_ip", "dst\_ip", "timestamp"\] |
| asset-dns-internal | dns\_log | \["any"\] | \["client\_ip", "query", "timestamp"\] |
| asset-secweaver-host-file-op | host\_file\_op | \["web\_hosts"\] | \["host", "path", "action", "timestamp"\] |
| asset-cmdb-hosts | asset\_inventory | \["full"\] | \["hostname", "ip"\] |

### 数据缺口与结论边界

- DNS 查询日志已参与域名/C2/DGA 解释，但不能替代 firewall/NTA/proxy 的会话路径、方向、字节数和代理动作证据。

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/data-source-completeness/s1-full-traceable.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s1-full-traceable.json>)
