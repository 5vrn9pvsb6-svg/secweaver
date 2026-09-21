# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

只有 2 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T00:00:00+08:00 | 2026-06-21T23:59:59+08:00 | 未提供 |

## 仅能告警分类

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s4-alert-triage-only；Skill：data-source-completeness。

### 结论

仅能做告警分类，不能确认攻击成功（alert\_triage\_only）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.56 | 未提供 | 未提供 | 未提供 |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 数据源能力

| 可溯源 | 具备打穿确认能力 | 下一技能受阻 | 下一技能 |
|---|---|---|---|
| 否 | 否 | 是 | alert\_confirmation |

| 需求 | 优先级 | 状态 | 缺口 |
|---|---|---|---|
| WAF 告警（含 payload） | P0 | ready | \[\] |
| WEB 访问日志 | P0 | ready | \[\] |
| WEB 主机命令执行 | P1 | missing | \["not\_registered"\] |
| WEB 主机主动外连 | P1 | missing | \["not\_registered"\] |
| WEB 主机文件操作 | P1 | missing | \["not\_registered"\] |
| WEB 主机持久化变更 | P1 | missing | \["not\_registered"\] |

| 接入顺序 | 数据源 | 缺失影响 | 采集建议 |
|---|---|---|---|
| 1 | WEB 主机命令执行 | 无法确认 WebShell、curl/wget 下载、命令执行链，不能证明攻击成功 | Linux 部署 audit-port-execmon，配置 whitelist\_ports 监控对外端口进程 exec |
| 2 | WEB 主机主动外连 | 无法关联下载域名与 C2，攻击链缺少外连证据 | audit-port-execmon 开启 monitor\_connect |
| 3 | WEB 主机文件操作 | 无法确认 WebShell 落地或异常文件写入 | audit-port-execmon 开启 monitor\_file\_ops |
| 4 | WEB 主机持久化变更 | 无法确认 cron/systemd/authorized\_keys 等持久化落地，攻击后留驻证据缺失 | secweaver-agent 开启 host-persistence 模块，监控 cron、systemd、authorized\_keys、sudoers、profile 等持久化位置 |

### 原始证据时间线

本例没有实际事件；只评估登记数据源。

| 数据源 | 类型 | 覆盖 | 字段 |
|---|---|---|---|
| asset-waf-prod-01 | waf\_alert | \["web\_zone"\] | \["src\_ip", "timestamp", "url", "payload"\] |
| asset-web-access-prod | web\_access\_log | \["web\_zone"\] | \["src\_ip", "timestamp", "url"\] |

### 数据缺口与结论边界

- WEB 主机命令执行: missing \['not\_registered'\]
- WEB 主机主动外连: missing \['not\_registered'\]
- WEB 主机文件操作: missing \['not\_registered'\]
- WEB 主机持久化变更: missing \['not\_registered'\]

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/data-source-completeness/s4-alert-triage-only.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s4-alert-triage-only.json>)
