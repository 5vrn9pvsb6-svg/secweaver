# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

只有 3 份数据源登记信息，无事件取数；能力评分不代表攻击发生概率。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-21T08:00:00+08:00 | 2026-06-21T20:00:00+08:00 | 未提供 |

## 主机证据缺失时阻止过度结论

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：missing-host-exec-data；Skill：data-source-completeness。

### 结论

缺少关键数据源，溯源受阻（not\_traceable）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.38 | 未提供 | 未提供 | 未提供 |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 数据源能力

| 可溯源 | 具备打穿确认能力 | 下一技能受阻 | 下一技能 |
|---|---|---|---|
| 否 | 否 | 是 | traceability\_analysis |

| 需求 | 优先级 | 状态 | 缺口 |
|---|---|---|---|
| WEB/WAF 日志 | P0 | ready | \[\] |
| WEB 服务器进程命令执行 | P0 | missing | \["not\_registered"\] |
| SSH/syslog 认证日志 | P0 | partial | \["coverage\_partial"\] |
| WEB 服务器主动外连 | P1 | missing | \["not\_registered"\] |
| 防火墙/全流量内网连接 | P1 | missing | \["not\_registered"\] |
| DNS 查询日志 | P1 | missing | \["not\_registered"\] |
| WEB 服务器文件操作 | P2 | missing | \["not\_registered"\] |
| 资产清单 | P2 | ready | \[\] |

| 接入顺序 | 数据源 | 缺失影响 | 采集建议 |
|---|---|---|---|
| 1 | WEB 服务器进程命令执行 | 无法确认 WebShell、curl/wget 下载、命令执行链，不能证明攻击成功 | Linux 部署 audit-port-execmon，配置 whitelist\_ports 监控对外端口进程 exec |
| 2 | SSH/syslog 认证日志 | 无法追踪 SSH 横向移动与暴力破解 | 可选兼容入口：rsyslog 采集 /var/log/auth.log，保留 src\_ip、user、result、timestamp |
| 3 | WEB 服务器主动外连 | 无法关联下载域名与 C2，攻击链缺少外连证据 | audit-port-execmon 开启 monitor\_connect |
| 4 | 防火墙/全流量内网连接 | 无法可视化内网连接路径（如 WEB→SSH） | 防火墙 syslog 或 NetFlow，保留五元组与时间戳 |
| 5 | DNS 查询日志 | 只能看到 IP 无法解析下载/C2 域名 | 内网 DNS 查询日志或 DNS 安全网关 |

### 原始证据时间线

本例没有实际事件；只评估登记数据源。

| 数据源 | 类型 | 覆盖 | 字段 |
|---|---|---|---|
| waf\_01 | waf\_alert | \["web\_zone"\] | \["src\_ip", "timestamp", "url", "payload", "action"\] |
| ssh\_logs | ssh\_auth | \["partial\_internal"\] | \["host", "src\_ip", "user", "result", "timestamp"\] |
| cmdb | asset\_inventory | \["full"\] | \["hostname", "ip", "zone"\] |

### 数据缺口与结论边界

- 缺少 P0 数据源: WEB 服务器进程命令执行
- WEB 服务器进程命令执行: missing \['not\_registered'\]
- SSH/syslog 认证日志: partial \['coverage\_partial'\]
- WEB 服务器主动外连: missing \['not\_registered'\]
- 防火墙/全流量内网连接: missing \['not\_registered'\]
- DNS 查询日志: missing \['not\_registered'\]
- WEB 服务器文件操作: missing \['not\_registered'\]
- S1/S3/S7/S8 仍受网络侧证据缺口限制：防火墙/全流量内网连接；DNS 只能补充域名解析，不能单独证明完整链路或外传体量。

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/data-source-completeness/s1-not-traceable-missing-exec.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/missing-host-exec-data.json>)
