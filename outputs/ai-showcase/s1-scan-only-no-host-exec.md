# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 5 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| waf\_alert | 2 |
| web\_access\_log | 2 |
| host\_exec | 0 |
| host\_connect | 0 |
| host\_file\_op | 0 |
| ssh\_auth | 0 |
| firewall\_log | 0 |
| asset\_inventory | 1 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 2026-06-22T12:00:00+08:00 | 2026-06-22T18:00:00+08:00 | 2026-06-22T14:20:00+08:00 |

## 仅扫描无主机执行

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：s1-scan-only-no-host-exec；Skill：traceability-analysis。

### 结论

仅观察到扫描或尝试（scanning\_or\_attempt\_only）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.62 | 0.62 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 入口与横向证据

| 观察目标 | 入口角色 | 首次攻破点状态 | URL | 主要证据 |
|---|---|---|---|---|
| 10.0.1.5 | suspicious\_request | candidate | http://10.0.1.5/wp-login.php | \["web-101"\] |

观察到的控制点不等于原始攻破方式；规范化 URL、关联边和 ATT&CK 标签需结合原始证据复核。

| 横向分类 | 来源 | 目标 | 账号 | 确认时间 | 证据 |
|---|---|---|---|---|---|

| 影响目标（脚本标签） | 角色 | 排查优先级 |
|---|---|---|
| 10.0.1.5 | initial\_compromise | P0 |

| 建议动作 |
|---|
| 持续观察该 IP，检查 WAF 规则与封禁策略 |

ATT&CK（规则映射）：\["T1190", "T1505.003", "T1059.004"\]。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 未提供 | asset\_inventory | 未提供 | 未提供 | {"hostname": "web-01", "ip": "10.0.1.5", "zone": "dmz"} |
| 2026-06-22T14:19:50+08:00 | web\_access\_log | web-101 | web-01 | 来源：198.18.0.99；方法：GET；路径：/wp-login.php；响应状态：404 |
| 2026-06-22T14:19:55+08:00 | waf\_alert | waf-102 | web-01 | 来源：198.18.0.99；路径：/wp-admin/setup-config.php；载荷：；动作：block |
| 2026-06-22T14:20:00+08:00 | waf\_alert | waf-101 | web-01 | 来源：198.18.0.99；路径：/.env；载荷：；动作：block |
| 2026-06-22T14:20:02+08:00 | web\_access\_log | web-102 | web-01 | 来源：198.18.0.99；方法：GET；路径：/.env；响应状态：403 |

### 数据缺口与结论边界

- host\_exec 未接入或时间窗内无事件
- no\_match:web\_access\_to\_host\_exec (WEB 请求落到主机命令执行（攻击是否成功）)
- no\_match:d2\_exec\_connect\_same\_listener (同一对外入口进程下的命令执行与外连)
- no\_match:host\_connect\_to\_dns (外连 IP 解析对应域名（C2/下载站）)
- no\_match:attacker\_ip\_to\_ssh\_auth (外网攻击 IP 是否尝试/成功 SSH 登录)
- no\_match:host\_ip\_to\_ssh\_auth\_lateral (受害主机作为跳板对内网 SSH 横向)
- not\_evaluated:host\_connect\_to\_dns (missing asset\_type: dns\_log)

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/traceability/s1-scan-only-no-host-exec.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/s1-scan-only-no-host-exec.json>)
