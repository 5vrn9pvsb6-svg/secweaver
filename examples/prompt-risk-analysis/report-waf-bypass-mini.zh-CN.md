# 研判报告 — WAF 漏过黄金样例

## 1. 证据概要

`fetch_summary`：原始 8 条，保留 7 条，去重 1 条，无失败查询与截断。报告统一以 retained events 为计数分母。

| asset_type | raw | retained | deduplicated |
|---|---:|---:|---:|
| waf_alert | 1 | 1 | 0 |
| web_access_log | 5 | 4 | 1 |
| host_exec | 1 | 1 | 0 |
| host_file_op | 1 | 1 | 0 |

## 2. 结论

- severity: **P0**
- attack_status: **confirmed_success**
- confidence: **high**
- disposition: **alert_required**

WAF 拦截了一次上传，但后续上传和 WebShell 命令请求未产生 WAF 告警，并分别由主机文件创建和 nginx 命令执行证据确认。

## 3. 场景与覆盖

主场景 S4，次要场景 S2。

| waf_coverage | 数量 |
|---|---:|
| waf_alert_count | 1 |
| web_access_raw_count | 5 |
| web_access_retained_count | 4 |
| blocked_count | 1 |
| backend_reached_count | 3 |
| suspicious_without_waf_count | 2 |
| confirmed_bypass_count | 2 |
| unmatched_waf_count | 0 |
| deduplicated_count | 1 |

`confirmed_bypass_count` 是 `suspicious_without_waf_count` 的子集；良性 `/health` 未计入漏过。

## 4. 时间线

| 时间 | 事件 | evidence_id |
|---|---|---|
| 12:00:00 | WAF 拦截上传，请求未到达 upstream | `waf-mini-001`, `web-mini-001` |
| 12:00:05 | 第二次上传无 WAF 告警，返回 302 并到达后端 | `web-mini-002` |
| 12:00:06 | 主机文件审计记录 `shell.phtml` 创建 | `file-mini-001` |
| 12:00:09 | nginx:80 执行 `id`，成功且 exit=0 | `web-mini-003`, `exec-mini-001` |

## 5. 风险发现

| 级别 | attack_status | 发现 | 证据 |
|---|---|---|---|
| P0 | confirmed_success | 上传漏过导致脚本落地 | `web-mini-002`, `file-mini-001` |
| P0 | confirmed_success | WebShell 命令漏过导致 nginx 执行 | `web-mini-003`, `exec-mini-001` |

所有证据引用均为 `redacted: true`，报告不包含可复用敏感值。

## 6. 影响与置信度

`10.0.0.10` 已确认脚本落地与命令执行。攻击链置信度高；是否为演练未知。

## 7. 处置与补数

1. 立即隔离 `10.0.0.10`，保全上传脚本、nginx 进程与日志证据。
2. 补充 `.phtml`、上传后执行和 query 命令模式的 WAF 规则。
3. 补拉 `asset-secweaver-host-connect`，检查 `d2_exec_connect_same_listener`。
