# SQL Injection + Path Traversal + WAF Alert Confirmation Lab

> SQL 注入 + 路径穿越 + WAF 告警确认 演练环境

## 覆盖场景

| 场景 | Skill | 说明 |
|------|-------|------|
| S4 | alert-confirmation | WAF 检测到攻击但未拦截 → 反向追溯确认真/误报 |
| S1 部分 | risk-identification | WAF 交互、SQL 注入利用 |

## 拓扑

```
  攻击者 (Host)
      │ HTTP
      ▼
 ┌──────────┐  MySQL (3306)  ┌──────────┐
 │ 10.66.6.91│ ─────────────▶ │ 10.66.6.92│
 │ OpenEuler│                │ CentOS 7 │
 │ Nginx+PHP│                │ MariaDB  │
 │ WAF(log) │                │ prod_db  │
 └──────────┘                └──────────┘
  SQLi + 路径穿越              敏感数据
  WAF(DetectionOnly)
```

## 部署

```bash
# 在 92 上先执行 (MySQL 需先就绪)
bash deploy-92.sh

# 在 91 上执行
bash deploy-91.sh
```

## 漏洞说明

| 组件 | 漏洞 | 细节 |
|------|------|------|
| search.php | SQL 注入 | `$_GET['q']` 直接拼入 SQL，可 UNION SELECT |
| page.php | 路径穿越 | `$_GET['tpl']` 未过滤 `../`，可读 /etc/passwd |
| WAF 层 (PHP) | DetectionOnly | SQLi/路径穿越仅 log 不拦截，XSS 拦截 (403) |

## WAF 行为矩阵

| 攻击类型 | WAF 动作 | HTTP 响应 | 后续主机行为 | S4 结论 |
|---------|---------|----------|-----------|--------|
| SQL 注入 | log (检测) | 200 | mysql 查询执行 | 真阳性 |
| 路径穿越 | log (检测) | 200 | 文件被读取 | 真阳性 |
| XSS | block (拦截) | 403 | 无 | 已阻断 |
| 正常搜索含 SQL 关键词 | log (可能) | 200 | 无恶意行为 | 误报 |

## 攻击流程

```bash
bash attack.sh                    # 默认目标
bash attack.sh 10.66.6.91 80       # 指定目标
```

## 日志采集点

| 主机 | 日志路径 | 对应 SecWeaver 证据类型 |
|------|---------|----------------------|
| 91 | `/var/log/nginx/access.log` | web_access_log |
| 91 | `/var/log/waf_alert.log` | waf_alert |
| 91 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | host_exec |
| 91 | `/opt/secweaver-agent/logs/syslog-risk-json.log` | syslog_risk_alert |
