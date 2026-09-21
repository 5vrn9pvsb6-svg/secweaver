# Command Injection → C2 Communication → Persistence Lab

> 命令注入 → C2 通信 → 持久化 演练环境

## 覆盖场景

| 场景 | Skill | 说明 |
|------|-------|------|
| S5 | risk-identification | 主机异常多阶段: 命令注入→信息收集→C2→持久化 |
| S5 | external-listener-cmd-risk | nginx 子进程执行异常命令 (listener_port=80) |
| S5 | external-listener-connect-risk | nginx 子进程发起外连到 C2 |
| S1 部分 | traceability-analysis | C2 心跳通信 + 工具下载 + 数据外传 |

## 与 webPenetrateToSSH 的关键差异

| 维度 | webPenetrateToSSH | cmdInjectionC2 |
|------|-------------------|----------------|
| 入口漏洞 | 文件上传 (.phtml WebShell) | OS 命令注入 (diag.php) |
| 连接方向 | 91 SSH→ 92 | 91 HTTP→ 92 (C2) |
| 92 角色 | 弱口令 SSH 目标 | C2 监听器 |
| 持久化 | 无 | crontab beacon + SUID 后门 |
| 攻击阶段 | 5 阶段 | 10 阶段 (含工具下载/提权/持久化) |

## 拓扑

```
  攻击者 (Host)
      │ HTTP
      ▼
 ┌──────────┐  curl (C2心跳/外传)  ┌──────────┐
 │ 10.66.6.91│ ──────────────────▶ │ 10.66.6.92│
 │ OpenEuler│                     │ CentOS 7 │
 │ Nginx+PHP│                     │ C2 :8443 │
 │ 命令注入  │                     │ Python   │
 └──────────┘                     └──────────┘
  diag.php?host=;cmd               HTTP listener
```

## 部署

```bash
# 在 91 上执行
bash deploy-91.sh

# 在 92 上执行
bash deploy-92.sh
```

## 漏洞说明

| 组件 | 漏洞 | 细节 |
|------|------|------|
| diag.php | OS 命令注入 | `$host` 直接拼入 `ping -c3 $host`，无过滤 |
| config/app.conf | 凭证明文 | 数据库密码、API 密钥明文存储在 web 目录 |
| nginx | 进程权限 | PHP 以 nginx 用户运行，命令注入获得 nginx 权限 |

## 攻击流程

```bash
bash attack.sh                    # 默认目标
bash attack.sh 10.66.6.91 80       # 指定目标
```

### 攻击阶段

1. **正常流量** — 正常使用 ping/nslookup 工具
2. **命令注入探测** — `;id` `;whoami` 确认注入点
3. **RCE 信息收集** — 系统信息/网络/进程/passwd
4. **凭证发现** — find 配置文件, 读取 app.conf
5. **C2 心跳** — 4 次 GET 到 92:8443/beacon
6. **工具下载** — curl 从 C2 拉取 scan.sh/privesc
7. **提权尝试** — sudo -l, SUID, /etc/shadow
8. **持久化** — crontab beacon (*/5 * * * *) + SUID bash 后门
9. **数据外传** — tar 打包→ curl POST 到 C2
10. **攻击后正常流量** — 正常 ping 请求

## 日志采集点

| 主机 | 日志路径 | 对应 SecWeaver 证据类型 |
|------|---------|----------------------|
| 91 | `/var/log/nginx/access.log` | web_access_log |
| 91 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | host_exec (进程审计) |
| 91 | `/opt/secweaver-agent/logs/syslog-risk-json.log` | syslog_risk_alert |
| 92 | `/var/log/c2-listener.log` | — (C2 接收日志) |
