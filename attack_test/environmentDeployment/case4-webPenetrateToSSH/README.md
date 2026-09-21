# Web Penetration → Lateral SSH Brute-force Lab

> Web 挂马 → 横向 SSH 爆破 演练环境

## 覆盖场景

| 场景 | Skill | 说明 |
|------|-------|------|
| S2 | risk-identification | WebShell 上传 (.phtml 绕过) + RCE 命令执行 |
| S5 | external-listener-cmd-risk | nginx 子进程执行异常命令 (nmap, sshpass) |
| S6 | data-source-completeness | SSH 暴力破解 (14 密码) → 弱口令命中 |
| S7 部分 | traceability-analysis | 横向移动后凭证窃取 |

## 拓扑

```
  攻击者 (Host)
      │ HTTP
      ▼
 ┌──────────┐  SSH (sshpass)  ┌──────────┐
 │ 10.66.6.91│ ──────────────▶ │ 10.66.6.92│
 │ OpenEuler│                │ CentOS 7 │
 │ Nginx+PHP│                │ SSH :22  │
 │ /webshell│                │ devops   │
 └──────────┘                └──────────┘
  文件上传漏洞                  弱口令 SSH 目标
```

## 部署

```bash
# 前置: 先执行 deploy-nginx-base.sh (共享 Nginx 配置)

# 在 92 上执行 (SSH 弱口令目标)
bash deploy-ssh-target.sh

# 在 91 上执行 (Web 应用)
bash deploy-web.sh
```

## 漏洞说明

| 组件 | 漏洞 | 细节 |
|------|------|------|
| upload.php | 扩展名黑名单不完整 | 拦截 `.php` 但遗漏 `.phtml` `.phar` |
| upload.php | MIME 类型检查可绕过 | 仅校验 `Content-Type` 请求头（客户端可控） |
| nginx | `.phtml` 被当作 PHP 执行 | `location ~ \.(php\|phtml)$` |
| nginx | uploads 目录开启 autoindex | 信息泄露 |
| 92:SSH | 弱口令 | `devops` / `devops123` |

## 攻击流程

```bash
bash attack.sh                    # 默认目标
bash attack.sh 10.66.6.91 80       # 指定目标
```

### 攻击阶段

1. **正常业务流量** — 多 UA 浏览 + 合法文件上传
2. **目录扫描** — 20 路径侦察
3. **WebShell 上传** — .phtml 绕过黑名单
4. **RCE 信息收集** — id, passwd, ip addr, ps
5. **凭证搜索 / 提权 / 内网发现** — nmap → 92:22 开放
6. **SSH 暴力破解** — 14 密码字典，含故意失败
7. **横向移动 + 数据窃取** — db-credentials.conf, deploy-token.json, .bash_history
8. **攻击后正常流量**

## 日志采集点

| 主机 | 日志路径 | 对应 SecWeaver 证据类型 |
|------|---------|----------------------|
| 91 | `/var/log/nginx/access.log` | web_access_log |
| 91 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | host_exec (进程审计) |
| 91 | `/opt/secweaver-agent/logs/syslog-risk-json.log` | syslog_risk_alert |
| 92 | `/var/log/secure` | ssh_auth |
| 92 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | host_exec |
