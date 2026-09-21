# SecWeaver Attack Lab Environments

> SecWeaver 安全演练环境部署与攻击模拟

**WARNING**: This directory contains lab-only attack simulation scripts for security analysis validation. All scripts must only be executed in isolated lab environments with proper authorization.

## 安全边界（必读 / Safety Guardrails）

**本目录所有脚本仅限隔离实验环境使用。** 部署脚本会修改 SELinux、防火墙、Nginx、SSH、MariaDB 和 systemd 配置，并创建弱口令用户——**禁止在任何生产主机上执行**。

文档和脚本使用 `10.66.6.91`、`10.66.6.92` 作为合成实验拓扑。它们不是已部署服务地址；运行物理机或虚机方案前，需要在隔离网中为两台一次性靶机分配该网段，或统一修改脚本和允许目标清单。容器方案不要求宿主机使用这些地址。

强制护栏（fail-closed，无法绕过）：

1. **显式确认**：所有脚本要求 `SECWEAVER_LAB_ACK=I_UNDERSTAND_THIS_IS_AN_ISOLATED_AUTHORIZED_LAB`，否则直接退出。
2. **靶机标记**：部署/卸载脚本要求 root，且靶机必须是容器，或已由运维创建 `/etc/secweaver-lab-host` 标记文件。
3. **目标白名单**：攻击脚本要求 `SECWEAVER_LAB_ALLOWED_TARGETS`（逗号分隔的实验主机清单），目标不在清单内即退出——防止复制的命令误打真实主机或公网服务。
4. **配置备份与范围化清理**：被修改的文件会在首次变更前快照到 `/var/lib/secweaver-lab-backup`；新建目录、用户、数据库和防火墙规则同时记录所有权。`teardown-lab.sh` 只删除有所有权标记的资源、移除带 `# secweaver-attack-lab` 标记的 cron 条目并恢复文件快照，不会删除原有 root crontab 或同名用户。

```bash
# 标准使用流程
export SECWEAVER_LAB_ACK=I_UNDERSTAND_THIS_IS_AN_ISOLATED_AUTHORIZED_LAB
export SECWEAVER_LAB_ALLOWED_TARGETS=10.66.6.91,10.66.6.92

# 部署 → 攻击 → 卸载
sudo env SECWEAVER_LAB_ACK="$SECWEAVER_LAB_ACK" bash deploy-nginx-base.sh
sudo env SECWEAVER_LAB_ACK="$SECWEAVER_LAB_ACK" bash case1-sqlInjectionAlertConfirm/deploy-91.sh
bash case1-sqlInjectionAlertConfirm/attack.sh
sudo env SECWEAVER_LAB_ACK="$SECWEAVER_LAB_ACK" bash teardown-lab.sh
```

**优先使用容器**：`case4-webPenetrateToSSH/docker-compose.yml` 提供容器化部署（`docker compose config` 可校验），无需修改宿主机任何系统配置。物理机/虚机部署仅作为无容器环境时的替代方案。

**清理限制**：范围化清理不会卸载软件包，也不会猜测恢复 Nginx、PHP-FPM、MariaDB、SSH 等通用服务原先的启用/运行状态。脚本会恢复有快照的配置并回退由实验新增的防火墙规则；已消费的恢复状态会改名为 `/var/lib/secweaver-lab-backup.restored-<timestamp>-<pid>`，防止重复卸载再次应用旧所有权标记。下一次部署会创建全新的活动状态目录。如需保证完全复原，应销毁并重建一次性虚机或容器。若部署遇到已有 `devops` 用户、`prod_db` 数据库、`app_user@%` 账户或未被实验声明所有权的应用/C2 目录，会直接拒绝覆盖。

---


## Overview

This directory contains 4 co-hosted security lab environments on 2 hosts, designed to generate real attack logs for validating SecWeaver's analysis skills. All environments deploy under `/var/www/html/` in separate subdirectories and share a single Nginx + PHP-FPM base configuration.

Unlike synthetic-data generators, these environments generate **real process chains, network connections, and log timelines** — closely matching production security analysis scenarios.

## Hosts & Network Topology

| Host | IP         | OS                  | Role                                             |
|------|------------|---------------------|--------------------------------------------------|
| 91   | 10.66.6.91  | OpenEuler 22.03 SP2 | Nginx + PHP-FPM, hosting 4 web applications      |
| 92   | 10.66.6.92  | CentOS 7            | MariaDB + C2 listener + SSH weak-password target  |

```
  Attacker (internal network)
      │ HTTP :80 (direct) / HTTPS :30443 (via WAF)
      ▼
 ┌─────────────────────────────────────┐
 │         10.66.6.91 (OpenEuler)       │
 │  /var/www/html/                     │
 │    ├── webshell/   SecureShare      │
 │    ├── sqli/       Product Search   │
 │    ├── cmdi/       NetTools         │
 │    └── exfil/      DataApp          │
 │                                     │
 │  Memory WebShell: /dev/shm/ (tmpfs) │
 │  Injection points: diag.php /       │
 │                    upload.php       │
 └───────────┬─────────────────────────┘
             │ MySQL :3306 / HTTPS :8443 (C2) / SSH :22
             ▼
 ┌─────────────────────────────────────┐
 │         10.66.6.92 (CentOS 7)       │
 │  MariaDB (prod_db)                 │
 │  C2 listener (Python :8443)        │
 │  SSH weak password target           │
 └─────────────────────────────────────┘
```

## Environment Summary

| #  | Environment                         | Subdirectory   | Entry Vulnerability              | C2 Method              | Scenarios     | Phases |
|----|-------------------------------------|----------------|----------------------------------|------------------------|---------------|--------|
| 1  | [case4-webPenetrateToSSH](#case4-web-penetrate-to-ssh)       | `/webshell/` | File upload blacklist bypass (.phtml) | SSH lateral movement | S2 S5 S6 S7 | 8      |
| 2  | [case1-sqlInjectionAlertConfirm](#case1-sql-injection-alert-confirm) | `/sqli/` | SQL injection (UNION SELECT)     | None                   | S4 S1        | 6      |
| 3  | [case2-cmdInjectionC2](#case2-command-injection-c2)             | `/cmdi/`     | OS command injection (ping)      | **Memory WebShell**    | S5 S1        | 10     |
| 4  | [case3-dataExfilC2](#case3-data-exfil-c2)                   | `/exfil/`    | File upload + WebShell           | **Memory WebShell (fileless)** | S7 S5 | 11     |

### Skill Coverage Matrix

| Skill                    | S1 risk-id | S2 WebShell | S4 alert-confirm | S5 host-anomaly | S6 SSH brute | S7 data-exfil |
|--------------------------|:----------:|:-----------:|:----------------:|:---------------:|:------------:|:-------------:|
| case4-webPenetrateToSSH        |            | **●**       |                  | **●**           | **●**        | **●**         |
| case1-sqlInjectionAlertConfirm | **●**      |             | **●**            |                 |              |               |
| case2-cmdInjectionC2           | **●**      |             |                  | **●**           |              |               |
| case3-dataExfilC2              |            |             |                  | **●**           |              | **●**         |

### Attack Script Variants

Each environment provides two attack script variants:

| Variant                | Target                 | Description                              |
|------------------------|------------------------|------------------------------------------|
| `attack.sh`            | Direct IP (10.66.6.91)  | Standard attack chain, no WAF involved   |
| `attack-domain-waf.sh` | WAF domain (HTTPS)     | Same chain routed through WAF, with WAF bypass techniques |

WAF variant scripts accept environment variable overrides:

```bash
export WAF_DOMAIN="https://your-waf-domain:port"
export WISID_COOKIE="WISID=<your-session-id>"
# 白名单使用纯主机名，不带协议、端口或路径。
export SECWEAVER_LAB_ALLOWED_TARGETS=10.66.6.91,10.66.6.92,your-waf-domain
bash <env>/attack-domain-waf.sh
```

---

## Memory WebShell Technical Overview

Environments 3 (case2-cmdInjectionC2) and 4 (case3-dataExfilC2) use a **memory-resident WebShell** as a covert C2 channel, rather than a traditional reverse-connect C2 server.

### How It Works

```
Attacker                        91 (Compromised Host)                92
  │                              │                                   │
  │  HTTP GET /cmdi/diag.php     │                                   │
  │  X-Forwarded-Port:           │                                   │
  │    <token>|<base64_cmd>      │                                   │
  │  X-Real-IP: body             │                                   │
  │ ─────────────────────────▶   │                                   │
  │                              │ @include(/dev/shm/.sess_xxx)      │
  │                              │ ↓ Parse request headers           │
  │                              │ ↓ Base64 decode command           │
  │                              │ ↓ shell_exec()                    │
  │                              │                                   │
  │  <!--MEM:base64_result:MEM-->│                                   │
  │ ◀─────────────────────────   │                                   │
  │                              │                                   │
  │  (data exfiltration)         │  curl POST → :8443                │
  │                              │ ──────────────────────────────▶   │
```

### Key Characteristics

| Feature            | Description                                                        |
|--------------------|--------------------------------------------------------------------|
| **Payload location** | `/dev/shm/.sess_<random>` — tmpfs (in-memory filesystem, no disk write, lost on reboot) |
| **Injection method** | `@include` injected into line 2 of legitimate PHP files (diag.php / upload.php) |
| **C2 protocol**      | HTTP header `X-Forwarded-Port: <token>\|<base64_cmd>`             |
| **Response format**  | Embedded HTML comment `<!--MEM:<base64_output>:MEM-->`            |
| **Authentication**   | Fixed token (lab simplification)                                   |
| **Port**             | 80 (blends with normal web traffic, no extra ports)               |
| **Fileless variant** | In case3-dataExfilC2, the initial .phtml WebShell self-deletes after memory shell injection |

### Detection Indicators

- `.sess_*` PHP files under `/dev/shm/`
- `@include("/dev/shm/...")` injected into legitimate PHP files
- `X-Forwarded-Port` header containing `|`-separated anomalous base64 content
- `audit-port-execmon`: php-fpm child processes executing unexpected commands (mysql, curl, tar)
- All C2 commands execute under the nginx user with php-fpm worker as parent process

---

## Deployment Guide

### Prerequisites

- Two hosts with network connectivity (91 ↔ 92)
- Root privileges on both hosts
- SSH access (direct or via JumpServer)

### Deployment Order

```bash
# ── Step 1: Host 92 (database + backend services) ──

# 1a. SSH weak-password target (required by case4-webPenetrateToSSH)
ssh lab-92 'sudo bash -s' < case4-webPenetrateToSSH/deploy-ssh-target.sh

# 1b. MariaDB database (required by sqli + exfil)
ssh lab-92 'sudo bash -s' < case1-sqlInjectionAlertConfirm/deploy-92.sh

# 1c. C2 listener + exfil tables (required by cmdi + exfil)
ssh lab-92 'sudo bash -s' < case2-cmdInjectionC2/deploy-92.sh
ssh lab-92 'sudo bash -s' < case3-dataExfilC2/deploy-92.sh

# ── Step 2: Host 91 (Nginx base + 4 web applications) ──

# 2a. Shared Nginx + PHP-FPM configuration (run once)
ssh lab-91 'sudo bash -s' < deploy-nginx-base.sh

# 2b. Individual web applications
ssh lab-91 'sudo bash -s' < case4-webPenetrateToSSH/deploy-web.sh
ssh lab-91 'sudo bash -s' < case1-sqlInjectionAlertConfirm/deploy-91.sh
ssh lab-91 'sudo bash -s' < case2-cmdInjectionC2/deploy-91.sh
ssh lab-91 'sudo bash -s' < case3-dataExfilC2/deploy-91.sh
```

### Verification

```bash
curl -s -o /dev/null -w "%{http_code}" http://10.66.6.91/webshell/   # 200
curl -s -o /dev/null -w "%{http_code}" http://10.66.6.91/sqli/       # 200
curl -s -o /dev/null -w "%{http_code}" http://10.66.6.91/cmdi/       # 200
curl -s -o /dev/null -w "%{http_code}" http://10.66.6.91/exfil/      # 200
```

---

## Environment Details

<a id="case4-web-penetrate-to-ssh"></a>

### 1. case4-webPenetrateToSSH

**Subdirectory**: `/webshell/` | **Scripts**: `attack.sh`, `attack-domain-waf.sh`

**Scenario**: File upload vulnerability → WebShell → network discovery → SSH brute-force → lateral movement → credential theft

```
Attacker ──HTTP──▶ 91:/webshell/ ──WebShell──▶ nmap ──▶ sshpass ──SSH──▶ 92 (devops)
```

#### Vulnerabilities

| Component    | Vulnerability               | Detail                                  |
|--------------|-----------------------------|-----------------------------------------|
| upload.php   | Incomplete extension blacklist | Blocks `.php` but misses `.phtml`     |
| upload.php   | MIME type spoofable         | Only validates `Content-Type` header    |
| nginx        | `.phtml` executed as PHP    | `location ~ \.(php\|phtml)$`           |
| 92:SSH       | Weak password               | `devops` / `devops123`                 |

#### Attack Phases

1. Pre-attack normal traffic (multi-UA browsing + legitimate file upload)
2. Reconnaissance scan (20-path directory enumeration)
3. WebShell upload (.phtml blacklist bypass)
4. RCE reconnaissance (id, passwd, ip addr, ps)
5. Credential search + privilege escalation + network discovery (nmap → 92:22)
6. SSH brute-force (14-password dictionary)
7. Lateral movement + data theft (db-credentials.conf, deploy-token.json)
8. Post-attack normal traffic

#### WAF Bypass (attack-domain-waf.sh)

- `/etc/passwd` → `/e??/passw?` (wildcard bypass)
- `/etc/shadow` → `/e??/shado?` (wildcard bypass)
- `.php` upload → `.phtml` upload (extension bypass)

---

<a id="case1-sql-injection-alert-confirm"></a>

### 2. case1-sqlInjectionAlertConfirm

**Subdirectory**: `/sqli/` | **Scripts**: `attack.sh`, `attack-domain-waf.sh`

**Scenario**: SQL injection + path traversal + WAF alert confirmation (true/false positive determination)

```
Attacker ──HTTP──▶ 91:/sqli/search.php ──SQL──▶ 92:MariaDB (prod_db)
                       │
                  Network-layer / Cloud WAF
```

#### Vulnerabilities

| Component    | Vulnerability | Detail                                                     |
|--------------|---------------|------------------------------------------------------------|
| search.php   | SQL injection | `$_GET['q']` concatenated into `WHERE LIKE '%$q%'`, allows UNION SELECT |
| page.php     | Path traversal| `$_GET['tpl']` unfiltered `../`, 5 levels deep reads `/etc/passwd`      |

#### WAF Behavior (S4 Core)

WAF deployed at network/cloud layer, detection-only mode (does not block). WAF alerts sourced from cloud logs.

| Attack Type             | WAF Detected | HTTP Response | Host-side Behavior | S4 Conclusion |
|-------------------------|:------------:|:-------------:|--------------------|--------------:|
| SQL injection (UNION)   | Yes          | 200           | MySQL query executed | True positive |
| Path traversal (../)    | Yes          | 200           | File read executed   | True positive |
| Normal search with SQL keywords | Yes (low) | 200    | No malicious action  | False positive|

#### Attack Phases

1. Pre-attack normal traffic (multi-UA browsing + legitimate searches)
2. Target reconnaissance (directory enumeration, fingerprinting, parameter discovery)
3. SQL injection probing (error trigger → ORDER BY → UNION → information_schema → data extraction)
4. Path traversal (parameter behavior → depth probing → /etc/passwd → /etc/shadow → source code credentials)
5. Normal searches triggering WAF false positives (legitimate queries containing SQL keywords)
6. Post-attack normal traffic

---

<a id="case2-command-injection-c2"></a>

### 3. case2-cmdInjectionC2

**Subdirectory**: `/cmdi/` | **Scripts**: `attack.sh`, `attack-domain-waf.sh`

**Scenario**: OS command injection → RCE → **memory WebShell injection** → credential discovery → privilege escalation → persistence → data exfiltration

```
Attacker ──HTTP──▶ 91:/cmdi/diag.php
                   │
                   ├── ;id → command injection confirmed
                   ├── Write memory WebShell → /dev/shm/.sess_xxx
                   ├── @include injected into diag.php
                   │
                   ├── X-Forwarded-Port: token|base64_cmd ← Memory WebShell C2
                   │     ↓ Reconnaissance, credential discovery, privilege escalation, persistence
                   │
                   └── Via memory WebShell: curl POST ──▶ 92:8443 (data exfiltration)
```

#### Key Differences from case4-webPenetrateToSSH

| Dimension       | case4-webPenetrateToSSH     | cmdInjectionC2                       |
|------------------|-----------------------|--------------------------------------|
| Entry vulnerability | File upload WebShell | OS command injection                |
| C2 method        | SSH lateral movement  | **Memory WebShell** (HTTP header C2) |
| Connection direction | 91 SSH → 92:22    | Memory WebShell C2 (port 80) + exfil → 92:8443 |
| Persistence      | None                  | crontab beacon                       |
| File artifacts   | .phtml WebShell       | /dev/shm/ (tmpfs, no disk write)     |

#### Vulnerabilities

| Component        | Vulnerability    | Detail                                              |
|------------------|------------------|-----------------------------------------------------|
| diag.php         | OS command injection | `$host` directly into `ping -c3 $host`, `;` injection |
| config/app.conf  | Plaintext credentials | DB password + API key stored in web directory      |

#### Attack Phases

1. Normal traffic (legitimate ping/nslookup requests)
2. Target reconnaissance (fingerprinting, parameter behavior, directory enumeration)
3. Command injection probing (`;id` → `whoami` → system info, progressive confirmation)
4. Memory WebShell injection (write /dev/shm/ → Python-inject @include → verify C2 channel)
5. System reconnaissance (via memory WebShell C2)
6. Credential discovery (via memory WebShell)
7. Privilege escalation attempt (via memory WebShell)
8. Persistence — crontab beacon (via memory WebShell)
9. Data packaging + exfiltration (via memory WebShell → C2 endpoint)
10. Post-attack normal traffic

#### WAF Bypass (attack-domain-waf.sh)

- WAF overwrites `X-Real-IP` → use `X-Debug` header instead
- `/etc/passwd` → `/e??/passw?` (wildcard bypass)
- Memory WebShell deployed via `.phtml` file upload (more stable than CmdI echo|base64)

---

<a id="case3-data-exfil-c2"></a>

### 4. case3-dataExfilC2

**Subdirectory**: `/exfil/` | **Scripts**: `attack.sh`, `attack-domain-waf.sh`

**Scenario**: File upload probing → WebShell initial foothold → **memory WebShell injection → fileless** → credential discovery → database theft → packaging + exfiltration → DNS tunneling

```
Attacker ──HTTP──▶ 91:/exfil/upload.php
                   │
                   ├── .php upload blocked → .phtml bypass → initial WebShell
                   ├── Via WebShell inject memory WebShell:
                   │     ├── Write PHP payload → /dev/shm/.sess_xxx
                   │     └── @include injected into upload.php
                   ├── Delete initial WebShell (.phtml) ← fileless
                   │
                   ├── X-Forwarded-Port: token|base64_cmd ← Memory WebShell C2
                   │     ↓ cat database.yml → credential discovery
                   │     ↓ mysql → sensitive DB queries
                   │     ↓ mysqldump → tar → packaging
                   │
                   ├── curl POST ──▶ 92:8443 (data exfiltration)
                   └── curl GET  ──▶ 92:8443/dns/<base64> (DNS tunnel simulation)
```

#### Vulnerabilities

| Component          | Vulnerability              | Detail                           |
|--------------------|----------------------------|----------------------------------|
| upload.php         | Extension blacklist gap    | Blocks `.php` but not `.phtml`   |
| config/database.yml| Plaintext credentials      | Database connection info in plaintext |

#### Reverse Tracing Path (S7 Core)

```
Detection point: audit-port-execmon records php-fpm child executing unexpected commands
  ↑ host_exec: curl POST @/tmp/.data.tar.gz → 92:8443 (data exfiltration)
  ↑ host_exec: tar czf /tmp/.data.tar.gz /tmp/.dump.sql
  ↑ host_exec: mysqldump prod_db users payment_cards credentials
  ↑ host_connect: 91 → 92:3306 (nginx/php-fpm child process)
  ↑ host_exec: cat /var/www/html/exfil/config/database.yml
  └─ Conclusion: File upload (.phtml) → memory WebShell → credential discovery → DB export → C2 exfil

Stealth: Upload directory has no suspicious files (WebShell deleted), C2 traffic on port 80
Secondary detection: Multiple HTTP requests to 92:8443/dns/<base64> (DNS tunnel simulation)
```

#### Attack Phases

1. Pre-attack normal traffic
2. Target reconnaissance (fingerprinting, upload form discovery, directory listing, endpoint confirmation)
3. File upload probing (normal .jpg → .php blocked → .phtml bypass → initial WebShell)
4. Memory WebShell injection + fileless (write /dev/shm/ → @include → verify C2 → **delete initial WebShell**)
5. Credential discovery (via memory WebShell)
6. Sensitive database queries (via memory WebShell)
7. Data export + packaging (mysqldump → tar, via memory WebShell)
8. Data exfiltration (via memory WebShell → C2 endpoint)
9. DNS tunnel simulation (7 base64-encoded chunks, via memory WebShell)
10. Trace cleanup (via memory WebShell)
11. Post-attack normal traffic

---

## Log Collection Points

Install the unified `secweaver-agent` before the exercise, using the
[SaaS customer guide](../../docs_user/29-secweaver-data-system-quickstart.md) or the
[standalone ES guide](../../src/tools/secweaver-agent/elasticsearch/README.md).
The paths below assume its default host configuration, not legacy module daemons.
Custom paths must follow `/opt/secweaver-agent/etc/config.json` and its module configs.
Container workload collection has a different evidence boundary; it does not provide
complete host audit visibility without a separately installed host Agent.

演练前先安装统一 `secweaver-agent`。以下路径对应默认主机配置，不是旧版独立模块服务。
先完成 Agent 预检和目标存储查询验收，再运行攻击脚本；不要把容器工作负载采集等同于完整宿主审计。

### Host 91 (OpenEuler)

| Log Path                             | Content                              | SecWeaver Evidence Type |
|--------------------------------------|--------------------------------------|-------------------------|
| `/var/log/nginx/access.log`          | All HTTP requests (4 subdirectories) | web_access_log          |
| `/opt/secweaver-agent/logs/audit-port-execmon.log`    | Process execution audit (incl. memory WebShell commands) | host_exec |
| `/opt/secweaver-agent/logs/syslog-risk-json.log`      | Risk events                          | syslog_risk_alert              |

### Host 92 (CentOS)

| Log Path                             | Content                              | SecWeaver Evidence Type |
|--------------------------------------|--------------------------------------|-------------------------|
| `/opt/secweaver-agent/logs/audit-port-execmon.log`    | Process execution audit              | host_exec               |
| `/opt/secweaver-agent/logs/syslog-risk-json.log`      | Risk events                          | syslog_risk_alert              |
| `/var/log/c2-listener.log`           | C2 endpoint logs (beacon + exfil)    | (server-side)           |
| `/var/log/secure`                    | SSH authentication log               | ssh_auth                |

---

## Running Attacks

```bash
# Run from attack_test/environmentDeployment/. Configure lab-91/lab-92 SSH aliases first.
# On each lab host, preflight must pass before the exercise.
ssh -t lab-91 'sudo /opt/secweaver-agent/bin/secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json -strict && sudo systemctl start secweaver-agent && sudo systemctl is-active secweaver-agent'
ssh -t lab-92 'sudo /opt/secweaver-agent/bin/secweaver-agent preflight -config /opt/secweaver-agent/etc/config.json -strict && sudo systemctl start secweaver-agent && sudo systemctl is-active secweaver-agent'

# Preserve evidence and shipper cursors. Record UTC time; do not truncate logs.
date -u +%Y-%m-%dT%H:%M:%SZ

# Run attacks (from a machine with HTTP access to host 91)
# Attacks require the acknowledgement + target allowlist from "Safety Guardrails":
export SECWEAVER_LAB_ACK=I_UNDERSTAND_THIS_IS_AN_ISOLATED_AUTHORIZED_LAB
export SECWEAVER_LAB_ALLOWED_TARGETS=10.66.6.91,10.66.6.92

# --- Direct IP variant ---
bash case4-webPenetrateToSSH/attack.sh           # ~2 min (includes SSH brute-force delay)
bash case1-sqlInjectionAlertConfirm/attack.sh    # ~5 sec
bash case2-cmdInjectionC2/attack.sh              # ~30 sec
bash case3-dataExfilC2/attack.sh                 # ~30 sec

# --- WAF variant (requires WAF domain + session cookie) ---
export WAF_DOMAIN="https://your-waf-domain:port"
export WISID_COOKIE="WISID=<your-session-id>"
# lab-safety.sh extracts the host from WAF_DOMAIN and requires this exact name.
export SECWEAVER_LAB_ALLOWED_TARGETS=10.66.6.91,10.66.6.92,your-waf-domain
bash case4-webPenetrateToSSH/attack-domain-waf.sh
bash case1-sqlInjectionAlertConfirm/attack-domain-waf.sh
bash case2-cmdInjectionC2/attack-domain-waf.sh
bash case3-dataExfilC2/attack-domain-waf.sh

# Record the end of the UTC window for DataAsset queries.
date -u +%Y-%m-%dT%H:%M:%SZ
```

### Export Restricted Logs / 导出受限日志

Agent logs are mode `0600`. Ordinary `scp` as a non-root user cannot read them.
Prefer querying the recorded window through SaaS/ES. For an authorized local export,
use a host-local administrator terminal on **each** lab host (not an AI prompt):

```bash
umask 077
LAB_EXPORT_DIR=$(mktemp -d /tmp/secweaver-lab-logs.XXXXXX)
sudo tar -C /opt/secweaver-agent/logs -cf - . > "$LAB_EXPORT_DIR/agent-logs.tar"
printf 'Local restricted export: %s\n' "$LAB_EXPORT_DIR/agent-logs.tar"
```

This archives the configured log directory including retained rotations; no recursive
permission changes, log truncation, or registry reset are needed. Inspect the archive and
tar exit status: a file changing during collection may require a retry or an approved
short Agent stop for a consistent snapshot. Do not quietly treat an incomplete export as
complete evidence. Web, SSH, and C2 logs have independent paths and permissions in the tables.

Record the printed path, transfer it to your restricted local analysis directory using the
host alias, and sanitize before sharing. Do not commit the archive or collected logs.

```bash
# Substitute the actual directory printed on lab-91; this placeholder is not executable as-is.
umask 077
mkdir -p collected-logs
scp lab-91:/tmp/secweaver-lab-logs.REPLACE_ME/agent-logs.tar collected-logs/91-agent-logs.tar
```

中文：优先使用 SaaS/ES 按演练起止时间查询。需要本地导出时，在每台靶机以有 sudo
权限的用户执行上述归档命令，保留 `0600` 权限及轮转文件。检查 tar 返回码和归档完整性；
文件正在变化时按授权重试或短暂停 Agent 后取一致快照，不清空历史日志或 shipper 游标。
传输后只在受限目录分析，分享前脱敏，不把日志提交到 Git。

---

## Directory Structure

```
environmentDeployment/
├── README.md                              ← This file
├── deploy-nginx-base.sh                   ← Shared Nginx + PHP-FPM config (host 91, run once)
├── teardown-lab.sh                        ← Ownership-aware cleanup and file restore
├── lib/lab-safety.sh                      ← Shared fail-closed guard (ack / allowlist / backup)
├── collected-logs/                        ← Local working dir for collected logs (created on demand)
│
├── case4-webPenetrateToSSH/                     ← Environment 1: Web penetration → SSH lateral
│   ├── deploy-web.sh                         Host 91: Web application (/webshell/)
│   ├── deploy-ssh-target.sh                  Host 92: SSH weak-password user
│   ├── attack.sh                             Attack script (direct IP)
│   ├── attack-domain-waf.sh                  Attack script (WAF variant)
│   ├── docker-compose.yml                    Alternative: containerized deployment
│   ├── web-01/                               Docker: web container files
│   ├── internal-01/                          Docker: internal target container files
│   ├── wordlist.txt                          SSH brute-force password dictionary
│   └── README.md
│
├── case1-sqlInjectionAlertConfirm/              ← Environment 2: SQLi + path traversal
│   ├── deploy-91.sh                          Host 91: Web application (/sqli/)
│   ├── deploy-92.sh                          Host 92: MariaDB
│   ├── attack.sh                             Attack script (direct IP)
│   ├── attack-domain-waf.sh                  Attack script (WAF variant)
│   └── README.md
│
├── case2-cmdInjectionC2/                        ← Environment 3: Command injection + memory WebShell
│   ├── deploy-91.sh                          Host 91: Web application (/cmdi/)
│   ├── deploy-92.sh                          Host 92: C2 listener
│   ├── attack.sh                             Attack script (direct IP)
│   ├── attack-domain-waf.sh                  Attack script (WAF variant)
│   └── README.md
│
└── case3-dataExfilC2/                           ← Environment 4: Data exfiltration + fileless WebShell
    ├── deploy-91.sh                          Host 91: Web application (/exfil/)
    ├── deploy-92.sh                          Host 92: MariaDB + C2 listener
    ├── attack.sh                             Attack script (direct IP)
    ├── attack-domain-waf.sh                  Attack script (WAF variant)
    └── README.md
```

## Comparison with synthetic datasets

| Dimension        | Synthetic generators          | environmentDeployment (this directory)   |
|------------------|------------------------------|------------------------------------------|
| Data source      | Python script simulation     | Real execution on real hosts             |
| Process chain    | Simulated PID/PPID           | Real PID/PPID + UID                      |
| Timing           | Script-computed timestamps   | Real system clock                        |
| Network          | Simulated src/dst            | Real TCP connections                     |
| C2 method        | Simulated outbound beacon    | Memory WebShell (HTTP header covert channel) |
| Log format       | JSON (normalized)            | Raw format (nginx combined, JSON syslog, etc.) |
| Reproducibility  | Fixed seed, 100% reproducible| Slight variations per execution          |
| Coverage         | 7 scenarios, 10 evidence types | 4 environments, 6 evidence types       |
