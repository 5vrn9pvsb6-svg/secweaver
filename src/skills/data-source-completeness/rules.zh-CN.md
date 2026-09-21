# 数据源完整性分析 — 规则矩阵

> 机器可读场景需求见 [scenarios.json](scenarios.json)；确定性评估见 [scripts/check.py](scripts/check.py)

## 一、数据源注册类型与数据域映射

| asset_type | 名称 | 数据域 | 默认关联键 |
|---|---|---|---|
| `waf_alert` | WAF/WEB 安全告警 | D1/D5 | src_ip, timestamp, url, payload, rule_id |
| `web_access_log` | WEB 访问日志 | D1 | src_ip, timestamp, url, status, user_agent |
| `host_exec` | 主机进程命令执行 | D2 | host, timestamp, pid, ppid, command, user |
| `host_connect` | 主机主动外连 | D2 | host, timestamp, pid, dst_ip, dst_port |
| `host_file_op` | 主机文件操作 | D2 | host, timestamp, path, action, pid |
| `windows_event_log` | Windows 系统/事件日志 | D2 | host, timestamp, event_id, channel, user |
| `linux_syslog` | Linux 系统/syslog 日志 | D2 | host, timestamp, message, program, severity |
| `ssh_auth` | SSH 认证日志 | D3 | host, src_ip, user, timestamp, result |
| `vpn_auth` | VPN 登录 | D3 | user, src_ip, timestamp, result |
| `firewall_log` | 防火墙日志 | D4 | src_ip, dst_ip, src_port, dst_port, timestamp |
| `network_traffic_audit` | 全流量审计日志 | D4 | src_ip, dst_ip, src_port, dst_port, protocol, timestamp |
| `dns_log` | DNS 查询 | D4 | client_ip, query, timestamp, response |
| `proxy_log` | 代理日志 | D4 | src_ip, dst_ip, url, timestamp |
| `ids_alert` | IDS/IPS 告警 | D5 | src_ip, dst_ip, signature, timestamp |
| `edr_event` | EDR 事件 | D2 | host, timestamp, process, action |
| `asset_inventory` | 资产清单 | D6 | hostname, ip, zone, owner, services |
| `vuln_scan` | 漏洞扫描 | D6 | host, cve, component, scan_time |

### SecWeaver 工具映射

| 工具 | 产出 asset_type |
|---|---|
| audit-port-execmon (exec) | `host_exec` |
| audit-port-execmon (connect) | `host_connect` |
| audit-port-execmon (file_op) | `host_file_op` |
| Winlogbeat / WEF → SLS（Security/System/Application/Sysmon） | `windows_event_log` |
| Filebeat/Fluent Bit/rsyslog → SLS（syslog、journald） | `linux_syslog` |
| NDR/TAP/全流量审计平台 → SLS/ES | `network_traffic_audit` |

---

## 二、场景需求矩阵

### S1 外网攻击 IP 溯源

| 优先级 | asset_type | 必需字段 | 覆盖要求 |
|---|---|---|---|
| P0 | `waf_alert` 或 `web_access_log` | src_ip, timestamp, url | 全部对外 WEB |
| P0 | `host_exec` | host, command, timestamp | **WEB 服务器** |
| P0 | `ssh_auth` | host, src_ip, user, result, timestamp | 可能横向的 SSH 主机 |
| P1 | `host_connect` | dst_ip, dst_port, timestamp | WEB 服务器 |
| P1 | `firewall_log` 或 `network_traffic_audit` | src_ip, dst_ip, port | WEB→内网网段 |
| P1 | `dns_log` | client_ip, query | WEB 服务器或 DNS 服务器 |
| P2 | `host_file_op` | path, action | WEB 服务器 |
| P2 | `asset_inventory` | hostname, ip, services | 内网 SSH 资产全集 |
| P2 | `edr_event` | process, action | 关键主机 |

### S2 WEB 入侵溯源

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `waf_alert` / `web_access_log` | 攻击请求与 payload |
| P0 | `host_exec` | WebShell 命令、系统命令 |
| P0 | `host_file_op` | WebShell 落地、异常文件 |
| P1 | `host_connect` | 反弹 shell、下载 |
| P1 | `web_access_log` | 告警前后访问序列 |
| P2 | `vuln_scan` | 被攻击组件漏洞 |

### S3 横向移动调查

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `ssh_auth` | 登录成功/失败、源 IP |
| P0 | `firewall_log` 或 `network_traffic_audit` | 内网连接关系 |
| P1 | `host_exec` | 跳板机上的 ssh/scp/nc |
| P1 | `host_connect` | 内网扫描、445/3389 |
| P2 | `vpn_auth` | 从 VPN 入口横向 |
| P2 | `asset_inventory` | 内网资产边界 |

### S4 WEB 告警确认

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `waf_alert` | **必须含 payload 或 request_body** |
| P0 | `web_access_log` | 告警前后 5-10 分钟上下文 |
| P1 | `host_exec` | 证明攻击成功（shell、whoami） |
| P1 | `host_connect` | 证明 C2 或下载成功 |
| P1 | `host_file_op` | WebShell 落地 |
| P2 | `vuln_scan` | 被攻击路径对应漏洞 |

**告警确认结论约束**：

| 数据状态 | 允许结论 |
|---|---|
| 仅 D1/D5 | 尝试攻击 / 疑似真实攻击 / 可能误报 |
| D1 + D2 exec/connect | 可判定真实攻击 + 是否成功 |
| 无 payload | 不得判定「SQLi/XSS 成功」，只能说「规则命中」 |

### S5 主机异常行为

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `host_exec` | 对外监听进程执行的命令 |
| P1 | `host_connect` | 主动外连目标 |
| P1 | `host_file_op` | 异常文件读写 |
| P2 | `waf_alert` | 解释触发来源 |

### S6 账号失陷

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `ssh_auth` / `vpn_auth` / AD 日志 | 异常登录 |
| P1 | `host_exec` | 登录后命令 |
| P1 | `firewall_log` | 异常外连 |
| P2 | `proxy_log` | 账号滥用 |

### S7 数据外传

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `host_connect` / `proxy_log` | 大量外连 |
| P0 | `host_file_op` | 打包、压缩、敏感路径 |
| P1 | `host_exec` | tar/zip/scp/rsync |
| P1 | `firewall_log` | 外传流量 |
| P2 | `dlp` | 敏感数据识别 |

### S8 C2 通信检测

| 优先级 | asset_type | 说明 |
|---|---|---|
| P0 | `host_connect` | 主机、目的 IP/端口与回连时间 |
| P1 | `network_traffic_audit` / `proxy_log` | beacon 周期、会话体量与代理路径 |
| P1 | `dns_log` | C2 域名与 DGA 归因 |
| P1 | `host_exec` | 进程/命令归因和反弹 Shell 上下文 |
| P2 | `syslog_risk_alert` | 独立的主机风险互证 |

---

## 三、单项评估规则

### 3.1 status 判定

```text
ready:
  - asset 已注册
  - coverage 覆盖调查涉及主机/网段
  - 必需 fields 齐全
  - retention 覆盖 time_start ~ time_end

partial:
  - 已注册但 coverage 仅部分主机
  - 或缺少非关键 field（如无 payload 但 S1 场景）
  - 或 retention 不足

missing:
  - 未注册
  - 或 registered 但 coverage=none

optional:
  - P2 且场景可降级分析
```

### 3.2 关联键检查

跨源关联至少需要 **3 项** ready：

| 键 | 用途 |
|---|---|
| `src_ip` | 攻击源串联 WAF→SSH |
| `host` / `dst_ip` | 受害主机定位 |
| `timestamp` | 时间线（时区统一 UTC+8 或标注） |
| `user` | 账号维度 |
| `pid` / `process` | 进程链 |
| `session` / `flow_id` | 网络会话 |

关联键 < 3 → `key_completeness = partial`，confidence 上限 0.75

### 3.3 时间窗

| 场景 | 默认窗口 |
|---|---|
| 已知告警时间 T | [T-24h, T+6h] |
| 仅知攻击 IP | 最近 7 天（可配置） |
| 横向移动 | 入口时间 -24h 至 最后活动 +12h |

retention < 所需窗口 → 该源 status = partial，gaps 加 `retention_insufficient`

### 3.4 覆盖度

| coverage | 含义 |
|---|---|
| `full` | 调查涉及全部主机/网段均有 |
| `partial` | 仅部分（如只有 web-01 无 web-02） |
| `none` | 无覆盖 |

**S1 特规**：WEB 主机 exec 必须覆盖**第一台可能被攻破的 WEB 服务器**，不能只有内网 SSH 无 WEB 侧行为。

---

## 四、整体结论规则

```text
IF 任一 P0 == missing:
  overall_verdict = not_traceable
  next_skill_blocked = true
  block_reason = "缺少 P0 数据源: {list}"

ELSE IF 场景含 S4 AND 无 host_exec AND 无 host_connect:
  can_confirm_breach = false
  IF 仅 waf_alert:
    overall_verdict = alert_triage_only

ELSE IF 所有 P0 == ready AND P1 ready率 >= 0.8:
  overall_verdict = full_traceable
  next_skill_blocked = false

ELSE IF 所有 P0 == ready:
  overall_verdict = partial_traceable
  next_skill_blocked = false

ELSE:
  overall_verdict = not_traceable
```

### confidence 计算

```text
P0_ready_rate = ready的P0数 / P0总数
P1_ready_rate = ready的P1数 / P1总数
key_score = 1.0(≥4键) | 0.7(3键) | 0.4(<3键)
time_score = 1.0(全满足) | 0.6(部分) | 0.3(不足)

confidence = 0.40*P0_ready_rate + 0.35*P1_ready_rate + 0.15*key_score + 0.10*time_score
```

---

## 五、接入建议优先级

生成 recommendations 时排序：

```text
1. 所有 P0 missing，按 impact 排序
2. P0 partial（覆盖/字段不足）的补全建议
3. P1 missing 且与当前调查直接相关
4. P2 optional
```

### collection_hint 标准话术

| asset_type | collection_hint |
|---|---|
| `host_exec` | Linux 部署 audit-port-execmon，配置 whitelist_ports 监控对外端口进程 exec |
| `host_connect` | audit-port-execmon 开启 monitor_connect |
| `host_file_op` | audit-port-execmon 开启 monitor_file_ops |
| `ssh_auth` | rsyslog 采集 /var/log/auth.log 或 journald，统一 timestamp 与 host 字段 |
| `waf_alert` | 接入 WAF API/syslog，确保含 payload/request |
| `firewall_log` | 防火墙 syslog 或 SIEM 转发，保留五元组 |
| `network_traffic_audit` | NDR/TAP 全流量平台导出，保留五元组、协议、字节数/会话 ID |
| `dns_log` | 内网 DNS 服务器查询日志或 DNS 安全网关 |

---

## 六、SecWeaver 场景要求实战检查清单

### 外网 IP 溯源（S1）

用户输入：时间 A、黑客 IP A、查攻破点 + 横向

智能体 必查：

- [ ] WAF/WEB 是否有该 IP 记录
- [ ] WEB 服务器是否有 exec（curl/bash/webshell）
- [ ] WEB 服务器是否有 connect（下载域名）
- [ ] SSH 日志是否覆盖内网可能目标
- [ ] 是否有 WEB→内网 防火墙记录
- [ ] 资产清单是否知道 SSH 服务器全集

缺 exec → 输出：「无法确认是否下载 SSH 暴力破解工具，无法证明打穿」

### WEB 告警确认（S4）

- [ ] WAF 是否有 payload
- [ ] 是否有 WEB 主机 exec 证明成功
- 无 D2 → 「无法确认攻击是否成功，仅能判断告警类型」

---

## 七、与下游 Skill 衔接

| 条件 | next_skill |
|---|---|
| S1/S2/S3 且 P0 齐全 | `traceability_analysis` |
| S4 且 P0 齐全 | `alert_confirmation` |
| S5 且 host_exec ready | `risk-identification` |
| P0 缺失 | 无，输出 recommendations |
