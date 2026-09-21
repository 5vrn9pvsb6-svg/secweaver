# 检测层标签目录（检测结果参考）

**语言：** [English](detection-catalog.md) | 简体中文（本文）

> 本文列出 **检测层** 输出的 `matched_rules[]` 标签。  
> 检测特征修改 JSON 规则包；告警策略同步修改 [`behavior-policy.md`](behavior-policy.md) 与可执行 JSON，局部环境例外见白名单指南。

---

## 检测层做什么

检测层（`rules/*.json` + 加载器）对每条原始日志做 **通用攻击模式识别**，输出：

| 字段 | 含义 |
|------|------|
| `matched_rules[]` | 命中的检测标签（下表） |
| `risk_tags[]` | 战术语义标签（collection / discovery 等，来自 rules/*.json） |
| `mitre_attack` | **MITRE ATT&CK** 映射（`techniques[]` / `tactics[]`，来自 `rules/attck-map.json`） |
| `severity` | 初判 P0–P3（**可被策略层覆盖**） |
| `risk_module` | exec / connect / dns / persistence / ssh / syslog |
| `summary` / `command` / `listener_*` | 供策略层裁决的上下文 |
| `has_tty` / `tty` | **会话形态**：WebShell/RCE 多为 `has_tty=false`；SSH 交互运维多为 `true`（见 [运营手册](OPS-HANDBOOK.zh-CN.md)） |

检测层 **不决定** 最终是否推送告警；`alert_required` 由 **策略层** `rules/behavior-policy.rules.json` 裁决，理由见 [`behavior-policy.md`](behavior-policy.md)。

---

## 字段信号：WebShell 无 TTY

经 HTTP/WebShell 触发的命令 **没有交互式终端**。audit-port-execmon 典型表现为：

- `has_tty=false`，`tty=(none)`
- `listener_process` 为 nginx/php-fpm 等 Web 入口
- `auid_name` 常为 `unset`

与 SSH 运维（`sshd` + `has_tty=true` + OPS-SSH-001）区分；单独 `has_tty=false` 不足以定案（cron/MOTD 同理）。

---

## exec 模块（host_exec）

| matched_rule | 初判 | 说明 |
|---|---|---|
| `external_listener_shell_exec` | P0 | Web 监听进程后代执行 shell 解释器 |
| `download_and_execute` | P0 | curl/wget 下载并执行 |
| `reverse_shell` | P0 | 反弹 shell 特征 |
| `persistence_modify` | P0 | 持久化（crontab、useradd、systemd 等） |
| `security_control_tampering` | P0 | 关审计/防火墙 |
| `sensitive_file_read` | P1 | 读 shadow、密钥、.env |
| `internal_recon` | P1 | nmap、whoami、内网 curl |
| `webshell_write` | P1 | 写 WebShell 或 s.phtml/?c= 特征 |
| `network_exfil_tools` | P1 | nc/scp/rsync 等外传工具 |
| `obfuscated_exec` | P1 | base64 -d、eval 等 |
| `data_staging` | P1 | 打包 web/home 到 /tmp |
| `database_dump` | P1 | mysqldump（Web 上下文） |
| `noise_command` | P3 | 纯噪声命令 |

代码位置：`rules/exec-rules.json`（运营可编辑，见 [rules/README.zh-CN.md](rules/README.zh-CN.md)）

Exec 规则包 1.3 在 `command_semantics.py` 对内置命令候选进一步判定：普通 HTTP
下载、健康检查、校验和管道不算 `download_and_execute`，必须出现解释器管道/替换
执行或对下载文件的执行。只读 `ls`/`grep`/`crontab -l`、从 service 文件复制**到备份**
不算 `persistence_modify`，写入持久化路径仍保留。纯 `scp -t`、`sftp-server` 接收端
不算 `network_exfil_tools`；向外发送、混合命令仍是候选，但不证明外传成功。

Python 引擎支持 POSIX 命令字符串、argv 数组和 JSON 编码 argv，最多展开四层 shell
`-c`。不会执行命令、完整解释 shell、展开变量或保证下载来源可信；Windows
PowerShell/cmd 需单独规则。其他规则和 Web 监听入口护栏继续生效，这不是域名或工具
白名单。自定义规则在 `command` 上使用这些内置 ID 时也采用上述语义检查，其他字段
仍按显式配置匹配。可用 `tests/test_detection_rules.py` 反例和仓库 Python 测试入口验证。

阈值统计前先去除原生事件的重复上传。SSH 同一秒内不同原生 ID 的失败认证仍分别计数；
缺少原生 ID 时沿用主机/来源/时间/用户的旧去重启发式，精度受源数据限制。
`evidence_deduplication` 给出各证据包的数量和保留/重复引用映射。

---

## connect 模块（host_connect）

| matched_rule | 初判 | 说明 |
|---|---|---|
| `external_c2_connect` | P0 | Web 监听进程外连公网 |
| `suspicious_port_connect` | P0/P1 | 4444、1337 等可疑端口 |
| `exec_correlated_egress` | P1 | 同窗有 curl/wget |
| `non_whitelist_egress` | P2 | 非公网白名单外连 |
| `business_whitelist_connect` | P3 | 内网业务端口 |

代码位置：`rules/connect-rules.json`

---

## dns 模块（dns_log + host_connect）

| matched_rule | 初判 | 说明 |
|---|---|---|
| `high_nxdomain_burst` | P1/P2 | 单 client 短时间高频 NXDOMAIN |
| `suspected_dga_domain` | P1 | 高熵、长标签或数字占比异常的疑似 DGA |
| `uncommon_tld_query` | P2 | 查询非常见/高滥用 TLD |
| `dns_tunnel_suspected` | P1 | 超长查询、长 label 或 TXT/NULL/ANY 隧道特征 |
| `doh_egress` | P1 | host_connect 指向已知 DoH resolver:443 |
| `dot_egress` | P1 | host_connect 指向 DNS-over-TLS 853 |

边界：DNS 可解释域名、DGA 和隧道画像，但不能替代 firewall/NTA/proxy 的会话方向、字节数、代理动作和 beacon 周期证据。

代码位置：`rules/dns-rules.json`

---


## persistence 模块（host_persistence）

| matched_rule | 初判 | 说明 |
|---|---|---|
| `persistence_ld_preload_modify` | P0 | ld.so.preload 被写入/修改，常用于进程注入和防御绕过 |
| `persistence_ssh_key_modify` | P0 | SSH authorized_keys 变化 |
| `persistence_sudoers_modify` | P1 | sudoers 或 sudoers.d 变化 |
| `persistence_systemd_modify` | P1 | systemd unit 变化 |
| `persistence_cron_modify` | P1 | cron/crontab 变化 |
| `persistence_profile_modify` | P1 | shell profile/bashrc/rc.local 变化 |
| `persistence_kernel_module_modify` | P1 | 内核模块自动加载/黑名单配置变化 |
| `persistence_generic_change` | P2 | 其他 host_persistence 监控路径变化 |

规则：`rules/persistence-rules.json`。路径变化是检测信号，最终告警仍受策略与环境上下文约束。

## ssh 模块（ssh_auth）

| matched_rule | 初判 | 说明 |
|---|---|---|
| `ssh_bruteforce` | P0 | 短时间大量认证失败 burst |

阈值参数（`rules/ssh-rules.json`，运营可编辑）：

- `brute_force.threshold`：形成 burst 的最小失败次数，默认 10
- `brute_force.window_sec`：滑动窗口秒数，默认 300
- `thresholds[]`：按 `fail_count` 映射 severity（如 ≥10→P0，≥5→P2）
- `brute_force_rule`：输出语义（`matched_rule`、`policy_rule_id`、`risk_tags`）

`assess.py` 当前通过 `params.ssh_brute_window_sec`（默认 300）和 `params.ssh_brute_threshold`（默认 10）显式传入聚合窗口与成波阈值，因此从该入口调参应设置这两个参数。直接调用 SSH 引擎且不传覆盖值时才使用规则包中的 `brute_force.window_sec` / `threshold`。`thresholds[]` 决定检测层等级；只有达到成波阈值才会产生风险项，随后 `SSH-BRUTE-001` 策略还可能把等级调整为 P0。

代码位置：`scripts/ssh_rules.py`；规则：`rules/ssh-rules.json`

---

## syslog 模块（syslog_risk_alert）

数据源：`asset_type=syslog_risk_alert`（syslog-risk-json 结构化事件），资产 ID 由接入配置决定。

| matched_rule | 初判 | 说明 |
|---|---|---|
| `account_created` | P0 | 本地账号创建 |
| `account_modified` | P1 | 账号/密码变更 |
| `sudo_high_risk` | P1 | 高危 sudo（risk_level high/critical） |
| `sudo_command` | P2 | 普通 sudo |
| `sudo_useradd` | P0 | message 命中 useradd/adduser |
| `sudo_chpasswd` | P1 | message 命中 chpasswd/passwd |
| `root_ssh_login` | P1 | root SSH 登录成功 |
| `root_session_opened` | P1 | root 会话 |
| `su_failure` | P1 | su 失败 |
| `security_policy_denied` | P1 | SELinux/AppArmor 拒绝 |
| `firewall_event` | P1 | 防火墙变更 |
| `suspicious_cron` | P1 | 可疑 cron |
| `kernel_panic` | P0 | kernel panic |
| `network_anomaly` | P2 | 网络异常 |
| `process_crash` / `oom_kill` / `device_attached` | P2 | 主机异常（部分默认 disabled） |

**与 ssh 模块分工**：SSH 暴破 raw 事件（`auth_failure`、`ssh_login_failed` 等）在 `exclude_event_types` 中排除，由 **ssh 模块** 做 burst 聚合。

代码位置：`rules/syslog-rules.json`

---

## MITRE ATT&CK 映射（`rules/attck-map.json`）

每条 `risk_item` 在策略裁决后会附加 `mitre_attack`：

```json
{
  "mitre_attack": {
    "technique_ids": ["T1505.003", "T1059.004"],
    "techniques": [
      { "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "tactic_id": "TA0003" }
    ],
    "tactics": [{ "id": "TA0003", "name": "persistence" }]
  }
}
```

| 来源 | 映射键 |
|------|--------|
| 检测层 | `matched_rules[]` → `attck-map.json` → `matched_rules.<id>.techniques[]` |
| 策略层 | `policy_rule_id` → `attck-map.json` → `policy_rules.<id>.techniques[]` |

运营扩展：在 `attck-map.json` 为新的 `matched_rule` 或策略 ID 追加 `techniques[]` 即可，无需改 Python。

---

## 策略层如何用这些标签

在 `behavior-policy.md` 中写规则时，可引用检测标签，例如：

> **何时命中**：`matched_rules` 含 `download_and_execute`，且 listener 为 sshd，命令访问 `portal.poc.id-net.cn` 安装 agent。

> **何时命中**：`matched_rules` 含 `persistence_modify`，且命令为 `useradd devops` + 诱饵文件（见 OPS-LAB-SETUP-001）。

标签与初判表用于阅读输出；规则的启用状态、具体条件和当前阈值以对应 JSON 为准，不代表每个事件必然告警。

完整策略写法见 [`behavior-policy.zh-CN.md`](behavior-policy.zh-CN.md)。

---

## 何时需要改代码（工程）

| 需求 | 改哪里 |
|------|--------|
| 新增/调整检测 pattern、关键词、端口列表 | **`rules/exec-rules.json`** 等（见 [rules/README.zh-CN.md](rules/README.zh-CN.md)） |
| 调整 **是否告警 / 降噪 / 例外** | 同步修改 `behavior-policy.md` 与 `rules/behavior-policy.rules.json` |
| 新增 portal 域名、agent 路径等 **环境例外** | 同步修改 `behavior-policy.md` 与 `rules/behavior-policy.rules.json`（OPS-* 条目） |
| 跨主机攻击链叙事 | `traceability-analysis` Skill |
