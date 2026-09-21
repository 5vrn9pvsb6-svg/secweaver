---
version: "1.1"
owner: security-ops
locale: zh-CN
format: natural_language_v1
description: >
  本文件是风险识别 Skill 的自然语言策略与审计入口（告警 / 降噪 / 硬护栏）。
  检测层（exec_rules 等）只产出 matched_rules 与初判 severity；
  最终 alert_required 与 severity 由本文裁决。
  运营同学同步维护本文件与 rules/behavior-policy.rules.json；常规规则无需修改 Python。
---

# 风险识别告警策略

> 完整架构设计文档：[DESIGN.zh-CN.md](DESIGN.zh-CN.md)  
> 运营同学请读：[OPS-HANDBOOK.zh-CN.md](OPS-HANDBOOK.zh-CN.md)

## 零、架构：检测层 vs 策略层

```text
┌─────────────────────────────────────────────────────────────────┐
│ 归一化事件（命令、外连、SSH、DNS、持久化、syslog）                 │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 检测层（运营维护 JSON，工程维护引擎）                              │
│   exec / connect / dns / persistence / ssh / syslog               │
│   输出：matched_rules[]、初判 severity、risk_item 上下文           │
│   目录：detection-catalog.md（只读参考）                           │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 策略层（运营维护 · 本文件 behavior-policy.md）                     │
│   硬护栏 → 必须告警 → 降噪 → 默认                                  │
│   输出：policy_rule_id、alert_required、最终 severity             │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
                      risk_items[] / top_incidents[]
                             │
                             ▼ 多主机 / 跨源
                   traceability-analysis（另一 Skill）
```

### 谁改什么

| 角色 | 改什么 | 不改什么 |
|------|--------|----------|
| **安全运营** | **`rules/*.json`** + **本文件** + **`rules/behavior-policy.rules.json`** | 检测引擎 Python（环境白名单另见 whitelist.zh-CN.md） |
| **工程** | 检测层代码、assess 编排、`policy_engine.py` | 日常告警策略正文（除非 Code Review 代提 PR） |

### 运营改规则的标准流程

1. 同步更新本文的规则说明、修订记录与 `rules/behavior-policy.rules.json` 的可执行规则；规则 ID 保持一致。
2. 准备应命中与不应命中的脱敏样例，回放检查最终 `severity`、`alert_required` 和 `policy_rule_id`；降噪必须覆盖硬护栏反例。
3. 从仓库根目录运行 `python3 src/skills/risk-identification/scripts/validate_policy_sync.py --strict`，再运行相关策略测试。
4. 在 PR 中记录样例预期与验证结果，审核后合并；下一次 `assess.py` 执行加载更新后的 JSON。

### 执行方式（CLI 与智能体）

智能体按 Skill 调用 `assess.py` 与直接运行 CLI 使用同一 JSON 策略引擎。本文负责自然语言说明与审计；仅修改 Markdown 不会改变默认执行结果。纯提示词试验应明确标注为独立研判，不代表确定性规则已生效。完整操作步骤见 [运营手册](OPS-HANDBOOK.zh-CN.md)。

---

## 如何使用

1. 检测层（exec/connect/dns/persistence/ssh/syslog 引擎与 JSON 规则）已给出 `risk_item`：`matched_rules`、初判 `severity`、命令摘要等。标签含义见 [detection-catalog.zh-CN.md](detection-catalog.zh-CN.md)。
2. 按 **章节优先级** 从上到下匹配：**第二节「绝不允许降级」> 第三节「必须告警」> 第四节「降级」> 第一节「默认」**。
3. 同一 risk_item 命中多条时，取 **最严重** 的决策（必须告警 优先于 降级）。
4. **第二节「绝不允许降级」** 对全文件生效：只要符合，任何降级规则都不适用。

---

## 一、默认行为（无其他规则命中时）

- 初判 **P0、P1** 的 risk_item：**需要告警**（`alert_required=true`）。
- 初判 **P2** 的：仅观察，不推送告警。
- 初判 **P3** 的：仅留痕。

---

## 二、绝不允许降级（硬护栏）

以下情况 **无论** 落在 sshd 还是会话运维上下文，**一律不得** 降为 P3 或 suppress：

1. 反弹 shell、/dev/tcp、bash -i、nc -e 等明确 Getshell 行为。
2. 新建系统用户、改密码、写 crontab、写 authorized_keys、systemd 持久化。
3. 读取 `/etc/shadow` 或批量读取密钥、.env、id_rsa。
4. 关闭 auditd、清空 iptables、setenforce 0 等安全机制破坏。
5. **Web 对外入口**（nginx、apache、httpd、openresty、php-fpm 等监听 80/443/8080 等）下出现的 **任何 shell/系统命令执行**（含 `sh -c id`、whoami、cat 文件）。

持久化路径出现不等于修改。`HARD-GUARDRAIL-PERSISTENCE` 与 `SSH-IMPACT-001`
的账户/持久化命令分支通过 `type=persistence_write` 与检测层共享写入语义：
只读检查和复制到备份不触发，实际写入、建号和改密保留。其他敏感读取分支不变。
策略层硬护栏与 force_alert 决策不得由后续环境白名单降级或抑制。

---

## 三、必须告警（P0 / P1，force alert）

### WEB-SHELL-001｜Web 入口命令执行

**何时命中**：对外 Web 监听进程（nginx/apache/php-fpm/gunicorn/uwsgi 等）的后代进程执行了 shell 或系统命令，例如 `sh -c id`、`whoami`、`cat /etc/passwd`、`nmap`、`find / -perm -4000`。

**决策**：P0，必须告警，视为 WebShell/RCE，建议隔离主机并溯源。

**说明**：Web 进程正常不应 fork 出 sh/bash；php-fpm 子进程跑 id 即高度可疑。

**字段特征（运营经验）**：经 HTTP/WebShell 触发的命令在 audit-port-execmon 中通常 **`has_tty=false`**、`tty=(none)`，因无 SSH 伪终端；与 **OPS-SSH-001**（sshd + 交互式 `has_tty=true` 运维）区分。勿单独以 `has_tty` 定案，须结合 listener 与命令语义。详见 **OPS-HANDBOOK.zh-CN.md 场景 G**。

---

### WEB-SHELL-002｜sshd 上下文 WebShell 触发（s.phtml / uploads）

**何时命中**：listener 为 **sshd:22**（非 nginx），但命令通过 **curl/wget 访问 s.phtml、uploads/*.php** 或 `?c=` 参数触发 shell/sshpass（WebShell 间接利用）。

**决策**：P0，必须告警，视为 WebShell/RCE 早期阶段。

**示例**：`curl http://127.0.0.1/uploads/s.phtml?c=id`、`curl …/s.phtml?c=sshpass+…`

**状态**：已实现；弥补 WEB-SHELL-001 仅覆盖 nginx/apache listener 的盲区。

---

### LATERAL-SSH-001｜Web 入口发起 SSH 密码喷洒

**何时命中**：命令行出现 `sshpass`，或从 Web 入口上下文向 **其他内网 IP** 发起 SSH 登录尝试（尤其带 `-p` 密码、多密码轮换）。

**决策**：P0，必须告警，视为横向移动。

**示例**：`sshpass -p 123456 ssh devops@192.0.2.92`、`curl webshell 间接触发 sshpass`。

---

### RECON-HIGH-001｜Web 入口内网侦察

**何时命中**：Web 入口上下文中对内网 IP 做 nmap、masscan、ping 扫描，或读取 `/etc/shadow`、sudo -l、查找 SUID。

**决策**：P0 或 P1，必须告警。

---

### SSH-IMPACT-001｜SSH 会话内的持久化与窃密

**何时命中**：listener 为 **sshd:22** 的会话里，出现：创建用户（useradd/adduser/chpasswd）、读 shadow、写启动项/计划任务/authorized_keys。

**决策**：P0，必须告警（**不可** 被「SSH 运维降噪」覆盖）。

**示例**：`useradd devops` + `chpasswd`、`cat /etc/shadow`。

---

### DOWNLOAD-MALICIOUS-001｜下载并执行未知远程脚本

**何时命中**：curl/wget 拉取 **非可信来源** 的 http(s) 脚本并执行，或写入 /tmp 后执行；且 **不是** 下文「可信部署源」中的地址。

**决策**：P0，必须告警。

---

### CONNECT-C2-001｜主动外连可疑 C2

**何时命中**：host_connect 项指向 **非公网业务白名单** 的境外或未知 IP 高危端口（4444、1337 等），且同窗有 curl/wget/bash 等 exec。

**决策**：P0/P1，必须告警。

---

### SSH-BRUTE-001｜SSH 认证暴力破解（需 ssh_auth 数据源）

**何时命中**：同一源 IP 在短时间对 sshd 产生大量 **Failed password** / **Invalid user**（具体阈值由环境定，建议 5 分钟内 ≥10 次）。

**决策**：P0，必须告警。

**状态**：已实现；数据源为 `tigersec-sys-messages` logstore（syslog-risk-json 结构化字段），非独立 sys-auth logstore。输出 `ssh_brute_waves[]` 列出全部波次；`victim_host == src_ip` 自环忽略。

---

### SYS-ACCOUNT-001｜syslog 本地账号创建

**何时命中**：`risk_module=syslog`，`matched_rules` 含 `account_created` 或 `sudo_useradd`，或 `event_type=account_created`；**且未** 命中 OPS-LAB-SETUP-001（演练 devops 预置）。

**决策**：P0，必须告警，视为持久化/后门创建。

**数据源**：`asset-secweaver-sys-risk-alert`（`syslog_risk_alert`）；检测规则见 `rules/syslog-rules.json`。

---

### SYS-SUDO-001｜syslog 高危 sudo

**何时命中**：`risk_module=syslog`，`matched_rules` 含 `sudo_high_risk` 或 `sudo_useradd`（syslog-risk-json 标 high/critical，或 message 命中 useradd/adduser）。

**决策**：P1，必须告警。

---

### SYS-FW-001｜syslog 防火墙变更

**何时命中**：`risk_module=syslog`，`event_type=firewall_event` 或 `matched_rules` 含 `firewall_event`（iptables/firewalld 变更）。

**决策**：P1，必须告警。

---

### SYS-KERNEL-001｜kernel panic

**何时命中**：`risk_module=syslog`，`event_type=kernel_panic` 或 `matched_rules` 含 `kernel_panic`。

**决策**：P0，必须告警。

**说明**：SSH 认证失败 raw 事件（`auth_failure` 等）由 **ssh 模块** 聚合，syslog 模块在 `syslog-rules.json` 的 `exclude_event_types` 中排除，避免重复告警。

---

## 四、降级 / 不告警（降噪）

### OPS-LAB-SETUP-001｜演练环境预置（devops + 诱饵凭据）

**何时命中**：

- listener 为 **sshd:22**；
- 命令为演练脚本预置：`useradd devops` + `chpasswd`、或 `tee` 写入 `db-credentials.conf` / `deploy-token.json` / `/home/devops/.bash_history` 等诱饵文件；
- **且未** 命中第二节硬护栏（真实攻击持久化）。

**决策**：P3，不告警，verdict=benign。

**说明**：红队靶场 192.0.2.92 上 14:34 环境搭建曾被误判为 SSH-IMPACT-001；与真实横向后的 useradd 需由 traceability-analysis 结合源 IP/时间线区分。

---

### OPS-SSH-001｜SSH 交互运维默认降噪

**何时命中**：

- listener 为 **sshd:22**；
- 命令属于常见运维：ls、grep、yum、systemctl status、安装/卸载 **LoongCollector/ilogtail**、查看日志；
- **且未** 命中第二节硬护栏或第三节必须告警任一条。

**决策**：降为 P3，`alert_required=false`，仅记录。

**说明**：SSH 登录后运维会产生大量 exec；默认降噪，但持久化/读 shadow 等已在第三节单独强制告警。

**前提**：典型 SSH 交互会话 **`has_tty=true`**（`tty=pts/N`）。若 listener 为 sshd 但 **`has_tty=false`** 且命令经 curl/s.phtml 间接触发，应走 **WEB-SHELL-002**，不得按本规则降噪。

---

### OPS-AGENT-001｜sshd 监控子进程

**何时命中**：

- listener 为 **sshd:22**；
- 命令 argv 为 `/usr/sbin/sshd -D`（可带 `-R`），即 audit-port-execmon 对 SSH 会话的跟踪子进程；
- 含 SLS 中 JSON 序列化形式：`["/usr/sbin/sshd","-D","-R"]`（assess 层会先归一化为 argv 再匹配）。

**决策**：P3，不告警，verdict=benign。

**说明**：该子进程在 exec 日志中大量重复出现；初判可能因 connect 上下文加权被抬到 P1/P2，仍应被本规则 suppress。

---

### OPS-LOCAL-CURL-001｜本地健康检查 curl

**何时命中**：curl/wget 目标为 `127.0.0.1` 或 `localhost`（如 `curl -w %{http_code} http://127.0.0.1/...`），且非第三节必须告警。

**决策**：P3，不告警；本地探测不等于 download_and_execute。

---

### OPS-AGENT-UNINSTALL-001｜Agent systemd 卸载

**何时命中**：`rm -f /etc/systemd/system/loongcollectord.service` 或 `ilogtaild.service` 等 LoongCollector/ilogtail 卸载。

**决策**：P3，不告警；属于 agent 运维，非恶意持久化（与 SSH-IMPACT-001 的 useradd/chpasswd 区分）。

---

### OPS-DEPLOY-001｜平台 Agent 官方部署

**何时命中**：从 **公司 portal**（如 `portal.poc.id-net.cn` 路径含 `audit-port-execmon`）下载 install.sh 或二进制并安装到 `/usr/local/bin/audit-port-execmon`、`syslog-risk-json`。

**决策**：降为 P2 或 P3，不推送告警，verdict=benign。

**说明**：演练环境 192.0.2.92 上 agent 部署曾被误判为 download_and_execute。

---

### OPS-CLOUD-001｜阿里云 metadata 与镜像源

**何时命中**：

- 访问 `100.100.100.200/latest/meta-data`；
- curl/wget 从 `mirrors.aliyun.com`、`*oss-cn-*.aliyuncs.com` 拉取 agent/镜像/内核 btf；
- LoongCollector/ilogtail 安装脚本内的 grep、chmod、systemctl。

**决策**：suppress 或 P3，不告警。

---

### OPS-NGINX-001｜nginx 配置检测

**何时命中**：命令仅为 `nginx -t` 或等价配置语法检查。

**决策**：P3，不告警。

---

### OPS-DNS-001｜SSH 会话内 DNS 查询外连

**何时命中**：host_connect 为 sshd 上下文下访问 **223.5.5.5:53** 或内网 DNS，且同窗是 yum/curl 等正常装包。

**决策**：P2，观察，不告警。

---

## 五、冲突与优先级（给 Agent 的裁决顺序）

```text
1. 第二节硬护栏 → 禁止降级
2. 第三节必须告警 → 任一命中则 alert_required=true（取最高 severity）
3. 第四节降噪 → 仅当未命中第三节
4. 第一节默认
```

---

## 六、输出要求（Agent 应用本策略后）

对每个 risk_item 补充：

| 字段 | 说明 |
|------|------|
| `policy_rule_id` | 命中的策略条目 ID，如 WEB-SHELL-001 |
| `policy_reason` | 用一句话说明为何如此裁决（可引用上文） |
| `alert_required` | 最终是否告警 |
| `severity` | 最终 P0–P3 |
| `original_risk` | 策略生效前的 severity/verdict |

汇总输出 `policy_hits[]` 供审计。

---

## 七、修订记录

| 日期 | 作者 | 变更 |
|------|------|------|
| 2026-09-18 | security-ops | JSON 1.0.1：持久化护栏区分路径引用和写入；白名单保留强制告警 |
| 2026-07-02 | security-ops | v1.1 架构：检测层 vs 策略层；运营只改本文件；detection-catalog |
| 2026-07-02 | security-ops | WEB-SHELL-001/OPS-SSH-001 补充 has_tty 字段说明（WebShell 无 TTY） |
| 2026-07-02 | security-ops | WEB-SHELL-002、OPS-LAB-SETUP-001、SSH-BRUTE 多波次 ssh_brute_waves[] |
| 2026-07-02 | security-ops | 初版：WebShell、横向、sshd 降噪、agent 部署 |
