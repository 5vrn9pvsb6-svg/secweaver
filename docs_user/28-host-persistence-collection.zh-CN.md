# host_persistence 数据采集介绍

**语言：** [English](28-host-persistence-collection.md) | 简体中文（本页）

`host_persistence` 是 SecWeaver 面向 Linux 主机新增的一类主机侧证据，用来记录“持久化能力相关位置”的新增、修改和删除。它关注的不是普通文件系统变化，而是攻击者常用来长期驻留、自动启动、保留访问入口或提权的关键配置位置。

典型场景包括：

1. 攻击者写入新的 cron 任务。
2. 新增或修改 systemd service/timer。
3. 往 `authorized_keys` 写入 SSH 公钥。
4. 修改 `sudoers` 获取免密提权。
5. 修改 shell profile，在登录时自动执行命令。
6. 写入 `/etc/ld.so.preload` 做动态库劫持。
7. 修改内核模块加载配置。

这些变化通常发生在攻击成功之后，是判断“是否已经落地、是否具备长期控制能力”的关键证据。

## 采集方式

`host_persistence` 由 `secweaver-agent` 内置模块 `host-persistence` 采集。模块源码位于：

```text
src/tools/secweaver-agent/pkg/hostpersistence/
```

它采用的是“**目标路径快照 + 状态基线比对 + auditd 富化**”方式：快照负责发现持久化文件是否新增、修改、删除；auditd 负责补充是谁、哪个进程执行了写入；小文本文件会额外记录受限的内容差异。

采集流程如下：

```text
读取配置
  |
  v
展开 watch 路径和通配符
  |
  v
启动 auditd watch 规则（可选）
  |
  v
扫描持久化相关文件/目录
  |
  v
记录文件元数据、小文件 SHA256 和小文本内容快照
  |
  v
读取上一轮 state baseline
  |
  v
比较 created / modified / deleted
  |
  v
匹配 auditd 写入记录，补充用户和进程信息
  |
  v
输出 host_persistence JSON Lines
  |
  v
保存新的 baseline
```

默认每 30 秒扫描一次。首次启动时默认只建立 baseline，不输出已有文件，避免一上线就把所有主机的历史状态打成告警。之后如果相关位置发生新增、修改或删除，才会输出事件。

默认会尝试通过 auditd 给 watch 路径添加 `wa` 规则，并从 `/var/log/audit/audit.log` 读取同一路径的写入事件。auditd 不可用、没有权限或系统未启用审计时，模块仍会输出快照差异，但 `user`、`process`、`command` 等字段可能为空。

如果需要盘点当前状态，可以显式打开 `emit_baseline=true`，让首次扫描输出 `observed` 事件。

## 默认监控范围

默认配置覆盖常见 Linux 持久化位置：

| 类别 | persistence_type | 默认路径 |
|---|---|---|
| 定时任务 | `cron` | `/etc/crontab`、`/etc/cron.d`、`/etc/cron.daily`、`/etc/cron.hourly`、`/etc/cron.weekly`、`/etc/cron.monthly`、`/var/spool/cron`、`/var/spool/cron/crontabs` |
| 服务自启动 | `systemd` | `/etc/systemd/system` |
| SysV 启动项 | `sysvinit` | `/etc/init.d` |
| rc.local | `rc_local` | `/etc/rc.local` |
| sudo 提权 | `sudoers` | `/etc/sudoers`、`/etc/sudoers.d` |
| SSH 持久化入口 | `ssh_authorized_keys` | `/root/.ssh/authorized_keys`、`/home/*/.ssh/authorized_keys` |
| shell 启动脚本 | `shell_profile` | `/etc/profile`、`/etc/profile.d`、`/etc/bashrc`、`/etc/bash.bashrc`、`/root/.bashrc`、`/root/.profile`、`/home/*/.bashrc`、`/home/*/.profile` |
| 动态库劫持 | `ld_preload` | `/etc/ld.so.preload` |
| 内核模块 | `kernel_module` | `/etc/modules-load.d`、`/etc/modprobe.d` |

目录扫描支持：

1. `recursive`：是否递归扫描目录。
2. `max_depth`：限制递归深度，避免扫太深。
3. `*` 通配符：例如 `/home/*/.ssh/authorized_keys`。

缺失路径会被忽略；权限不足的路径会跳过或输出 warning。生产环境建议以 root 运行 agent，否则 `/root`、`/etc/sudoers`、部分 cron spool 可能无法完整读取。

## 记录哪些信息

模块默认不输出完整文件内容，而是输出文件元数据、小文件 hash，以及小文本文件的受限内容差异。这样既能回答“发生了什么变化”，又避免把完整敏感配置长期写入日志。

每个被监控文件会记录：

| 字段 | 说明 |
|---|---|
| `path` | 文件路径 |
| `category` | 持久化大类，如 `scheduled_task`、`service_autostart` |
| `persistence_type` | 具体类型，如 `cron`、`systemd`、`ssh_authorized_keys` |
| `file_type` | `file`、`symlink`、`other` |
| `mode` | 文件权限字符串 |
| `size` | 文件大小 |
| `mod_time` | 修改时间 |
| `hash` | 小文件 SHA256 |
| `symlink_target` | 符号链接目标 |

默认只对不超过 `max_hash_bytes` 的普通文件计算 SHA256，当前默认值是 `1048576`，也就是 1 MB。这样可以识别文件内容变化，同时避免对大文件做高成本 hash。

如果 `include_content_diff=true`，模块还会对不超过 `max_content_bytes` 的文本文件保存内容快照，并在变更时输出：

| 字段 | 说明 |
|---|---|
| `content_diff` | 类 unified diff 的行级差异，`-` 表示旧内容，`+` 表示新内容 |
| `content_diff_truncated` | diff 是否因 `max_diff_lines` 限制被截断 |

默认只采集不超过 64 KB 的文本内容差异，最多输出 200 行 diff。二进制文件、超大文件或无法读取内容的文件只输出元数据和 hash 变化。

如果 auditd 富化成功，事件还会包含：

| 字段 | 说明 |
|---|---|
| `user` | 优先使用登录用户 `auid_name`，否则使用执行用户 `uid_name` |
| `uid` | 执行进程的 UID |
| `auid` | audit login UID，用来追踪最初登录身份 |
| `auid_name` | `auid` 对应用户名 |
| `pid` | 执行写入动作的进程 PID |
| `ppid` | 父进程 PID |
| `process` | 进程名 |
| `exe` | 进程可执行文件路径 |
| `command` | 命令行，优先来自 audit `proctitle` |
| `audit_id` | audit 事件序号 |
| `audit_syscall` | audit syscall 编号 |
| `actor_source` | 当前为 `auditd`，表示操作者信息来自 auditd |

## 事件如何产生

模块会把当前扫描结果与上一次保存的 baseline 比较，产生四种动作：

| action | 说明 |
|---|---|
| `observed` | 首次盘点事件，仅在 `emit_baseline=true` 时输出 |
| `created` | 新增持久化文件 |
| `modified` | 文件权限、大小、修改时间、hash、符号链接目标等发生变化 |
| `deleted` | 原来存在的持久化文件被删除 |

输出事件统一为：

```text
asset_type = host_persistence
event_type = persistence_change
```

示例 JSON Lines：

```json
{
  "evidence_id": "host-persistence-17a6f2...",
  "asset_type": "host_persistence",
  "time": "2026-07-09T10:20:30Z",
  "timestamp": "2026-07-09T10:20:30Z",
  "host": "web-01",
  "host_name": "web-01",
  "host_ip": "192.0.2.92",
  "event_type": "persistence_change",
  "action": "modified",
  "category": "account_access",
  "persistence_type": "ssh_authorized_keys",
  "path": "/home/www/.ssh/authorized_keys",
  "file_type": "file",
  "mode": "-rw-------",
  "size": 394,
  "mod_time": "2026-07-09T10:20:28Z",
  "hash": "f2c1...",
  "previous_hash": "9a81...",
  "user": "alice",
  "uid": "0",
  "auid": "1000",
  "auid_name": "alice",
  "pid": "1234",
  "ppid": "1198",
  "process": "bash",
  "exe": "/usr/bin/bash",
  "command": "bash -c echo ssh-rsa AAAA... >> /home/www/.ssh/authorized_keys",
  "audit_id": "88922",
  "audit_syscall": "257",
  "actor_source": "auditd",
  "content_diff": "+ssh-rsa AAAAB3Nza... attacker-key",
  "message": "host persistence modified: /home/www/.ssh/authorized_keys",
  "parser_version": "0.3.0"
}
```

## 配置示例

Linux 默认 agent 配置会启用该模块：

```json
{
  "modules": {
    "host-persistence": {
      "enabled": true,
      "restart": "on_failure",
      "restart_delay_seconds": 5,
      "args": [
        "-config",
        "/opt/secweaver-agent/etc/host-persistence.json"
      ]
    }
  }
}
```

模块配置示例：

```json
{
  "output_log": "/opt/secweaver-agent/logs/host-persistence.log",
  "state_path": "/opt/secweaver-agent/data/host-persistence-state.json",
  "poll_interval_seconds": 30,
  "include_hash": true,
  "max_hash_bytes": 1048576,
  "include_content_diff": true,
  "max_content_bytes": 65536,
  "max_diff_lines": 200,
  "emit_baseline": false,
  "audit": {
    "enabled": true,
    "audit_log": "/var/log/audit/audit.log",
    "key": "tb_host_persistence",
    "perm": "wa",
    "manage_rules": true,
    "fail_on_error": false,
    "from_start": false
  },
  "watch": [
    {
      "path": "/etc/crontab",
      "category": "scheduled_task",
      "persistence_type": "cron"
    },
    {
      "path": "/etc/systemd/system",
      "category": "service_autostart",
      "persistence_type": "systemd",
      "recursive": true,
      "max_depth": 4
    },
    {
      "path": "/home/*/.ssh/authorized_keys",
      "category": "account_access",
      "persistence_type": "ssh_authorized_keys"
    }
  ]
}
```

完整样例在：

```text
src/tools/secweaver-agent/host-persistence.example.json
```

## 输出和资产接入

默认输出文件：

```text
/opt/secweaver-agent/logs/host-persistence.log
```

默认 baseline 状态文件：

```text
/opt/secweaver-agent/data/host-persistence-state.json
```

数据接入 SecWeaver 后注册为：

```text
asset_type = host_persistence
```

当前已新增资产样例：

```text
dataasset/assets/asset-secweaver-host-persistence.json
```

已新增 connector 样例：

```text
dataasset/connectors/conn-sls-secweaver-host-persistence.json
```

已新增查询模板：

| 模板 | 用途 |
|---|---|
| `host_persistence_by_host_time` | 按主机查询持久化变更 |
| `host_persistence_by_host_ip_time` | 按主机 IP 查询持久化变更 |
| `host_persistence_by_path_time` | 按路径查询变更 |
| `host_persistence_by_type_time` | 按持久化类型查询变更 |

## 为什么不用全量文件审计

全量文件审计会带来三个问题：

1. 数据量大，普通系统更新、日志轮转、应用发布都会产生大量噪声。
2. 对内核能力和系统版本更敏感，部署复杂度更高。
3. 调查价值不一定高，安全运营真正关心的是攻击者能用来驻留的关键位置。

`host-persistence` 选择先覆盖高价值路径，用较低成本获取高信号证据。当前 auditd 只用于这些高价值路径的用户和进程富化，不做全量文件审计。后续如果需要更强实时性，可以再扩展 inotify 或 eBPF 版本。

## 安全运营使用方式

在告警确认或溯源分析中，`host_persistence` 适合回答这些问题：

1. WebShell 命令执行之后，主机上有没有新增启动项。
2. 攻击者是否写入了 SSH 公钥。
3. sudoers 是否被修改过。
4. 是否出现可疑 systemd service。
5. 是否有 `ld.so.preload` 或内核模块加载配置变化。
6. 删除行为是否发生在入侵窗口之后，是否可能是攻击者清理痕迹。

它通常和这些资产一起关联：

| 资产 | 关联价值 |
|---|---|
| `host_exec` | 哪个命令可能造成了持久化写入 |
| `host_file_op` | 文件操作证据补强 |
| `ssh_auth` | 写入公钥后是否出现 SSH 登录 |
| `web_access_log` | Web 攻击入口和后续落地行为关联 |
| `windows_event_log` | 混合环境下补齐 Windows/Linux 两侧持久化证据 |

## 部署建议

推荐生产配置：

1. 以 root 运行 `secweaver-agent`，保证关键路径可读。
2. 确认 Linux auditd 已启用，且 `/var/log/audit/audit.log` 可读；否则操作者和进程字段会缺失。
3. 保持 `emit_baseline=false`，避免首次上线产生大量 observed 事件。
4. 先在少量主机灰度启用，确认日志量和字段质量。
5. 根据系统类型增减 watch 路径，例如容器宿主机可增加 kubelet、containerd、Docker service/drop-in 目录。
6. 保护 state 文件目录，避免普通用户删除或篡改 baseline。
7. 输出日志接入 SLS/ES 后，再把 `asset-secweaver-host-persistence` 从 `draft` 改为 `active`。

## 当前局限

当前实现是第一版轻量采集，有几个边界需要明确：

1. 变更事件输出仍由扫描周期触发，发现时间取决于 `poll_interval_seconds`。
2. 它只监控配置中的路径，不会覆盖所有可能的持久化方式。
3. 它不记录完整文件内容，只对小文本文件输出受限 `content_diff`。
4. 操作者和进程字段依赖 auditd；auditd 未启用、日志轮转过快、权限不足或规则未成功下发时，这些字段可能为空。
5. 如果攻击者在两个扫描周期之间创建又删除文件，快照差异可能无法捕获。
6. 如果 state 文件被删除，下一次启动会重新建立 baseline。

这些取舍是为了让第一版足够稳定、低成本、容易部署。对安全运营来说，它能先把最常见、最值得看的 Linux 持久化变更纳入 SecWeaver 证据链。
