# Linux eBPF-only 采集模式

从 Agent 0.3.100 开始，Linux 宿主机在当前启动内核不支持 Audit、但支持包内
eBPF 程序时，可以使用产品级 eBPF-only 模式，无需为了开启 Audit 重启机器。
SLS SaaS 和 ES 使用同一套模式选择；Windows 和 Docker workload profile 不适用。

## 配置与选择

模块配置 `/opt/secweaver-agent/etc/audit-port-execmon.json` 新增：

```json
{
  "audit": { "mode": "auto" },
  "exec": { "monitor": true, "process_tree_backend": "auto" }
}
```

| audit.mode | 行为 |
| --- | --- |
| `auto`（默认，缺省字段也按此处理） | Audit 环境可用时保持原有完整路径；Audit 不可用时验证 eBPF-only；二者都不可用则报错退出 |
| `audit` | 强制要求 Audit，失败时报错，不自动切换 |
| `ebpf_only` | 强制使用 eBPF，不读取 audit.log，不创建或删除 Audit 规则；eBPF 不可用则报错 |

`audit.mode` 决定整个 Linux 采集运行的能力边界；`exec.process_tree_backend`
仍控制完整 Audit 模式中的进程树后端。显式 `audit`/`audit_pid` 后端与 eBPF-only
冲突时返回配置错误，不自动改写管理员选择。需要允许自动选择时把后端设为 `auto`。
独立模块命令可使用 `-collection-mode=auto|audit|ebpf_only` 覆盖 JSON 模式。

安装器在依赖准备后、注册和替换程序前验证环境。Audit 可用时保留队列预检查；
Audit 不可用时跳过所有 auditd 配置和服务操作，先检查架构/BTF/tracepoint，
再实际加载并挂载包内 eBPF 程序。通过后只持久化 `audit.mode=ebpf_only`。
失败信息区分内核能力、程序加载/verifier、挂载和显式策略冲突。不会要求操作者
重复安装来绕过失败。

## 支持条件与采集限制

eBPF-only 支持 Linux amd64/arm64 的 systemd 宿主机，需要 root、可读取的
`/sys/kernel/btf/vmlinux`、execve 进入/退出及成功执行 tracepoint，以及包内
fork/exit 程序实际可挂载。内核版本号不能单独证明支持；发行版回移功能、BPF
helper、权限和 verifier 都以实际加载为准。若 execveat tracepoint 对缺失，预检
给出警告，execve 仍可采集。目标机器无需 Clang、内核头文件或 libbpf。
Linux loong64 当前没有此 eBPF 后端，需要可用的 Audit。

| 能力 | eBPF-only 行为 |
| --- | --- |
| 监听进程及子进程 exec | 保留，使用原有 eBPF 归属与 JSONL 合约 |
| fork/exit、PID 复用保护、监听对账 | 保留；对账默认 300 秒 |
| 自定义采集规则、exec 自学习 | 保留，已有配置和学习名单不重置 |
| Audit connect/file_op、敏感文件读取 watch | 不采集；当前 eBPF 程序只提供进程证据 |
| host-persistence | 保留文件轮询/差异；关闭 Audit watch 和行为人补充 |
| syslog、host-process、host-state、健康日志与上传 | 保持原有能力；上传仍需正确配置 shipper/Logtail |

Agent 0.3.101 增加 exec 时的内核父进程 PID、名称、可执行路径与启动标识。
父进程退出或 PID 复用后不再查询当前 `/proc` 名称来替换快照；缺字段/路径
超限时明确标记。新增 JSON 字段、路径边界和真实内核验证见
[进程归属文档](process-attribution.zh-CN.md)。

eBPF 命令参数仍有原有数量/长度边界，截断会标记 `command_truncated=true`。
同一事件不会同时从 Audit 和 eBPF 输入重复采集。整机模式在 Agent 启动时选择，
子模块重启不能单独改变已选择的传输，防止与父进程订阅和其他模块不一致；
运行中 eBPF 流故障会按现有模块重启机制恢复，失败会明确报错，不切到不可用的 Audit。

## 操作与验证

对既有安装，先验证当前配置和实际 eBPF 加载：

```bash
sudo secweaver-agent config check-linux-collection \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json
```

该命令临时加载 eBPF，不注册设备、不建立监听根进程、不写事件或学习名单，
结束时关闭已加载资源。Audit 可用的 auto 配置会直接验证 Audit 环境。

显式启用并重启 Agent：

```bash
sudo secweaver-agent config set-audit-mode \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -mode ebpf_only
sudo systemctl restart secweaver-agent
sudo secweaver-agent preflight
sudo secweaver-agent doctor
```

应看到 `Linux collection mode: ebpf_only`、eBPF 加载成功和 `audit-mode` 的能力
限制警告；不应出现 auditd 不可用的致命错误。`preflight/doctor` 只做只读能力
检查，不能替代 `check-linux-collection` 和真实运行的加载验证。通过一个新 SSH
会话执行命令，检查 `audit-port-execmon.log` 的 `exec` 及 `ebpf:` 事件 ID。

自动升级仅替换二进制时，缺省/auto 的旧配置也会在启动前自动选择运行模式；
host-persistence 的 Audit 开关只在本次运行内覆盖，不改写其配置。升级不重置
学习状态。要恢复完整 Audit 能力，先准备好 Audit 环境，再把 `audit.mode` 改为
`auto` 并重启 Agent。若显式设过 `exec.process_tree_backend=ebpf`，恢复回退能力
还需把它改为 `auto`。两种传输都不可用时安装器或 Agent 非零退出并报告原因。
Agent 运行前能力验证失败使用退出码 `78`，发布包 systemd unit 不自动重启此
错误，避免形成循环；修复环境或配置后手工启动服务。

## 已验证范围

2026-10-14 在麒麟 V10 x86_64、内核 `4.19.90-89.27.v2401.ky10.x86_64`、
当前启动参数 `audit=0` 的测试机验证了真实加载和完整 Agent 运行。预检为
`error=0`，两轮隔离测试合计输出 191 条 `ebpf:` exec 事件，包含归属 `sshd`
的指定命令；host-persistence 输出 2 条文件变更。Audit 规则数为零，无共享
audit.log reader，auditd 保持未运行。测试没有接入 SLS/ES 上传，不代表云端
入库已验证。Linux amd64/arm64/loong64、Windows amd64/arm64 编译检查通过；
除上述麒麟 x86_64 外，其他内核的实际 eBPF 支持仍须在目标主机加载验证。
