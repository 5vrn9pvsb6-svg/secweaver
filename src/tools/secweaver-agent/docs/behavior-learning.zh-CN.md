# 行为学习与日志减量

**语言：** [English](behavior-learning.md) | 简体中文（本文）

## 版本与支持范围

Agent 源码 0.3.37 增加独立的 pkg/behaviorlearning，接入 Linux audit/eBPF 的 exec 输出。
这是首期保守实现，不代表完整设计中的所有管理能力或生产环境验收均已完成。
0.3.38 增加独立 Windows Sysmon exec 适配器，0.3.39 在该适配器增加合格网络/文件事件学习。
容器内无宿主机采集权限的模式不启用 Linux 学习。

新安装复制的 audit-port-execmon.example.json 默认 enabled=true、shadow=false：
首次成功启动采集就学习，不需要等到次日或手动启用；学习期间全量输出。
旧安装保留原配置，缺少 behavior_learning 时不启用。正常重启保留学习进度。
启动及健康中断后有 10 分钟稳定观测保护期，之后累计 24 小时有效时间。
停机不计时；未知/不完整事件继续输出且不成为候选，不影响其他完整行为的学习。
明确丢事件、输入故障、队列溢出和异常退出使本代学习降级，需要显式重新学习。

Linux 只允许可验证的、**直接由监听服务根进程启动**的非交互 ELF 执行进入名单。
父程序和执行程序必须位于 root 管理且组/其他用户不可写的路径，身份一致、
无有效 capabilities，并有完整参数和明确 unset 登录身份。脚本、解释器、
交互式命令、敏感操作和未知上下文始终输出。多层祖先和无法验证的短命进程仍全量输出。

audit 需要 SYSCALL/EXECVE/CWD/PATH 的完整证据，核对执行文件 inode/device 和进程时间。
eBPF 新增执行时有效 UID/GID、登录 UID、启动时间、文件 inode/device；
CO-RE 字段不存在或内核读取失败时 identity_valid=false，不能获得免报资格。
/proc 中已退出、身份改变或无法与内核证据对应的进程仍原样输出。
实际减量比例取决于合格事件占比，不承诺固定百分比。

## 配置

### Windows（0.3.39）

新安装的 `config.windows.example.json` 给统一 reader `windows-eventlog-risk-json` 默认添加
`-behavior-learning`。备用独立 reader `windows-process-execmon` 支持相同参数，但不能与统一
证据输出同时启用。已有配置未带此参数时不改变行为。已实现 Windows amd64/arm64 代码支持；
真实 Windows Sysmon/ACL 和完整 24 小时验收仍需在生产推广前完成。

同样累计 24 小时健康学习，保留 10 分钟保护期、候选晋级阈值、冻结名单、shadow、频率异常
保护和故障恢复全量输出。只有启用 SHA256 的 Sysmon Event 1，具备进程/父进程 GUID、完整命令、
父命令、工作目录、相同内置 SYSTEM/LOCAL SERVICE/NETWORK SERVICE 身份，以及 session 0、
System 完整性级别，才可能合格。程序须为 Windows System32 或 Program Files 下的 `.exe`。
使用执行时 Sysmon 字段，不在轮询后反查 PID；不宣称具备 Linux 式实时父文件/ACL 校验或完整
祖先重建。父程序路径、命令和身份参与指纹，Event 1 不提供父程序文件哈希。

Security 4688 没有执行时哈希和 GUID，始终全量输出。Agent 安装程序不会自动安装/配置 Sysmon。
没有 Sysmon、SHA256、ParentUser 或字段不完整时，不能形成可用名单；名单为空则降级全量输出。
PowerShell、cmd、脚本解释器、敏感工具、交互/提权/身份不一致、历史事件、延迟超过 10 分钟的
事件继续输出，风险日志不参与过滤。尤其只有 4688 的主机，不承诺减量。

从 0.3.39 开始，新装 Windows 显式启用 `exec,active_connect,file_op`，每类使用独立指纹、计数
和合格证据。网络/文件事件必须在本次 reader 运行中先观察到合格 Event 1，并用相同主机和
ProcessGuid、程序路径、用户关联；数字 PID 复用不会继承资格。重启不恢复内存身份缓存，
启动前已存在的进程保持全量，直到观察到合格创建。缓存最多 1,024 条/4 MiB，活跃事件续期，
闲置 1 小时过期，每分钟清理。观察到 Sysmon Event 5、身份不一致或输入故障即撤销对应上下文；
无法仅凭无事件推断未收到的进程退出。

| 类型 | 自动名单资格 | 始终输出 |
| --- | --- | --- |
| `exec` | 原有 Event 1 SHA256、服务身份及完整命令验证 | 4688、敏感工具、字段不完整/交互身份 |
| `active_connect` | Sysmon 3、`Initiated=true` 外连、精确内网目标 IP/端口、TCP/UDP、精确源 IP 和执行身份 | 公网/特殊地址、入站、方向/协议未知、SSH/RDP/SMB/RPC/DNS/认证/管理端口 |
| `file_op` | Sysmon 11、指定 `file_roots` 内普通 `.log` 的精确创建路径和执行身份 | 删除、重命名、不明确动作、其他扩展名、敏感路径、审计/认证/安全/Agent 日志 |
| 认证、风险、持久化、身份/服务变化 | 不自动免报 | 原有关键证据全部保留 |
| 进程/端口/主机状态快照 | 沿用已有快照增量机制 | 不用白名单丢弃基线和状态变化 |

文件目录只限定学习范围，不是路径通配白名单，每个完整路径仍须满足学习晋级阈值。
新装 Windows 样例指定 `C:\ProgramData`，非 C 盘环境需要填写真实绝对路径。
Windows/Microsoft/Startup/Tasks/凭证/SSH 等路径即使处于目录范围内也不免报。
学习参数不会新增 Sysmon 规则或开启网络/文件采集器，必须已具备源事件。
本次未扩展 Linux audit/eBPF 的 exec 以外过滤，Linux 网络和文件原文继续保留。

Sysmon Event 11 表示**创建或覆盖**，不提供内容差异，原有标准化 `action=create` 包含这两种情况。
业务安全/审计日志即使以 `.log` 结尾，也不应放入允许目录。Sysmon 网络 Event 3 默认不启用，
需要运维已开启源采集。语义见[微软事件说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)。
观察到 CreateRemoteThread（8）或 ProcessTampering（25）会让本代降级全量输出；GUID 未变不能
证明进程从未被注入。

在 `config.json` 中实际拥有证据输出的 `modules.<模块名>.args` 添加：

```text
-behavior-learning
-learning-duration 24h
-learning-generation 0
-learning-shadow=false
-learning-event-types exec,active_connect,file_op
-learning-file-roots "C:\ProgramData\Example\logs"
```

`-behavior-learning=false` 关闭，`-learning-shadow` 保留全部原文；增加 `-learning-generation`
重新学习可读取的状态。调整学习时长仍须满足默认跨 6 小时、3 个小时桶等门槛。
修改后重启 `secweaver-agent` 服务。`-learning-state-dir`、`-learning-output` 可指定绝对路径。
`-learning-event-types` 用逗号分隔；`-learning-file-roots` 多目录用分号分隔，最多 16 个绝对路径，
不允许通配符。省略事件类型仍是旧版 exec-only；省略目录则文件事件全部输出。
已有基线扩大类型/目录范围时须增加 generation，否则配置指纹不一致会拒绝过滤并保留原文。
升级不会静默修改已有磁盘配置。
默认状态目录 `C:\ProgramData\SecWeaver\Agent\data\behavior-learning-windows`，摘要为进程
日志旁的 `behavior-learning.log`；自定义游标目录决定默认状态目录。必须有已注册设备的
`SECWEAVER_DEVICE_ID`；身份缺失、状态损坏或锁冲突时提示警告并保留原文。
Windows 状态使用 SYSTEM/Administrators 受保护继承 ACL、独占句柄锁和 write-through 原子替换，
下文 Unix 0600 权限描述不替代 Windows ACL。

两个入口复用同一个同步、字段大小受限的适配器，不额外查询 Windows、不扫描进程、不启动哈希
子进程。每秒 ticker 在适配器锁下推进计时/检查点，只有近期成功完成的整轮查询续期健康状态。
查询失败、观察到 Sysmon 重启/配置变化/错误或事件日志清空会使本代降级；不宣称能发现所有
未观察到的日志覆盖或 Sysmon 过滤造成的缺失。原文与摘要刷盘后才推进 EventRecordID；Windows
游标检查点也会刷出非空计数，因此摘要窗口可能短于 300 秒。游标与学习状态是不同文件，崩溃
后降级，不能据此承诺精确一次计数。
正常停止也先刷盘两个输出再标记状态为正常退出；最终刷盘失败会持久化降级状态。

Windows SaaS 0.3.50 受管安装要求签名采集清单包含摘要文件，缺失规则时安装失败，
见 [Windows 采集就绪](windows-installation.zh-CN.md#windows-sls-采集就绪)。
外部输送模式需要给 Filebeat/ES Shipper 或 Logtail 增加 Windows 摘要文件，接入独立的
`host_behavior_summary`，云端 Logstore 可命名为 `host-behavior-summary`，不能混作 `host_exec`。
Linux 路径样例不会自动完成 Windows 上传。验收应先开 shadow，对照本地及云端
`behavior_learning_status`，并核对命令/哈希变化、PowerShell、交互和 4688 原文均保留。

### Linux

在 audit-port-execmon.json 增加以下块，其他模块字段保持原值：

```json
{
  "behavior_learning": {
    "enabled": true,
    "learning_duration_seconds": 86400,
    "generation": 0,
    "shadow": false
  }
}
```

默认摘要周期 300 秒；晋级要求至少 5 次、3 个不同有效小时桶、跨度 6 小时。
默认最多 10,000 条基线、20,000 条候选，内存/状态预算各 64 MiB；
实际容量还受保守的字节准入预算限制，可能先于条数上限停止接纳。
验证和输出由单一后台 worker 持有，队列 128 条，单条最多 64 KiB；超限恢复原始输出并降级。
状态文件每 60 秒检查点写入，学习计数的最后一分钟在故障时可能丢失。
字段完整清单见 pkg/behaviorlearning/config.go；未知学习字段使功能停用并在 stderr
报告原因，核心采集继续。缩短学习时间也必须同步调整晋级阈值。

shadow=true 仍全量输出，用于保留证据验证名单；不作为默认额外学习日。

从 0.3.40 起，Linux 父进程在子模块停止完成后才关闭共享 audit reader。正常重启保留
健康学习代次，停机时间不累计；真实断流仍会降级。0.3.37-0.3.39 正常停止时可能误写入
`audit_reader_failed`。升级不会自动信任已降级的代次：先备份配置和状态，再将 audit
模块配置的 `behavior_learning.generation` 增加 1，重启后重新累计 24 个健康小时。
不要手改带完整性校验的状态文件。验收时比较第二次正常重启前后：baseline ID 和 generation
应不变，模式保持 `learning`/`enforcing`，且不再新增 `audit_reader_failed`。
此修复针对 Linux 父进程托管采集，Windows 学习前提和真实故障恢复策略不变。

enabled=false 停止学习过滤。generation 增加表示显式建立新一代名单；
策略阈值改变但未增加 generation 会拒绝复用旧状态，保持全量输出。
更改后按现有模块配置重启流程生效；手工部署可执行：

```bash
sudo systemctl restart secweaver-agent
```

不要删除 state.json 来尝试重新学习；初始化标记会将这种情况识别为状态损坏。
损坏状态无法通过 generation 自动修复：先禁用学习、备份整个状态目录，
排除磁盘问题，再在停服务的维护窗口更换 state_dir 并明确重新学习。
不得在服务运行时手改名单、密钥或复制其他主机的基线。

## 状态与文件

默认目录实际沿用 Agent data 布局，而不是早期设计中的 state 路径：

- /opt/secweaver-agent/data/behavior-learning/state.json：HMAC 校验的状态封装，
  内含学习进度、候选、冻结 entries、最近命中和干净退出标记。
- 同目录 key、initialized、lock：本地指纹密钥、初始化标记和单写者锁。
- /opt/secweaver-agent/logs/behavior-learning.log：摘要和状态事件，沿用 0600、
  缓冲、轮转、磁盘预算及主机/企业字段注入。
- state_dir/output_log 可使用绝对路径自定义；具有 logs/data 同级目录的自定义根会自动跟随；其他布局需显式设置 state_dir。
  output_log 省略时跟随原始事件日志的所在目录。

状态目录 0700，文件 0600。名单只保存 HMAC 指纹、程序路径、次数和资格证据，
不持久化完整 argv、口令或可逆参数样本。当前文件格式与早期设计示例不同，
以实现的 schema_version=1 为准；HMAC 保护本地完整性，不能防御已掌握 root 的攻击者。

运行中查看最近检查点，不争抢采集器的独占锁：

```bash
sudo /opt/secweaver-agent/bin/secweaver-agent module audit-port-execmon \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -learning-status
```

状态最多落后 60 秒。摘要中的 source_healthy 表示输入健康，filtering_active 表示当前实际过滤，
shadow 表示验证模式；仅 learning_state=enforcing 不意味着已经跳过重启保护期。
状态文件丢失会报错并保留原始输出，不会自动当作首次安装重新学习。
基线、策略或设备不匹配时不自动扩大名单；
正常重启先全量输出 10 分钟重建频率状态，崩溃/强杀后进入 degraded。
generation 增加可以在完整可读的状态上显式重新学习。
本版未实现逐条撤销、基线版本回滚或专用远程管理 API。

## 匹配与取证

名单使用设备、策略版本、服务/父进程上下文、程序摘要、完整 argv、
工作目录、身份和后端能力生成 HMAC。PID 不参与跨次匹配；进程实例另外验证。
程序、参数、用户或服务变化都会恢复原始输出。未知行为不会因重复而自动入名单。

每条基线的滚动 5 分钟上限为 max(10, 3 × 学习期 P95)。
采用单调时间的 5 秒桶，边界保守多覆盖最多 5 秒，不给跨窗口突发双倍额度。
超过上限立即输出本次事件和摘要，随后至少 10 分钟保持原始输出；
持续高频会延长保护期。30 天未命中失效。

进程树跟踪先于学习判定。可用的被抑制祖先可按真实 event_id 补发为 context_only；
无法取得祖先执行实例时标记 ancestry_context_missing，不伪造链条。
首期多层祖先关联仍有限制，不承诺完整历史取证；需要完整原始历史时关闭过滤。
有界内存无法缓存当前执行证据时，不免报该事件。

经过学习适配器的原始事件增加 event_id、baseline_id、behavior_fingerprint、learning_state、
learning_decision、decision_reason、fingerprint_version 和 ancestry_context_missing。
日志权限与原有脱敏行为不变；学习模块不把原始命令写入状态文件。

## ES、SLS 与资产

新事件类型：behavior_summary、behavior_learning_status；
asset_type=host_behavior_summary，不能当作 host_exec 使用。
非空行为摘要新增 `source_event_type`，值为 `exec`、`active_connect` 或 `file_op`；状态记录省略。
旧摘要缺少此字段时按 exec 解释。必须按类型分别统计，网络/文件计数不能当作进程执行次数，
也不能构造进程树边。ES 设为 keyword、SLS 设为 text，随包模板和资产已声明该字段。
完整摘要满足 observed_count = suppressed_count + original_emitted_count；
祖先补发单列 context_reemitted_count。按 summary_id 去重后统计；
counter_complete=false 或重启缺口时不能把计数当作完整执行次数。

- ES：随包 elasticsearch/filebeat.yml 增加新文件路径和
  secweaver-public-agent-behavior-learning-* 索引。index-template.json 增加
  keyword/long/date/boolean 映射。已存在模板需按 ES 指南检查漂移并迁移，
  初始化程序不会自动覆盖已存在的模板。
- SLS：运维需为新文件创建 JSON 采集配置并绑定现有用户自定义标识机器组；
  logtail/behavior-learning.example.json 提供字段与索引参考，不是可跨版本直接提交的 API 请求。
- Community 提供 ES、SLS、SLS Proxy 的独立摘要资产/连接器草案和按主机时间查询模板。
  替换连接参数并完成真实上传查询验收后再设为 active。
- 私有 Operator、SaaS 物理 Logstore 和独立 shipper 的交付配置必须同步增加新日志路由。
  本次 Community 改动不会远程修改已部署的 Filebeat/Logtail 或私有资产库。

发布启用前须确认新日志真正上传；验证时可先配置 shadow=true。
技能应同时读取摘要/状态，明确记录免报及缺口，不能把“缺原始 exec”解释为没有执行，
也不能从聚合记录构造 PID 进程边。

## 验证与待验收项

在 Agent 源码目录运行：

```bash
go test ./pkg/behaviorlearning ./pkg/auditportexecmon ./pkg/processtracker/...
go test -race ./pkg/behaviorlearning ./pkg/auditportexecmon
go test ./pkg/behaviorlearning -run '^$' -bench BenchmarkKnownBehavior -benchmem
```

Linux eBPF 测试可验证对象布局和解码；编译通过不等于内核加载验收通过。
发布前仍需真实 amd64/arm64/loong64 内核加载、24 小时学习、至少 7 天稳定性、
完整攻击演练，以及真实 ES/SLS 摘要入库对照。新代码不自动发布或部署二进制。
