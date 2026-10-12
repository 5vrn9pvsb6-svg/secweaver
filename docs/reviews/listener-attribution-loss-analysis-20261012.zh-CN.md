# 从监听服务开始跟踪，为什么还会丢失 listener_process

分析日期：2026-10-12。

源码基线：SecWeaver Community 提交 `0c9c0200b6b521735a6c1aca7d76ff4d976d19c4`，Agent `0.3.95`。开始分析时工作区干净。历史对照：提交 `428557704fbcd58ed20dc71e0310e25d58b900e0`，Agent `0.3.93`。

本文是 [exec 全链路分析](exec-event-processing-analysis-20261012.zh-CN.md) 的归属专题补充。此次只做源码分析、隔离复现和文档更新，没有修改 Agent 实现、配置或版本，没有部署，也没有重新查询生产主机或 SLS。下文版本均指核对过的源码版本，不能据此认定某台生产主机正在运行该版本。

> 后续状态：用户在本报告后明确要求“按照你的建议修复”。0.3.96 已按第 6 节的快照/活跃状态分离方案实施，见本文第 8 节及 [当前归属指南](../../src/tools/secweaver-agent/docs/process-attribution.zh-CN.md)。第 1—7 节保留 0.3.95 的分析基线，不代表修复后的当前行为。

## 1. 结论：用户的疑问成立

**一条已经可靠确认由监听服务进程树产生的事件，其历史归属不应仅因为处理时进程已经退出而消失。**

当前实现确实从监听根建立跟踪关系，但“已有监听归属”仍依赖处理时的 `/proc` 状态和可变 PID 缓存。它把两件事绑在了一起：

- 当前是否还能验证该进程、是否应该继续安装或保留监控规则。
- 已经发生的事件，当时属于哪个监听服务实例。

第一件事随进程退出发生变化，不能自动推翻第二件事。当前实现没有完整分离这两个生命周期，导致已知历史被再次判为不确定。

因此，之前将这些情况统一概括为“无法确认监听服务归属”不够准确。至少需要区分：**从未确认过归属、确认后未保存足够证据、身份真正冲突**。

旧版 `0.3.93` 对其中的不确定事件会清空监听字段并输出；当前 `0.3.95` 拒绝输出。后者满足“不要记录无监听归属的业务事件”的边界，但没有完整解决原本可归属事件的漏采问题。

## 2. 为什么“从监听服务出发”仍不等于“事件永远携带完整归属”

### eBPF 路径

当前内核 `process_owner` 保存根 PID 和根启动时间标识；fork 把这些信息继承给子进程，事件也携带这些值。见 [process_lifecycle.c](../../src/tools/secweaver-agent/pkg/processtracker/ebpf/process_lifecycle.c)。

但是，完整监听名称、地址和端口仍需在用户态的 `pidListener` / `listeners` 中解析。即使匹配到同一根实例，用户态还会重新要求该根在当前 `/proc` 中存在且启动时间一致。见 [monitor_ebpf.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_ebpf.go) 的 `observeEBPFEvent()` 和 [attribution.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/attribution.go) 的 `listenerLifetimeLocked()`。

所以，内核已经记录过来源，不代表后续用户态一定接受这份来源。归属可以在消费阶段被降为 unknown。

### audit 路径

固定规则 audit 在内核侧采集较宽的 exec/clone 事件流，用户态再按监听根筛选。见 [audit_bounded.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/audit_bounded.go) 和 [audit_rules.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/audit_rules.go) 的 `addGlobalAuditRules()`。

因此，audit 原始候选事件中确实可能有从未属于监听服务的事件。这些应正常排除，不能因为命中 audit key 就补上监听名称。

但本次更关键的复现是：**候选事件已经通过了监听归属校验，后续组装仍然可以丢失它的归属。** 这与最初就不在监听范围内是不同的问题。

## 3. 最直接的证据：旧版会主动清空字段

历史提交 `4285577` 的 `pkg/auditportexecmon/ebpf_events.go` 第 146 行附近：

```go
if listener.AttributionUnknown {
    event.ListenerPID, event.ListenerPort = 0, 0
    event.ListenerProcess, event.ListenerAddress = "", ""
    event.AttributionStatus = "unknown"
}
```

同一提交的 `learning.go` 中，unknown 事件直接写原文，避免进入学习匹配；当时的统一输出函数没有现在的监听归属门禁。audit 输出也允许部分 unknown 事件通过。

这意味着空字段并不一定来自“最初没有识别到服务名称”，也可能是**已经保存过名称，但后续校验失败，代码主动清空后继续输出**。

当前 `0.3.95` 已增加三处相关防线：

- eBPF 消费与输出拒绝 unknown 或无名称事件。
- audit 组装完成后，匹配失败或 unknown 就结束该记录，不写业务日志。
- [learning.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/learning.go) 的 `hasOutputListener()`、`emitNormalizedEvent()`、`WriteEvent()` 在序列化、学习排队和直写前再次拒绝。

本次没有找到当前 Linux exec 业务输出路径绕过这些门禁继续写空监听字段的证据。但“空字段减少”不能证明“原有事件的归属保留正确”，因为被误判 unknown 的事件也一起消失了。

## 4. 已复现的五条归属丢失路径

以下均调用当前真实 Go 归属/组装函数，只替换进程身份读取为合成输入。它们证明代码行为和触发条件，不代表已经统计出各条件在生产中的发生频率。

| 场景 | 仍然成立的历史证据 | 当前行为 | 影响 |
| --- | --- | --- | --- |
| eBPF 事件消费前，监听根退出 | 事件携带原根 PID、根启动标识，缓存还保存 `mysqld` | 因根当前不可读而标 unknown | 已捕获事件被拒绝输出 |
| audit 主记录已通过校验，组装期间后代退出 | 同一 audit ID 的 SYSCALL 已确认归属，监听根仍活着 | 只保留“曾接受”布尔标识；输出时重新查进程失败 | 可靠接收过的事件在组装结束时丢失 |
| audit 后代被重新托管，PPID 变为 1 | 子进程 PID 和启动时间均未改变 | PPID 与缓存不同，删除原 owner | 进程身份未变，却失去原历史来源 |
| audit 后代存活超过 5 秒后执行并快速退出 | 之前已建立监听关系；本次 exec 时间很新 | 退出后的补偿窗口从 fork 出生时间计算，无法覆盖 | 不只是积压超过 5 秒才会漏采 |
| eBPF 一次根身份读取失败，随后恢复 | 根和子进程启动时间都恢复为同一实例 | unknown 写回子进程缓存，后续查找与普通 reseed 仍不恢复 | 一次读取失败可影响后续多次事件 |

### 4.1 根进程消失，不应自动抹掉已发生事件的来源

`listenerLifetimeLocked()` 会读取根 PID 当前的启动时间；读不到返回 unknown，读到不同启动时间返回 unrelated。这个检查适合阻止给新进程安装旧规则，却不足以判断旧事件是否合法。

`observeEBPFEvent()` 又执行：

```go
listener.AttributionUnknown = listener.AttributionUnknown ||
    m.listenerLifetimeLocked(listener) != attributionVerified
```

隔离复现中，返回的内部 `listener.Process` 仍是 `mysqld`，事件也携带原根启动标识，但最终输出字节数为零。问题发生在已知身份被重新降级的步骤。

安全修复不能简单移除当前进程检查。应先有与原根实例绑定的可信历史记录，再据事件实例和时序使用它；缺失这样的证据时仍需拒绝。

### 4.2 audit 组装会丢掉已经接受过的身份

`shouldDropBoundedAuditPrimary()` 匹配成功后只写入 `attribution_accepted=yes`，没有把本次事件已经确认的监听实例快照存入 `auditAccumulator`。

在 `emitOne()` 中，EXECVE/PROCTITLE 等记录组装完毕后，再次调用 `matchListener()`。如果此时子进程和直接父进程已消失，而又没有可用的短时 fork 证明，就会变为 unknown。

复现时间线：

```text
t0  已跟踪：mysqld → helper-parent → helper-child
t1  helper-child 的 SYSCALL 到达，校验通过
t2  helper-parent、helper-child 退出；mysqld 仍运行
t3  同一 audit ID 的 EXECVE/PROCTITLE 组装完成
t4  再读进程身份失败，丢弃这条原来已确认的事件
```

复现使用已发现的现存后代，不假定必然有一个刚发生的 fork 可用于补偿。这是“监听根没死，为什么也丢归属”的直接答案。

相关实现：[monitor_pid.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid.go)、[types.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/types.go)、[audit_event.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/audit_event.go)。

### 4.3 PPID 改变与进程实例改变被混为一谈

`cachedListenerLocked()` 在发现事件 PPID 与缓存 parent 不同时，会调用 `invalidateOwnerLocked()` 删除原归属。即使已经读到子进程启动时间与缓存一致，也没有先保留这个已确认实例的历史来源。

父进程退出、后代被 init 或其他收养进程接管时，PPID 可以变化；这不等于子进程变成了另一个进程。当前数值 PID 和启动时间都没变的复现仍然删除了 owner。

应把当前父子关系更新与历史监听来源分开。仅凭 PID 相同仍不能保留归属；这里的关键前提是子进程实例身份一致。

### 4.4 五秒窗口并不是“只补偿五秒日志延迟”

当前 `unknownProcessIdentityTTL` 是 5 秒。已退出进程通过短时 fork 证据恢复身份，要求事件时间距 fork、当前时间距 fork，以及距观测时间均在限定窗口内。

所以，一个后代在 fork 后运行 10 秒，再执行命令并快速退出，即便该 exec 刚刚到达，仍可能超出补偿窗口。不能将所有失败解释为日志 reader 积压。

此外，[monitor_pid_cleanup.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid_cleanup.go) 的清理也使用 fork 时间窗口，并且会随着规则清理删除归属缓存。当前缺少独立于活跃规则的、有界历史实例记录。

延长固定 TTL 可以改变概率，不能替代实例身份与事件历史的正确建模。

### 4.5 unknown 状态存在难以恢复的传播路径

eBPF 路径可把 unknown owner 写回子进程。下一次匹配优先拿该子进程的 owner，再通过逻辑或保留原 unknown；即使根重新可读且启动时间完全相同，也不会自然恢复。

复现中，随后执行普通清理和 `expandPIDExpected()` 仍未恢复。原因之一是 [monitor_pid_rules.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid_rules.go) 的 `reservePIDExpansion()` 看到 PID 已 monitored 就直接返回，不刷新该 owner。

这里注入的是“一次身份读取不可用”，不是声称生产 `/proc` 已出现瞬时故障。当前读取函数把读取失败表示为零，没有在该接口中区分退出、不可读等原因。需要区分可重新验证的暂时不确定与真正的实例冲突。

## 5. 已验证的正常边界

不能把上述结论扩大为“短命进程都会漏采”或“身份校验都应该删除”。三个对照场景已经通过：

1. eBPF：监听根仍活着，直接子进程已经退出，仍可正确归属到根。
2. audit：同样的直接子进程退出场景，仍可通过活着的根 PPID 正确归属。
3. 根数值 PID 被新实例复用：旧事件不能采用新根的身份，当前代码正确拒绝。

之前防止 runc、同容器兄弟服务或复用 PID 被错误关联的方向仍然必要。不能用同容器、同可执行文件、单独的数值 PID 或一个历史名称替代真实继承证据。

## 6. 应对齐的正确模型

建议将以下三种状态分离：

| 状态 | 身份与生命周期 | 用途 |
| --- | --- | --- |
| 活跃进程与规则 | 当前 PID、启动时间、当前父进程、规则状态 | 决定是否继续跟踪及安装/移除规则 |
| 监听服务实例及继承记录 | 主机启动实例 + 根 PID + 根启动时间；子进程实例与已验证继承关系 | 保存事件来源，避免 PID 复用错配 |
| 事件归属快照 | 事件 ID/源时间、进程实例、根实例、当时监听名称与地址端口、证明方式 | 保证后续组装、学习和输出不会仅因当前进程退出而改判 |

具体优先顺序：

1. **在首次充分确认事件归属时，保存本事件的实例快照。** audit 主记录通过校验后，后续补充命令参数时沿用同一事件快照，不能只记一个 accepted 布尔值。
2. **建立有界的监听根与进程实例历史。** eBPF 的原根标识可以查到相应历史服务快照；退出后停止活跃规则不等于立即删除所有在途事件的历史身份。保留必须受事件引用、容量、时间窗口等约束，不能无限增长。
3. **进程实例一致时允许更新 PPID。** 重新托管不自动删除历史来源；确认实例变化时才隔离旧关系，不能把旧关系转给新实例。
4. **区分暂时不可验证与已确认冲突。** 只允许基于充分的同实例证据恢复，不能简单把 unknown 全部设回 false。
5. **保留拒绝门禁并补充原因计数。** 从未证明属于监听服务、缺失必要身份信息、实例冲突的事件仍不进入业务日志；分别统计组装期丢归属、历史过期、冲突和当前不可读，避免仅凭空字段数量判断健康度。

必须明确的语义边界：本次优先修复目标是“已经发生且可靠确认归属的事件不因后续退出丢失”。根退出以后，仍存活后代的新事件是否继续纳入业务监控，是另一个范围策略；不能把停止未来采集与删除既有事件来源混在同一动作里。

## 7. 验证记录与限制

在临时目录创建 Go overlay 测试，不向 Agent 源码目录写入测试或变更。运行：

```sh
go test -overlay=/tmp/secweaver-listener-lineage-20261012-131816/overlay.json \
  ./pkg/auditportexecmon -run '^TestLineageReport' -v -count=1
```

结果：`PASS`，包耗时 `0.388s`。共 7 个顶层测试函数，其中一个包含两个后端子测试，对应 **5 个问题复现和 3 个正常边界对照**。这里的 PASS 表示测试成功确认了上述当前行为，不表示缺陷已经修复。

临时证据目录包含 `lineage_probe_test.go`、`overlay.json`、`probes.log` 和分析开始时的源码哈希快照 `snapshot.json`；它不是发行包或长期保存的测试套件。上述命令依赖本次本机临时文件，跨机器不能直接运行。后续实施修复时应将这些场景转为仓库回归测试。

限制：验证使用合成 PID、启动时间和内存事件，在本地调用真实 Go 函数；没有启动 Linux BPF/audit 内核链路，没有安装规则、产生真实进程重新托管，也没有外发通知。生产问题的占比与具体触发主机，仍须结合实际后端、Agent 版本、事件源时间、进程生命周期和丢弃原因取证，不能由这组隔离测试直接推出。

后续修复的最低验收项应包括：事件排队后根退出、audit 分片期间父子退出、已运行超过五秒的后代快速退出、PPID 重新托管、同实例可读性恢复、监听根重启、PID 复用、历史缓存淘汰，以及同容器不同服务隔离。需要同时保证已证明的事件保留、未证明的事件不被误补归属。

## 8. 0.3.96 实施与验证记录

本次按用户确认的范围修复，复用现有 Go 模块与后端，不使用数据库，不新增依赖，也未修改服务端协议或 eBPF 内部事件布局。只在 Community 仓库维护，没有部署或重新查询生产数据。

| 已确认目标 | 实现归属 | 验证 |
| --- | --- | --- |
| 已接收事件不因组装期进程退出失去归属 | `attribution_snapshot.go`、两个 audit reader 与 accumulator 生命周期 | 三种后端的退出/复用测试；真实本地文件和 pipe reader 分段读取测试 |
| 根退出后保留已有 eBPF 事件 | `attribution_history.go`、`monitor_ebpf.go` | 排队事件、清理后恢复、根复用后保留旧名称但不修改新实例 |
| 重新托管与暂时不可读能够正确恢复 | `attribution.go`、`monitor_pid_rules.go` | 同启动时间 PPID 变化、PID 复用反例、eBPF 后续同实例恢复 |
| 历史恢复不能扩大活跃规则范围 | `Historical` 内部标识、跟踪入口与根退休索引 | 历史事件不新增 monitored/规则；zombie 不能重开旧根；过期不能复活退休实例 |
| 历史资源有界且证据不足仍拒绝 | 4,096 根 / 16,384 进程记录、30 秒恢复有效期及原 5 秒 fork 规则 | 容量淘汰、过期、时间区间外拒绝、重新监听不跨越空白区间 |
| 能区分历史恢复与拒绝原因 | `attribution_metrics.go` | 接收/输出使用计数、淘汰计数与现有运行诊断集成 |

与原分析中“五秒问题”的对应边界：0.3.96 可以恢复**已验证存活区间内**的旧进程延迟事件，也可保留已经接收的事件快照；并未把所有“fork 超过五秒后进程已消失”的事件自动判为可信。audit 缺少源进程代际标识，若事件超出末次正向验证且没有其他证明，仍需拒绝。这样修复证据丢失，而不通过扩大裸 PID 的信任时间重新引入误归属。

新增 12 组 `TestSnapshot*` 回归，覆盖上述正例和拒绝边界。另在提交 `0c9c020` 的隔离源码快照中运行兼容旧接口的两个回归：重新托管与暂时身份失败恢复均按预期失败；当前实现的相应用例通过。旧版实验最初因 macOS 路径别名未命中 Go overlay，出现 `no tests to run`；该结果没有作为证据，改为在隔离源码树写入测试后确认了真实失败。

已执行：Agent `make check`（格式、vet、全量 Go 测试、全量 race、Linux/Windows amd64 构建）通过。其后补充实际文件/流式 reader 测试和退休清理边界，最终受影响模块 `go test -race ./pkg/auditportexecmon` 与 `go vet ./pkg/auditportexecmon` 通过；最终 Linux/Windows amd64 构建、格式、文档链接/公开命令检查和 `git diff --check` 均通过。补充构建曾因本机磁盘空间不足而链接失败；清理本次生成的项目编译缓存及隔离源码副本后重跑通过，未清理用户源文件，旧版回归探针和结果日志仍保留。

验证使用合成进程身份、真实本地文件/pipe 和生产组装/输出逻辑，未执行真实 Linux 内核挂载、真实主机安装或 SLS 灰度。因此本次交付是源码修复与本地验证，不是已发布或已完成生产验收。
