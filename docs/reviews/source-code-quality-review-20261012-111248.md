# listener_process 归属正确性与局部工程质量评估

评审日期：2026-10-12。结论适用于本地 Agent 0.3.94 工作区，不能代替线上主机版本核验。此次进行源码分析与隔离测试，未修改实现、提交或部署。

## 1. 已核实问题

### F-01：监听发现的 procfs 兜底读取了错误的 inode 列

- 严重程度：高。没有 netstat 或 netstat 缺少 PID 时，会漏掉实际监听服务，后续进程树无法建立。
- 关联维度：SQ-15；同一错误列定位出现在两个解析入口，修复必须同步。
- 定位：[listeners.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/listeners.go) 第 442、503 行，分别位于 `findPIDByListenAddressPort` 和 `parseProcNetListeners`。
- 证据：E-02、E-09。两处均使用 `fields[len(fields)-2]` 取 inode。Linux 标准 TCP 表中 inode 是第 10 个空白分隔字段，即 `fields[9]`，后面还跟随其他统计字段，不能从末尾倒数。标准格式的 IPv4/IPv6 LISTEN 行均复现已知 inode/PID 无法解析。
- 影响与反证：netstat 直接给出有效 PID 的常见路径不受此错误影响；因此已有 mock 发现源测试通过，不能证明真实 procfs 文本兜底正确。也不能据此认定某台线上主机一定命中了兜底。
- 来源：既有。相关实现与评审基线 HEAD 相同。
- 建议及验证：提取一个固定字段解析函数供两个入口共用；验证 IPv4/IPv6、尾部字段长度变化、空/截断行、非 LISTEN、loopback、inode 不可解析以及同一 socket 多个持有者。先修复解析，再讨论替换发现技术。

### F-02：相同可执行文件的独立服务会被播种到同一个监听根

- 严重程度：高。错误的归属能获得非空标签，继续通过输出过滤；可能污染服务基线和风险统计。
- 关联维度：SQ-15、SQ-16。Java 匹配兜底已经要求实际后代，但初始化仍把相同 exe 视为相同服务，维护一个入口不能覆盖整个契约。
- 定位：[monitor_pid.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid.go) 第 67、80、269 行；[monitor_bootstrap.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_bootstrap.go) 第 179、200 行。
- 证据：E-03、E-09。`findMonitorSeedPIDs` 对大部分带 MonitorExe 的根调用全主机 `findRootPIDsByExe`，未限定当前监听实例。两个独立 Java 根共用同一 exe、分别监听 8080/9090，仅初始化 A，即把 B 的事件归为 A/8080。
- 影响与反证：需要多个实例共用 exe 的条件；不能把仅安装一个实例的成功测试推广为多实例正确。后代扩展开关不能纠正初始种子已经混入其他实例的问题。并发 bootstrap 和后续扫描还可能覆盖已有归属。
- 来源：既有。相关初始化与种子选择代码与 HEAD 相同。
- 建议及验证：监听根身份使用 PID 与启动时间，种子限于实际监听持有者和可证明的同一服务进程家族。Nginx 共享监听 socket 可以保留专门处理，但不能扫描全主机相同 exe 后合并。验证双 Java、双 Nginx、相同运行时不同容器、重启及扫描顺序反转。

### F-03：exe 兜底可绕过根进程生命周期和父子关系校验

- 严重程度：高。服务根已退出或 PID 被复用时，仍可填入旧服务名。
- 关联维度：SQ-15。缓存命中执行生命周期校验，而非 Java 的 ExeOnly 和 companion exe 命中直接返回 owner，同一身份规则存在不同入口。
- 定位：[monitor_pid.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid.go) 第 193–225 行；[attribution.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/attribution.go) 第 65、138 行。
- 证据：E-04、E-09。构造未缓存的新 PID，根启动时间已由 100 变为 300；`audit_pid` 和 eBPF 辅助 audit 两种路径，各自的普通 exe 与 companion exe 命中仍返回旧 Nginx owner。对返回标签调用统一输出函数，实际产生输出。
- 影响与反证：已缓存的旧子进程命中 quarantine 时可以正确拒绝。本问题针对未命中该保护而落入 exe 兜底的事件；不能概括为所有生命周期校验均无效。
- 来源：既有。相关兜底实现与 HEAD 相同；本地 0.3.94 新增的空标签输出门禁不能拦截这里产生的非空错误标签。
- 建议及验证：让所有 owner 返回路径通过共同的身份判定，exe 只负责选候选或扩大采集范围，不能单独证明归属。验证根退出、PID 复用、无关同 exe 进程，以及当前有效的真实后代。

### F-04：Web 关联后端的自动推断过宽，可能把查询命令或其他应用归给网关

- 严重程度：高。字段看起来完整，但并没有足够证据证明事件属于该监听服务。
- 关联维度：SQ-15、SQ-16。显式生命周期缓存和启发式网关回退具有不同的证据标准，定位错误标签需追踪两条路径。
- 定位：[companion.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/companion.go) 第 87、101、226、358、383、436 行。
- 证据：E-05、E-09。命令行任意位置包含关键词即可匹配；隔离测试中 `pgrep -fl unicorn.* worker` 被判断为 Unicorn backend。静态调用链继续显示：关联发现按全主机 backend PID 扫描；祖先搜索命中 backend 后，`preferredWebGatewayLocked` 优先返回第一个 0.0.0.0 网关，否则返回第一个网关，不要求真实代理关联。exe 索引也只有一份 gateway 映射。
- 影响与反证：支持 Nginx 与 PHP 等非父子关系后端是合理需求；问题在于默认猜测具体归属。命令误识别已实际复现，多网关误绑定为调用链核实的条件风险，未连接生产验证其发生率。
- 来源：既有。companion.go 与 HEAD 相同。
- 建议及验证：命令判定基于实际 executable/入口参数结构，不能全字符串包含即认定；关联要求明确配置或可验证的服务范围/代理关系。容器或 cgroup 可限制候选，但也不单独证明代理关系。多候选无法消歧时保持未知并拒绝输出。验证 pgrep/grep/shell 查询、多个网关、多个 PHP/Ruby/Python 应用和明确关联的正例。

### F-05：audit_pid 会丢失已经收到 fork 证据的短命后代归属

- 严重程度：高。合法监听服务子进程可能因读取时已经退出而无法归属；在当前输出门禁下，该事件被丢弃。
- 关联维度：SQ-15、SQ-16。历史事件身份与当前规则安装共用生命周期路径，两个后端对相同 fork 证据的处理不一致。
- 定位：[monitor_pid.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_pid.go) 第 135、228 行；[monitor_worker.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_worker.go) 第 101 行。
- 证据：E-06、E-09。输入有效的 `listener → sh → pgrep` 两条成功 clone 记录与随后的 exec，根仍存活、记录时间在 5 秒内，但两个后代的 /proc 已消失。`audit` 保留归属，`audit_pid` 返回 unknown。后者登记链路走异步规则扩展，入口会拒绝已经退出的 PID；只有 bounded audit 分支登记源 clone 时间。
- 影响与反证：不应为退出的 PID 安装规则，这个约束正确；缺陷是把“不需要装规则”等同于“不保存已经观察到的历史父子证据”。未收到 fork、超过可信时间窗或存在 PID 复用冲突时，仍应拒绝归属。
- 来源：既有。跟踪/规则队列代码与 HEAD 相同；0.3.94 丢弃未知事件使该缺口表现为漏报。现有 process-attribution 文档的短命关联描述也需要在修复时明确各后端支持条件。
- 建议及验证：历史事件归属账本与存活 PID 的规则安装账本分离；收到成功 fork 后立即登记有界的源时间与根身份。共享严格时间窗和冲突处理，不放宽为“只看 PPID”。验证多级短命链、乱序/重复旧日志、超时、队列满、根退出及 PID 复用。

### F-06：eBPF 事件只携带根 PID，旧事件可能被归给同 PID 的新根

- 严重程度：中。需要根 PID 复用、旧事件延迟到达且旧子/父缓存缺失的组合条件，但一旦发生会给出确定的错误标签。
- 关联维度：SQ-15、SQ-16。用户态保存根启动时间，事件传输契约却不能独立表达事件所属的那一代根。
- 定位：[monitor_ebpf.go](../../src/tools/secweaver-agent/pkg/auditportexecmon/monitor_ebpf.go) 第 9、112 行；[tracker.go](../../src/tools/secweaver-agent/pkg/processtracker/tracker.go) 第 20–40 行。
- 证据：E-07、E-09。RootPID 是数字 PID，没有根 generation 字段；子进程 StartBootNS 不能直接代替根身份。旧父子缓存不存在时，代码回退到当前根记录。隔离输入一个旧事件和已更换的根，返回新根 `replacement` 且 AttributionUnknown 为 false。
- 影响与反证：旧父/子缓存仍存在时，现有优先检查可以识别旧根代际；不能忽略此保护。此次复现用户态决策缺口，未在 Linux 内核中实际诱发 PID 复用或 ring-buffer 延迟。
- 来源：既有。monitor_ebpf.go 相比 HEAD 只有输出策略注释变动，相关决策逻辑相同；tracker.go 相同。
- 建议及验证：内核根映射与事件携带稳定的根代际 token，并在用户态核对；统一时钟/单位与兼容策略。不能仅因当前同数字 PID 的根还活着，就认为历史事件属于它。补充缓存缺失、旧新事件交错、根重启、清理与事件消费竞态测试。

## 2. 对象与范围

| 字段 | 内容 |
| --- | --- |
| 项目、评审日期 | SecWeaver Community，2026-10-12，Asia/Shanghai |
| 评估模式与范围 | 局部源码归属正确性评估；工程维度只评 SQ-14、SQ-15、SQ-16 |
| 评审前快照与比较基线 | 2026-10-12 11:03:49 CST；HEAD `428557704fbcd58ed20dc71e0310e25d58b900e0`；Agent VERSION 0.3.94；详见 E-01 |
| 评审前已有改动 | 含上一轮无归属事件不输出的实现、测试和双语文档；既有未跟踪 listener_output_test.go 已纳入快照；不是本轮评审新增 |
| 用途与约束 | 用户要求从真实 listener_process 开始监控，无可信归属的事件不记录、不上传；不能用猜测标签掩盖空字段 |
| 已检查与排除 | 监听发现、根播种、audit/audit_pid/eBPF 归属和输出门禁；未全面检查 Agent、Skills、SaaS、安装器或 Windows 采集 |
| 本轮评审输出 | 本报告；临时目录中的 Go overlay 用例、快照、日志及正常 Go 工具缓存；不作为工程质量正证据 |
| 材料变化与重核 | 最终核验通过：64 个范围内源文件及 VERSION 哈希、Agent tracked diff 和 HEAD 均与审前一致；日志见同一临时目录 verification.log |
| 扩展/维护场景及依据 | 多 Java/Nginx 实例、容器独立网络命名空间、短命 shell、服务重启和延迟消费，来自当前实现分支与用户线上问题；并未断言线上已出现所有场景 |
| 方法版本 | source-code-quality-review 1.4；SOURCE-QUALITY-2.1 |

### 当前识别流程

1. `netstat -tlnp` 发现当前网络命名空间的对外 TCP LISTEN，排除 loopback、白名单端口和端口过滤器不匹配项；失败或信息不完整时回退 `/proc/net/tcp{,6}` 与 `/proc/<pid>/fd` 的 inode 关联。
2. 监听项携带 PID、进程名、地址、端口；进程名优先来自 netstat，之后尝试 comm/可执行文件名。初始化绑定根启动时间；Nginx/Java 等还会启用 exe 相关策略。
3. 初始化进程树，维护 PID 到监听根的映射。后续 audit clone/fork 或 eBPF 生命周期事件扩展后代，周期扫描修复变化；默认监听重扫间隔为 5 分钟。
4. 事件先检查缓存中的 PID/根启动时间和父子关系；部分路径再走 exe 或 companion 网关兜底，问题主要集中于这些入口与初始化的不同证据标准。
5. 当前本地 0.3.94 在原始序列化、学习队列和降级输出前拒绝空 listener_process 或 unknown attribution。该门禁能阻止空/未知标签，但不能证明上游填入的非空标签正确。

`listener_process` 是归属服务上下文，不是执行命令的进程名，也不是事件的直接父进程；`ppid` 才表示直接父 PID。必须把“真实进程树归属”和“配置确认的网关关联”区分清楚。

### 覆盖记录

| 路径/业务流程 | 选择依据与关联维度 | 文件与调用/依赖边界 | 检查深度 | 正常、失败及边界分支 | 未覆盖内容与评分限制 |
| --- | --- | --- | --- | --- | --- |
| TCP 监听发现 | 无根即无后续归属；SQ-14/15 | listeners.go → netstat/procfs.go → inode/PID | 源码、标准格式核对、解析函数实际执行 | netstat 可用/缺 PID、IPv4/IPv6、procfs 尾部字段 | 未在目标 Linux 上做 FD 全扫描 |
| 监听根播种 | 多实例隔离；SQ-14/15/16 | monitor_bootstrap.go → monitor_pid.go → procfs 缓存 | 调用链与受控状态测试 | 两个同 exe 的 Java 根、重复 owner 登记 | 未量化所有容器/共享 socket 拓扑 |
| audit 归属 | 生命周期与输出契约；SQ-14/15/16 | attribution.go → monitor_pid.go → monitor_worker.go → audit_event.go/learning.go | 源码、隔离执行、已有包测试 | 有效根、PID 复用、exe 兜底、成功 fork 后已退出 | 未接入真实 auditd，不评估内核审计丢包率 |
| companion 关联 | 非父子后端的错误归属；SQ-14/15/16 | companion.go → command/exe/proc ancestor → gateway | 命令分类实际执行、关联调用链 | 查询命令关键词、多 gateway 的选择规则 | 多 gateway 实机关系仅为条件推断 |
| eBPF 用户态 owner | 根身份传递；SQ-14/15/16 | processtracker.Event → monitor_ebpf.go → output | 事件契约和用户态隔离测试 | 旧根缓存存在/缺失、复用根 PID | macOS 未挂载 Linux eBPF；生成对象未全面复审 |
| 运维可观测性 | 如何诊断空标签与丢弃；SQ-16 | metrics.go、status.go、输出门禁 | 局部源码检查 | parser/learning 计数与归属失败原因的区别 | 不评价整个监控系统或在线仪表盘 |

## 3. 八维评分

分数是局部工程属性的 1–5 级判断，不是归属准确率，不取平均分，也不构成发布结论。

| 编号 | 维度 | 分数 | 状态 | 对应锚点与评分理由 | 正证据 | 反证/核实缺口 | 充分度与限制 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SQ-11 | 文档完整性与一致性 | null | 未知 | 未系统检查此维度 | 不适用 | 局部读到的归属说明不能代表文档全貌 | 本次未评分 |
| SQ-04 | 代码清晰度与可读性 | null | 未知 | 未系统检查此维度 | 不适用 | 未按模块全面评估命名和复杂度 | 本次未评分 |
| SQ-12 | 架构合理性 | null | 未知 | 未开展整体架构评估 | 不适用 | 缺少全部运行约束和系统边界核查 | 本次未评分 |
| SQ-03 | 模块划分、内聚与耦合 | null | 未知 | 不因本次跨文件追踪自动评价整体模块设计 | 不适用 | 未检查整个 Agent 的责任边界 | 本次未评分 |
| SQ-13 | 扩展性 | null | 未知 | 本次以既有行为正确性为主 | 不适用 | 未演练新 backend/新平台接入 | 本次未评分 |
| SQ-14 | 可测试性 | 2 | 已评估 | 纯解析、事件输入和启动时间可替换；但关键多实例播种场景仍需改写包内 procfs 全局缓存，不能只通过实例级依赖构造，符合局部可隔离但关键全局边界不足的锚点 | E-02、E-08、E-09 | E-03 的夹具需锁定、备份并恢复 pidsByExeCache/ppidMapCache；共享函数替身只能受控串行运行 | 中等；到 3 需让关键 discovery/identity 快照按实例可控，不以“现有测试通过”代替结构证据 |
| SQ-15 | 复用与一致性 | 2 | 已评估 | 已有共同生命周期检查和输出入口，但播种、exe、companion、eBPF 与 fork 账本仍以不同证据返回同一 owner 契约 | E-08 | F-02/03/04/05/06；F-01 有两个同类解析入口 | 高，限归属链；到 3 需统一必要身份规则并保留有依据的后端差异 |
| SQ-16 | 变更与维护成本 | 3 | 已评估 | 本次能够定位每个问题的责任文件、调用者和对应回归输入；无需修改无关项目，但定位“空/错误标签”还需重建多个缓存和回退分支 | E-02 至 E-09 | F-02 至 F-06；E-10 缺少归属原因计数，未到故障原因可直接追踪的 4 分 | 中等；没有维护工时历史，不能预测修复成本；本报告本身不作为正证据 |

## 4. 总体判断

总体结论：**基本可维护但有局部风险**。

监听发现、进程跟踪和输出已有明确函数与可定位的依赖边界，也有启动时间校验、短期 clone 证据和统一输出门禁。主要问题在于“可采集”与“可证明归属”没有在所有路径保持一致：exe 和后端关键词可以扩大候选，却不应直接成为服务身份。

业务正确性结论比工程结构判断更严格：**目前不能认为 listener_process 已经识别准确；仅丢弃空标签不足以完成用户目标。** 六类边界用例揭示实际缺口，其中既有误归属，也有漏归属。应在修复后以多实例、短命链、重启和容器场景重新验收。

对于 172.16.144.45 的具体日志，此次没有重新查询 SLS 或登录该机，不能从代码缺口直接认定它的唯一根因。还需要对应事件时段的部署版本、backend、监听快照和 fork/exec 记录。历史已有日志也不会因为本地代码更新而被重写。

产物与个人贡献：本报告只评价工程产物，不据此判断个人提出、理解或驾驭相关实现的能力。

## 5. 证据登记

以下源文件行号均针对 E-01 工作区。原始执行材料保存在本机 `/tmp/secweaver-listener-review-20261012-110349/`，临时目录可能被系统清理。

| 证据 ID | 版本与定位 | 类型 | 可核对事实 | 限制 |
| --- | --- | --- | --- | --- |
| E-01 | snapshot.json、tracked.diff、untracked/；HEAD 428557704fbcd58ed20dc71e0310e25d58b900e0；VERSION 0.3.94 | 直接事实 | 记录审前源码 SHA-256、Agent diff、未跟踪测试；diff SHA-256 为 e61c5823dd1b97c05b5bc1bdc763a6515b1698b6d88ff7103318e9af674a6f86 | 脏工作区，不能等同于已发布二进制 |
| E-02 | listeners.go:414、442、471、503；probes.log 的 TestReviewProcNetListenerUsesInodeColumn | 直接事实 | 两处倒数取 inode；IPv4/IPv6 标准行解析为零监听项 | 使用临时文本文件和已知 inode/PID 映射 |
| E-03 | monitor_pid.go:67、80、269；monitor_bootstrap.go:179；TestReviewSharedExecutableSeedsOnlyActualRoot | 直接事实 | 相同 exe 的独立 Java 根 B 被标为 A/8080 | 合成 PID/启动时间和受控 procfs 缓存，不修改真实进程 |
| E-04 | monitor_pid.go:193–225；TestReviewExecutableFallbackRejectsExpiredRoot | 直接事实 | audit_pid/eBPF 辅助 audit 的两种 exe 入口均返回过期 owner；输出 emitted=true | 与原生 eBPF exec 事件入口不同 |
| E-05 | companion.go:87、101、226、358、383、436；TestReviewCompanionCommandIsNotService | 直接事实及条件推断 | pgrep 误识别实测；首个网关回退和单一 exe→gateway 映射由源码核实 | 未测线上多网关误归属频率 |
| E-06 | monitor_pid.go:135、228；monitor_worker.go:101；TestReviewShortLivedGrandchildKeepsObservedForkChain | 直接事实 | 相同有效 fork/exec 输入在 audit 通过、audit_pid 失去归属 | 已收到审计记录，不涉及记录本身是否被内核收集 |
| E-07 | monitor_ebpf.go:9、112；processtracker/tracker.go:20；TestReviewDelayedEBPFRootCannotUseReplacement | 直接事实及条件推断 | 用户态给旧事件返回当前替代根；事件不含根代际 token | 内核中达到该组合条件的发生率未验证 |
| E-08 | attribution.go:23、65、138；learning.go:121；existing-tests.log | 直接事实 | 共同启动时间校验、未知隔离、输出门禁存在；原有包级 race 测试通过 | 通过不说明所有归属分支都遵守同一契约 |
| E-09 | attribution_probe_test.go、overlay.json、probes.log | 直接事实 | 六个顶层边界测试组均触发缺口，audit 短命链正例通过；仅替换依赖/输入，不改受测业务实现 | 本地临时复现，不是已合入的永久回归保护 |
| E-10 | metrics.go:7；types.go:99；listeners.go:185；procfs.go:283 | 直接事实 | parser 有事件/累加器计数；监听默认 5 分钟重扫；只读取当前 netns TCP 表；inode 仅保留首个 PID | 局部可观测性和发现覆盖检查，不代表系统无其他监控 |
| E-11 | [Linux 内核 proc_net_tcp 文档](https://docs.kernel.org/networking/proc_net_tcp.html) | 官方格式说明 | 表示 inode 所在字段，后面还有 TCP 统计字段；支持 F-01 的列定位判断 | 格式依据，不是目标主机现场抓取 |

## 6. 实际检查与未验证项

环境：Go 1.26.5，darwin/arm64；Agent 根目录下执行 Go 命令。测试未调用 auditctl、修改主机规则、发送告警或访问生产凭证。

| 检查 | 版本、规则/配置及环境 | 命令与原始结果定位 | 状态 | 范围与限制 |
| --- | --- | --- | --- | --- |
| 原有归属包测试与 race | E-01 本地工作区 | `go test -race ./pkg/auditportexecmon -count=1`；existing-tests.log | 通过，退出 0；3.342 秒 | 包级受控测试，不是 Linux 内核实机验证 |
| 补充边界复现 | 同一工作区，Go overlay 注入临时测试 | `go test -overlay /tmp/secweaver-listener-review-20261012-110349/overlay.json ./pkg/auditportexecmon -run '^TestReview' -count=1 -v`；probes.log | 失败，退出 1；6 个顶层组揭示缺口，audit 短命链子用例通过 | 断言表达应有契约，失败即复现；没有修改源码使测试通过 |
| 比较既有/新增实现 | 对比 HEAD 与当前 dirty tree | `git diff HEAD --` 后接本报告所列实现文件 | 已核对 | F-01 至 F-06 的问题实现属于既有代码；当前输出行为使用上一轮改动 |
| 文档检查及报告完整性 | 新增本报告 | `make docs-check`、报告七章节/八维/引用检查；docs-check.log、verification.log | 通过，退出 0；链接与公开命令检查均为 0 issue，报告结构检查通过 | 不重新执行无关构建与发布测试 |
| 线上主机与 SLS | 172.16.144.45 等现场 | 未执行 | 未运行 | 无线上发生率与单事件根因断言 |
| Linux eBPF/audit 实机 | 各实际 kernel/backend 组合 | 未执行 | 未运行 | 后续修复需专门灰度验收 |

候选问题与证据缺口：

- 当前发现源只覆盖自身网络命名空间的 TCP LISTEN。独立容器 netns 中的监听进程可能不在发现表内，宿主机 proxy/NAT 也不代表应用的父子树；需要分别验证 host-network、bridge 和多容器部署。建议按唯一 netns 有界扫描，避免每个 PID 重复扫描。
- inode 映射只保留首个持有者；继承监听 FD 的多 worker、SO_REUSEPORT、多端口同 PID 如何选择“服务根”需建立明确语义和 fixture，不应用全主机同 exe 合并代替。
- 发现阶段可以填入字符串 `unknown`，而输出门禁检查的是非空名称和 AttributionStatus。占位名称能否到达最终输出，需要增加实际 discovery→输出的用例；本报告未把这个候选计入六个已复现问题。
- 当前 parser/learning 状态不足以解释“没有监听根”“身份过期”“关联歧义”等归属失败原因。建议增加有界聚合计数，不记录或上传被拒绝事件的原始详情。对用户界面不要把归属丢弃混作学习过滤成功。
- 本地 process-attribution 文档对“已确认归属”的描述强于上述边界实际行为；后续修复必须同步中英文说明和各后端限制。

专项边界：进行了指定归属业务规则的受控正确性检查与原有 race 测试；未开展全仓安全扫描、吞吐性能评测、生产查询或部署验证。本报告不是发布批准。

## 7. 优先改进

| 优先级 | 关联问题/维度 | 最小建议及取舍 | 怎样验证改善 |
| --- | --- | --- | --- |
| P1 | F-01、SQ-15 | 统一 procfs 行解析，修正 inode 列；无需为此全面替换发现机制 | IPv4/IPv6 标准行、缺 netstat、缺 PID、尾部字段差异测试与 Linux 实机对照 |
| P1 | F-02/03、SQ-15/16 | 按真实根身份播种；让所有 owner 入口满足根代际和范围校验；保留必要采集规则优化 | 双 Java/Nginx 同 exe、根退出/复用、无关进程、重扫顺序变化仍精确隔离 |
| P1 | F-04、SQ-15/16 | 去除任意命令关键词与首个网关的确定性归属；只接受明确关系 | pgrep 查询不成为 backend；多网关和多个后端服务可消歧，歧义事件无输出 |
| P1 | F-05、SQ-14/15/16 | fork 历史身份登记与 auditctl 规则安装分离，统一各 backend 的可信短期关联 | 已退出多级后代可凭有效证据归属；无证据/超时/冲突仍拒绝 |
| P2 | F-06、SQ-15/16 | 根代际 token 贯通 eBPF 映射、事件、用户态缓存；升级时处理契约兼容 | 原父子缓存清空后，旧事件也不能归给新根；Linux 上验证生命周期竞态 |
| P2 | SQ-14/16、发现覆盖候选 | 提供实例级可控 procfs 快照、聚合归属原因计数，再针对容器 netns 补覆盖 | 测试不改写共享缓存；可观察正确归属/明确拒绝的数量，无拒绝事件原始输出 |

验收底线：真实后代应有证据地归属；运行时兄弟进程、相同 exe 的其他服务和不明确的代理后端不能被填入猜测标签。无可信归属时继续不记录、不上传，不能为了降低空名单比例放松证据要求。
