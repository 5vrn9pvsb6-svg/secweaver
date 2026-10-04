# SecWeaver Agent 升级模块与架构

**文档状态：** 本轮设计已实施；测试通过，未包含打包、生产迁移和部署。  
**内容版本：** `upgrade-architecture-r2`，2026-10-04；依赖需求 `upgrade-requirements-r2` 第 8 节。  
**对应需求：** [升级功能需求](agent-upgrade-requirements.zh-CN.md)  
**设计原则：** 服务端决定“谁可以升级”，客户端决定“如何安全地安装并恢复”。

本文区分模块归属、协议边界和已实施行为。第 11 节记录本轮实现；生产发布前仍需按发布门禁验证。

## 1. 系统边界

```text
企业工作台
    | 租户自动升级许可
    v
Agent Server / Agent Gateway
    | 心跳响应：活动、灰度资格、租约、维护窗口
    v
secweaver-agent
    | 清单/公钥/物料 HTTPS
    v
发布服务器或私有升级源

secweaver-agent -> systemd (Linux) / Windows SCM (Windows)
secweaver-agent -> 本地状态、备份、JSONL 健康与升级日志
```

### 1.1 内外部边界

| 边界 | 归属 | 关键约束 |
|---|---|---|
| 租户自动升级许可 | Agent Server 数据库和企业工作台 | 默认关闭；只有 Owner/Admin 可改；每次变化写变更审计；客户端不能伪造 |
| 活动/灰度/租约 | Agent Server `controlplane` | 心跳事务内决定资格，单租户更新锁保证一致性 |
| 清单和物料 | 发布系统/升级源 | HTTPS、代次、SHA-256、Ed25519；私钥不下发 |
| 安装事务 | Agent `pkg/agentupdate` | 锁、备份、原子替换、恢复标记由一个模块拥有 |
| 进程生命周期 | systemd/SCM 适配层 | 只负责停止、启动和平台文件占用，不解释策略 |
| 健康结果 | Agent 运行时 + Agent Server 心跳 | 客户端产生证据，服务端记录活动结果和熔断状态 |

## 2. 模块职责与依赖

### 2.1 Agent 模块

| 模块/代码归属 | 负责 | 不负责 | 允许依赖 |
|---|---|---|---|
| `agent_config.go` | 解析 `update` 配置、默认值和合法性 | 不决定租户是否授权 | `pkg/agentupdate`、配置类型 |
| `scheduled_update.go` | 定时循环、初始 jitter、策略门控、下载 spread 等待、退避、健康监视触发 | 不解析数据库、不直接修改租户策略 | `pkg/agentlicense`、`pkg/agentupdate`、metrics |
| `controlplane.go` | 注册、心跳、授权状态、策略通道、网络退避 | 不替换二进制 | `pkg/agentlicense`、调度器回调 |
| `pkg/agentlicense` | 设备身份、设备密钥、心跳响应和 `UpdatePolicy` 映射 | 不执行升级文件操作 | HTTPS 传输、受保护身份状态 |
| `pkg/agentupdate/manifest.go` | 严格解析清单、签名、代次、平台物料和回退指令 | 不决定租户资格 | trust/version/transport |
| `pkg/agentupdate/trust.go` | 公钥信任集合、轮换和撤销 | 不保存私钥 | 本地受保护状态目录 |
| `pkg/agentupdate/transport.go` | HTTPS/本地清单读取、流式物料下载、CA 和超时 | 不做安装策略 | `context.Context`、文件系统 |
| `pkg/agentupdate/update.go` | Check、Install、Rollback、健康观察、状态 JSON、升级锁和备份 | 不调用 Agent Server 策略数据库 | 平台替换适配、layout、output |
| `pkg/agentupdate/atomic_replace_*` | Unix/Windows 原子替换差异 | 不改变状态机 | OS API |
| `pkg/agentupdate/replace_helper_*` | Windows SCM 退出后替换和重启；Linux 启动恢复辅助 | 不判断灰度/签名 | SCM/systemd、状态目录 |
| `metrics` 和 operations health | 升级状态指标、健康 JSONL、诊断快照 | 不作为升级授权源 | 状态只读投影 |
| `packaging/`、`examples/update-server/` | 生成安装包、清单和部署样例 | 不在运行时决定版本 | 发布工具链 |

依赖方向固定为：配置/调度 -> 协议与升级包；协议不反向调用安装器；安装器不反向读取服务端数据库；平台适配只被升级事务调用。采集模块不依赖 `pkg/agentupdate`。

### 2.2 服务端模块

| 模块/代码归属 | 负责 |
|---|---|
| Agent Server `controlplane/updates.go` | 活动策略校验、成员快照、灰度桶、维护窗口、并发租约、失败熔断、暂停/恢复和结果协调 |
| Agent Server `controlplane/store.go` / heartbeat handler | 在设备心跳事务内读取租户许可、记录升级状态并返回策略；向后兼容受支持旧 Agent 的请求与响应 |
| Agent Server migrations | 保存租户自动升级开关、活动、成员、租约和结果所需的 schema |
| SaaS Server 企业工作台 | Owner/Admin 修改租户许可及本租户灰度/并发/维护窗口/熔断参数，写变更审计；不直接替换设备 |
| CI | 构建、测试、生成 provenance 和待签名物料；不要求长期保存发布私钥 |
| 发布运维 + `cmd/update-sign` | 在受控环境保管私钥，签名 manifest/物料摘要，执行轮换、撤销和全局签名停更；记录发布操作 |
| 发布系统/Operator | 发布已签名物料、公钥、URL 和版本目录；不读取或导出私钥 |

采用现有本地签名工具，不建设独立签名服务/KMS。受控签名环境是运维操作环境，不新增常驻服务或网络签名接口。

服务端是授权唯一归属。客户端只消费 `UpdatePolicy`，不能通过本地配置覆盖服务端返回的显式拒绝。租户管理员的暂停/关闭是租户级控制；全局签名停更由发布运维使用当前可信私钥生成停更清单，企业工作台不能接触私钥或伪造签名。

### 2.3 简化签名与密钥操作

以下流程复用现有签名命令，无新服务依赖；流程细节随本架构整体待确认：

1. CI 构建并验证不可变版本的各平台物料及来源记录；发布运维确认目标版本和摘要。
2. 私钥存放在受控发布主机或工作站，以 `0600`/等效 ACL 限制读取，离线加密备份；不存放在 Git、公共下载目录、Operator 包或客户主机。
3. 发布运维用现有 `cmd/update-sign` 签名物料和清单，再用公钥执行 `-verify` 验证；发布目录仅包含已签名物料、清单和必要公钥，不包含私钥。
4. 正常轮换使用 `-add-public-key-file` 先加入新 key，确认适用设备已建立信任后，后续清单用新 key 签名并通过 `-revoke-key-id` 撤销旧 key。不识别轮换的历史 Agent 和离线主机采用人工更新信任路径。
5. 紧急停更先暂停服务端相关升级活动，拒发新租约；发布运维可用当前可信私钥和 `-emergency-stop-reason` 发布递增代次的签名停更清单。清单只对支持该能力的 Agent 生效，不能替代旧 Agent 的服务端禁用契约，也不强行中止已经提交的本地事务。
6. 记录版本、摘要、key ID、操作人、时间、原因及结果，不记录私钥内容。私钥丢失先从备份恢复；无法恢复时停止签名发布并人工迁移客户端信任，不用新私钥覆盖旧签名身份。

## 3. 关键契约

### 3.1 Agent 配置到运行时

`updateConfig` 映射到 `scheduledUpdateConfig` 和 `agentupdate.Options`。`enabled=false` 不启动调度；`auto_install=false` 只允许检查；`require_server_policy=true` 要求设备身份、心跳和有效服务端策略。当前生产模板默认：6 小时检查、60 秒首次延迟、300 秒 jitter、1 分钟到 1 小时退避、90 秒健康观察、1 小时陈旧锁回收、3 份备份、256 MiB 磁盘余量。

### 3.2 Agent Server -> Agent

策略字段包括：

- 身份和版本：`campaign_id`、`policy_revision`、`target_version`、`channel`、`manifest_url`；
- 授权和资格：`enabled`、`auto_update_allowed`、`eligible`、`paused`、`reason`；
- 租约和资源：`lease_granted`、`lease_expires_at`、`active_update_leases`、`concurrent_capacity`；
- 灰度和窗口：`rollout_bucket`、`rollout_percentage`、维护时区/日期/起止时间；
- 风险控制：失败阈值、最小样本、`allow_downgrade` 和 `rollback_reason`。

客户端处理顺序必须是：租户许可 -> 活动存在 -> 暂停/维护窗口 -> 灰度资格 -> 自动安装开关 -> 目标版本 -> 租约和租约安全余量 -> manifest URL/通道绑定。任何一步失败都只能产生 `policy_deferred`。企业工作台配置的灰度、并发、窗口和熔断参数由服务端校验并固化到活动策略，客户端不重新解释租户参数。

### 3.3 Signed manifest

```json
{
  "key_id": "ed25519-...",
  "payload": "base64(manifest-json)",
  "signature": "base64(ed25519(payload))"
}
```

payload 的清单包含 `schema_version`、`app`、`channel`、`generated_at/generation`、`expires_at`、`latest`、按平台的 `binaries`，以及 standalone 使用的 `rollout`。受管模式中服务端已经决定资格，`download_spread_seconds` 只负责削峰。

清单接受顺序：读取 -> 解析 envelope -> 选择可信 key -> 验签 -> 严格解析 payload -> 校验代次/摘要/过期 -> 校验目标版本、平台和 URL -> 校验物料大小/SHA-256/二进制签名 -> 才能进入安装事务。

### 3.4 本地恢复状态

`pkg/agentupdate` 的 `state.json` 是恢复权威，字段包括：

| 字段组 | 作用 |
|---|---|
| 版本 | `current_version`、`previous_version`、`target_version`、`latest_version` |
| 事务 | `attempt_id`、`campaign_id`、`policy_revision`、`phase` |
| 证据 | `manifest_generation`、`manifest_digest`、`last_check_at`、`last_update_at` |
| 恢复 | `previous_binary`、`pending_binary`、`health_pending`、健康起止时间 |
| 失败 | `last_update_status`、`last_error`、`failure_class`、`retryable`、`next_retry_at` |

状态写入失败时不得清理唯一备份或恢复标记；下一次启动必须先处理未完成事务，再恢复普通调度。

### 3.5 SaaS 服务端向后兼容 Agent

以下为第 3 项确认后的契约要求，不代表本轮已经补齐实现：

- **兼容归属：** Agent Server 协议入口识别受支持历史协议并规范化请求；活动/租约模块只消费规范化结果，不向旧客户端强制新增必填字段。
- **请求与响应：** 保留旧注册/心跳路径和字段语义。新增响应字段须可被兼容客户端忽略；服务端通过已验证的协议/能力生成旧客户端可以识别的控制结果，不能只凭 `agent_version` 宣称能力存在。
- **授权不降级：** 不认识 `auto_update_allowed` 的旧 Agent 在租户关闭时仍收到其已支持的禁用字段，服务端拒发租约。不具备安全升级能力时暂停受管升级，不因升级协议变化中断受支持的注册、心跳和采集。
- **结果兼容：** 老 Agent 可能缺少 `campaign_id`、`attempt_id` 或健康证据。仅在设备、租户和目标可以可靠关联时归属记录；重复上报保持幂等，缺失健康证据标记未知/未验证，不能伪造 `healthy`。
- **版本矩阵：** 每个服务端发布测试“新服务端 + 受支持旧 Agent”“新服务端 + 当前 Agent”和混合版本活动。历史协议退出是独立生命周期决策，不采用一个发布周期后强制全量客户升级。

## 4. 关键时序

### 4.1 受管检查与安装

```text
Agent scheduler
  -> current policy channel
  -> apply tenant/activity/rollout/window/lease gates
  -> fetch signed manifest
  -> validate generation/version/platform/signature
  -> wait download spread, observing policy changes
  -> acquire update lock
  -> stream artifact + size/SHA/signature checks
  -> reserve disk and back up current binary
  -> persist commit_prepared
  -> CommitGuard: lease/policy still valid
  -> atomic replace or Windows scheduled replacement
  -> persist installed_pending_health
  -> service manager restarts Agent
  -> health monitor confirms modules/output
  -> healthy, or locked rollback
```

CommitGuard 是策略取消和二进制提交之间的边界。提交前可取消；提交开始后必须完成结果记录或进入恢复流程，不能丢弃事务语义。

### 4.2 健康失败

```text
new process starts
  -> PrepareHealthCheck takes update lock
  -> target version matches state
  -> observe modules for configured timeout
  -> all healthy + business output or collector-health evidence -> MarkHealthy
  -> otherwise -> RollbackForReason
  -> Linux atomic restore / Windows scheduled restore
  -> report rolled_back or rollback_failed
```

**已确认的低流量判定，待实现/验证：** 没有业务事件时，健康观察器可以使用各启用模块的采集循环健康探测/模块心跳进展，加上成功的本地 health JSONL 写入作为替代证据。证据属于本次启动且在观察窗口内取得；观察器主动收集，不等待常规上报周期。仅有父进程或通用心跳不能证明采集模块健康；模块卡住、探测出错或本地健康写入失败仍不能通过。验收不要求云端收到日志，不产生伪造的安全事件。本轮仅定义规则，不代表当前代码已经支持该路径。

### 4.3 策略变化与停止

- 调度器通过 channel 接收新策略；活动暂停、租约即将过期或设备撤销时，在提交前取消等待/下载。
- `context.Context` 贯穿清单读取、下载和策略等待；停止服务不能留下无限网络请求。
- `managedInstallCommitGate` 保护“策略可撤销”与“提交已开始”两个状态，锁只保护本地事务，不代替服务端租约。

## 5. 并发、锁与资源边界

1. 每个设备只能有一个 Agent 升级循环；本地 `update` 锁串行化检查后的安装、健康恢复和回滚。
2. Agent Server 的单租户更新锁串行化策略、活动成员和租约决策，避免旧策略发放新租约。
3. 远程策略 channel 不拥有本地二进制；服务端断连只让客户端进入退避，不能杀死采集进程。
4. 下载使用有限临时文件、磁盘余量门槛和上下文取消；旧备份按保留数清理，但当前恢复事务引用的备份必须被 pin 住。
5. Windows 替换助手必须与服务进程退出和文件句柄释放有界协调，诊断文件按事务隔离且有限保留。
6. `license` 状态的 bbolt/文件锁与 update 状态锁职责不同：前者保护身份和授权状态，后者保护升级事务，禁止交叉持锁形成环路。

## 6. 平台架构

| 平台 | 替换方式 | 服务重启 | 特殊失败 |
|---|---|---|---|
| Linux/systemd | 同文件系统原子 rename；稳定启动器识别专用重启退出码 | systemd | 新二进制不能执行、单元启动失败、健康超时 |
| Windows/SCM | 同目录 pending 文件；服务退出后由 helper 原子替换 | Windows SCM | exe 被占用、父服务 PID 退出超时、SCM 启动失败、健康超时 |
| standalone ES | 本地/私有 HTTPS manifest 和公钥；完全离线暂时只允许人工 `update install` | 由平台服务管理器 | 不具备 SaaS 租约时不能声称有服务端灰度 |
| SLS SaaS | Agent Gateway 心跳策略和设备租约 | 平台服务管理器 | 企业开关关闭、活动暂停、租约/策略过期 |

## 7. 安全边界

- 租户权限在服务端心跳事务中判定；客户端的 `auto_install` 不是授权凭证。
- 设备私钥只用于设备认证，不用于发布清单签名；发布私钥和客户端信任公钥严格分离。
- 清单和二进制均使用 HTTPS/CA、大小、SHA-256 和签名检查；开发用 HTTP/无签名必须显式配置且不能成为生产模板。
- 状态和备份目录应仅允许 Agent 服务账户访问；日志默认不输出令牌、私钥或完整授权信息。
- 回退也必须经过本地锁、版本匹配和恢复材料检查；不能把回滚当作绕过签名的新安装路径。

## 8. 失败矩阵与可观测性

| 阶段 | 典型失败 | 结果 | 必须记录 |
|---|---|---|---|
| 策略 | 租户关闭、灰度外、暂停、无租约 | `policy_deferred` | reason、campaign、revision、lease |
| 清单 | HTTPS/CA/签名/代次/版本失败 | `failed`，不下载或不替换 | manifest URL、generation/digest、failure class |
| 下载 | 超时、状态码、大小/hash 不匹配 | `failed`，清理临时文件 | retryable、next retry、HTTP/安全原因 |
| 提交前 | 锁、磁盘、备份失败 | `failed`，运行版本不变 | state path、backup、failure class |
| 提交 | 原子替换/Windows helper 失败 | 恢复或等待下一次启动处理 | commit phase、attempt、helper 状态 |
| 健康 | 模块停止、输出停滞、版本不符 | 自动回滚 | health window、module/output evidence |
| 回滚 | 备份缺失、替换失败、SCM/systemd 失败 | `rollback_failed`，告警 | recovery path、OS error、人工动作建议 |

升级状态应同时出现在 `state.json`、升级 JSONL、health JSONL/metrics 和 Agent Server 心跳结果中；这些是不同投影，不能互相伪造成功。低流量替代证据已获允许，必须记录健康通过使用的证据类型，区分业务输出和模块健康探测，不能把通用心跳误作采集模块证据。

## 9. 测试与发布门禁

### 9.1 单元/契约测试

- 配置默认值、非法窗口、非法 URL、策略门控、旧字段兼容。
- 新 Agent Server 对旧请求缺字段、旧响应语义、未知能力、幂等状态归属和健康证据缺失的契约测试。
- 稳定灰度桶、并发租约、自动暂停、重试/Retry-After、租约安全余量。
- 清单签名、key 轮换/撤销、代次回放、平台缺失、hash/size/signature 负例。
- 状态事务、锁竞争、提交取消边界、备份保留和恢复标记。

### 9.2 系统测试

- Linux systemd：健康升级、启动失败、健康超时、人工回滚、远程授权回退。
- Windows SCM：计划替换、服务正常停止、文件句柄占用、helper 超时、启动失败和自动回滚。
- 两平台均验证零业务事件且模块健康时通过，只有父进程/通用心跳时不能通过，以及模块卡住、过期证据、探测或健康写入失败时回滚。
- SaaS：租户关闭/打开、活动暂停/恢复、灰度、维护窗口、并发上限和失败熔断。
- SaaS 混合版本：新旧 Agent 并存，服务端升级后仍能注册/心跳；租户关闭同时阻断新旧 Agent 的受管升级。
- 网络：清单源不可达、下载中断、CA 错误、断线恢复；Agent 进程不得退出。
- 私有化/离线：自定义 CA、本地 manifest、无公网和包内公钥验证。

### 9.3 发布门禁

1. Agent 源码、配置或包内容变化必须递增 immutable `VERSION` 后再打包。
2. 发布清单必须包含平台完整性信息和 provenance；私钥不能进入产物。
3. 先小比例 ring，再扩大 rollout；观察失败率、健康回滚率、租约占用、下载峰值和错误分类。
4. 生产发布前必须确认租户开关默认值、回滚备份、SaaS/ES 安装文档和 Windows/Linux 服务测试结果。

## 10. 需求映射与未决取舍

| 需求 | 主要模块 | 验证 |
|---|---|---|
| REQ-UPG-001/002/004 | Agent Server `controlplane`、`pkg/agentlicense`、`scheduled_update.go` | 策略/心跳/租约测试 |
| REQ-UPG-003/005 | `scheduled_update.go`、`pkg/agentupdate/transport.go` | jitter、退避、取消、下载 spread 测试 |
| REQ-UPG-006 | `pkg/agentupdate/manifest.go`、`trust.go` | 签名与代次负例 |
| REQ-UPG-007/008 | `pkg/agentupdate/update.go`、平台 helper | systemd/SCM 集成测试 |
| REQ-UPG-009 | status/state、metrics、health reporter、Server result recording | JSON schema/doctor/端到端检查 |
| REQ-UPG-010 | Agent Server 协议入口/heartbeat/result recording、packaging、Bootstrap | 新服务端与新旧 Agent 契约及混合版本测试；五平台/私有 CA/离线测试 |

业务选择及修复目标已记录；历史 Agent 矩阵仍需契约证据。下面的详细设计需确认后实现，不建设签名基础设施。

## 11. 本轮修复设计（已实施）

**状态：** 下列行为已写入代码、迁移、工作台和测试；不包含生产迁移/部署或密钥操作。

### 11.1 事务与独立恢复

- `pkg/agentupdate` 统一拥有恢复事务；Install、PrepareHealthCheck、MarkHealthy、Rollback 和计划失败记录使用同一状态锁，调用者不直接并发写恢复文件。
- 清单检查可锁外执行但不写 `state.json`；锁/检查失败及策略拒绝写日志或独立检查投影。安装失败只在锁内落盘，有待替换/待确认事务时拒绝新安装。
- 确认/回滚核对 attempt、目标、启动身份，旧观察器不确认/清理新事务；提交和恢复清理同属持锁生命周期。陈旧锁核对进程实例，不能仅因时间抢活锁；不确定时 fail closed。
- 调度配置与恢复配置分开。`update.enabled=false` 不启动定时调度，但存在待确认事务时仍启动本地健康确认/回滚，不要求清单 URL、网络或租户租约。
- Windows pending 放入受保护的 exe 目录以保证同卷；助手、状态和恢复材料关联同一 attempt，交接失败保留旧版本/诊断。

### 11.2 采集循环健康证据

当前实现不新增采集模块控制协议；supervisor 记录每个运行模块的 `last_health_at`，升级健康观察在“输出文件有新内容”或“模块持续运行且本地 supervisor 心跳新鲜”之间取证。

1. supervisor 在子进程成功启动后立即记录一次，并每 15 秒更新一次受状态写入器保护的 `last_health_at`。
2. 有配置输出的模块优先以输出文件在观察窗口内产生新内容作为证据；低流量模块可使用新鲜的模块生命周期心跳，不伪造安全事件。
3. 模块重启、停止、状态写入失败或证据过期会阻止确认；状态文件中保留模块健康时间，便于 doctor/运维诊断。

触点为 supervisor、modulecontrol、status、operations reporter 和各采集主循环，证据与业务日志分离；正常运行不增加永久高频全量扫描。

### 11.3 调度与取消

- 设备/活动的绝对检查、重试、下载就绪期限独立持久化，重启不重置未到期等待。
- 比较活动/revision/目标/manifest/通道/资格/暂停/窗口/租户许可/回退授权；相同策略心跳最多每 10 分钟投递一次以刷新租约，不让 3 分钟心跳重置检查和退避。
- 权限收紧、租约不足、活动改变可取消提交前工作，提交后只完成/恢复；manifest/物料用 context，CLI spread 用可取消 timer，停止/锁等待有界。
- 指数退避 1 分钟至 1 小时，但更长 Retry-After 是不得早于的服务器期限，不截短；相同心跳不提前重试。

### 11.4 兼容与活动完成

- Agent 心跳可选发送 `update_capabilities`；当前能力包括事务锁、健康证据和签名清单。旧 Agent 缺少字段仍可心跳，但达到目标版本且没有 `healthy` 证据时 Server 返回 `health_unknown`、不发租约。
- 协议适配与真实历史请求/响应 fixture 建立验证矩阵；不凭未验证声明或版本授予安全能力。未知能力只禁升级、不发租约，正常采集保持支持；v1 桥仍显式租户凭证，认证不放宽。
- 目标版本仅 `version_reached`；可靠关联设备/租户/目标/活动的幂等健康结果才成功，缺失/歧义为 `health_unknown`，不完成或捏造失败样本。
- 新增迁移替换进度/协调函数，不改已发布迁移；历史完成保留，活动内推断成功需再验证或人工结案，不强制回滚现有采集版本。

### 11.5 租户策略与审计

- SaaS 拥有 Owner/Admin UI/请求审计，Agent Server 拥有活动/租约；租户偏好通过数据库 capability 写入，前端不直接写 `proxy.update_*`。
- 工作台使用 PATCH `enterprises/{id}/agent-update-policy`，幂等键、权限、范围校验、租户锁和旧/新值审计均已接入。
- 租户设灰度/并发/窗口/熔断，不选未发布程序或改信任公钥；活动受偏好限制不静默放宽，变更取同租户锁、递增策略/撤销租约，不扩大成员快照或自动创建活动。
- **新租户默认值：** 灰度 `10%`、最多并发 `10` 台、失败率 `20%`、最小观察样本 `1`；维护窗口显式保存为全天或具体时段。
- 许可默认关闭；既有许可值不被迁移静默改写。新活动由 Agent Server 将租户策略作为安全边界应用。
- 原子审计旧/新值、租户/操作者/revision、请求/来源/原因/结果；失败请求使用请求审计，不在成功事务伪造失败。

### 11.6 安装选择与信任

- 清单不再自动开本地检查/安装；规划 Linux `--enable-auto-update`、Windows `-EnableAutoUpdate`，新安装默认关闭但保留信任材料，升级保留既有明确设置。
- 安装 UI 默认不勾选本地升级，仅勾选生成参数；租户许可不强改本地关闭，工作台显示原因与指引。
- 受管自动安装强制可信公钥和清单/物料签名，缺信任阻止启升级不停止采集；开发无签名必须显式且不用于受管生产，已有信任不降级。
- Windows 过渡包保持兼容，正式发布记录签名/发布者结果，空允许列表不声称 Authenticode 已通过；继续工具/受控私钥，不建签名服务/KMS。

### 11.7 投影与实施门禁

持锁提交事实后投影升级 JSONL、health `update`、metrics/心跳；投影失败独立诊断重试，不更改事务结果/恢复材料。doctor 显示开关、带观测时间的租户许可、等待期限、活动/attempt/阶段/证据/材料/错误，脱敏 URL。

| 阶段 | 范围 | 回归门禁 |
|---|---|---|
| A | 事务、独立恢复、Windows staging | 并发安装/确认/回滚、锁失败、中断点、关闭调度人工升级 |
| B | 健康证据、调度/取消 | 零事件、卡住/旧证据/写失败、续租、长 spread、Retry-After |
| C | 能力/活动完成、增量迁移 | 真实旧/新/混合 fixture、缺证据、租户关闭、迁移兼容 |
| D | 租户 API/UI、审计、安装选项、投影 | 权限/隔离/冲突/默认、双平台安装和 UI |
| E | 生产信任、双语文档、发布验证 | 签名负例、无私钥产物、schema/doctor、systemd/SCM |

每阶段同步注释、测试、文档，不删有效断言、不弱化健康/TLS。计划不是结果，需实现后重新验证。

### 11.8 确认边界

需求范围为 `upgrade-requirements-r2` 第 8 节；用户已确认按架构第 11 节实施，并确认默认灰度 10%、最大并发 10 台、维护窗口显式配置。实现涉及 Agent、Agent Server schema 28 和 SaaS 工作台；本轮未打包、未做生产迁移/部署。后续包使用新的不可变 Agent 版本，Server/Operator 独立版本。
