# 行为学习与日志减量

**语言：** [English](behavior-learning.md) | 简体中文（本文）

## 当前规则（0.3.85）

所有已接入白名单的事件使用同一规则：**学习阶段，同一设备、同一类型的匹配字段完全相同，
滚动一小时内出现 5 次不同源事件就入白名单；第 5 次先持久化再过滤，不必等到学习结束。**
前 4 次保留原文。入名单后持续精确匹配，不要求每小时重新累计 5 次。
默认从安装后首次成功启动采集开始累计 24 个健康小时，结束后只冻结新增名单。

| 事件 | 精确匹配字段 | 前提 |
| --- | --- | --- |
| Linux exec | listener_process、pid_name、exe、command_line | 四字段非空且有效；按实际采集字符串匹配，不要求完整 argv |
| Windows exec | listener_process、pid_name、exe、command_line | Sysmon 1 或 Security 4688 的真实完整命令 |
| Linux/Windows file_op | file_paths、listener_process、pid_name、exe、command_line | 完整路径与命令证据，详见文件事件 |
| Windows active_connect | listener_process、pid_name、exe、command_line、protocol、目标 IP、目标端口 | Sysmon 3、Initiated=true、同主机同 ProcessGuid 的 Sysmon 1 |
| Windows powershell_script_block | provider、channel、user_sid、Path、完整脚本 SHA-256 | 原生 4104，所有分片完整；原生空 Path 允许 |

Windows 的 listener_process 固定为空字符串，其余进程字段必须完整。pid_name 从 exe 提取。
匹配规范化后的上述字段，不折叠大小写或命令空白，不做通配；file_paths 的顺序也参与匹配。
Linux command_line 沿用 argv 以空格拼接的格式；拼接结果相同就视为同一字段。
从 0.3.85 起，Linux exec 不使用适配器的命令完整性或原因诊断作为候选/匹配门槛：
缺少 EXECVE、PROCTITLE 回填、截断参数及执行失败，只要上述四字段有效且源事件 ID 可确认，
均按同一规则计数。success、exit 和原因诊断不参与匹配键。
因此实际不同命令若被采集为同一个截断字符串，也会合并计数和过滤；这是按采集字段匹配的
明确取舍，不代表补齐了原始命令。需要保留此类原文时使用 shadow 或关闭学习。
Windows 网络目标取标准化事件的 dst_ip/dst_port；临时源端口、源 IP、数字 PID、
ProcessGuid、父进程、用户、文件哈希和文件动作均不加入进程/网络/文件的匹配键。
PowerShell 的用户 SID 是其自身匹配键之一，空 Path 不是任意路径通配。

不再使用旧的服务账号、镜像目录、敏感工具、私有目标/端口列表、CDXML 类列表、
3 个小时桶、跨度 6 小时、P95 频率上限、10 分钟预热、30 天闲置到期或祖先补发策略。
学习只减少输出，不改变进程树跟踪，不阻断执行；入名单不表示行为安全。
频率突增也不会自动退出已命中的名单，需要完整原始历史时使用 shadow 或关闭学习。

范围边界：认证、持久化、身份/服务变化、已识别的 high/critical 风险告警继续按原规则输出；
快照继续使用既有增量机制。Linux 网络原本没有接入这套学习，本次仍输出原文。
学习开关不安装 Sysmon、不新增 audit/Sysmon 采集规则、不改变模块严重级别筛选、
Agent 自采集排除和已有源事件范围。Windows 网络/文件需要先有对应 Sysmon 事件。

## 统一流程

1. 原采集模块先完成解析、分类和归属，再交给学习适配器。
2. 缺少必要匹配字段、无效字段或不可确认的源 ID 不训练，保留原文。Linux exec 的命令
   不完整/截断及适配器原因诊断不阻止计数；其余类型仍要求完整证据、有效关联及非历史回看。
3. 不同源事件才计数，重读同一事件不会凑够 5 次。
4. 源健康、仍在学习且尚未入名单：记录最近一小时内的接收时间。
5. 第 5 次将指纹写入持久化 journal，成功后立即过滤；写入失败保留原文并降级。
6. 已入名单且源健康：过滤并计数；shadow 则保留原文。
7. 学习结束：清空候选、冻结新增；名单外事件继续输出。空名单为 enforcing + baseline_empty，
   filtering_active=false，不因空名单本身降级。

接收时间窗口含恰好 60 分钟的边界。窗口与健康计时不同：停机/输入不健康不增加健康学习时间，
但不会暂停现实的一小时窗口。Windows 只接纳本次 reader 启动后、延迟不超过 10 分钟且
不超前超过 1 分钟的记录；这用于排除回看数据，不是入名单预热。
Security 4688 和 Sysmon 1 的原生记录分别计为源事件，不声称跨通道精确一次。

## 安装选择与状态（0.3.71）

Linux install.sh/Bootstrap 支持 --learning-mode preserve|shadow|enable|disable；
Windows 使用 -LearningMode，对应语义相同，默认 preserve。

| 选项 | 行为 |
| --- | --- |
| preserve | 新安装使用模板的默认首日学习；旧安装保留现有选择，未配置仍关闭 |
| shadow | 开启学习，所有原文保留，名单命中也不丢弃 |
| enable | 开启学习及即时匹配过滤 |
| disable | 关闭学习过滤，保留已有状态 |

保留旧的关闭配置时输出：
`behavior learning: disabled; reason=existing-config-preserved`。
这些选项不重置 generation、不修复损坏状态。升级不静默开启原本关闭的学习。

```bash
sudo secweaver-agent config set-learning-mode \
  -config /opt/secweaver-agent/etc/audit-port-execmon.json -mode enable
sudo systemctl restart secweaver-agent
sudo secweaver-agent doctor -config /opt/secweaver-agent/etc/config.json
```

Linux 标准配置：

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

未指定 event_types 时 Linux exec/file_op 参与；显式指定时只学习选择的类型。
默认摘要周期 300 秒，学习时长可设 1 小时至 7 天。
旧 min_occurrences、min_distinct_hours、min_span_seconds、baseline_idle_expiry_days
仍可解析，但不再控制任何已接入的简化策略。资源与路径参数仍有效，未知字段会拒绝学习配置，
保留普通采集并报告错误。

## Windows（0.3.39）

当前 0.3.83 代码支持 Windows amd64/arm64。统一 reader windows-eventlog-risk-json
和备用 windows-process-execmon 共用适配器，只能由一个 reader 拥有证据输出。
需已注册的 SECWEAVER_DEVICE_ID、可读的原生事件通道与完整命令。
4688 不再要求 Sysmon SHA256/父进程/服务身份；仅有 4688 的部署需保证已配置的通道
均可正常查询。配置了不可用的 Sysmon 等通道时仍按源故障停止过滤，保留原文。

在拥有证据输出的模块 args 中使用：

```text
-behavior-learning
-learning-duration 24h
-learning-generation 0
-learning-shadow=false
-learning-event-types exec,active_connect,file_op
```

新安装模板已有三种类型；省略 learning-event-types 仍为 exec-only。
learning-file-roots 保留兼容，不约束新的文件名单。
learning-state-dir、learning-output 可覆盖默认绝对路径。

文件/网络共用有界的 host+ProcessGuid 命令缓存，不查实时 PID、不启动哈希子进程：
最多 1024 项/4 MiB，空闲一小时淘汰，每分钟清理，退出/源故障/同 GUID 不同 exe 立即清理。
缓存不跨重启保存，未观察到创建的存量进程文件/网络事件保留原文。
Sysmon 3 需要运维启用源采集。入站、方向不明、无效地址/协议/端口不训练；
公网地址及 SSH/RDP 等端口不再因目标类别被排除。

## Windows 风险日志（0.3.78）

0.3.83 将普通 PowerShell 4104 改为上述统一五次规则，允许任意已知 SID、
业务脚本、普通路径和内联空 Path，不再要求 SYSTEM 或内置 CDXML 类。
完整脚本文本的空白也参与 SHA-256。PID、ScriptBlockId、记录 ID 只用于拼装/去重，
不参与名单匹配。high/critical 告警及跨分片检测到的可疑命令仍保留原文。

```text
-risk-behavior-learning
-risk-learning-duration 24h
-risk-learning-generation 0
-risk-learning-shadow=false
```

新装模板默认启用，升级保留旧选择。风险基线独立于 exec/file/network：
增加 learning-generation 不会重置它，使用 risk-learning-generation。
状态目录默认是游标目录旁的 behavior-learning-windows-risk，可用 risk-learning-state-dir 覆盖。
仅需原生 PowerShell Operational 通道，不依赖 Sysmon。

4104 分片跨查询页拼接，但不跨已提交轮询保存：
最多 64 片、完整脚本 512 KiB、64 个待拼脚本、8 MiB 组装预算。
一份完整脚本计一次，不能用五个片段凑五次。缺片、冲突、超预算保留所有可用原文，
未完成片段在游标提交前刷盘。完整脚本再次进行已有风险分类以检测跨片危险内容。

风险摘要仍写 windows-eventlog-risk-json.log，沿用 host-sys-messages/ES 风险日志路由：
asset_type=host_behavior_summary、source_stream=windows_risk、
source_event_type=powershell_script_block、count_unit=script_blocks、risk_level=info。
保留原生 event_id=4104；script_block_sha256 为完整内容摘要，
不同于每片 script_sha256。退出 suppressed 指标按片段计数。无需新增 shipper 路由。

## 文件事件（0.3.82）

Linux audit file_op 与 Windows Sysmon 11/23 使用同一五字段规则。
file_paths 是有序数组。创建/覆盖/删除/读取等动作、路径后缀及目录都不作为额外门槛；
五字段相同即可合并计数，敏感路径也适用，独立 host-persistence/风险记录不受影响。
Sysmon 11 的 create 包含创建或覆盖，不代表能观察文件内容差异。

Linux 需要完整 PATH 组，命令来自完整 EXECVE 或有效且少于 128 字节的 PROCTITLE。
达到内核上限、缺失或不完整时保留原文；PROCTITLE 是可变化的进程标题，不是不可篡改的启动参数。
Windows 用同主机同 ProcessGuid 的真实 Sysmon 1 命令补齐，listener_process 固定为空。
保留 path 并输出 file_paths、pid_name、listener_process、command_line。

## 状态、迁移与故障恢复

| 名单 | 默认状态位置 |
| --- | --- |
| Linux exec | /opt/secweaver-agent/data/behavior-learning |
| Linux file_op | 上述目录/file-operations |
| Windows exec | 游标目录/behavior-learning-windows |
| Windows file_op | 上述 Windows exec 目录/file-operations |
| Windows active_connect | 上述 Windows exec 目录/network-operations |
| Windows PowerShell | 游标目录/behavior-learning-windows-risk |

每个目录拥有自己的 key、initialized、lock、state.json、admissions.jsonl。
Linux 权限为目录 0700/文件 0600；Windows 使用 SYSTEM/Administrators ACL 和独占句柄。
名单仅保存 HMAC 指纹、次数、时间及进度，不保存命令或脚本正文。
匹配发生在输出脱敏前，避免不同口令被脱敏成同一个行为。旧状态 schema_version=1 保持可读。

0.3.85 保持 Linux exec 的策略指纹、baseline_id、名单、候选和学习进度，不自动重新学习。
升级后仍在 learning 的主机从新收到的事件开始计数，不回放旧日志补次数；已结束学习或
degraded 的主机不会因本次放宽准入而新增名单，需要按下述流程显式重新学习。
回滚旧版本保留相同状态格式，但旧代码仍会对命令证据不完整的事件输出原文。

0.3.81 的 Linux、0.3.83 的 Windows exec/PowerShell 首次迁移时：
同设备、同 generation、旧配置指纹匹配且状态完整可读，归档为 legacy-state.json，
生成新 baseline_id 重新学习，旧条目不导入。Windows reason=simple_policy_migrated；
Linux 保留 simple_exec_policy_migrated。旧网络条目随旧 exec 状态归档，
新网络目录开始独立学习。0.3.82 的文件名单保持兼容，不重置进度。
这仅发生在已启用的学习链路，不改写磁盘配置，也不会把其他设备/策略或损坏状态当新安装。

正常停止先刷原文、摘要及状态，再标记 clean；正常重启保留名单、候选和有效学习时间。
所有当前策略在获得健康输入后即可恢复匹配，没有旧的十分钟重启等待。
输入健康缺失时暂停学习/过滤；明确丢事件、队列溢出、输出/持久化失败、源连续性中断、
异常退出或时钟回退使本代 degraded，后续保留原文。Sysmon 8/25 继续触发完整性故障保护。
学习累计在线期限默认 72 小时，届时仍未达到健康学习时长则降级。

可读的降级状态：备份后增加对应 generation，重启显式重新学习。
损坏状态：先停学习并备份整个目录，排查磁盘，再在停服务维护窗口换 state_dir 重新学习。
不要手改 HMAC 状态、删除单个 state.json 或复制其他主机名单。
回滚旧版本前停服务并备份，恢复归档或关闭学习；没有逐条名单编辑或远程撤销接口。

每个引擎默认最多 10000 条名单、20000 条候选，内存/状态预算各 64 MiB；
保守字节准入预算可能先触发。源 ID HMAC 去重一小时、最多 65536 项；每个候选最多
保留 5 个时间点。容量不足输出原文且不训练。Linux 队列 128 条，单条最多 64 KiB。
Windows 同步处理后才提交游标。新增名单先 journal 持久化，60 秒检查点后压缩 journal；
没有每事件全盘扫描，也不持久化每次被过滤的原文。崩溃可能损失最近候选/计数，
降级不能补回已过滤的原文，不承诺精确一次或完整历史取证。

## 诊断与上传

doctor 展示 exec、file、network、risk 的独立状态；Windows 对应
exec-learning/status、file-learning/status、network-learning/status、risk-learning/status。
Linux 保留 learning/status 和 file-learning/status。
filtering_active 需要健康输入、非 shadow、非空有效名单；learning 与 enforcing 都可过滤。
状态检查只读认证检查点和最多 128 KiB 摘要尾部，不抢运行锁；检查点最多落后 60 秒。
启动后旧/缺失摘要不构成过滤就绪证据。

现有 SaaS behavior_learning 心跳仍代表 exec 主基线，不代表其余独立名单。
保持默认三分钟心跳。Gateway 需 0.6.0-rc.72+ 接受 learning + filtering_active，
工作台 rc.112+ 支持显示；先发布兼容服务端，再启用新版 Agent。

Linux/Windows 进程、文件、连接的摘要仍写日志目录的 behavior-learning.log。
Linux exec 原文的 decision_reason 表示本次学习/输出原因，例如 learning、shadow、
baseline_miss 或故障原因，不再因命令不完整而拒绝候选。新增可选 command_evidence_reason
保留适配器诊断，例如 incomplete_or_truncated_command；该字段不参与匹配，也不影响计数。
原有 command_truncated 等已采集字段仍保留；缺失该字段不能被当作完整参数的证明。
按 baseline_id/source_event_type 分开统计；摘要为 behavior_summary 或 behavior_learning_status，
不能作为原始 host_exec 事件或构造 PID 进程树。fingerprint_version：Linux exec=2，
file=3，0.3.83 Windows exec/network/PowerShell=4；不再生成祖先补发。
完整计数满足 observed_count=suppressed_count+original_emitted_count（晋级前原文不重计），
按 summary_id 去重；counter_complete=false/重启缺口不能视为完整次数。

ES 使用既有 behavior-learning 文件绑定、摘要索引和 keyword 字段映射；
SLS/Logtail 需绑定 behavior-learning.log 到现有自定义标识机器组及摘要 Logstore，
参考 logtail/behavior-learning.example.json。托管 Windows 安装需签名采集清单包含摘要。
学习能力不证明日志已经上传，部署后须核验本地和 ES/SLS 的原文、摘要及状态。

## 验证与限制

```bash
make check
go test ./pkg/behaviorlearning ./internal/windowsevidence ./pkg/windowseventlogriskjson
go test ./pkg/behaviorlearning -run '^$' -bench BenchmarkSimpleExecKnown -benchmem
```

回归覆盖缺少 EXECVE 的失败调用、截断命令候选和诊断分离、其他事件完整性门槛隔离，
以及四/五次边界、窗口过期、精确字段变化、去重、冻结、shadow、持久化错误、
迁移/正常重启、GUID 复用、文件/网络缓存上限和完整脚本/分片计数。
跨平台构建不替代真实 Linux audit/eBPF、Windows Event Log/SCM、24 小时学习和 ES/SLS 入库验收。
源码更新不等于已打包或部署。
