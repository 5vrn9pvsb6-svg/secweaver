# Agent 文件事件简化学习架构

对应[需求](34-agent-simple-file-learning-requirements.zh-CN.md)，Agent 0.3.82。

## 数据流与所有权

标准化 file_op → 平台完整性检查/命令行关联 → 五字段 HMAC → 滚动一小时计数 → 第五次先持久化再过滤 → behavior-learning.log 汇总。

复用 exec 的有界精确匹配引擎、持久化 journal、健康时钟和故障退回原始输出机制。文件状态位于原学习目录的 `file-operations/`；平台策略标识独立，旧文件名单不导入。exec/连接旧状态保持原策略，不重新学习。各引擎独立使用配置的资源上限。

Linux 复用现有有界队列和单 worker，不新增 audit reader。PATH 条目须齐全；完整 EXECVE 或未达到内核长度上限的 PROCTITLE 提供命令证据。PROCTITLE 是内核采样的进程标题，不等价于不可篡改的启动 argv；缺失、无效或达到截断上限时不学习。

Windows 复用统一 reader，使用独立的 host+ProcessGuid 命令缓存（最多 1024 项、4 MiB、空闲一小时淘汰）。只缓存真实 Sysmon 1 CommandLine，不受旧 exec 白名单资格限制；退出、重复/冲突创建、源连续性故障使关联失效。缓存不落盘，重启后缺关联的文件事件正常输出。mu 同时保护两个引擎与缓存，源游标落盘前必须完成两个引擎和原始/汇总输出的 checkpoint。

## 数据契约与状态

Windows file_op 保留 `path`，增加 `file_paths`、`pid_name`、固定空的 `listener_process`；有关联时补齐 command/command_line。文件匹配指纹版本为 3，不改变 Linux exec 版本 2。基线只保存键控摘要和计数，不保存命令原文。

两个引擎共用原汇总文件，文件记录标记 `source_event_type=file_op`。状态读取必须按 baseline 选择，防止文件汇总覆盖 exec 状态。主机现有学习心跳仍表示原 exec/活动基线；文件状态可通过独立状态读取与文件汇总检查。

## 故障与验证

队列溢出、源丢失和共享输出故障对两个引擎同时失效；单个文件状态初始化失败仅使文件保留原始输出。测试覆盖持久化失败、游标提交顺序、缓存容量/失效、精确字段与平台隔离。跨平台编译不能替代真实 Windows Sysmon 和 Linux audit 现场验收。

2026-10-08 源码验证：`make check`（fmt/vet、全量测试、竞态、Linux/Windows amd64 编译）、Linux/Windows arm64 编译、`make docs-check` 和 `git diff --check` 均通过。最后的适配器整理另通过 auditportexecmon/windowsevidence 竞态回归，含原生 audit 多记录拼接至学习入口测试。本次未生成发布包、部署或执行真实主机/SLS 验收。
