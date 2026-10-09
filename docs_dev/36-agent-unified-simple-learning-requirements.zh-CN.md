# Agent 统一简化学习需求

**语言：** [English](36-agent-unified-simple-learning-requirements.md) | 简体中文

适用源码版本：Agent 0.3.83，承接 0.3.81 exec 与 0.3.82 file_op。
范围依据：用户要求“其他原来复杂的逻辑也这样修改成简单逻辑”。沿用已确定的
一小时五次、第五次立即过滤、默认首日学习以及 Windows 空 listener 约定。
不增加数据库、配置开关或部署操作；本地状态继续用受保护的 HMAC JSON/journal。

## 行为契约

| 流 | 匹配字段 |
| --- | --- |
| Windows exec | 空 listener_process、pid_name、exe、完整 command_line |
| Windows active_connect | 上述四字段、protocol、目标 IP、目标端口 |
| Windows PowerShell 4104 | provider、channel、user_sid、Path、完整脚本 SHA-256 |

所有流复用 Linux/file 已有的滚动一小时五次计数。第五次持久化成功即过滤，
学习继续接纳其他行为，24 个健康小时结束后仅冻结新增名单。空名单不因数量为零降级。
移除服务身份、父进程哈希、路径前缀、工具名单、内网/端口、CDXML 类以及旧频率模型门槛。
Windows 4688 在完整原生命令且配置源健康时也参与；Sysmon 1 不再要求 SHA256。
源记录 ID/GUID 用于去重/关联，不是稳定行为字段，不把缺字段视为通配。

Windows 网络目标使用标准化 dst_ip/dst_port，源端口/IP 不参与名单。
只学习源证明为主动发起的连接，保留协议/地址/端口完整性校验。
Windows 文件/网络通过同主机同 GUID 的原生创建事件补全命令，不查询实时 PID。
PowerShell 的空 Path 是合法内联来源；完整脚本计一次，分片不能独立凑次数。

## 保留边界

- Linux exec/file 已完成的精确策略保持兼容。Linux 网络原本没有学习适配器，继续输出原文。
- 认证、持久化、身份/服务变化、快照不新增白名单；已有 high/critical 风险告警继续输出。
- 缺字段、历史数据、源故障、输出或持久化错误、容量不足保留原文。
- 进程跟踪、原有风险分类、源采集范围、严重级别过滤、Agent 自身噪声排除保持原逻辑。
- shadow、总开关及用户配置保持原选择；不因升级自动启用原本关闭的功能。

## 迁移与验收

兼容且可读的旧 Windows exec/风险基线先归档再开启新学习，不导入旧条目。
网络基线独立创建，文件基线不重置。正常重启保留新名单；故障恢复仍需显式 generation。
状态和摘要必须标明 source_event_type；doctor 分开报告每份名单。SaaS 心跳保持 exec 主基线契约。

验收覆盖五次边界、窗口到期、字段变化、重复读取、冻结、shadow、持久化失败、
兼容迁移和正常重启，以及 Windows 原生形状数据从分类到本地 JSONL 的完整调用链。
本地 Go/竞态与跨平台编译是源码验收；真实 Windows/SLS/ES 和长期运行另需部署验收。
完整配置、资源限制与恢复步骤见[使用指南](../src/tools/secweaver-agent/docs/behavior-learning.zh-CN.md)。
