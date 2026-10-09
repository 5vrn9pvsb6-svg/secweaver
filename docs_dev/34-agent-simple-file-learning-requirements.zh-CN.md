# Agent 文件事件简化学习需求

状态：按用户确认实施。适用版本：Agent 0.3.82。

## 范围与规则

- Linux audit `file_op`、Windows Sysmon 11/23 `file_op` 使用独立文件名单。
- 五个字段 `file_paths`、`listener_process`、`pid_name`、`exe`、`command_line` 全部精确相同，才是同一行为。路径数组顺序也必须相同，不折叠大小写、空格、路径或参数。
- Windows 的 `listener_process` 固定为空字符串；其余字段必须完整。命令行仅从同一主机、同一 ProcessGuid 的 Sysmon 1 获取，不使用 PID 猜测或以 exe 代替。
- 学习阶段滚动一小时内累计五个不同源事件即入名单，第五条立即过滤。前四条正常输出。默认累计健康学习一天，结束后冻结名单，不再新增。
- 不以文件动作、用户、文件后缀、目录、可执行文件哈希或进程父子关系增加准入条件。创建和删除只要五字段相同就合并计数。`host-persistence` 独立输出不受影响。
- 保留学习总开关、shadow、显式 event_types 范围和 generation 重学。Linux 未指定 event_types 时包含 exec/file_op；Windows 仍按安装参数选择事件范围。
- 缺字段、截断、关联不足、源异常、资源不足或持久化失败时输出原始事件。不因此扩大内核采集规则。

## 验收

验证第五条立即过滤、任一字段变化保留、一小时边界、源事件重放不累计、shadow、健康故障、停止/重启与日志游标；验证 Windows GUID 隔离和缺失命令行保留、Linux PATH/PROCTITLE 不完整保留。现有 exec、连接、PowerShell 和风险日志策略继续通过回归。
